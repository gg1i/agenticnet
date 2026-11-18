"""Tool registry, uniform execution wrapper, audit logging, and capability manifest."""

from __future__ import annotations

import logging
import platform
import threading
import time
from collections.abc import Callable
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from agenticnet import __schema_version__, __version__
from agenticnet.adapters.base import GuiBackend, ScriptBackend
from agenticnet.adapters.router import BackendRouter
from agenticnet.console.engine import DeviceConsoleEngine
from agenticnet.console.transport import ConsoleTransport, WindowsGuiConsoleTransport
from agenticnet.core.enums import OperationStatus, PermissionTier
from agenticnet.core.exceptions import (
    AgenticNetError,
    ApprovalRequiredError,
    PermissionDeniedError,
)
from agenticnet.core.models import ExecutionLogEntry, OperationResult, new_operation_id
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.devices import DEFAULT_CATALOG, DeviceCatalog
from agenticnet.diagnostics.engine import DiagnosticsEngine
from agenticnet.gui.adapter import create_gui_backend
from agenticnet.gui.calibration import CalibrationManager
from agenticnet.gui.safety import EmergencyStopController
from agenticnet.gui.windows_backend import WindowsGuiBackend
from agenticnet.ios.generators import IOSGenerator
from agenticnet.mcp.profiles import TOOL_PROFILE_NAMES, resolve_tool_profile
from agenticnet.security.permissions import PermissionGuard, PermissionPolicy
from agenticnet.security.redaction import redact_cli_text, redact_secrets
from agenticnet.simulation.engine import SimulationEngine
from agenticnet.storage.project_manager import ProjectManager

logger = logging.getLogger("agenticnet.mcp")


class ToolDescriptor(BaseModel):
    """Machine-readable metadata for a registered AgenticNet tool."""

    name: str
    category: str
    permission_tier: PermissionTier
    description: str
    status: str = "stable"
    read_only: bool = False
    destructive: bool = False


class ToolRegistry:
    """Tracks registered tools, resources, and prompts to emit a capability manifest."""

    def __init__(self, allowed_tool_names: frozenset[str] | None = None) -> None:
        self.allowed_tool_names = allowed_tool_names
        self.tools: list[ToolDescriptor] = []
        self.resource_uris: list[str] = []
        self.prompt_names: list[str] = []
        self._allowed_tool_names = allowed_tool_names

    def register_tool(
        self,
        server: MCPServer,
        *,
        name: str,
        category: str,
        permission_tier: PermissionTier,
        description: str,
        fn: Callable[..., dict[str, Any]],
        status: str = "stable",
        read_only: bool = False,
        destructive: bool = False,
        idempotent: bool = False,
    ) -> None:
        """Register a tool on both the MCPServer and the AgenticNet manifest registry."""
        if self._allowed_tool_names is not None and name not in self._allowed_tool_names:
            return
        annotations = ToolAnnotations(
            title=name,
            readOnlyHint=read_only,
            destructiveHint=destructive,
            idempotentHint=idempotent,
            openWorldHint=False,
        )
        server.add_tool(
            fn,
            name=name,
            title=name,
            description=description,
            annotations=annotations,
            meta={
                "category": category,
                "permission_tier": permission_tier.value,
                "status": status,
            },
            structured_output=True,
        )
        self.tools.append(
            ToolDescriptor(
                name=name,
                category=category,
                permission_tier=permission_tier,
                description=description,
                status=status,
                read_only=read_only,
                destructive=destructive,
            )
        )


class AgenticNetRuntime:
    """Shared runtime container injected into all AgenticNet tools, resources, and prompts."""

    def __init__(
        self,
        settings: AgenticNetSettings | None = None,
        *,
        catalog: DeviceCatalog | None = None,
        gui_backend: GuiBackend | None = None,
        console_transport: ConsoleTransport | None = None,
        script_backend: ScriptBackend | None = None,
        safety: EmergencyStopController | None = None,
    ) -> None:
        self.settings = settings or AgenticNetSettings.from_env()
        self.catalog = catalog or DEFAULT_CATALOG
        self.manager = ProjectManager(self.settings, catalog=self.catalog)
        self.ios = IOSGenerator(catalog=self.catalog)
        existing_safety = getattr(script_backend, "safety", None)
        self.safety = (
            safety
            or (existing_safety if isinstance(existing_safety, EmergencyStopController) else None)
            or EmergencyStopController()
        )
        self._exec_lock = threading.RLock()
        self.calibration = CalibrationManager(self.settings)
        self.gui: GuiBackend = gui_backend or create_gui_backend(
            self.settings, calibration=self.calibration, safety=self.safety
        )
        pt_gui = self.gui if isinstance(self.gui, WindowsGuiBackend) else None
        fallback_console = console_transport or (
            WindowsGuiConsoleTransport(pt_gui)
            if pt_gui is not None and platform.system() == "Windows"
            else None
        )
        self.script: ScriptBackend | None = script_backend
        if self.script is not None and hasattr(self.script, "safety"):
            self.script.safety = self.safety
        self.router = BackendRouter(
            script_backend=script_backend,
            gui_backend=self.gui,
            fallback_console=fallback_console,
        )
        self.console = DeviceConsoleEngine(
            catalog=self.catalog,
            transport=self.router.console_transport,
            gui_backend=pt_gui,
        )
        self.simulation = SimulationEngine(
            gui_backend=self.gui,
            console_engine=self.console,
            catalog=self.catalog,
        )
        self.diagnostics = DiagnosticsEngine(
            console_engine=self.console,
            simulation_engine=self.simulation,
        )
        policy = PermissionPolicy.from_profile(
            self.settings.permission_profile,
            require_destructive_confirmation=self.settings.require_destructive_confirmation,
        )
        if "allowed_tiers" in self.settings.model_fields_set:
            policy.allowed_tiers = set(self.settings.allowed_tiers)
        self.guard = PermissionGuard(policy)
        self.registry = ToolRegistry(
            allowed_tool_names=resolve_tool_profile(self.settings.tool_profile)
        )

    def execute(
        self,
        tool_name: str,
        tier: PermissionTier,
        params: dict[str, Any],
        handler: Callable[[], OperationResult],
        *,
        confirm: bool = False,
        destructive_reason: str | None = None,
    ) -> dict[str, Any]:
        """Run a tool handler through permission checks, exception mapping, and audit logging."""
        op_id = new_operation_id()
        start = time.perf_counter()
        project_id = self.manager.active_project_id

        with self._exec_lock:
            try:
                self.guard.check(
                    tool_name,
                    tier,
                    confirmed=confirm,
                    destructive_reason=destructive_reason,
                )
                result = handler()
                result.operation_id = op_id
                if (
                    result.success
                    and tier != PermissionTier.READ_ONLY
                    and tool_name not in {"project_close", "project_save"}
                ):
                    try:
                        self.manager.persist_active_if_open()
                    except Exception:
                        logger.warning(
                            "Failed to auto-persist active project after %s",
                            tool_name,
                            exc_info=True,
                        )
            except ApprovalRequiredError as exc:
                result = OperationResult.fail(
                    tool_name,
                    exc.message,
                    error_code=exc.error_code,
                    details=exc.details,
                    remediation=exc.remediation,
                    status=OperationStatus.APPROVAL_REQUIRED,
                    operation_id=op_id,
                )
            except PermissionDeniedError as exc:
                result = OperationResult.fail(
                    tool_name,
                    exc.message,
                    error_code=exc.error_code,
                    details=exc.details,
                    remediation=exc.remediation,
                    status=OperationStatus.BLOCKED,
                    operation_id=op_id,
                )
            except AgenticNetError as exc:
                result = OperationResult.fail(
                    tool_name,
                    exc.message,
                    error_code=exc.error_code,
                    details=exc.details,
                    remediation=exc.remediation,
                    status=OperationStatus.FAILED,
                    operation_id=op_id,
                )
            except Exception as exc:  # pragma: no cover - defensive boundary
                logger.exception("Unhandled error in MCP tool %s", tool_name)
                result = OperationResult.fail(
                    tool_name,
                    f"Unexpected internal error: {exc}",
                    error_code="INTERNAL_ERROR",
                    status=OperationStatus.FAILED,
                    operation_id=op_id,
                )

            elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
            raw_audit: dict[str, Any] = dict(params)
            if "commands" not in raw_audit and isinstance(result.data, dict):
                if isinstance(result.data.get("commands_redacted"), list):
                    raw_audit["commands_summary"] = [
                        redact_cli_text(str(c)) for c in result.data["commands_redacted"][:25]
                    ]
                elif isinstance(result.data.get("transcripts"), list):
                    raw_audit["commands_summary"] = [
                        redact_cli_text(str(t.get("command", "")))
                        for t in result.data["transcripts"][:25]
                        if isinstance(t, dict) and t.get("command")
                    ]
            audit_params = redact_secrets(raw_audit)
            entry = ExecutionLogEntry(
                operation_id=op_id,
                project_id=self.manager.active_project_id or project_id,
                tool_name=tool_name,
                permission_tier=tier,
                status=result.status,
                state_level=result.state_level,
                summary=result.summary,
                params_redacted=(
                    audit_params if isinstance(audit_params, dict) else {"value": audit_params}
                ),
                duration_ms=elapsed_ms,
            )
            try:
                self.manager.store.append_execution_log(entry)
            except Exception:
                logger.warning("Failed to persist audit log for operation %s", op_id, exc_info=True)

            return result.model_dump(mode="json")

    def build_manifest(self) -> dict[str, Any]:
        """Generate a machine-readable capability manifest for the server."""
        categories: dict[str, int] = {}
        for t in self.registry.tools:
            categories[t.category] = categories.get(t.category, 0) + 1

        return {
            "name": "agenticnet",
            "version": __version__,
            "schema_version": __schema_version__,
            "disclaimer": (
                "AgenticNet is an independent open-source project and is not affiliated with "
                "or endorsed by Cisco Systems, Inc."
            ),
            "transports": {
                "default": "stdio",
                "supported": ["stdio", "streamable-http", "sse"],
            },
            "security": {
                "permission_profile": self.guard.policy.profile_name,
                "allowed_tiers": sorted(t.value for t in self.guard.policy.allowed_tiers),
                "require_destructive_confirmation": (
                    self.guard.policy.require_destructive_confirmation
                ),
            },
            "roadmap": {
                "current_phase": "Phase 5 — Full Multi-Engine Platform Release",
                "phases": {
                    "phase_1_core_foundation": "completed",
                    "phase_2_packet_tracer_adapter": "completed",
                    "phase_3_live_network_automation": "completed",
                    "phase_4_intelligent_diagnostics": "completed",
                    "phase_5_public_release": "completed",
                },
            },
            "tool_profile": self.settings.tool_profile,
            "available_tool_profiles": list(TOOL_PROFILE_NAMES),
            "tool_count": len(self.registry.tools),
            "categories": categories,
            "platform_core": {
                "architecture": "modular_adapter_core",
                "default_target_mode": "packet_tracer",
                "supported_target_modes": ["packet_tracer"],
                "state_levels": ["planned", "executed", "verified"],
                "execution_backends": [
                    "offline_model",
                    "script_backend",
                    "gui_backend",
                    "hybrid",
                ],
                "subsystems": [
                    "capability_registry",
                    "topology_and_ipam_engine",
                    "config_lifecycle_and_pre_apply_validator",
                    "execution_and_console_engine",
                    "diagnostics_and_verification_engine",
                    "sqlite_state_and_preferences_store",
                ],
            },
            "adapters": [
                {
                    "adapter_id": "cisco_packet_tracer",
                    "display_name": "Cisco Packet Tracer Adapter",
                    "status": "active",
                    "tested_simulator_version": "8.2.2",
                    "supported_modes": ["packet_tracer"],
                    "verified_model_count": len(self.catalog.list_profiles()),
                    "connection_requirements": {
                        "primary_bridge": (
                            "Packet Tracer 8.2.2+ with Script Module 'netforge_bridge.pts' "
                            "enabled On Startup over authenticated localhost HTTP IPC."
                        ),
                        "gui_fallback": (
                            "Unlocked Windows 10/11 desktop session (optional; required only "
                            "for Physical-tab or GUI-only dialogs)."
                        ),
                        "offline_mode": (
                            "Cross-platform (Windows, Linux, macOS) with zero external "
                            "simulator process required for planning, validation, and SQLite."
                        ),
                    },
                    "capabilities": [
                        "device_add_remove_move",
                        "link_create_delete_and_mdi_mdix_validation",
                        "ios_and_asa_cli_execution_with_paging_and_submodes",
                        "host_ipv4_dhcp_static_gateway_dns_configuration",
                        "copy_on_write_pkt_pka_lifecycle_and_live_hydration",
                        "live_cli_root_cause_diagnostics_and_self_repair",
                        "closed_loop_verify_lab_grade_lab_and_reversible_failure_drills",
                    ],
                    "limitations": [
                        "PT IOS-XE (4321/ISR4331) omits route-map, ip prefix-list, and PBR.",
                        "PT 3560-24PS omits NAT/PAT; 2960-24TT is Layer-2 only.",
                        "PT ASA (5505/5506-X) omits dynamic routing, HA failover, and IKEv2.",
                        "Server-PT services, WLC Web GUI, and Laptop NIC swaps require GUI mode.",
                        "Locked .pka assessments fail closed in grade_lab and use verify_lab.",
                    ],
                }
            ],
            "tools": [t.model_dump(mode="json") for t in self.registry.tools],
            "resources": list(self.registry.resource_uris),
            "prompts": list(self.registry.prompt_names),
            "supported_device_models": [
                {
                    "model": p.model,
                    "display_name": p.display_name,
                    "category": p.category.value,
                    "supports_ios_cli": p.supports_ios_cli
                    if hasattr(p, "supports_ios_cli")
                    else (self.catalog.capability_report(p.model).supports_ios_cli),
                }
                for p in self.catalog.list_profiles()
            ],
        }


class ToolBatchItem(BaseModel):
    """Generic helper model used when schemas reference small specs."""

    id: str = Field(default="")


# Backward-compatibility alias for pre-rename callers importing NetForgeRuntime.
NetForgeRuntime = AgenticNetRuntime
