"""Tool registry, uniform execution wrapper, audit logging, and capability manifest."""

from __future__ import annotations

import logging
import platform
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
from agenticnet.security.redaction import redact_secrets
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
    ) -> None:
        self.settings = settings or AgenticNetSettings.from_env()
        self.catalog = catalog or DEFAULT_CATALOG
        self.manager = ProjectManager(self.settings, catalog=self.catalog)
        self.ios = IOSGenerator(catalog=self.catalog)
        self.safety = EmergencyStopController()
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
        self.guard = PermissionGuard(
            PermissionPolicy(
                profile_name=self.settings.permission_profile,
                allowed_tiers=set(self.settings.allowed_tiers),
                require_destructive_confirmation=self.settings.require_destructive_confirmation,
            )
        )
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

        try:
            self.guard.check(
                tool_name,
                tier,
                confirmed=confirm,
                destructive_reason=destructive_reason,
            )
            result = handler()
            result.operation_id = op_id
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
        entry = ExecutionLogEntry(
            operation_id=op_id,
            project_id=self.manager.active_project_id or project_id,
            tool_name=tool_name,
            permission_tier=tier,
            status=result.status,
            state_level=result.state_level,
            summary=result.summary,
            params_redacted=redact_secrets(params),
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
