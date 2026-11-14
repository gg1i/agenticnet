"""MCP tools for Packet Tracer device CLI console automation and state inspection."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from netforge.adapters.router import transport_to_execution_backend
from netforge.core.enums import PermissionTier, StateLevel
from netforge.core.models import OperationResult
from netforge.mcp.registry import NetForgeRuntime


def _resolve_device_model(
    runtime: NetForgeRuntime, device_name: str, explicit_model: str | None
) -> str:
    if explicit_model:
        return explicit_model
    if runtime.manager.has_active_project:
        _, topo, _, _ = runtime.manager.require_active()
        if device_name in topo.model.devices:
            return topo.model.devices[device_name].model
    return "2911"


def register_cli_tools(server: MCPServer, runtime: NetForgeRuntime) -> None:
    """Register device CLI console tools (complementing `command_validate`)."""

    def console_open(
        device_name: str,
        model: str | None = None,
        disable_paging: bool = True,
    ) -> dict[str, Any]:
        """Attach to an open Packet Tracer device CLI window and stabilize its prompt."""

        def _run() -> OperationResult:
            resolved_model = _resolve_device_model(runtime, device_name, model)
            data = runtime.console.open_console(
                device_name,
                model=resolved_model,
                disable_paging=disable_paging,
            )
            sess = data["session"]
            backend = transport_to_execution_backend(str(sess.get("transport_name", "")))
            return OperationResult.ok(
                "console_open",
                (
                    f"Opened console for '{device_name}' ({resolved_model}) "
                    f"in mode '{sess['current_mode']}'."
                ),
                data=data,
                state_level=StateLevel.VERIFIED,
                execution_backend=backend,
                evidence=[f"Observed prompt: {sess.get('last_prompt')!r}"],
            )

        return runtime.execute(
            "console_open",
            PermissionTier.GUI_CONTROL,
            {"device_name": device_name, "model": model, "disable_paging": disable_paging},
            _run,
        )

    def console_execute(
        device_name: str,
        commands: list[str],
        model: str | None = None,
        target_mode: Literal[
            "preserve", "user_exec", "privileged_exec", "global_config"
        ] = "preserve",
        verification_commands: list[str] | None = None,
        stop_on_error: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Execute commands inside a device CLI console with prompt tracking and error detection."""

        def _run() -> OperationResult:
            resolved_model = _resolve_device_model(runtime, device_name, model)
            data = runtime.console.execute_commands(
                device_name,
                commands,
                model=resolved_model,
                target_mode=target_mode,
                verification_commands=verification_commands,
                stop_on_error=stop_on_error,
                dry_run=dry_run,
            )
            if dry_run:
                return OperationResult.ok(
                    "console_execute",
                    f"Dry-run prepared {len(commands)} CLI command(s) for '{device_name}'.",
                    data=data,
                    state_level=StateLevel.PLANNED,
                    execution_backend="offline_model",
                    evidence=["Validated device console profile without dispatching keystrokes."],
                )

            sess = data.get("session", {})
            backend = transport_to_execution_backend(str(sess.get("transport_name", "")))
            if not data.get("all_commands_succeeded", True):
                return OperationResult.fail(
                    "console_execute",
                    f"CLI errors detected while executing on '{device_name}': "
                    f"{data.get('failed_commands')}",
                    error_code="CLI_COMMAND_FAILED",
                    details=data,
                    remediation="Inspect failed_commands and transcripts in error details.",
                    state_level=StateLevel.EXECUTED,
                    execution_backend=backend,
                )

            lvl = StateLevel(data.get("state_level", StateLevel.EXECUTED.value))
            return OperationResult.ok(
                "console_execute",
                f"Executed {len(data.get('transcripts', []))} command(s) on '{device_name}'.",
                data=data,
                state_level=lvl,
                execution_backend=backend,
                warnings=data.get("warnings", []),
                evidence=data.get("evidence", []),
            )

        return runtime.execute(
            "console_execute",
            PermissionTier.CONFIGURATION,
            {
                "device_name": device_name,
                "command_count": len(commands),
                "target_mode": target_mode,
                "dry_run": dry_run,
            },
            _run,
        )

    def console_capture(device_name: str, model: str | None = None) -> dict[str, Any]:
        """Capture current CLI buffer output for `device_name` and detect prompt/errors."""

        def _run() -> OperationResult:
            resolved_model = _resolve_device_model(runtime, device_name, model)
            data = runtime.console.capture_output(device_name, model=resolved_model)
            backend = transport_to_execution_backend(runtime.console.transport.transport_name)
            return OperationResult.ok(
                "console_capture",
                f"Captured terminal buffer for '{device_name}' "
                f"(mode={data['parsed_prompt']['mode']}).",
                data=data,
                state_level=StateLevel.VERIFIED,
                execution_backend=backend,
                evidence=[f"Captured {len(data.get('captured_output', ''))} characters."],
            )

        return runtime.execute(
            "console_capture",
            PermissionTier.READ_ONLY,
            {"device_name": device_name},
            _run,
        )

    def console_inspect(device_name: str, model: str | None = None) -> dict[str, Any]:
        """Inspect console session state, active IOS mode, hostname, and interaction profile."""

        def _run() -> OperationResult:
            resolved_model = _resolve_device_model(runtime, device_name, model)
            data = runtime.console.inspect_session(device_name, model=resolved_model)
            sess = data["session"]
            lvl = StateLevel(data.get("state_level", StateLevel.PLANNED.value))
            backend = transport_to_execution_backend(str(sess.get("transport_name", "")))
            return OperationResult.ok(
                "console_inspect",
                f"Console session '{device_name}': open={sess['is_open']}, "
                f"mode={sess['current_mode']}.",
                data=data,
                state_level=lvl,
                execution_backend=backend,
                evidence=[f"Transport: {sess['transport_name']}."],
            )

        return runtime.execute(
            "console_inspect",
            PermissionTier.READ_ONLY,
            {"device_name": device_name},
            _run,
        )

    specs = [
        ("console_open", console_open, PermissionTier.GUI_CONTROL, False),
        ("console_execute", console_execute, PermissionTier.CONFIGURATION, False),
        ("console_capture", console_capture, PermissionTier.READ_ONLY, True),
        ("console_inspect", console_inspect, PermissionTier.READ_ONLY, True),
    ]
    for name, fn, tier, ro in specs:
        runtime.registry.register_tool(
            server,
            name=name,
            category="cli",
            permission_tier=tier,
            description=(fn.__doc__ or name).strip(),
            fn=fn,
            read_only=ro,
            idempotent=ro,
        )
