"""MCP tools for Packet Tracer device CLI console automation and state inspection."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from agenticnet.adapters.router import transport_to_execution_backend
from agenticnet.adapters.script_bridge import HttpScriptBridgeBackend
from agenticnet.core.enums import PermissionTier, StateLevel
from agenticnet.core.exceptions import ValidationError
from agenticnet.core.models import OperationResult
from agenticnet.mcp.registry import AgenticNetRuntime


def _resolve_device_model(
    runtime: AgenticNetRuntime, device_name: str, explicit_model: str | None
) -> str:
    if explicit_model:
        return explicit_model
    if runtime.manager.has_active_project:
        _, topo, _, _ = runtime.manager.require_active()
        if device_name in topo.model.devices:
            return topo.model.devices[device_name].model
    return "2911"


def register_cli_tools(server: MCPServer, runtime: AgenticNetRuntime) -> None:
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
        device_name: str = "",
        commands: list[str] | None = None,
        model: str | None = None,
        target_mode: Literal[
            "preserve", "user_exec", "privileged_exec", "global_config"
        ] = "preserve",
        verification_commands: list[str] | None = None,
        stop_on_error: bool = True,
        dry_run: bool = False,
        batch_configs: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        """Execute commands inside one or multiple device CLI consoles with prompt tracking."""
        normalized_batch: dict[str, list[str]] = (
            {str(dev): list(cmds) for dev, cmds in batch_configs.items()}
            if batch_configs is not None
            else {}
        )
        cmd_list = list(commands or [])
        if batch_configs is not None:
            total_cmds = sum(len(v) for v in normalized_batch.values())
            exec_params: dict[str, Any] = {
                "batch_devices": sorted(normalized_batch.keys()),
                "command_count": total_cmds,
                "target_mode": target_mode,
                "dry_run": dry_run,
            }
        else:
            total_cmds = len(cmd_list)
            exec_params = {
                "device_name": device_name,
                "command_count": total_cmds,
                "target_mode": target_mode,
                "dry_run": dry_run,
            }

        def _run() -> OperationResult:
            if batch_configs is not None:
                if not normalized_batch:
                    raise ValidationError("batch_configs must map at least one device to commands.")
                resolved_models = {
                    dev: _resolve_device_model(runtime, dev, model) for dev in normalized_batch
                }

                def _exec_one(dev: str, cmds: list[str]) -> dict[str, Any]:
                    return runtime.console.execute_commands(
                        dev,
                        cmds,
                        model=resolved_models[dev],
                        target_mode=target_mode,
                        verification_commands=verification_commands,
                        stop_on_error=stop_on_error,
                        dry_run=dry_run,
                    )

                use_parallel = (
                    not dry_run
                    and len(normalized_batch) > 1
                    and runtime.router.has_live_script()
                    and isinstance(runtime.router.script_backend, HttpScriptBridgeBackend)
                )
                if use_parallel:
                    with ThreadPoolExecutor(max_workers=min(len(normalized_batch), 6)) as pool:
                        futures = {
                            dev: pool.submit(_exec_one, dev, cmds)
                            for dev, cmds in normalized_batch.items()
                        }
                        results_by_dev = {dev: fut.result() for dev, fut in futures.items()}
                else:
                    results_by_dev = {
                        dev: _exec_one(dev, cmds) for dev, cmds in normalized_batch.items()
                    }

                reports: dict[str, dict[str, Any]] = {}
                failed_devices: dict[str, list[str]] = {}
                all_warnings: list[str] = []
                all_evidence: list[str] = []
                backends_seen: list[str] = []
                for dev in normalized_batch:
                    rep = results_by_dev[dev]
                    reports[dev] = rep
                    sess = rep.get("session", {})
                    b_tag = transport_to_execution_backend(str(sess.get("transport_name", "")))
                    backends_seen.append(b_tag)
                    all_warnings.extend(rep.get("warnings", []))
                    all_evidence.extend(f"[{dev}] {ev}" for ev in rep.get("evidence", []))
                    if not dry_run and not rep.get("all_commands_succeeded", True):
                        failed_devices[dev] = list(rep.get("failed_commands", []))

                if dry_run:
                    return OperationResult.ok(
                        "console_execute",
                        (
                            f"Dry-run prepared {total_cmds} CLI command(s) across "
                            f"{len(normalized_batch)} device(s)."
                        ),
                        data={"dry_run": True, "batch_reports": reports},
                        state_level=StateLevel.PLANNED,
                        execution_backend="offline_model",
                        evidence=["Validated batch console profiles without dispatching commands."],
                    )

                final_backend = (
                    "script_backend"
                    if any(b == "script_backend" for b in backends_seen)
                    else (backends_seen[-1] if backends_seen else "offline_model")
                )
                batch_data: dict[str, Any] = {
                    "batch_reports": reports,
                    "devices": list(normalized_batch.keys()),
                    "all_commands_succeeded": len(failed_devices) == 0,
                    "failed_devices": failed_devices,
                    "warnings": all_warnings,
                    "evidence": all_evidence,
                }
                if failed_devices:
                    return OperationResult.fail(
                        "console_execute",
                        f"Batch CLI errors on device(s): {failed_devices}",
                        error_code="CLI_COMMAND_FAILED",
                        details=batch_data,
                        remediation="Inspect batch_reports and failed_devices in error details.",
                        state_level=StateLevel.EXECUTED,
                        execution_backend=final_backend,
                    )
                if runtime.router.watch_mode and final_backend == "script_backend":
                    runtime.router.record_watch_action(
                        "console_execute",
                        (
                            f"Configured {len(normalized_batch)} device(s) "
                            f"({total_cmds} total commands)."
                        ),
                        data=batch_data,
                        evidence=all_evidence,
                    )
                lvl = (
                    StateLevel.VERIFIED
                    if any(
                        r.get("state_level") == StateLevel.VERIFIED.value
                        for r in reports.values()
                    )
                    else StateLevel.EXECUTED
                )
                return OperationResult.ok(
                    "console_execute",
                    (
                        f"Executed {total_cmds} command(s) across "
                        f"{len(normalized_batch)} device(s)."
                    ),
                    data=batch_data,
                    state_level=lvl,
                    execution_backend=final_backend,
                    warnings=all_warnings,
                    evidence=all_evidence,
                )

            if not str(device_name).strip():
                raise ValidationError("Provide device_name and commands, or batch_configs.")

            resolved_model = _resolve_device_model(runtime, device_name, model)
            data = runtime.console.execute_commands(
                device_name,
                cmd_list,
                model=resolved_model,
                target_mode=target_mode,
                verification_commands=verification_commands,
                stop_on_error=stop_on_error,
                dry_run=dry_run,
            )
            if dry_run:
                return OperationResult.ok(
                    "console_execute",
                    f"Dry-run prepared {len(cmd_list)} CLI command(s) for '{device_name}'.",
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
            ev_list = list(data.get("evidence", []))
            if runtime.router.watch_mode and backend == "script_backend":
                runtime.router.record_watch_action(
                    "console_execute",
                    f"Executed {len(cmd_list)} CLI command(s) on '{device_name}'.",
                    data=data,
                    evidence=ev_list,
                )
            return OperationResult.ok(
                "console_execute",
                f"Executed {len(data.get('transcripts', []))} command(s) on '{device_name}'.",
                data=data,
                state_level=lvl,
                execution_backend=backend,
                warnings=data.get("warnings", []),
                evidence=ev_list,
            )

        return runtime.execute(
            "console_execute",
            PermissionTier.CONFIGURATION,
            exec_params,
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
