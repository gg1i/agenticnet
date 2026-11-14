"""MCP tools for Packet Tracer GUI detection, calibration, capture, input, and recovery."""

from __future__ import annotations

from contextlib import suppress
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from netforge.core.enums import PermissionTier, StateLevel
from netforge.core.exceptions import ValidationError
from netforge.core.models import OperationResult
from netforge.mcp.registry import NetForgeRuntime


def _call_with_optional(fn: Any, *args: Any, optional: dict[str, Any], **kwargs: Any) -> Any:
    """Invoke a backend method with newer optional kwargs, falling back cleanly for fakes."""
    active = {k: v for k, v in optional.items() if v is not None}
    try:
        return fn(*args, **kwargs, **active)
    except TypeError:
        return fn(*args, **kwargs)


def register_gui_tools(server: MCPServer, runtime: NetForgeRuntime) -> None:
    """Register Packet Tracer GUI automation and safety tools."""

    def packet_tracer_detect() -> dict[str, Any]:
        """Detect Cisco Packet Tracer installation, running process, DPI, window, and dialogs."""

        def _run() -> OperationResult:
            data = runtime.gui.detect_application()
            status_str = "running" if data.get("running") else "not running"
            summary = f"Packet Tracer binary detected={data.get('detected_binary')}, {status_str}."
            return OperationResult.ok(
                "packet_tracer_detect",
                summary,
                data=data,
                state_level=StateLevel.VERIFIED,
                execution_backend="gui_backend",
                evidence=["Queried local OS process table and visible application windows."],
            )

        return runtime.execute("packet_tracer_detect", PermissionTier.READ_ONLY, {}, _run)

    def packet_tracer_launch(
        executable_path: str | None = None,
        project_file: str | None = None,
        wait_seconds: float = 15.0,
        background: bool | None = None,
    ) -> dict[str, Any]:
        """Launch Cisco Packet Tracer (or attach if already running) and wait for window."""

        def _run() -> OperationResult:
            data = _call_with_optional(
                runtime.gui.launch_application,
                executable_path,
                optional={"background": background},
                project_file=project_file,
                wait_seconds=wait_seconds,
            )
            state_lvl = StateLevel(data.get("state_level", StateLevel.EXECUTED.value))
            summary = (
                "Attached to already-running Cisco Packet Tracer instance."
                if data.get("already_running")
                else f"Launched Cisco Packet Tracer (PID={data.get('pid')})."
            )
            return OperationResult.ok(
                "packet_tracer_launch",
                summary,
                data=data,
                state_level=state_lvl,
                execution_backend="gui_backend",
                evidence=["Inspected process launch and Win32 window state."],
            )

        return runtime.execute(
            "packet_tracer_launch",
            PermissionTier.GUI_CONTROL,
            {"executable_path": executable_path, "project_file": project_file},
            _run,
        )

    def gui_screenshot(
        output_path: str | None = None,
        full_window: bool = False,
        focus_first: bool = False,
        dialog_title: str | None = None,
    ) -> dict[str, Any]:
        """Capture a screenshot of Packet Tracer or a dialog offscreen and inspect layout."""

        def _run() -> OperationResult:
            data = _call_with_optional(
                runtime.gui.capture_screenshot,
                optional={
                    "full_window": full_window,
                    "focus_first": focus_first,
                    "dialog_title": dialog_title,
                },
                output_path=output_path,
            )
            return OperationResult.ok(
                "gui_screenshot",
                f"Captured Packet Tracer screenshot to {data.get('screenshot_path')}.",
                data=data,
                state_level=StateLevel.VERIFIED,
                execution_backend="gui_backend",
                evidence=[f"PNG saved at {data.get('screenshot_path')}."],
            )

        return runtime.execute(
            "gui_screenshot",
            PermissionTier.READ_ONLY,
            {
                "output_path": output_path,
                "full_window": full_window,
                "dialog_title": dialog_title,
            },
            _run,
        )

    def gui_calibrate(profile_id: str = "default") -> dict[str, Any]:
        """Calibrate normalized Packet Tracer UI coordinates against live window geometry/DPI."""

        def _run() -> OperationResult:
            data = runtime.gui.calibrate(profile_id=profile_id)
            prof = data["profile"]
            return OperationResult.ok(
                "gui_calibrate",
                f"Saved calibration profile '{profile_id}' "
                f"({prof['client_width']}x{prof['client_height']} @ {prof['dpi']} DPI).",
                data=data,
                state_level=StateLevel.VERIFIED,
                execution_backend="gui_backend",
                evidence=[f"Calibration profile written to {data.get('profile_path')}."],
            )

        return runtime.execute(
            "gui_calibrate",
            PermissionTier.GUI_CONTROL,
            {"profile_id": profile_id},
            _run,
        )

    def gui_click(
        x: int | None = None,
        y: int | None = None,
        nx: float | None = None,
        ny: float | None = None,
        anchor_name: str | None = None,
        button: Literal["left", "right", "middle"] = "left",
        clicks: int = 1,
        dry_run: bool = False,
        background: bool | None = None,
        restore_focus: bool = False,
    ) -> dict[str, Any]:
        """Click an anchor, normalized `(nx, ny)`, or screen `(x, y)` inside Packet Tracer."""

        def _run() -> OperationResult:
            data = _call_with_optional(
                runtime.gui.click,
                optional={"background": background, "restore_focus": restore_focus},
                x=x,
                y=y,
                nx=nx,
                ny=ny,
                anchor_name=anchor_name,
                button=button,
                clicks=clicks,
                dry_run=dry_run,
            )
            lvl = StateLevel(data.get("state_level", StateLevel.EXECUTED.value))
            verb = "Planned dry-run" if dry_run else "Executed"
            return OperationResult.ok(
                "gui_click",
                f"{verb} {button} click x{clicks} at ({data['screen_x']}, {data['screen_y']}).",
                data=data,
                state_level=lvl,
                execution_backend="gui_backend",
                evidence=[f"Resolved via {data.get('resolution_source')}."],
            )

        return runtime.execute(
            "gui_click",
            PermissionTier.GUI_CONTROL,
            {
                "x": x,
                "y": y,
                "nx": nx,
                "ny": ny,
                "anchor_name": anchor_name,
                "background": background,
                "dry_run": dry_run,
            },
            _run,
        )

    def gui_keypress(
        keys: str,
        text: str | None = None,
        dry_run: bool = False,
        confirm: bool = False,
        background: bool | None = None,
        restore_focus: bool = False,
    ) -> dict[str, Any]:
        """Send a key chord (e.g. 'ctrl+s', 'enter') or text input to Packet Tracer."""

        def _run() -> OperationResult:
            data = _call_with_optional(
                runtime.gui.keypress,
                keys,
                optional={
                    "confirm": confirm,
                    "background": background,
                    "restore_focus": restore_focus,
                },
                text=text,
                dry_run=dry_run,
            )
            lvl = StateLevel(data.get("state_level", StateLevel.EXECUTED.value))
            verb = "Planned dry-run" if dry_run else "Sent"
            return OperationResult.ok(
                "gui_keypress",
                f"{verb} key input '{keys}' (text_length={data.get('text_length', 0)}).",
                data=data,
                state_level=lvl,
                execution_backend="gui_backend",
                evidence=[f"Key chord validated ({keys})."],
            )

        return runtime.execute(
            "gui_keypress",
            PermissionTier.GUI_CONTROL,
            {"keys": keys, "has_text": bool(text), "dry_run": dry_run},
            _run,
            confirm=confirm,
        )

    def gui_state_inspect() -> dict[str, Any]:
        """Inspect live Packet Tracer window state, open modal dialogs, calibration, and abort."""

        def _run() -> OperationResult:
            data = runtime.gui.inspect_state()
            report = data["report"]
            return OperationResult.ok(
                "gui_state_inspect",
                f"PT running={report['running']}, dialogs={len(report['dialogs'])}, "
                f"calibrated={report['calibration_loaded']}.",
                data=data,
                state_level=StateLevel.VERIFIED,
                execution_backend="gui_backend",
                warnings=report.get("warnings", []),
                evidence=["Inspected Win32 windows, child popups, and calibration store."],
            )

        return runtime.execute("gui_state_inspect", PermissionTier.READ_ONLY, {}, _run)

    def gui_recover(
        strategy: Literal[
            "dismiss_dialog",
            "emergency_stop",
            "reset_abort",
            "discard_changes",
            "force_close_dialogs",
        ] = "dismiss_dialog",
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Recover from modal dialogs or arm/reset emergency automation stop."""

        def _run() -> OperationResult:
            data = runtime.gui.recover(strategy=strategy, confirm=confirm)
            lvl = StateLevel(data.get("state_level", StateLevel.EXECUTED.value))
            return OperationResult.ok(
                "gui_recover",
                f"Executed GUI recovery strategy '{strategy}'.",
                data=data,
                state_level=lvl,
                execution_backend="gui_backend",
                evidence=[f"Recovery strategy '{strategy}' completed."],
            )

        return runtime.execute(
            "gui_recover",
            PermissionTier.GUI_CONTROL,
            {"strategy": strategy, "confirm": confirm},
            _run,
            confirm=confirm,
        )

    def gui_batch(
        actions: list[dict[str, Any]],
        background: bool | None = None,
        restore_focus: bool = True,
        stop_on_error: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Execute a sequence of calibrated GUI actions in one low-latency batch."""

        def _run() -> OperationResult:
            batch_fn = getattr(runtime.gui, "execute_batch", None)
            if batch_fn is None:
                raise ValidationError("Configured GUI backend does not support batch execution.")
            data = batch_fn(
                actions,
                background=background,
                restore_focus=restore_focus,
                stop_on_error=stop_on_error,
                dry_run=dry_run,
            )
            lvl = StateLevel(data.get("state_level", StateLevel.EXECUTED.value))
            verb = "Planned" if dry_run else "Executed"
            return OperationResult.ok(
                "gui_batch",
                f"{verb} GUI batch ({data.get('completed_steps')}/{data.get('total_steps')} "
                f"steps in {data.get('elapsed_ms', 0)}ms).",
                data=data,
                state_level=lvl,
                execution_backend="gui_backend",
                evidence=[
                    f"background={data.get('background')}, failed={data.get('failed_steps', 0)}."
                ],
            )

        return runtime.execute(
            "gui_batch",
            PermissionTier.GUI_CONTROL,
            {
                "action_count": len(actions),
                "background": background,
                "restore_focus": restore_focus,
                "dry_run": dry_run,
            },
            _run,
        )

    def gui_attach_ip_phone_power(
        device_name: str = "IP_PHONE1",
        canvas_x: float | None = None,
        canvas_y: float | None = None,
        close_dialog: bool = True,
        restore_focus: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Attach AC power adapter onto a 7960 IP Phone in Packet Tracer's Physical tab.

        Status: experimental: not yet validated by the 5-attempt live protocol.
        """

        def _run() -> OperationResult:
            fn = getattr(runtime.gui, "attach_ip_phone_power", None)
            if fn is None:
                raise ValidationError(
                    "Configured GUI backend does not support IP Phone power-adapter attachment."
                )

            resolved_x, resolved_y = canvas_x, canvas_y
            pt_title = device_name
            with suppress(Exception):
                pt_title = runtime.router.resolve_pt_device_name(device_name)

            if resolved_x is None or resolved_y is None:
                with suppress(Exception):
                    _, topo, _, _ = runtime.manager.require_active()
                    node = topo.model.devices.get(device_name)
                    if node is not None:
                        if resolved_x is None:
                            resolved_x = float(node.position.x)
                        if resolved_y is None:
                            resolved_y = float(node.position.y)

            data = fn(
                device_name=device_name,
                pt_device_title=pt_title,
                canvas_x=500.0 if resolved_x is None else float(resolved_x),
                canvas_y=180.0 if resolved_y is None else float(resolved_y),
                close_dialog=close_dialog,
                restore_focus=restore_focus,
                dry_run=dry_run,
            )
            lvl = StateLevel(data.get("state_level", StateLevel.EXECUTED.value))
            verb = "Planned dry-run" if dry_run else "Dragged 7960 AC power adapter onto"
            return OperationResult.ok(
                "gui_attach_ip_phone_power",
                f"{verb} '{data.get('pt_device_title', device_name)}' Physical-tab DC socket.",
                data=data,
                state_level=lvl,
                execution_backend="gui_backend",
                evidence=[
                    f"HWND={data.get('hwnd')}, DPI={data.get('dpi')}, "
                    f"socket_roi_diff={data.get('socket_roi_diff_ratio')}."
                ],
            )

        return runtime.execute(
            "gui_attach_ip_phone_power",
            PermissionTier.GUI_CONTROL,
            {
                "device_name": device_name,
                "canvas_x": canvas_x,
                "canvas_y": canvas_y,
                "close_dialog": close_dialog,
                "dry_run": dry_run,
            },
            _run,
        )

    specs = [
        ("packet_tracer_detect", packet_tracer_detect, PermissionTier.READ_ONLY, True),
        ("packet_tracer_launch", packet_tracer_launch, PermissionTier.GUI_CONTROL, False),
        ("gui_screenshot", gui_screenshot, PermissionTier.READ_ONLY, True),
        ("gui_calibrate", gui_calibrate, PermissionTier.GUI_CONTROL, False),
        ("gui_click", gui_click, PermissionTier.GUI_CONTROL, False),
        ("gui_keypress", gui_keypress, PermissionTier.GUI_CONTROL, False),
        ("gui_state_inspect", gui_state_inspect, PermissionTier.READ_ONLY, True),
        ("gui_recover", gui_recover, PermissionTier.GUI_CONTROL, False),
        ("gui_batch", gui_batch, PermissionTier.GUI_CONTROL, False),
        (
            "gui_attach_ip_phone_power",
            gui_attach_ip_phone_power,
            PermissionTier.GUI_CONTROL,
            False,
        ),
    ]
    for name, fn, tier, ro in specs:
        runtime.registry.register_tool(
            server,
            name=name,
            category="gui",
            permission_tier=tier,
            description=(fn.__doc__ or name).strip(),
            fn=fn,
            read_only=ro,
            idempotent=ro,
        )
