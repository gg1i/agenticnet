"""Tests for GUI models, calibration, OpenCV visual matching, safety stops, and Win32 detect."""

from __future__ import annotations

import asyncio
import platform
from pathlib import Path
from typing import Any

import pytest
from PIL import Image, ImageDraw

from netforge.adapters.base import GuiBackend
from netforge.core.exceptions import (
    AdapterUnavailableError,
    ApprovalRequiredError,
    ValidationError,
)
from netforge.core.settings import NetForgeSettings
from netforge.gui.calibration import CalibrationManager
from netforge.gui.models import GuiDialogInfo, Rect, WindowInfo
from netforge.gui.safety import AutomationStopError, EmergencyStopController
from netforge.gui.vision import (
    compute_image_stats,
    detect_ui_regions_from_image,
    image_diff_ratio,
    match_template,
)
from netforge.gui.windows_backend import (
    DialogType,
    WindowsGuiBackend,
    _classify_dialog,
    _parse_key_chord,
    _parse_pt_window_title,
)
from netforge.mcp.server import create_mcp_server


class _FakeGuiBackend(GuiBackend):
    """Deterministic in-memory GUI backend verifying MCP GUI tools offline."""

    def __init__(self, settings: NetForgeSettings) -> None:
        self.calibration = CalibrationManager(settings)
        self.safety = EmergencyStopController()
        self.window = WindowInfo(
            hwnd=12345,
            pid=9999,
            process_name="PacketTracer.exe",
            title="Cisco Packet Tracer - campus.pkt*",
            window_rect=Rect(left=0, top=0, right=1600, bottom=900),
            client_rect=Rect(left=8, top=32, right=1592, bottom=892),
            dpi=120,
            scale_factor=1.25,
            active_file_hint="campus.pkt",
            has_unsaved_changes=True,
        )

    def detect_application(self) -> dict[str, Any]:
        return {
            "detected_binary": True,
            "executable_path": (
                "C:\\Program Files\\Cisco Packet Tracer 8.2.2\\bin\\PacketTracer.exe"
            ),
            "running": True,
            "processes": [{"pid": 9999, "name": "PacketTracer.exe"}],
            "window": self.window.model_dump(mode="json"),
            "dialogs": [],
            "calibration_loaded": self.calibration.active_profile is not None,
            "state_level": "verified",
        }

    def capture_screenshot(self, output_path: str | None = None, **_: Any) -> dict[str, Any]:
        return {
            "screenshot_path": output_path or "fake.png",
            "rect": self.window.client_rect.model_dump(),
            "stats": {"width": 1584, "height": 860, "looks_blank": False},
            "state_level": "verified",
        }

    def calibrate(self, *, profile_id: str = "default") -> dict[str, Any]:
        prof = self.calibration.create_from_window(self.window, profile_id=profile_id)
        return {
            "profile": prof.model_dump(mode="json"),
            "profile_path": str(self.calibration.calibration_dir / f"{profile_id}.json"),
            "state_level": "verified",
        }

    def click(
        self,
        x: int | None = None,
        y: int | None = None,
        *,
        nx: float | None = None,
        ny: float | None = None,
        anchor_name: str | None = None,
        button: str = "left",
        clicks: int = 1,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        self.safety.check_safe_to_act(live_input=False)
        sx, sy, src, verified = self.calibration.resolve_screen_point(
            self.window.client_rect,
            x=x,
            y=y,
            nx=nx,
            ny=ny,
            anchor_name=anchor_name,
        )
        return {
            "dry_run": dry_run,
            "screen_x": sx,
            "screen_y": sy,
            "button": button,
            "clicks": clicks,
            "resolution_source": src,
            "anchor_verified": verified,
            "state_level": "planned" if dry_run else "executed",
        }

    def inspect_state(self) -> dict[str, Any]:
        return {
            "report": {
                "detected": True,
                "running": True,
                "dialogs": [],
                "calibration_loaded": self.calibration.active_profile is not None,
                "warnings": [],
            },
            "state_level": "verified",
        }

    def keypress(
        self,
        keys: str,
        *,
        text: str | None = None,
        dry_run: bool = False,
        **_: Any,
    ) -> dict[str, Any]:
        return {
            "keys": keys,
            "text_length": len(text or ""),
            "dry_run": dry_run,
            "state_level": "planned" if dry_run else "executed",
        }

    def recover(self, *, strategy: str = "dismiss_dialog", confirm: bool = False) -> dict[str, Any]:
        return {"strategy": strategy, "confirm": confirm, "state_level": "executed"}

    def execute_batch(
        self,
        actions: list[dict[str, Any]],
        *,
        background: bool | None = None,
        restore_focus: bool = True,
        stop_on_error: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return {
            "completed_steps": len(actions),
            "total_steps": len(actions),
            "failed_steps": 0,
            "elapsed_ms": 1,
            "background": bool(background),
            "state_level": "planned" if dry_run else "executed",
        }


@pytest.mark.unit
def test_calibration_bounds_and_vision_template_matching(
    isolated_settings: NetForgeSettings,
    tmp_path: Path,
) -> None:
    cal = CalibrationManager(isolated_settings)
    win = WindowInfo(
        hwnd=1,
        pid=10,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=100, top=50, right=1700, bottom=950),
        client_rect=Rect(left=108, top=80, right=1692, bottom=942),
        dpi=144,
        scale_factor=1.5,
    )
    prof = cal.create_from_window(win, profile_id="hq-144dpi")
    assert prof.dpi == 144

    sx, sy, src, verified = cal.resolve_screen_point(
        win.client_rect, anchor_name="canvas_center", profile=prof
    )
    assert win.client_rect.contains(sx, sy)
    assert src == "anchor:canvas_center"
    assert verified is False

    with pytest.raises(ValidationError):
        cal.resolve_screen_point(win.client_rect, x=5, y=5)

    # Synthetic OpenCV template matching & visual diff check
    screen = Image.new("RGB", (600, 400), color=(235, 235, 235))
    draw = ImageDraw.Draw(screen)
    draw.rectangle([240, 150, 290, 200], fill=(40, 120, 200), outline=(10, 10, 10))
    tpl = screen.crop((240, 150, 290, 200))

    match = match_template(screen, tpl, anchor_name="router_icon", client_rect=win.client_rect)
    assert match is not None
    assert match.confidence >= 0.98
    assert match.screen_x == 108 + 265

    screen_after = screen.copy()
    ImageDraw.Draw(screen_after).rectangle([10, 10, 110, 110], fill=(200, 30, 30))
    assert image_diff_ratio(screen, screen_after) > 0.02
    assert compute_image_stats(screen).looks_blank is False
    assert detect_ui_regions_from_image(screen)["width"] == 600


@pytest.mark.unit
def test_emergency_stop_dialog_classification_and_key_chords() -> None:
    safety = EmergencyStopController(max_actions_per_minute=5)
    safety.request_stop("Emergency abort test")
    with pytest.raises(AutomationStopError):
        safety.check_safe_to_act(live_input=False)
    safety.reset()
    safety.check_safe_to_act(live_input=False)

    with pytest.raises(ApprovalRequiredError):
        safety.require_confirmation_for_risky_action("discard_changes", confirm=False)

    assert _classify_dialog("Skills for All Login") == DialogType.LOGIN_WALL
    assert _classify_dialog("Do you want to save changes?") == DialogType.SAVE_PROMPT
    assert _parse_pt_window_title("Cisco Packet Tracer - campus.pkt*") == ("campus.pkt", True)
    chord = _parse_key_chord("ctrl+s")
    assert [tok for tok, _ in chord] == ["ctrl", "s"]


@pytest.mark.unit
def test_mcp_gui_tools_with_fake_backend(isolated_settings: NetForgeSettings) -> None:
    fake = _FakeGuiBackend(isolated_settings)
    server, _ = create_mcp_server(isolated_settings, gui_backend=fake)

    async def _call() -> dict[str, Any]:
        cal_res = await server.call_tool("gui_calibrate", {"profile_id": "lab"})
        click_res = await server.call_tool(
            "gui_click", {"anchor_name": "canvas_center", "dry_run": True}
        )
        return {
            "cal": cal_res.structured_content,
            "click": click_res.structured_content,
        }

    out = asyncio.run(_call())
    assert out["cal"]["success"] is True
    assert out["cal"]["execution_backend"] == "gui_backend"
    assert out["click"]["state_level"] == "planned"
    assert out["click"]["data"]["dry_run"] is True
    assert out["click"]["execution_backend"] == "gui_backend"


@pytest.mark.unit
def test_all_gui_tools_report_gui_backend_never_offline_model(
    isolated_settings: NetForgeSettings,
) -> None:
    fake = _FakeGuiBackend(isolated_settings)
    server, _ = create_mcp_server(isolated_settings, gui_backend=fake)

    calls = [
        ("packet_tracer_detect", {}),
        ("gui_screenshot", {}),
        ("gui_calibrate", {"profile_id": "prov-test"}),
        ("gui_click", {"anchor_name": "canvas_center", "dry_run": True}),
        ("gui_keypress", {"keys": "enter", "dry_run": True}),
        ("gui_state_inspect", {}),
        ("gui_recover", {"strategy": "dismiss_dialog"}),
        ("gui_batch", {"actions": [{"action": "sleep", "seconds": 0.01}], "dry_run": True}),
    ]

    async def _run() -> list[tuple[str, dict[str, Any]]]:
        results: list[tuple[str, dict[str, Any]]] = []
        for name, args in calls:
            raw = await server.call_tool(name, args)
            assert raw.structured_content is not None
            results.append((name, dict(raw.structured_content)))
        return results

    for name, payload in asyncio.run(_run()):
        assert payload["success"] is True, f"{name} failed: {payload}"
        assert payload["execution_backend"] == "gui_backend", (
            f"{name} reported {payload['execution_backend']!r} instead of 'gui_backend'"
        )
        assert payload["execution_backend"] != "offline_model"


@pytest.mark.unit
def test_non_invasive_windows_packet_tracer_detection(
    isolated_settings: NetForgeSettings,
) -> None:
    if platform.system() != "Windows":
        pytest.skip("Win32 detection test applies to Windows only.")
    backend = WindowsGuiBackend(isolated_settings)
    det = backend.detect_application()
    assert "detected_binary" in det
    assert "running" in det


@pytest.mark.unit
def test_windows_backend_rejects_tiny_boot_window_calibration(
    isolated_settings: NetForgeSettings,
) -> None:
    tiny = {"client_rect": {"left": 0, "top": 0, "right": 1, "bottom": 1}}
    usable = {"client_rect": {"left": 0, "top": 29, "right": 1920, "bottom": 1019}}
    assert WindowsGuiBackend._has_usable_window_bounds(None) is False
    assert WindowsGuiBackend._has_usable_window_bounds(tiny) is False
    assert WindowsGuiBackend._has_usable_window_bounds(usable) is True

    backend = WindowsGuiBackend(isolated_settings)
    tiny_win = WindowInfo(
        hwnd=111,
        pid=222,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=0, top=0, right=1, bottom=1),
        client_rect=Rect(left=0, top=0, right=1, bottom=1),
        dpi=120,
        scale_factor=1.25,
    )
    backend._require_main_window = lambda: (tiny_win, [])  # type: ignore[method-assign]
    backend.focus_window = lambda hwnd=None: tiny_win  # type: ignore[method-assign]

    with pytest.raises(AdapterUnavailableError):
        backend.calibrate(profile_id="bad_boot")
    assert not (backend.calibration.calibration_dir / "bad_boot.json").exists()


@pytest.mark.unit
def test_click_focuses_dialog_when_point_is_inside_dialog(
    isolated_settings: NetForgeSettings,
) -> None:
    backend = WindowsGuiBackend(isolated_settings)
    main_win = WindowInfo(
        hwnd=100,
        pid=222,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=0, top=0, right=1920, bottom=1040),
        client_rect=Rect(left=0, top=29, right=1920, bottom=1020),
        dpi=120,
        scale_factor=1.25,
    )
    dlg = GuiDialogInfo(
        hwnd=999,
        title="Router0",
        class_name="Qt51516QWindowIcon",
        dialog_type=DialogType.DEVICE_WINDOW,
        rect=Rect(left=663, top=131, right=1556, bottom=1028),
    )
    focused: list[int | None] = []
    clicked: list[tuple[int, int]] = []
    backend._require_main_window = lambda: (main_win, [dlg])  # type: ignore[method-assign]
    backend.focus_window = lambda hwnd=None: (focused.append(hwnd) or main_win)  # type: ignore[method-assign]
    backend._send_mouse_click = lambda sx, sy, button="left", clicks=1: clicked.append((sx, sy))  # type: ignore[method-assign]

    backend.click(x=845, y=191, background=False)
    backend.click(x=200, y=200, background=False)
    assert focused == [999, 100]
    assert clicked == [(845, 191), (200, 200)]


@pytest.mark.unit
def test_gui_background_mode_defaults_true_and_env_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("NETFORGE_DATA_DIR", str(tmp_path / ".nf"))
    monkeypatch.delenv("NETFORGE_GUI_BACKGROUND", raising=False)
    assert NetForgeSettings.from_env().gui_background_mode is True

    monkeypatch.setenv("NETFORGE_GUI_BACKGROUND", "false")
    assert NetForgeSettings.from_env().gui_background_mode is False


@pytest.mark.unit
def test_click_background_mode_routes_postmessage_without_focus_steal(
    isolated_settings: NetForgeSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netforge.gui.windows_backend as wb

    backend = WindowsGuiBackend(isolated_settings)
    main_win = WindowInfo(
        hwnd=100,
        pid=222,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=0, top=0, right=1920, bottom=1040),
        client_rect=Rect(left=0, top=29, right=1920, bottom=1020),
        dpi=120,
        scale_factor=1.25,
    )
    dlg = GuiDialogInfo(
        hwnd=999,
        title="Router0",
        class_name="Qt51516QWindowIcon",
        dialog_type=DialogType.DEVICE_WINDOW,
        rect=Rect(left=663, top=131, right=1556, bottom=1028),
    )
    focused: list[int | None] = []
    posted: list[tuple[int, int, int]] = []
    backend._require_main_window = lambda: (main_win, [dlg])  # type: ignore[method-assign]
    backend.focus_window = lambda hwnd=None: (focused.append(hwnd) or main_win)  # type: ignore[method-assign]
    monkeypatch.setattr(wb.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        wb,
        "_post_mouse_click_to_hwnd",
        lambda hwnd, sx, sy, button="left", clicks=1: (posted.append((hwnd, sx, sy)) or hwnd),
    )

    res_dlg = backend.click(x=845, y=191)
    res_main = backend.click(x=200, y=200)
    assert focused == []
    assert posted == [(999, 845, 191), (100, 200, 200)]
    assert res_dlg["background"] is True
    assert res_main["target_hwnd"] == 100


@pytest.mark.unit
def test_execute_batch_supports_click_dialog_and_paste_lines(
    isolated_settings: NetForgeSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netforge.gui.windows_backend as wb

    backend = WindowsGuiBackend(isolated_settings)
    main_win = WindowInfo(
        hwnd=100,
        pid=222,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=0, top=0, right=1920, bottom=1040),
        client_rect=Rect(left=0, top=29, right=1920, bottom=1020),
        dpi=120,
        scale_factor=1.25,
    )
    dlg = GuiDialogInfo(
        hwnd=999,
        title="Router0",
        class_name="Qt51516QWindowIcon",
        dialog_type=DialogType.DEVICE_WINDOW,
        rect=Rect(left=663, top=131, right=1556, bottom=1028),
    )
    posted_clicks: list[tuple[int, int, int]] = []
    posted_text: list[tuple[int, str]] = []
    posted_keys: list[tuple[int, str]] = []
    backend._require_main_window = lambda: (main_win, [dlg])  # type: ignore[method-assign]
    monkeypatch.setattr(wb.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        wb,
        "_post_mouse_click_to_hwnd",
        lambda hwnd, sx, sy, button="left", clicks=1: (
            posted_clicks.append((hwnd, sx, sy)) or hwnd
        ),
    )
    monkeypatch.setattr(wb, "_resolve_focus_child_hwnd", lambda hwnd: hwnd + 1)
    monkeypatch.setattr(wb, "_post_text_to_hwnd", lambda hwnd, txt: posted_text.append((hwnd, txt)))
    monkeypatch.setattr(
        wb,
        "_post_key_chord_to_hwnd",
        lambda hwnd, chord: (posted_keys.append((hwnd, chord)) or [chord]),
    )

    out = backend.execute_batch(
        [
            {"op": "wait_dialog", "title_contains": "Router0", "timeout_s": 0.5},
            {
                "op": "click_dialog",
                "title_contains": "Router0",
                "offset_x": 182,
                "offset_y": 60,
                "delay_ms": 0,
            },
            {
                "op": "paste_lines",
                "title_contains": "Router0",
                "lines": ["enable", "conf t"],
                "delay_ms": 0,
            },
            {"op": "sleep", "ms": 0},
        ],
        background=True,
    )
    assert out["completed_steps"] == 4
    assert out["failed_steps"] == 0
    assert posted_clicks == [(999, 845, 191)]
    assert posted_text == [(1000, "enable"), (1000, "conf t")]
    assert posted_keys == [(1000, "enter"), (1000, "enter")]


@pytest.mark.unit
def test_gui_batch_tool_calls_backend_execute_batch(
    isolated_settings: NetForgeSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netforge.mcp.server import create_mcp_server

    server, runtime = create_mcp_server(isolated_settings)
    assert server.name == "netforge-mcp"
    captured: list[dict[str, Any]] = []

    def _fake_batch(
        actions: list[dict[str, Any]],
        *,
        background: bool | None = None,
        restore_focus: bool = True,
        stop_on_error: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        captured.append(
            {
                "actions": actions,
                "background": background,
                "restore_focus": restore_focus,
                "stop_on_error": stop_on_error,
                "dry_run": dry_run,
            }
        )
        return {
            "dry_run": dry_run,
            "background": True if background is None else background,
            "total_steps": len(actions),
            "completed_steps": len(actions),
            "failed_steps": 0,
            "elapsed_ms": 1.2,
            "results": [],
            "state_level": "planned" if dry_run else "executed",
        }

    monkeypatch.setattr(runtime.gui, "execute_batch", _fake_batch, raising=False)
    import json

    import anyio

    async def _invoke() -> dict[str, Any]:
        raw = await server.call_tool(
            "gui_batch",
            {"actions": [{"op": "sleep", "ms": 5}], "background": True, "dry_run": True},
        )
        blocks = raw[0] if isinstance(raw, tuple) else raw.content
        return json.loads(blocks[0].text)

    res = anyio.run(_invoke)
    assert res["success"] is True
    assert res["data"]["completed_steps"] == 1
    assert captured[0]["background"] is True
    assert captured[0]["dry_run"] is True


@pytest.mark.unit
def test_capture_screenshot_printwindow_background_returns_open_dialogs(
    isolated_settings: NetForgeSettings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from PIL import Image

    import netforge.gui.windows_backend as wb

    backend = WindowsGuiBackend(isolated_settings)
    main_win = WindowInfo(
        hwnd=100,
        pid=222,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=0, top=0, right=800, bottom=600),
        client_rect=Rect(left=0, top=20, right=800, bottom=580),
        dpi=96,
        scale_factor=1.0,
    )
    dlg = GuiDialogInfo(
        hwnd=999,
        title="Router0",
        class_name="Qt51516QWindowIcon",
        dialog_type=DialogType.DEVICE_WINDOW,
        rect=Rect(left=50, top=50, right=300, bottom=300),
    )
    backend._require_main_window = lambda: (main_win, [dlg])  # type: ignore[method-assign]
    monkeypatch.setattr(backend, "_require_windows", lambda: None)
    monkeypatch.setattr(wb, "_get_foreground_hwnd", lambda: 555)
    monkeypatch.setattr(
        wb,
        "_capture_window_printwindow",
        lambda hwnd, wrect, crect, full_window=False: Image.new("RGB", (800, 560), (40, 80, 120)),
    )

    out_png = tmp_path / "pw_test.png"
    res = backend.capture_screenshot(output_path=str(out_png), focus_first=False)
    assert out_png.exists()
    assert res["capture_mode"] == "printwindow_background"
    assert len(res["open_dialogs"]) == 1
    assert res["open_dialogs"][0]["title"] == "Router0"


@pytest.mark.unit
def test_capture_window_printwindow_crops_client_rect_with_mock_gdi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ctypes

    import netforge.gui.windows_backend as wb

    class _FakeUser32:
        def GetWindowDC(self, _hwnd: int) -> int:
            return 101

        def PrintWindow(self, _hwnd: int, _dc: int, _flags: int) -> int:
            return 1

        def ReleaseDC(self, _hwnd: int, _dc: int) -> int:
            return 1

    class _FakeGdi32:
        def CreateCompatibleDC(self, _dc: int) -> int:
            return 202

        def CreateDIBSection(
            self,
            _dc: int,
            _bmi: Any,
            _u: int,
            ptr_ref: Any,
            _sec: Any,
            _off: int,
        ) -> int:
            ctypes.cast(ptr_ref, ctypes.POINTER(ctypes.c_void_p))[0] = 0x1234
            return 303

        def SelectObject(self, _dc: int, _obj: int) -> int:
            return 404

        def DeleteObject(self, _obj: int) -> int:
            return 1

        def DeleteDC(self, _dc: int) -> int:
            return 1

    w, h = 20, 16
    raw_bgra = bytes([10, 20, 30, 255] * (w * h))

    class _FakeWindll:
        user32 = _FakeUser32()
        gdi32 = _FakeGdi32()

    monkeypatch.setattr(wb.ctypes, "windll", _FakeWindll(), raising=False)
    monkeypatch.setattr(wb.ctypes, "string_at", lambda _ptr, _n: raw_bgra)

    wrect = Rect(left=0, top=0, right=20, bottom=16)
    crect = Rect(left=2, top=3, right=18, bottom=15)
    cropped = wb._capture_window_printwindow(99, wrect, crect, full_window=False)
    assert cropped is not None
    assert cropped.size == (16, 12)
    assert cropped.getpixel((0, 0)) == (30, 20, 10)


@pytest.mark.unit
def test_ensure_usable_window_unminimizes_collapsed_pt_and_restores_focus(
    isolated_settings: NetForgeSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netforge.gui.windows_backend as wb

    backend = WindowsGuiBackend(isolated_settings)
    collapsed = WindowInfo(
        hwnd=100,
        pid=222,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=-32000, top=-32000, right=-31801, bottom=-31966),
        client_rect=Rect(left=-32000, top=-32000, right=-32000, bottom=-32000),
        dpi=120,
        scale_factor=1.25,
        is_minimized=True,
    )
    restored = WindowInfo(
        hwnd=100,
        pid=222,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=-9, top=-9, right=1929, bottom=1029),
        client_rect=Rect(left=0, top=29, right=1920, bottom=1020),
        dpi=120,
        scale_factor=1.25,
        is_minimized=False,
    )
    show_calls: list[tuple[int, int]] = []
    restored_fg: list[tuple[int, int]] = []
    states = iter([restored])

    class _FakeUser32:
        def ShowWindow(self, hwnd: int, cmd: int) -> int:
            show_calls.append((hwnd, cmd))
            return 1

    class _FakeWindll:
        user32 = _FakeUser32()

    monkeypatch.setattr(wb.platform, "system", lambda: "Windows")
    monkeypatch.setattr(wb.ctypes, "windll", _FakeWindll(), raising=False)
    monkeypatch.setattr(wb, "_get_foreground_hwnd", lambda: 777)
    monkeypatch.setattr(
        wb,
        "_restore_user_foreground_and_cursor",
        lambda fg, cursor, push_hwnd=0: restored_fg.append((fg, push_hwnd)),
    )
    monkeypatch.setattr(wb.time, "sleep", lambda _s: None)
    backend._require_main_window = lambda: (next(states, restored), [])  # type: ignore[method-assign]

    out_win, _ = backend._ensure_usable_window(collapsed, [], background=True)
    assert out_win.client_rect.width == 1920
    assert show_calls[0] == (100, wb._SW_SHOWNOACTIVATE)
    assert restored_fg == [(777, 100)]


@pytest.mark.unit
def test_send_unicode_text_batches_sendinput_per_line(
    isolated_settings: NetForgeSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netforge.gui.windows_backend as wb

    backend = WindowsGuiBackend(isolated_settings)
    send_counts: list[int] = []
    chords: list[str] = []

    class _FakeUser32:
        def SendInput(self, count: int, _inputs: Any, _size: int) -> int:
            send_counts.append(count)
            return count

    class _FakeWindll:
        user32 = _FakeUser32()

    monkeypatch.setattr(wb.ctypes, "windll", _FakeWindll(), raising=False)
    backend._send_key_chord = lambda c: (chords.append(c) or [c])  # type: ignore[method-assign]

    backend._send_unicode_text("enable\nconf t")
    assert send_counts == [12, 12]
    assert chords == ["enter"]


@pytest.mark.unit
def test_capture_screenshot_dialog_title_uses_dialog_printwindow(
    isolated_settings: NetForgeSettings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import netforge.gui.windows_backend as wb

    backend = WindowsGuiBackend(isolated_settings)
    main_win = WindowInfo(
        hwnd=100,
        pid=222,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=0, top=0, right=1920, bottom=1080),
        client_rect=Rect(left=0, top=29, right=1920, bottom=1020),
        dpi=120,
        scale_factor=1.25,
    )
    phone_dlg = GuiDialogInfo(
        hwnd=555,
        title="IP Phone0",
        class_name="Qt51516QWindowIcon",
        dialog_type=DialogType.DEVICE_WINDOW,
        rect=Rect(left=600, top=150, right=1400, bottom=950),
    )
    pw_calls: list[tuple[int, bool]] = []

    monkeypatch.setattr(backend, "_require_main_window", lambda: (main_win, [phone_dlg]))
    monkeypatch.setattr(wb, "_get_foreground_hwnd", lambda: 999)

    def _fake_pw(hwnd: int, _wr: Rect, _cr: Rect, *, full_window: bool = False) -> Image.Image:
        pw_calls.append((hwnd, full_window))
        return Image.new("RGB", (800, 800), (240, 240, 240))

    monkeypatch.setattr(wb, "_capture_window_printwindow", _fake_pw)

    out_png = tmp_path / "dlg.png"
    res = backend.capture_screenshot(str(out_png), dialog_title="IP Phone0")
    assert res["capture_mode"] == "printwindow_dialog_background"
    assert res["dialog_title"] == "IP Phone0"
    assert pw_calls == [(555, True)]
    assert out_png.exists()

    with pytest.raises(ValidationError):
        backend.capture_screenshot(str(out_png), dialog_title="NonExistent99")


@pytest.mark.unit
def test_execute_batch_drag_and_drag_dialog_dispatch(
    isolated_settings: NetForgeSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netforge.gui.windows_backend as wb

    backend = WindowsGuiBackend(isolated_settings)
    main_win = WindowInfo(
        hwnd=100,
        pid=222,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=0, top=0, right=1920, bottom=1080),
        client_rect=Rect(left=0, top=29, right=1920, bottom=1020),
        dpi=120,
        scale_factor=1.25,
    )
    phone_dlg = GuiDialogInfo(
        hwnd=777,
        title="IP Phone0",
        class_name="Qt51516QWindowIcon",
        dialog_type=DialogType.DEVICE_WINDOW,
        rect=Rect(left=500, top=100, right=1300, bottom=900),
    )
    bg_drags: list[tuple[int, int, int, int, int]] = []
    fg_drags: list[tuple[int, int, int, int]] = []
    restored: list[int] = []

    monkeypatch.setattr(wb.platform, "system", lambda: "Windows")
    monkeypatch.setattr(wb, "_get_foreground_hwnd", lambda: 888)
    monkeypatch.setattr(wb, "_get_cursor_pos", lambda: (10, 20))
    monkeypatch.setattr(
        wb,
        "_restore_user_foreground_and_cursor",
        lambda fg, _cur, push_hwnd=0: restored.append(fg),
    )
    monkeypatch.setattr(
        wb,
        "_post_mouse_drag_to_hwnd",
        lambda hwnd, sx, sy, ex, ey, **_kw: (bg_drags.append((hwnd, sx, sy, ex, ey)) or hwnd),
    )
    monkeypatch.setattr(backend, "_require_main_window", lambda: (main_win, [phone_dlg]))
    monkeypatch.setattr(backend, "_call_focus_window", lambda _h, **_kw: main_win)
    monkeypatch.setattr(
        backend,
        "drag",
        lambda sx, sy, ex, ey, **_kw: (fg_drags.append((sx, sy, ex, ey)) or {"ok": True}),
    )

    out = backend.execute_batch(
        [
            {
                "op": "drag_dialog",
                "title_contains": "IP Phone0",
                "from_x": 700,
                "from_y": 600,
                "to_x": 350,
                "to_y": 420,
                "delay_ms": 0,
            },
            {
                "op": "drag",
                "from_nx": 0.1,
                "from_ny": 0.2,
                "to_nx": 0.3,
                "to_ny": 0.4,
                "background": False,
                "delay_ms": 0,
            },
        ],
        background=True,
        restore_focus=True,
    )
    assert out["completed_steps"] == 2
    assert bg_drags == [(777, 1200, 700, 850, 520)]
    assert len(fg_drags) == 1
    assert restored == [888]


@pytest.mark.unit
def test_execute_batch_paste_lines_does_not_exhaust_rate_limit(
    isolated_settings: NetForgeSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netforge.gui.windows_backend as wb

    safety = EmergencyStopController(
        corner_failsafe=False, escape_failsafe=False, max_actions_per_minute=5
    )
    backend = WindowsGuiBackend(isolated_settings, safety=safety)
    main_win = WindowInfo(
        hwnd=100,
        pid=222,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=0, top=0, right=1920, bottom=1080),
        client_rect=Rect(left=0, top=29, right=1920, bottom=1020),
        dpi=120,
        scale_factor=1.25,
    )
    dlg = GuiDialogInfo(
        hwnd=500,
        title="Router0",
        class_name="Qt51516QWindowIcon",
        dialog_type=DialogType.DEVICE_WINDOW,
        rect=Rect(left=100, top=100, right=900, bottom=800),
    )
    posted_lines: list[str] = []
    monkeypatch.setattr(wb.platform, "system", lambda: "Windows")
    monkeypatch.setattr(wb, "_get_foreground_hwnd", lambda: 999)
    monkeypatch.setattr(wb, "_resolve_focus_child_hwnd", lambda h: h)
    monkeypatch.setattr(wb, "_post_text_to_hwnd", lambda _h, t: posted_lines.append(t))
    monkeypatch.setattr(wb, "_post_key_chord_to_hwnd", lambda _h, c: [c])
    monkeypatch.setattr(backend, "_require_main_window", lambda: (main_win, [dlg]))

    lines = [f"line {i}" for i in range(60)]
    out = backend.execute_batch(
        [{"op": "paste_lines", "title_contains": "Router0", "lines": lines, "delay_ms": 0}],
        background=True,
        restore_focus=False,
    )
    assert out["completed_steps"] == 1
    assert len(posted_lines) == 60
