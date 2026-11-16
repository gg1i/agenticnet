"""Unit tests verifying Packet Tracer 8.2.2 GUI hardening, geometry settle, and script safety."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from agenticnet.core.settings import AgenticNetSettings
from agenticnet.gui.calibration import DEFAULT_PT_ANCHORS
from agenticnet.gui.models import DialogType, GuiDialogInfo, Rect, WindowInfo
from agenticnet.gui.windows_backend import (
    WindowsGuiBackend,
    _classify_dialog,
    _resolve_focus_child_hwnd,
)
from agenticnet.ios.validators import load_ios_command_sequence


def _sample_window_and_dialog() -> tuple[WindowInfo, GuiDialogInfo]:
    win = WindowInfo(
        hwnd=100,
        pid=222,
        process_name="PacketTracer.exe",
        title="Cisco Packet Tracer",
        window_rect=Rect(left=0, top=0, right=1920, bottom=1040),
        client_rect=Rect(left=0, top=32, right=1920, bottom=1023),
        dpi=120,
        scale_factor=1.25,
    )
    dlg = GuiDialogInfo(
        hwnd=999,
        title="IP Phone0",
        class_name="Qt51516QWindowIcon",
        dialog_type=DialogType.DEVICE_WINDOW,
        # Stale initial spawn position before Qt constrains top=198 -> top=131.
        rect=Rect(left=500, top=198, right=1393, bottom=1095),
    )
    return win, dlg


@pytest.mark.unit
def test_classify_dialog_pt_voip_and_app_windows() -> None:
    assert _classify_dialog("IP Phone0") == DialogType.DEVICE_WINDOW
    assert _classify_dialog("Home VoIP0") == DialogType.DEVICE_WINDOW
    assert _classify_dialog("Analog Phone0") == DialogType.DEVICE_WINDOW
    assert _classify_dialog("PDU Information") == DialogType.DEVICE_WINDOW
    assert _classify_dialog("Check Results") == DialogType.DEVICE_WINDOW
    assert _classify_dialog("Save As", "#32770") == DialogType.FILE_DIALOG
    assert _classify_dialog("Invalid Interface Warning") == DialogType.ERROR_DIALOG


@pytest.mark.unit
def test_calibration_default_anchors_verified_pt822() -> None:
    assert DEFAULT_PT_ANCHORS["canvas_center"].verified is False
    required_verified = (
        "menu_file",
        "top_save_icon",
        "tool_select",
        "tool_inspect",
        "tool_delete",
        "pdu_simple",
        "pdu_complex",
        "workspace_logical",
        "workspace_physical",
        "power_cycle_devices",
        "fast_forward_time",
        "mode_realtime",
        "mode_simulation",
        "toggle_pdu_panel",
    )
    for key in required_verified:
        box = DEFAULT_PT_ANCHORS[key]
        assert box.verified is True, f"Anchor {key} should be marked verified"
        assert 0.0 <= box.rx <= 1.0
        assert 0.0 <= box.ry <= 1.0


@pytest.mark.unit
def test_batch_click_and_drag_dialog_use_live_refreshed_geometry(
    isolated_settings: AgenticNetSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agenticnet.gui.windows_backend as wb

    backend = WindowsGuiBackend(isolated_settings)
    win, dlg = _sample_window_and_dialog()
    settled_rect = Rect(left=500, top=131, right=1393, bottom=1028)

    backend._require_main_window = lambda: (win, [dlg])  # type: ignore[method-assign]
    monkeypatch.setattr(backend, "_require_windows", lambda: None)
    monkeypatch.setattr(backend.safety, "check_safe_to_act", lambda **_kw: None)
    monkeypatch.setattr(
        backend,
        "_refresh_dialog_info",
        lambda d: d.model_copy(update={"rect": settled_rect}),
    )

    clicks: list[tuple[int, int]] = []
    drags: list[tuple[int, int, int, int]] = []
    restored: list[tuple[int, Any, int]] = []

    monkeypatch.setattr(
        backend,
        "_dispatch_click",
        lambda _w, _ds, sx, sy, **_kw: clicks.append((sx, sy)) or dlg.hwnd,
    )
    monkeypatch.setattr(backend, "_call_focus_window", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        backend,
        "drag",
        lambda sx, sy, ex, ey, **_kw: drags.append((sx, sy, ex, ey)) or {"ok": True},
    )
    monkeypatch.setattr(wb, "_get_foreground_hwnd", lambda: 777)
    monkeypatch.setattr(wb, "_get_cursor_pos", lambda: (120, 240))
    monkeypatch.setattr(
        wb,
        "_restore_user_foreground_and_cursor",
        lambda fg, cur, push_hwnd=0: restored.append((fg, cur, push_hwnd)),
    )

    res = backend.execute_batch(
        [
            {"op": "click_dialog", "title_contains": "IP Phone0", "offset_x": 128, "offset_y": 60},
            {
                "op": "drag_dialog",
                "title_contains": "IP Phone0",
                "from_x": 805,
                "from_y": 770,
                "to_x": 322,
                "to_y": 300,
                "background": False,
            },
        ],
        background=True,
        restore_focus=True,
    )

    assert res["completed_steps"] == 2
    assert clicks == [(628, 191)]
    assert drags == [(1305, 901, 822, 431)]
    assert restored == [(777, (120, 240), 999)]


@pytest.mark.unit
def test_batch_wait_dialog_waits_for_qt_geometry_settle(
    isolated_settings: AgenticNetSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = WindowsGuiBackend(isolated_settings)
    win, dlg = _sample_window_and_dialog()
    settled_rect = Rect(left=500, top=131, right=1393, bottom=1028)

    backend._require_main_window = lambda: (win, [dlg])  # type: ignore[method-assign]
    monkeypatch.setattr(backend, "_require_windows", lambda: None)
    monkeypatch.setattr(backend.safety, "check_safe_to_act", lambda **_kw: None)

    rects = iter([settled_rect, settled_rect])
    monkeypatch.setattr(
        backend,
        "_refresh_dialog_info",
        lambda d: d.model_copy(update={"rect": next(rects, settled_rect)}),
    )

    res = backend.execute_batch(
        [{"op": "wait_dialog", "title_contains": "IP Phone0", "timeout_s": 1.0}],
        background=True,
        restore_focus=False,
    )
    assert res["results"][0]["rect"]["top"] == 131


@pytest.mark.unit
def test_resolve_focus_child_hwnd_targets_file_dialog_edit_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeWin32Gui:
        classes = {500: "#32770", 501: "ToolbarWindow32", 502: "Edit", 503: "Edit"}
        rects = {502: (100, 120, 300, 140), 503: (100, 420, 460, 444)}

        @classmethod
        def GetClassName(cls, hwnd: int) -> str:
            return cls.classes.get(hwnd, "")

        @classmethod
        def EnumChildWindows(cls, _top: int, cb: Any, _lp: Any) -> None:
            for hwnd in (501, 502, 503):
                cb(hwnd, None)

        @staticmethod
        def IsWindowVisible(_hwnd: int) -> bool:
            return True

        @staticmethod
        def IsWindowEnabled(_hwnd: int) -> bool:
            return True

        @classmethod
        def GetWindowRect(cls, hwnd: int) -> tuple[int, int, int, int]:
            return cls.rects[hwnd]

    fake_mod = types.ModuleType("win32gui")
    fake_mod.GetClassName = _FakeWin32Gui.GetClassName  # type: ignore[attr-defined]
    fake_mod.EnumChildWindows = _FakeWin32Gui.EnumChildWindows  # type: ignore[attr-defined]
    fake_mod.IsWindowVisible = _FakeWin32Gui.IsWindowVisible  # type: ignore[attr-defined]
    fake_mod.IsWindowEnabled = _FakeWin32Gui.IsWindowEnabled  # type: ignore[attr-defined]
    fake_mod.GetWindowRect = _FakeWin32Gui.GetWindowRect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "win32gui", fake_mod)

    assert _resolve_focus_child_hwnd(500) == 503


@pytest.mark.unit
def test_load_ios_command_sequence_device_class_safety(tmp_path: Path) -> None:
    ios_file = tmp_path / "sw.ios"
    ios_file.write_text("enable\nconfigure terminal\nhostname Switch0\n", encoding="utf-8")

    sw_cmds = load_ios_command_sequence(ios_file, device_type="switch")
    assert sw_cmds[0] != "no"
    assert "no" not in [c.lower() for c in sw_cmds]
    assert "no ip domain-lookup" in sw_cmds

    rtr_cmds = load_ios_command_sequence(ios_file, device_type="router")
    assert rtr_cmds[0] == "no"
    assert "no ip domain-lookup" in rtr_cmds


@pytest.mark.unit
def test_calibration_load_profile_backfills_new_anchors(
    isolated_settings: AgenticNetSettings,
) -> None:
    from agenticnet.gui.calibration import CalibrationManager
    from agenticnet.gui.models import AnchorBox, CalibrationProfile

    cal = CalibrationManager(isolated_settings)
    stale = CalibrationProfile(
        profile_id="legacy",
        client_width=1920,
        client_height=991,
        dpi=120,
        scale_factor=1.25,
        anchors={
            "mode_realtime": AnchorBox(
                name="mode_realtime", rx=0.905, ry=0.735, rw=0.04, rh=0.035, verified=False
            )
        },
    )
    cal.save_profile(stale)
    loaded = cal.load_profile("legacy")
    assert loaded.anchors["mode_realtime"].verified is True
    assert loaded.anchors["mode_realtime"].ry == pytest.approx(0.8668)
    assert "pdu_complex" in loaded.anchors
    assert "mode_simulation" in loaded.verified_anchors

