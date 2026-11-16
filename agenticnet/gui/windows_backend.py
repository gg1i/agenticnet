"""Native Windows GUI automation backend using pywin32, ctypes SendInput, psutil, and OpenCV."""

from __future__ import annotations

import ctypes
import platform
import re
import subprocess
import time
from contextlib import suppress
from ctypes import wintypes
from pathlib import Path
from typing import Any

try:
    import psutil  # type: ignore[import-untyped]
except ImportError:
    psutil = None

try:
    from PIL import Image, ImageGrab  # type: ignore[import-untyped]
except ImportError:
    Image = None
    ImageGrab = None

from agenticnet.adapters.base import AdapterConnectionState, BackendStatus, GuiBackend
from agenticnet.adapters.discovery import (
    detect_packet_tracer_binary,
    require_interactive_desktop_for_launch,
)
from agenticnet.core.enums import StateLevel
from agenticnet.core.exceptions import AdapterUnavailableError, ValidationError
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.gui.calibration import CalibrationManager
from agenticnet.gui.models import (
    DialogType,
    GuiDialogInfo,
    GuiStateReport,
    Rect,
    WindowInfo,
)
from agenticnet.gui.safety import EmergencyStopController
from agenticnet.gui.vision import compute_image_stats, detect_ui_regions_from_image, save_image_png
from agenticnet.security.validation import safe_resolve_path

_DPI_INITIALIZED = False


def enable_per_monitor_dpi_awareness() -> None:
    """Enable Win32 Per-Monitor V2 DPI awareness once per process at runtime startup."""
    global _DPI_INITIALIZED
    if _DPI_INITIALIZED or platform.system() != "Windows":
        return
    with suppress(Exception):
        # -4 == DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    _DPI_INITIALIZED = True


_enable_per_monitor_dpi_awareness = enable_per_monitor_dpi_awareness

_MOUSEEVENTF_MOVE = 0x0001
_MOUSEEVENTF_LEFTDOWN = 0x0002
_MOUSEEVENTF_LEFTUP = 0x0004
_MOUSEEVENTF_RIGHTDOWN = 0x0008
_MOUSEEVENTF_RIGHTUP = 0x0010
_MOUSEEVENTF_MIDDLEDOWN = 0x0020
_MOUSEEVENTF_MIDDLEUP = 0x0040
_MOUSEEVENTF_ABSOLUTE = 0x8000
_MOUSEEVENTF_VIRTUALDESK = 0x4000

_KEYEVENTF_EXTENDEDKEY = 0x0001
_KEYEVENTF_KEYUP = 0x0002
_KEYEVENTF_UNICODE = 0x0004

_INPUT_MOUSE = 0
_INPUT_KEYBOARD = 1

_VK_MAP: dict[str, int] = {
    "ctrl": 0x11,
    "control": 0x11,
    "shift": 0x10,
    "alt": 0x12,
    "enter": 0x0D,
    "return": 0x0D,
    "esc": 0x1B,
    "escape": 0x1B,
    "tab": 0x09,
    "space": 0x20,
    "backspace": 0x08,
    "delete": 0x2E,
    "del": 0x2E,
    "up": 0x26,
    "down": 0x28,
    "left": 0x25,
    "right": 0x27,
    "home": 0x24,
    "end": 0x23,
    "pageup": 0x21,
    "pagedown": 0x22,
    **{f"f{i}": 0x6F + i for i in range(1, 13)},
    **{chr(c): c for c in range(ord("A"), ord("Z") + 1)},
    **{str(d): ord(str(d)) for d in range(10)},
}


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    ]


class _INPUT_UNION(ctypes.Union):
    _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT), ("hi", _HARDWAREINPUT)]


class _INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("ii", _INPUT_UNION)]


def _parse_pt_window_title(title: str) -> tuple[str | None, bool]:
    """Extract active `.pkt`/`.pka` filename hint and unsaved marker from PT title bar."""
    cleaned = title.strip()
    has_unsaved = cleaned.endswith("*") or "* -" in cleaned
    candidate = cleaned.split(" - ")[-1].strip() if " - " in cleaned else cleaned
    match = re.search(r"([A-Za-z0-9_.()\- ]+\.(?:pkt|pka))\s*\*?", candidate, re.IGNORECASE)
    file_hint = match.group(1).strip() if match else None
    return file_hint, has_unsaved


def _classify_dialog(title: str, class_name: str = "") -> DialogType:
    """Classify a Packet Tracer popup or detached window by title and Win32 class."""
    low = title.lower().strip()
    if any(
        k in low for k in ("skills for all", "netacad", "networking academy", "log in", "login")
    ):
        return DialogType.LOGIN_WALL
    if any(k in low for k in ("save changes", "do you want to save", "confirm save")):
        return DialogType.SAVE_PROMPT
    if "overwrite" in low or "already exists" in low or "replace" in low:
        return DialogType.CONFIRM_OVERWRITE
    if class_name == "#32770" or any(k in low for k in ("save as", "open file", "select file")):
        return DialogType.FILE_DIALOG
    if any(
        k in low
        for k in (
            "router",
            "switch",
            "pc",
            "laptop",
            "server",
            "printer",
            "wrt",
            "access point",
            "command prompt",
            "cli",
            "ip phone",
            "home voip",
            "analog phone",
            "ata",
            "modem",
            "cloud",
            "multiserver",
            "wireless",
            "linksys",
            "terminal",
            "web browser",
            "ip configuration",
            "pdu information",
            "complex pdu",
            "simulation panel",
            "check results",
            "activity wizard",
        )
    ):
        return DialogType.DEVICE_WINDOW
    if any(k in low for k in ("error", "warning", "alert", "invalid", "failed")):
        return DialogType.ERROR_DIALOG
    return DialogType.UNKNOWN


def _parse_key_chord(chord: str) -> list[tuple[str, int]]:
    """Convert a chord string like 'ctrl+s' into normalized `(token, virtual_key_code)` list."""
    tokens = [part.strip().lower() for part in chord.split("+") if part.strip()]
    if not tokens:
        raise ValidationError("Key chord cannot be empty.", details={"keys": chord})

    parsed: list[tuple[str, int]] = []
    for tok in tokens:
        key_lookup = tok.upper() if len(tok) == 1 and tok.isalpha() else tok
        vk = _VK_MAP.get(key_lookup)
        if vk is None:
            raise ValidationError(
                f"Unsupported key token '{tok}' in chord '{chord}'.",
                details={"token": tok, "supported_modifiers": ["ctrl", "shift", "alt"]},
            )
        parsed.append((tok, vk))
    return parsed


def _clipboard_read() -> str:
    if platform.system() != "Windows":
        return ""
    import win32clipboard  # type: ignore[import-untyped]
    import win32con  # type: ignore[import-untyped]

    for _ in range(5):
        try:
            win32clipboard.OpenClipboard()
            try:
                if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                    data = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                    return str(data)
                return ""
            finally:
                win32clipboard.CloseClipboard()
        except Exception:
            time.sleep(0.05)
    return ""


def _clipboard_write(text: str) -> None:
    if platform.system() != "Windows":
        return
    import win32clipboard  # type: ignore[import-untyped]
    import win32con  # type: ignore[import-untyped]

    for _ in range(5):
        try:
            win32clipboard.OpenClipboard()
            try:
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, text)
                return
            finally:
                win32clipboard.CloseClipboard()
        except Exception:
            time.sleep(0.05)


_TOOLHELP_SNAP_PROCESS = 0x00000002
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_CWP_SKIPINVISIBLE = 0x0001
_CWP_SKIPDISABLED = 0x0002
_PW_RENDERFULLCONTENT = 0x00000002
_DIB_RGB_COLORS = 0
_WM_MOUSEMOVE = 0x0200
_WM_LBUTTONDOWN = 0x0201
_WM_LBUTTONUP = 0x0202
_WM_LBUTTONDBLCLK = 0x0203
_WM_RBUTTONDOWN = 0x0204
_WM_RBUTTONUP = 0x0205
_WM_RBUTTONDBLCLK = 0x0206
_WM_MBUTTONDOWN = 0x0207
_WM_MBUTTONUP = 0x0208
_WM_MBUTTONDBLCLK = 0x0209
_MK_LBUTTON = 0x0001
_MK_RBUTTON = 0x0002
_MK_MBUTTON = 0x0010
_WM_KEYDOWN = 0x0100
_WM_KEYUP = 0x0101
_WM_CHAR = 0x0102
_SW_MAXIMIZE = 3
_SW_SHOWNOACTIVATE = 4
_SW_RESTORE = 9
_SWP_NOSIZE = 0x0001
_SWP_NOMOVE = 0x0002
_SWP_NOACTIVATE = 0x0010
_EXTENDED_VKS = {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E,  # pgup..del
    0xA3, 0xA5,  # rctrl, ralt
}


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class _GUITHREADINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("hwndActive", wintypes.HWND),
        ("hwndFocus", wintypes.HWND),
        ("hwndCapture", wintypes.HWND),
        ("hwndMenuOwner", wintypes.HWND),
        ("hwndMoveSize", wintypes.HWND),
        ("hwndCaret", wintypes.HWND),
        ("rcCaret", wintypes.RECT),
    ]


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class _BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", _BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 3)]


def _query_process_exe(pid: int) -> str | None:
    """Resolve full image path for a single PID without iterating system-wide processes."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    handle = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return None
    try:
        buf = ctypes.create_unicode_buffer(512)
        size = wintypes.DWORD(len(buf))
        if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value
        return None
    finally:
        k32.CloseHandle(handle)


def _snapshot_pt_processes() -> list[dict[str, Any]] | None:
    """Enumerate Packet Tracer processes in <1ms using CreateToolhelp32Snapshot."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    k32.Process32FirstW.restype = wintypes.BOOL
    k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    k32.Process32NextW.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL

    snap = k32.CreateToolhelp32Snapshot(_TOOLHELP_SNAP_PROCESS, 0)
    if snap == ctypes.c_void_p(-1).value or not snap:
        return None
    matches: list[dict[str, Any]] = []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            exe_name = entry.szExeFile or ""
            if "packettracer" in exe_name.lower():
                pid = int(entry.th32ProcessID)
                matches.append(
                    {
                        "pid": pid,
                        "name": exe_name,
                        "exe": _query_process_exe(pid),
                        "status": "running",
                    }
                )
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
        return matches
    finally:
        k32.CloseHandle(snap)


def _get_foreground_hwnd() -> int:
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return 0
    return int(windll.user32.GetForegroundWindow() or 0)


def _get_cursor_pos() -> tuple[int, int] | None:
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return None
    pt = wintypes.POINT()
    if windll.user32.GetCursorPos(ctypes.byref(pt)):
        return int(pt.x), int(pt.y)
    return None


def _restore_user_foreground_and_cursor(
    prev_fg: int, prev_cursor: tuple[int, int] | None, *, push_hwnd: int = 0
) -> None:
    """Restore the user's previous foreground window and cursor position without disruption."""
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return
    u32 = windll.user32
    k32 = windll.kernel32
    if prev_cursor is not None:
        with suppress(Exception):
            u32.SetCursorPos(int(prev_cursor[0]), int(prev_cursor[1]))
    if prev_fg and u32.IsWindow(int(prev_fg)):
        if push_hwnd and push_hwnd != prev_fg and u32.IsWindow(int(push_hwnd)):
            with suppress(Exception):
                u32.SetWindowPos(
                    int(push_hwnd),
                    int(prev_fg),
                    0,
                    0,
                    0,
                    0,
                    _SWP_NOMOVE | _SWP_NOSIZE | _SWP_NOACTIVATE,
                )
        curr_fg = int(u32.GetForegroundWindow() or 0)
        tid_curr_fg = int(u32.GetWindowThreadProcessId(curr_fg, None) or 0) if curr_fg else 0
        tid_prev_fg = int(u32.GetWindowThreadProcessId(int(prev_fg), None) or 0)
        tid_self = int(k32.GetCurrentThreadId() or 0)
        attached_curr = False
        attached_prev = False
        try:
            if tid_curr_fg and tid_curr_fg != tid_self:
                attached_curr = bool(u32.AttachThreadInput(tid_self, tid_curr_fg, True))
            if tid_prev_fg and tid_prev_fg not in {tid_self, tid_curr_fg}:
                attached_prev = bool(u32.AttachThreadInput(tid_self, tid_prev_fg, True))
            with suppress(Exception):
                u32.SetForegroundWindow(int(prev_fg))
        finally:
            if attached_prev:
                with suppress(Exception):
                    u32.AttachThreadInput(tid_self, tid_prev_fg, False)
            if attached_curr:
                with suppress(Exception):
                    u32.AttachThreadInput(tid_self, tid_curr_fg, False)


def _capture_window_printwindow(
    hwnd: int, window_rect: Rect, client_rect: Rect, *, full_window: bool = False
) -> Image.Image | None:
    """Capture a window offscreen via Win32 PrintWindow (works when occluded behind other apps)."""
    if Image is None:
        return None
    width = int(window_rect.width)
    height = int(window_rect.height)
    if width <= 0 or height <= 0:
        return None
    u32 = ctypes.windll.user32
    g32 = ctypes.windll.gdi32
    hwnd_dc = u32.GetWindowDC(int(hwnd))
    if not hwnd_dc:
        return None
    mem_dc = 0
    hbmp = 0
    old_obj = 0
    try:
        mem_dc = g32.CreateCompatibleDC(hwnd_dc)
        if not mem_dc:
            return None
        bmi = _BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = width
        bmi.bmiHeader.biHeight = -height
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = 0
        bits_ptr = ctypes.c_void_p()
        hbmp = g32.CreateDIBSection(
            mem_dc, ctypes.byref(bmi), _DIB_RGB_COLORS, ctypes.byref(bits_ptr), None, 0
        )
        if not hbmp or not bits_ptr.value:
            return None
        old_obj = g32.SelectObject(mem_dc, hbmp)
        byte_count = width * height * 4
        img: Image.Image | None = None
        for pw_flag in (_PW_RENDERFULLCONTENT, 0):
            if u32.PrintWindow(int(hwnd), mem_dc, pw_flag) and bits_ptr.value:
                raw = ctypes.string_at(bits_ptr.value, byte_count)
                cand = Image.frombuffer(
                    "RGBA", (width, height), raw, "raw", "BGRA", 0, 1
                ).convert("RGB")
                if cand.getbbox() is not None:
                    img = cand
                    break
        if img is None:
            return None
        if not full_window:
            left = max(0, int(client_rect.left - window_rect.left))
            top = max(0, int(client_rect.top - window_rect.top))
            right = min(width, int(client_rect.right - window_rect.left))
            bottom = min(height, int(client_rect.bottom - window_rect.top))
            if right - left > 10 and bottom - top > 10:
                img = img.crop((left, top, right, bottom))
        return img
    finally:
        if old_obj and mem_dc:
            with suppress(Exception):
                g32.SelectObject(mem_dc, old_obj)
        if hbmp:
            with suppress(Exception):
                g32.DeleteObject(hbmp)
        if mem_dc:
            with suppress(Exception):
                g32.DeleteDC(mem_dc)
        with suppress(Exception):
            u32.ReleaseDC(int(hwnd), hwnd_dc)


def _resolve_child_window_at_point(top_hwnd: int, sx: int, sy: int) -> tuple[int, int, int]:
    """Walk native child windows down to the deepest HWND at screen `(sx, sy)` and client xy."""
    u32 = ctypes.windll.user32
    curr = int(top_hwnd)
    for _ in range(16):
        pt = wintypes.POINT(int(sx), int(sy))
        if not u32.ScreenToClient(curr, ctypes.byref(pt)):
            break
        child = int(
            u32.ChildWindowFromPointEx(curr, pt, _CWP_SKIPINVISIBLE | _CWP_SKIPDISABLED) or 0
        )
        if not child or child == curr:
            return curr, int(pt.x), int(pt.y)
        curr = child
    pt = wintypes.POINT(int(sx), int(sy))
    u32.ScreenToClient(curr, ctypes.byref(pt))
    return curr, int(pt.x), int(pt.y)


def _find_file_dialog_edit_hwnd(top_hwnd: int) -> int | None:
    """Return the visible, enabled File Name Edit child HWND inside a `#32770` dialog."""
    try:
        import win32gui  # type: ignore[import-untyped]
    except Exception:
        return None
    candidates: list[tuple[int, int]] = []

    def _enum(hwnd: int, _lparam: Any) -> bool:
        try:
            if (
                win32gui.GetClassName(hwnd) == "Edit"
                and win32gui.IsWindowVisible(hwnd)
                and win32gui.IsWindowEnabled(hwnd)
            ):
                left, top, right, bottom = win32gui.GetWindowRect(hwnd)
                if right > left and bottom > top:
                    candidates.append((top * 10000 + (right - left), hwnd))
        except Exception:
            pass
        return True

    with suppress(Exception):
        win32gui.EnumChildWindows(int(top_hwnd), _enum, None)
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    return candidates[-1][1]


def _resolve_focus_child_hwnd(top_hwnd: int) -> int:
    """Resolve the focused child control HWND inside a top-level Packet Tracer window."""
    try:
        import win32gui  # type: ignore[import-untyped]

        if win32gui.GetClassName(int(top_hwnd)) == "#32770":
            edit_hwnd = _find_file_dialog_edit_hwnd(int(top_hwnd))
            if edit_hwnd:
                return edit_hwnd
    except Exception:
        pass
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return int(top_hwnd)
    u32 = windll.user32
    tid = int(u32.GetWindowThreadProcessId(int(top_hwnd), None) or 0)
    if tid:
        info = _GUITHREADINFO()
        info.cbSize = ctypes.sizeof(_GUITHREADINFO)
        if u32.GetGUIThreadInfo(tid, ctypes.byref(info)):
            focus_hwnd = int(info.hwndFocus or 0)
            if focus_hwnd and (
                focus_hwnd == top_hwnd or bool(u32.IsChild(int(top_hwnd), focus_hwnd))
            ):
                return focus_hwnd
    return int(top_hwnd)


def _post_mouse_click_to_hwnd(
    top_hwnd: int, sx: int, sy: int, *, button: str = "left", clicks: int = 1
) -> int:
    """Post mouse move and click messages directly to the resolved child HWND in background."""
    u32 = ctypes.windll.user32
    target_hwnd, cx, cy = _resolve_child_window_at_point(top_hwnd, sx, sy)
    lparam = ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)
    btn_map = {
        "left": (_WM_LBUTTONDOWN, _WM_LBUTTONUP, _WM_LBUTTONDBLCLK, _MK_LBUTTON),
        "right": (_WM_RBUTTONDOWN, _WM_RBUTTONUP, _WM_RBUTTONDBLCLK, _MK_RBUTTON),
        "middle": (_WM_MBUTTONDOWN, _WM_MBUTTONUP, _WM_MBUTTONDBLCLK, _MK_MBUTTON),
    }
    down_msg, up_msg, dbl_msg, mk_flag = btn_map[button]
    u32.PostMessageW(target_hwnd, _WM_MOUSEMOVE, 0, lparam)
    time.sleep(0.006)
    for idx in range(clicks):
        press_msg = dbl_msg if idx == 1 else down_msg
        u32.PostMessageW(target_hwnd, press_msg, mk_flag, lparam)
        time.sleep(0.012)
        u32.PostMessageW(target_hwnd, up_msg, 0, lparam)
        if idx + 1 < clicks:
            time.sleep(0.025)
    return target_hwnd


def _post_mouse_drag_to_hwnd(
    top_hwnd: int,
    start_x: int,
    start_y: int,
    end_x: int,
    end_y: int,
    *,
    steps: int = 12,
    duration_s: float = 0.16,
) -> int:
    """Post mouse down, interpolated move, and release messages to a background HWND."""
    u32 = ctypes.windll.user32
    target_hwnd, csx, csy = _resolve_child_window_at_point(top_hwnd, start_x, start_y)
    # Convert end screen point into the SAME target_hwnd client space so Qt tracks one gesture.
    end_pt = wintypes.POINT(int(end_x), int(end_y))
    u32.ScreenToClient(target_hwnd, ctypes.byref(end_pt))
    cex, cey = int(end_pt.x), int(end_pt.y)

    def _lp(cx: int, cy: int) -> int:
        return ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)

    step_count = max(1, int(steps))
    step_delay = max(0.004, float(duration_s) / step_count)
    u32.PostMessageW(target_hwnd, _WM_MOUSEMOVE, 0, _lp(csx, csy))
    time.sleep(0.01)
    u32.PostMessageW(target_hwnd, _WM_LBUTTONDOWN, _MK_LBUTTON, _lp(csx, csy))
    time.sleep(0.015)
    for idx in range(1, step_count + 1):
        frac = idx / step_count
        ix = int(round(csx + (cex - csx) * frac))
        iy = int(round(csy + (cey - csy) * frac))
        u32.PostMessageW(target_hwnd, _WM_MOUSEMOVE, _MK_LBUTTON, _lp(ix, iy))
        time.sleep(step_delay)
    u32.PostMessageW(target_hwnd, _WM_LBUTTONUP, 0, _lp(cex, cey))
    return target_hwnd


def _key_lparam(vk: int, *, is_up: bool = False) -> int:
    scan = int(ctypes.windll.user32.MapVirtualKeyW(int(vk), 0) or 0) & 0xFF
    lparam = 1 | (scan << 16)
    if int(vk) in _EXTENDED_VKS:
        lparam |= 1 << 24
    if is_up:
        lparam |= (1 << 30) | (1 << 31)
    return lparam


def _post_key_chord_to_hwnd(target_hwnd: int, chord: str) -> list[str]:
    """Post a key chord via Win32 PostMessageW to a background child HWND."""
    u32 = ctypes.windll.user32
    parsed = _parse_key_chord(chord)
    for _, vk in parsed:
        u32.PostMessageW(target_hwnd, _WM_KEYDOWN, vk, _key_lparam(vk, is_up=False))
    time.sleep(0.012)
    for _, vk in reversed(parsed):
        u32.PostMessageW(target_hwnd, _WM_KEYUP, vk, _key_lparam(vk, is_up=True))
    return [tok for tok, _ in parsed]


def _post_text_to_hwnd(target_hwnd: int, text: str) -> None:
    """Post Unicode text via WM_CHAR directly to a background HWND without touching clipboard."""
    u32 = ctypes.windll.user32
    for ch in text:
        if ch == "\n":
            vk_ret = _VK_MAP["enter"]
            u32.PostMessageW(target_hwnd, _WM_KEYDOWN, vk_ret, _key_lparam(vk_ret, is_up=False))
            u32.PostMessageW(target_hwnd, _WM_KEYUP, vk_ret, _key_lparam(vk_ret, is_up=True))
        else:
            u32.PostMessageW(target_hwnd, _WM_CHAR, ord(ch), 1)


class WindowsGuiBackend(GuiBackend):
    """Windows native automation adapter for Cisco Packet Tracer."""

    def __init__(
        self,
        settings: AgenticNetSettings,
        calibration: CalibrationManager | None = None,
        safety: EmergencyStopController | None = None,
    ) -> None:
        self.settings = settings
        self.calibration = calibration or CalibrationManager(settings)
        self.safety = safety or EmergencyStopController()
        self.screenshots_dir = settings.data_dir / "screenshots"
        _enable_per_monitor_dpi_awareness()

    def _require_windows(self) -> None:
        if platform.system() != "Windows":
            raise AdapterUnavailableError(
                f"WindowsGuiBackend requires Windows (detected {platform.system()}).",
                remediation="Implement or select a Linux/macOS GuiBackend per docs.",
            )

    def _find_pt_processes(self) -> list[dict[str, Any]]:
        snapshot = None
        if platform.system() == "Windows":
            with suppress(Exception):
                snapshot = _snapshot_pt_processes()
        if snapshot is not None:
            return snapshot
        if psutil is None:
            return []

        matches: list[dict[str, Any]] = []
        for proc in psutil.process_iter(["pid", "name", "exe", "status"]):
            try:
                name = (proc.info.get("name") or "").lower()
                if "packettracer" in name:
                    matches.append(
                        {
                            "pid": int(proc.info["pid"]),
                            "name": proc.info.get("name"),
                            "exe": proc.info.get("exe"),
                            "status": proc.info.get("status"),
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return matches

    def _enumerate_pt_windows(
        self, pt_pids: set[int], *, include_dialog_buttons: bool = True
    ) -> tuple[WindowInfo | None, list[GuiDialogInfo]]:
        self._require_windows()
        import win32gui  # type: ignore[import-untyped]
        import win32process  # type: ignore[import-untyped]

        fg_hwnd = win32gui.GetForegroundWindow()
        candidates: list[WindowInfo] = []
        dialogs: list[GuiDialogInfo] = []

        def _enum_cb(hwnd: int, _: Any) -> None:
            if not win32gui.IsWindowVisible(hwnd):
                return
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            title = win32gui.GetWindowText(hwnd) or ""
            class_name = win32gui.GetClassName(hwnd) or ""
            belongs_to_pt = pid in pt_pids or "cisco packet tracer" in title.lower()
            if not belongs_to_pt or not title.strip():
                return

            w_left, w_top, w_right, w_bottom = win32gui.GetWindowRect(hwnd)
            c_left_rel, c_top_rel, c_right_rel, c_bottom_rel = win32gui.GetClientRect(hwnd)
            c_left, c_top = win32gui.ClientToScreen(hwnd, (c_left_rel, c_top_rel))
            c_right, c_bottom = win32gui.ClientToScreen(hwnd, (c_right_rel, c_bottom_rel))
            w_rect = Rect(left=w_left, top=w_top, right=w_right, bottom=w_bottom)
            c_rect = Rect(left=c_left, top=c_top, right=c_right, bottom=c_bottom)

            dpi = 96
            try:
                dpi_val = int(ctypes.windll.user32.GetDpiForWindow(hwnd))
                if dpi_val >= 72:
                    dpi = dpi_val
            except Exception:
                dpi = 96

            is_main_pt = "cisco packet tracer" in title.lower() and class_name != "#32770"
            if is_main_pt:
                file_hint, has_unsaved = _parse_pt_window_title(title)
                candidates.append(
                    WindowInfo(
                        hwnd=hwnd,
                        pid=pid,
                        process_name="PacketTracer.exe",
                        title=title,
                        class_name=class_name,
                        window_rect=w_rect,
                        client_rect=c_rect,
                        dpi=dpi,
                        scale_factor=round(dpi / 96.0, 3),
                        is_minimized=bool(win32gui.IsIconic(hwnd)),
                        is_foreground=(hwnd == fg_hwnd),
                        active_file_hint=file_hint,
                        has_unsaved_changes=has_unsaved,
                    )
                )
            else:
                buttons: list[str] = []
                if include_dialog_buttons:

                    def _child_cb(child_hwnd: int, _: Any) -> None:
                        try:
                            c_cls = (win32gui.GetClassName(child_hwnd) or "").lower()
                            c_txt = (win32gui.GetWindowText(child_hwnd) or "").strip()
                            if c_txt and ("button" in c_cls or "pushbutton" in c_cls):
                                buttons.append(c_txt)
                        except Exception:
                            return

                    with suppress(Exception):
                        win32gui.EnumChildWindows(hwnd, _child_cb, None)

                dialogs.append(
                    GuiDialogInfo(
                        hwnd=hwnd,
                        title=title,
                        class_name=class_name,
                        dialog_type=_classify_dialog(title, class_name),
                        buttons=buttons,
                        rect=w_rect,
                    )
                )

        win32gui.EnumWindows(_enum_cb, None)
        primary = max(
            candidates, key=lambda w: w.window_rect.width * w.window_rect.height, default=None
        )
        return primary, dialogs

    def backend_status(self) -> BackendStatus:
        """Inspect Windows runtime and Packet Tracer presence."""
        exe_path = detect_packet_tracer_binary(self.settings.packet_tracer_path)
        procs = self._find_pt_processes()
        state = AdapterConnectionState.OFFLINE_PLANNING
        if procs:
            primary, _ = self._enumerate_pt_windows({p["pid"] for p in procs})
            state = (
                AdapterConnectionState.CONNECTED
                if primary is not None
                else AdapterConnectionState.DETECTED_IDLE
            )
        return BackendStatus(
            backend_name="WindowsGuiBackend",
            connection_state=state,
            platform=platform.platform(),
            executable_path=exe_path,
            capabilities=[
                "win32_window_detection",
                "dpi_aware_calibration",
                "opencv_template_matching",
                "sendinput_hardware_input",
                "modal_dialog_recovery",
                "emergency_stop_failsafe",
            ],
            notes="Native pywin32/ctypes/OpenCV backend.",
        )

    @staticmethod
    def _has_usable_window_bounds(window_dict: dict[str, Any] | None) -> bool:
        if not isinstance(window_dict, dict):
            return False
        crect = window_dict.get("client_rect") or {}
        width = int(crect.get("right", 0)) - int(crect.get("left", 0))
        height = int(crect.get("bottom", 0)) - int(crect.get("top", 0))
        return width >= 400 and height >= 300

    def detect_application(self, *, include_dialog_buttons: bool = True) -> dict[str, Any]:
        """Detect running Packet Tracer processes, main window bounds, DPI, and popups."""
        self._require_windows()
        cached_exe = getattr(self, "_cached_exe_path", None)
        if cached_exe is None:
            cached_exe = detect_packet_tracer_binary(self.settings.packet_tracer_path)
            if cached_exe is not None:
                self._cached_exe_path = cached_exe
        exe_path = cached_exe
        procs = self._find_pt_processes()
        pt_pids = {p["pid"] for p in procs}
        primary, dialogs = (
            self._enumerate_pt_windows(pt_pids, include_dialog_buttons=include_dialog_buttons)
            if pt_pids
            else (None, [])
        )

        return {
            "detected_binary": exe_path is not None,
            "executable_path": exe_path,
            "running": len(procs) > 0,
            "processes": procs,
            "window": primary.model_dump(mode="json") if primary else None,
            "dialogs": [d.model_dump(mode="json") for d in dialogs],
            "calibration_loaded": self.calibration.ensure_or_default() is not None,
            "state_level": StateLevel.VERIFIED.value,
        }

    def _detect_fast(self) -> dict[str, Any]:
        """Call detect_application skipping dialog button enumeration while honoring test mocks."""
        try:
            return self.detect_application(include_dialog_buttons=False)
        except TypeError:
            return self.detect_application()

    def _resolve_background(self, background: bool | None) -> bool:
        if background is None:
            return bool(getattr(self.settings, "gui_background_mode", True))
        return bool(background)

    def launch_application(
        self,
        executable_path: str | None = None,
        *,
        project_file: str | None = None,
        wait_seconds: float = 15.0,
        background: bool | None = None,
    ) -> dict[str, Any]:
        """Launch Cisco Packet Tracer cleanly and wait for its main window."""
        self._require_windows()
        require_interactive_desktop_for_launch("WindowsGuiBackend.launch_application")
        self.safety.check_safe_to_act(live_input=False)
        use_bg = self._resolve_background(background)
        prev_fg = _get_foreground_hwnd() if use_bg else 0

        existing = self._detect_fast()
        has_login_wall = any(
            d.get("dialog_type") == DialogType.LOGIN_WALL.value
            for d in existing.get("dialogs", [])
        )
        if existing["running"] and (
            self._has_usable_window_bounds(existing["window"]) or has_login_wall
        ):
            return {
                "already_running": True,
                "launched": False,
                "background": use_bg,
                "detection": existing,
                "state_level": StateLevel.VERIFIED.value,
            }

        if existing["running"] and existing["window"] is None and not existing["dialogs"]:
            # Never spawn a second Packet Tracer instance (ports 38000/39000 contention);
            # wait briefly for an already-starting instance to surface its window or login dialog.
            time.sleep(1.0)
            existing = self._detect_fast()

        already_running = bool(existing["running"])
        proc_pid: int | None = None
        exe = existing.get("executable_path")
        if not already_running:
            exe = detect_packet_tracer_binary(executable_path or self.settings.packet_tracer_path)
            if not exe:
                raise AdapterUnavailableError(
                    "Cisco Packet Tracer executable was not found.",
                    remediation=(
                        "Install Cisco Packet Tracer or set AGENTICNET_PT_PATH "
                        "(or legacy NETFORGE_PT_PATH)."
                    ),
                )

            cmd: list[str] = [exe]
            if project_file:
                resolved_pkt = safe_resolve_path(project_file)
                if not resolved_pkt.exists():
                    raise ValidationError(
                        f"Packet Tracer project file does not exist: {resolved_pkt}",
                        details={"project_file": str(resolved_pkt)},
                    )
                cmd.append(str(resolved_pkt))

            popen_kwargs: dict[str, Any] = {
                "cwd": str(Path(exe).parent),
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
            }
            if use_bg and hasattr(subprocess, "STARTUPINFO"):
                si = subprocess.STARTUPINFO()
                si.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0x00000001)
                si.wShowWindow = _SW_SHOWNOACTIVATE
                popen_kwargs["startupinfo"] = si

            proc = subprocess.Popen(cmd, **popen_kwargs)
            proc_pid = proc.pid

        deadline = time.monotonic() + max(1.0, min(wait_seconds, 60.0))
        detection = existing
        while time.monotonic() < deadline:
            time.sleep(0.25)
            detection = self._detect_fast()
            if any(
                d.get("dialog_type") == DialogType.LOGIN_WALL.value
                for d in detection.get("dialogs", [])
            ):
                if use_bg and prev_fg:
                    _restore_user_foreground_and_cursor(prev_fg, None)
                break
            if self._has_usable_window_bounds(detection["window"]):
                # Allow Qt docks and toolbars to finish sizing after window appears.
                time.sleep(0.45)
                detection = self.detect_application()
                if use_bg and prev_fg and detection.get("window"):
                    pt_hwnd = int(detection["window"]["hwnd"])
                    _restore_user_foreground_and_cursor(prev_fg, None, push_hwnd=pt_hwnd)
                break

        ready = self._has_usable_window_bounds(detection["window"]) or bool(detection["dialogs"])
        result: dict[str, Any] = {
            "already_running": already_running,
            "launched": not already_running,
            "background": use_bg,
            "detection": detection,
            "state_level": StateLevel.VERIFIED.value if ready else StateLevel.EXECUTED.value,
        }
        if proc_pid is not None:
            result["pid"] = proc_pid
        if exe is not None:
            result["executable_path"] = exe
        return result

    def _require_main_window(
        self, *, include_dialog_buttons: bool = False
    ) -> tuple[WindowInfo, list[GuiDialogInfo]]:
        detection = (
            self.detect_application()
            if include_dialog_buttons
            else self._detect_fast()
        )
        win_raw = detection.get("window")
        if not win_raw:
            dialogs = [GuiDialogInfo.model_validate(d) for d in detection.get("dialogs", [])]
            if any(d.dialog_type == DialogType.LOGIN_WALL for d in dialogs):
                raise AdapterUnavailableError(
                    "Packet Tracer is blocked by a Login / Skills for All dialog.",
                    details={"dialogs": detection.get("dialogs", [])},
                    remediation="Sign in to Packet Tracer on desktop, then retry.",
                )
            raise AdapterUnavailableError(
                "No visible Cisco Packet Tracer main window detected.",
                details={"running": detection["running"], "dialogs": detection.get("dialogs", [])},
                remediation="Launch Packet Tracer via packet_tracer_launch or open it manually.",
            )
        return WindowInfo.model_validate(win_raw), [
            GuiDialogInfo.model_validate(d) for d in detection.get("dialogs", [])
        ]

    def _call_focus_window(
        self, hwnd: int | None = None, *, cached_win: WindowInfo | None = None
    ) -> WindowInfo:
        """Invoke focus_window with cached_win when supported, preserving monkeypatched mocks."""
        try:
            return self.focus_window(hwnd, cached_win=cached_win)
        except TypeError:
            return self.focus_window(hwnd)

    def focus_window(
        self, hwnd: int | None = None, *, cached_win: WindowInfo | None = None
    ) -> WindowInfo:
        """Restore/maximize and bring Packet Tracer or a child window to foreground."""
        import win32api  # type: ignore[import-untyped]
        import win32con  # type: ignore[import-untyped]
        import win32gui  # type: ignore[import-untyped]
        import win32process  # type: ignore[import-untyped]

        win = cached_win
        if win is None:
            win, _ = self._require_main_window()
        target_hwnd = hwnd or win.hwnd
        if target_hwnd == win.hwnd:
            is_zoomed = bool(getattr(win32gui, "IsZoomed", lambda _h: False)(target_hwnd))
            if win32gui.IsIconic(target_hwnd) or not is_zoomed:
                win32gui.ShowWindow(target_hwnd, win32con.SW_SHOWMAXIMIZED)
                time.sleep(0.06)
        elif win32gui.IsIconic(target_hwnd):
            win32gui.ShowWindow(target_hwnd, win32con.SW_RESTORE)
            time.sleep(0.06)

        if (
            win32gui.GetForegroundWindow() == target_hwnd
            and not win32gui.IsIconic(target_hwnd)
            and win.client_rect.width >= 400
            and win.client_rect.height >= 300
        ):
            return win

        tid_target, _ = win32process.GetWindowThreadProcessId(target_hwnd)
        tid_current = win32api.GetCurrentThreadId()
        attached = False
        try:
            if tid_target and tid_target != tid_current:
                win32process.AttachThreadInput(tid_current, tid_target, True)
                attached = True
            win32gui.SetForegroundWindow(target_hwnd)
        except Exception:
            # Windows focus-stealing rules may fall back to BringWindowToTop cleanly.
            with suppress(Exception):
                win32gui.BringWindowToTop(target_hwnd)
        finally:
            if attached:
                with suppress(Exception):
                    win32process.AttachThreadInput(tid_current, tid_target, False)

        fg_deadline = time.monotonic() + 0.12
        while win32gui.GetForegroundWindow() != target_hwnd and time.monotonic() < fg_deadline:
            time.sleep(0.012)
        # Brief yield so Qt's WM_ACTIVATE handler processes before the first click arrives.
        time.sleep(0.025)

        if target_hwnd == win.hwnd and (
            win.client_rect.width < 400 or win.client_rect.height < 300
        ):
            refreshed, _ = self._require_main_window()
            settle_deadline = time.monotonic() + 2.5
            while (
                refreshed.client_rect.width < 400 or refreshed.client_rect.height < 300
            ) and time.monotonic() < settle_deadline:
                win32gui.ShowWindow(target_hwnd, win32con.SW_SHOWMAXIMIZED)
                time.sleep(0.15)
                refreshed, _ = self._require_main_window()
            return refreshed

        refreshed, _ = self._require_main_window()
        return refreshed

    def _ensure_usable_window(
        self,
        win: WindowInfo,
        dialogs: list[GuiDialogInfo],
        *,
        background: bool,
    ) -> tuple[WindowInfo, list[GuiDialogInfo]]:
        """Un-minimize Packet Tracer silently if collapsed (-32000) while preserving user focus."""
        if (
            not win.is_minimized
            and win.client_rect.left > -10000
            and win.client_rect.width >= 400
            and win.client_rect.height >= 300
        ):
            return win, dialogs
        if platform.system() != "Windows":
            return win, dialogs

        u32 = ctypes.windll.user32
        prev_fg = _get_foreground_hwnd() if background else 0
        u32.ShowWindow(int(win.hwnd), _SW_SHOWNOACTIVATE)
        deadline = time.monotonic() + 0.18
        while time.monotonic() < deadline:
            time.sleep(0.02)
            win, dialogs = self._require_main_window()
            if (
                not win.is_minimized
                and win.client_rect.width >= 400
                and win.client_rect.height >= 300
            ):
                break

        if win.is_minimized or win.client_rect.width < 400 or win.client_rect.height < 300:
            u32.ShowWindow(int(win.hwnd), _SW_MAXIMIZE)
            deadline = time.monotonic() + 0.35
            while time.monotonic() < deadline:
                time.sleep(0.025)
                win, dialogs = self._require_main_window()
                if (
                    not win.is_minimized
                    and win.client_rect.width >= 400
                    and win.client_rect.height >= 300
                ):
                    break

        if background:
            if prev_fg and prev_fg != int(win.hwnd):
                _restore_user_foreground_and_cursor(prev_fg, None, push_hwnd=int(win.hwnd))
            else:
                # HWND_BOTTOM = 1 pushes window behind all non-topmost windows without activation.
                with suppress(Exception):
                    u32.SetWindowPos(
                        int(win.hwnd), 1, 0, 0, 0, 0, _SWP_NOMOVE | _SWP_NOSIZE | _SWP_NOACTIVATE
                    )
        return win, dialogs

    def capture_screenshot(
        self,
        output_path: str | None = None,
        *,
        full_window: bool = False,
        focus_first: bool = False,
        dialog_title: str | None = None,
    ) -> dict[str, Any]:
        """Capture Packet Tracer's main window or matching dialog offscreen via PrintWindow."""
        self._require_windows()
        win, dialogs = self._require_main_window()

        target_dlg: GuiDialogInfo | None = None
        if dialog_title is not None and dialog_title.strip():
            target_dlg = self._find_dialog_by_title(dialogs, dialog_title.strip())
            if target_dlg is None:
                raise ValidationError(
                    f"No open dialog matching '{dialog_title}' found.",
                    details={"open_dialogs": [d.title for d in dialogs]},
                )
            if focus_first:
                self._call_focus_window(target_dlg.hwnd, cached_win=win)
                _, dialogs = self._require_main_window()
                target_dlg = self._find_dialog_by_title(dialogs, dialog_title.strip()) or target_dlg
            target_hwnd = target_dlg.hwnd
            w_rect = target_dlg.rect
            c_rect = target_dlg.rect
            capture_full = True
        else:
            if focus_first:
                win = self._call_focus_window(win.hwnd, cached_win=win)
            elif win.is_minimized or win.client_rect.left <= -10000:
                win, dialogs = self._ensure_usable_window(win, dialogs, background=True)
            target_hwnd = win.hwnd
            w_rect = win.window_rect
            c_rect = win.client_rect
            capture_full = full_window

        rect = w_rect if capture_full else c_rect
        if rect.width <= 10 or rect.height <= 10:
            raise AdapterUnavailableError(
                "Packet Tracer window rect is collapsed or off-screen.",
                details={"rect": rect.model_dump()},
            )

        capture_mode = "screen_grab"
        img: Image.Image | None = None
        if not focus_first and _get_foreground_hwnd() != int(target_hwnd):
            with suppress(Exception):
                img = _capture_window_printwindow(
                    target_hwnd,
                    w_rect,
                    c_rect,
                    full_window=capture_full,
                )
            if img is not None:
                capture_mode = (
                    "printwindow_dialog_background"
                    if target_dlg is not None
                    else "printwindow_background"
                )

        if img is None:
            if ImageGrab is None:
                raise AdapterUnavailableError(
                    "Pillow (ImageGrab) is required for desktop screenshot capture.",
                    remediation="Install optional GUI extras: pip install 'agenticnet[gui]'.",
                )
            img = ImageGrab.grab(
                bbox=(rect.left, rect.top, rect.right, rect.bottom),
                all_screens=True,
            )
        if output_path:
            target = safe_resolve_path(output_path)
        else:
            self.screenshots_dir.mkdir(parents=True, exist_ok=True)
            stamp = int(time.time() * 1000)
            target = self.screenshots_dir / f"pt_{stamp}.png"

        save_image_png(img, target)
        stats = compute_image_stats(img)
        regions = detect_ui_regions_from_image(img)
        result: dict[str, Any] = {
            "screenshot_path": str(target),
            "capture_mode": capture_mode,
            "rect": rect.model_dump(),
            "stats": stats.model_dump(),
            "ui_regions": regions,
            "window_title": win.title,
            "open_dialogs": [d.model_dump(mode="json") for d in dialogs],
            "state_level": StateLevel.VERIFIED.value,
        }
        if target_dlg is not None:
            result["dialog_title"] = target_dlg.title
        return result

    def calibrate(self, *, profile_id: str = "default") -> dict[str, Any]:
        """Inspect PT client geometry/DPI and save a normalized calibration profile."""
        win, dialogs = self._require_main_window()
        if win.client_rect.width < 400 or win.client_rect.height < 300:
            win = self._call_focus_window(win.hwnd, cached_win=win)
        if win.client_rect.width < 400 or win.client_rect.height < 300:
            raise AdapterUnavailableError(
                "Packet Tracer main window is not ready for calibration yet.",
                details={
                    "client_width": win.client_rect.width,
                    "client_height": win.client_rect.height,
                },
                remediation=(
                    "Ensure Cisco Packet Tracer is maximized and visible on desktop, then retry."
                ),
            )
        profile = self.calibration.create_from_window(win, profile_id=profile_id)
        path = self.calibration.save_profile(profile)
        return {
            "profile": profile.model_dump(mode="json"),
            "profile_path": str(path),
            "window": win.model_dump(mode="json"),
            "open_dialogs": [d.model_dump(mode="json") for d in dialogs],
            "state_level": StateLevel.VERIFIED.value,
        }

    @staticmethod
    def _to_virtual_abs(sx: int, sy: int) -> tuple[int, int]:
        sm_x = ctypes.windll.user32.GetSystemMetrics(76)  # SM_XVIRTUALSCREEN
        sm_y = ctypes.windll.user32.GetSystemMetrics(77)  # SM_YVIRTUALSCREEN
        sm_w = max(1, ctypes.windll.user32.GetSystemMetrics(78))  # SM_CXVIRTUALSCREEN
        sm_h = max(1, ctypes.windll.user32.GetSystemMetrics(79))  # SM_CYVIRTUALSCREEN
        abs_x = int(((sx - sm_x) * 65535) / sm_w)
        abs_y = int(((sy - sm_y) * 65535) / sm_h)
        return abs_x, abs_y

    def _send_mouse_click(self, sx: int, sy: int, button: str, clicks: int) -> None:
        abs_x, abs_y = self._to_virtual_abs(sx, sy)

        down_up = {
            "left": (_MOUSEEVENTF_LEFTDOWN, _MOUSEEVENTF_LEFTUP),
            "right": (_MOUSEEVENTF_RIGHTDOWN, _MOUSEEVENTF_RIGHTUP),
            "middle": (_MOUSEEVENTF_MIDDLEDOWN, _MOUSEEVENTF_MIDDLEUP),
        }.get(button.lower())
        if down_up is None:
            raise ValidationError(
                f"Unsupported mouse button {button!r}. Expected left, right, or middle."
            )

        down_flag, up_flag = down_up
        base_move = _MOUSEEVENTF_MOVE | _MOUSEEVENTF_ABSOLUTE | _MOUSEEVENTF_VIRTUALDESK
        u32 = ctypes.windll.user32

        mv = (_INPUT * 1)()
        mv[0].type = _INPUT_MOUSE
        mv[0].ii.mi = _MOUSEINPUT(abs_x, abs_y, 0, base_move, 0, 0)
        if u32.SendInput(1, mv, ctypes.sizeof(_INPUT)) != 1:
            raise AdapterUnavailableError("Win32 SendInput mouse move failed.")
        time.sleep(0.008)

        for idx in range(max(1, clicks)):
            dn = (_INPUT * 1)()
            dn[0].type = _INPUT_MOUSE
            dn[0].ii.mi = _MOUSEINPUT(abs_x, abs_y, 0, down_flag, 0, 0)
            up = (_INPUT * 1)()
            up[0].type = _INPUT_MOUSE
            up[0].ii.mi = _MOUSEINPUT(abs_x, abs_y, 0, up_flag, 0, 0)
            if u32.SendInput(1, dn, ctypes.sizeof(_INPUT)) != 1:
                raise AdapterUnavailableError("Win32 SendInput mouse down failed.")
            time.sleep(0.008)
            if u32.SendInput(1, up, ctypes.sizeof(_INPUT)) != 1:
                raise AdapterUnavailableError("Win32 SendInput mouse up failed.")
            time.sleep(0.02 if idx + 1 < clicks else 0.006)

    def drag(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        steps: int = 15,
        duration_s: float = 0.35,
    ) -> dict[str, Any]:
        """Press left mouse button at `(start_x, start_y)`, drag to end point, and release."""
        self._require_windows()
        self.safety.check_safe_to_act(live_input=True)
        step_count = max(1, steps)
        step_delay = max(0.005, duration_s / step_count)
        base_move = _MOUSEEVENTF_MOVE | _MOUSEEVENTF_ABSOLUTE | _MOUSEEVENTF_VIRTUALDESK

        abs_sx, abs_sy = self._to_virtual_abs(int(start_x), int(start_y))
        start_move = (_INPUT * 1)()
        start_move[0].type = _INPUT_MOUSE
        start_move[0].ii.mi = _MOUSEINPUT(abs_sx, abs_sy, 0, base_move, 0, 0)
        ctypes.windll.user32.SendInput(1, start_move, ctypes.sizeof(_INPUT))
        time.sleep(0.03)

        down_input = (_INPUT * 1)()
        down_input[0].type = _INPUT_MOUSE
        down_input[0].ii.mi = _MOUSEINPUT(abs_sx, abs_sy, 0, _MOUSEEVENTF_LEFTDOWN, 0, 0)
        if ctypes.windll.user32.SendInput(1, down_input, ctypes.sizeof(_INPUT)) != 1:
            raise AdapterUnavailableError("Win32 SendInput drag start failed.")
        time.sleep(0.04)

        for i in range(1, step_count + 1):
            frac = i / step_count
            ix = int(round(start_x + (end_x - start_x) * frac))
            iy = int(round(start_y + (end_y - start_y) * frac))
            abs_ix, abs_iy = self._to_virtual_abs(ix, iy)
            move_input = (_INPUT * 1)()
            move_input[0].type = _INPUT_MOUSE
            move_input[0].ii.mi = _MOUSEINPUT(abs_ix, abs_iy, 0, base_move, 0, 0)
            ctypes.windll.user32.SendInput(1, move_input, ctypes.sizeof(_INPUT))
            time.sleep(step_delay)

        time.sleep(0.03)
        abs_ex, abs_ey = self._to_virtual_abs(int(end_x), int(end_y))
        up_input = (_INPUT * 1)()
        up_input[0].type = _INPUT_MOUSE
        up_input[0].ii.mi = _MOUSEINPUT(
            abs_ex, abs_ey, 0, _MOUSEEVENTF_LEFTUP | base_move, 0, 0
        )
        if ctypes.windll.user32.SendInput(1, up_input, ctypes.sizeof(_INPUT)) != 1:
            raise AdapterUnavailableError("Win32 SendInput drag release failed.")
        time.sleep(0.07)

        return {
            "start": [int(start_x), int(start_y)],
            "end": [int(end_x), int(end_y)],
            "steps": step_count,
            "state_level": StateLevel.EXECUTED.value,
        }

    def _send_key_chord(self, chord: str) -> list[str]:
        parsed = _parse_key_chord(chord)
        n = len(parsed)
        inputs = (_INPUT * (2 * n))()
        idx = 0
        for _, vk in parsed:
            inputs[idx].type = _INPUT_KEYBOARD
            inputs[idx].ii.ki = _KEYBDINPUT(vk, 0, 0, 0, 0)
            idx += 1
        for _, vk in reversed(parsed):
            inputs[idx].type = _INPUT_KEYBOARD
            inputs[idx].ii.ki = _KEYBDINPUT(vk, 0, _KEYEVENTF_KEYUP, 0, 0)
            idx += 1

        sent = ctypes.windll.user32.SendInput(2 * n, inputs, ctypes.sizeof(_INPUT))
        if sent != 2 * n:
            raise AdapterUnavailableError(
                f"Win32 SendInput keyboard dispatch failed for {chord!r}."
            )
        return [tok for tok, _ in parsed]

    def _send_unicode_text(self, text: str) -> None:
        if not text:
            return
        u32 = ctypes.windll.user32
        chunk_max = 64
        parts = text.split("\n")
        for p_idx, part in enumerate(parts):
            for start in range(0, len(part), chunk_max):
                seg = part[start : start + chunk_max]
                n = len(seg)
                inputs = (_INPUT * (2 * n))()
                for i, ch in enumerate(seg):
                    code = ord(ch)
                    inputs[2 * i].type = _INPUT_KEYBOARD
                    inputs[2 * i].ii.ki = _KEYBDINPUT(0, code, _KEYEVENTF_UNICODE, 0, 0)
                    inputs[2 * i + 1].type = _INPUT_KEYBOARD
                    inputs[2 * i + 1].ii.ki = _KEYBDINPUT(
                        0, code, _KEYEVENTF_UNICODE | _KEYEVENTF_KEYUP, 0, 0
                    )
                u32.SendInput(2 * n, inputs, ctypes.sizeof(_INPUT))
            if p_idx + 1 < len(parts):
                self._send_key_chord("enter")

    @staticmethod
    def _find_dialog_at_point(
        dialogs: list[GuiDialogInfo], sx: int, sy: int
    ) -> GuiDialogInfo | None:
        """Return the open Packet Tracer dialog containing `(sx, sy)`, if any."""
        for dlg in reversed(dialogs):
            if dlg.rect.left <= sx <= dlg.rect.right and dlg.rect.top <= sy <= dlg.rect.bottom:
                return dlg
        return None

    @staticmethod
    def _resolve_keypress_focus_hwnd(
        win: WindowInfo, dialogs: list[GuiDialogInfo]
    ) -> int | None:
        """Pick which PT window/dialog needs focus for keyboard dispatch without burying dialogs."""
        try:
            import win32gui  # type: ignore[import-untyped]
            import win32process  # type: ignore[import-untyped]

            fg_hwnd = win32gui.GetForegroundWindow()
            if fg_hwnd:
                _, fg_pid = win32process.GetWindowThreadProcessId(fg_hwnd)
                if fg_pid == win.pid or any(d.hwnd == fg_hwnd for d in dialogs):
                    return None
        except Exception:
            pass

        for dlg in reversed(dialogs):
            if dlg.title.strip().lower() != "packettracer":
                return dlg.hwnd
        return win.hwnd

    def _dispatch_click(
        self,
        win: WindowInfo,
        dialogs: list[GuiDialogInfo],
        sx: int,
        sy: int,
        *,
        button: str = "left",
        clicks: int = 1,
        focus_first: bool = True,
        use_bg: bool = True,
        restore_focus: bool = False,
    ) -> int:
        """Execute a mouse click in either background PostMessage mode or foreground SendInput."""
        target_dlg = self._find_dialog_at_point(dialogs, sx, sy)
        top_hwnd = target_dlg.hwnd if target_dlg is not None else win.hwnd

        if use_bg and platform.system() == "Windows":
            if win.is_minimized:
                ctypes.windll.user32.ShowWindow(int(win.hwnd), _SW_SHOWNOACTIVATE)
                time.sleep(0.05)
            return _post_mouse_click_to_hwnd(top_hwnd, sx, sy, button=button, clicks=clicks)

        prev_fg = _get_foreground_hwnd() if restore_focus else 0
        prev_cursor = _get_cursor_pos() if restore_focus else None
        try:
            if target_dlg is not None and focus_first:
                self._call_focus_window(target_dlg.hwnd, cached_win=win)
            elif focus_first or win.is_minimized:
                self._call_focus_window(win.hwnd, cached_win=win)
            self._send_mouse_click(sx, sy, button=button, clicks=clicks)
        finally:
            if restore_focus and (prev_fg or prev_cursor is not None):
                _restore_user_foreground_and_cursor(
                    prev_fg, prev_cursor, push_hwnd=top_hwnd if prev_fg else 0
                )
        return top_hwnd

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
        focus_first: bool = True,
        background: bool | None = None,
        restore_focus: bool = False,
    ) -> dict[str, Any]:
        """Resolve calibrated point inside PT client rect and optionally perform click."""
        self.safety.check_safe_to_act(live_input=not dry_run)
        use_bg = self._resolve_background(background)
        win, dialogs = self._require_main_window()
        if not dry_run or win.is_minimized or win.client_rect.left <= -10000:
            win, dialogs = self._ensure_usable_window(win, dialogs, background=use_bg)

        profile = self.calibration.ensure_or_default()
        sx, sy, source, anchor_verified = self.calibration.resolve_screen_point(
            win.client_rect,
            x=x,
            y=y,
            nx=nx,
            ny=ny,
            anchor_name=anchor_name,
            profile=profile,
        )

        if dry_run:
            return {
                "dry_run": True,
                "background": use_bg,
                "screen_x": sx,
                "screen_y": sy,
                "button": button,
                "clicks": clicks,
                "resolution_source": source,
                "anchor_verified": anchor_verified,
                "open_dialogs": [d.model_dump(mode="json") for d in dialogs],
                "state_level": StateLevel.PLANNED.value,
            }

        target_hwnd = self._dispatch_click(
            win,
            dialogs,
            sx,
            sy,
            button=button,
            clicks=clicks,
            focus_first=focus_first,
            use_bg=use_bg,
            restore_focus=restore_focus,
        )
        return {
            "dry_run": False,
            "background": use_bg,
            "target_hwnd": target_hwnd,
            "screen_x": sx,
            "screen_y": sy,
            "button": button,
            "clicks": clicks,
            "resolution_source": source,
            "anchor_verified": anchor_verified,
            "state_level": StateLevel.EXECUTED.value,
        }

    def _dispatch_keypress(
        self,
        win: WindowInfo,
        dialogs: list[GuiDialogInfo],
        keys: str,
        *,
        text: str | None = None,
        focus_first: bool = True,
        use_bg: bool = True,
        restore_focus: bool = False,
        target_hwnd: int | None = None,
    ) -> tuple[list[str], int]:
        """Dispatch a key chord and/or text in background PostMessage or foreground mode."""
        parsed = _parse_key_chord(keys) if keys.strip() else []
        top_hwnd = target_hwnd
        if top_hwnd is None:
            resolved = self._resolve_keypress_focus_hwnd(win, dialogs)
            if resolved is not None:
                top_hwnd = resolved
            else:
                # Active PT dialog or main window already focused; pick dialog if present.
                non_main = [
                    d.hwnd for d in reversed(dialogs) if d.title.strip().lower() != "packettracer"
                ]
                top_hwnd = non_main[0] if non_main else win.hwnd

        if use_bg and platform.system() == "Windows":
            child_hwnd = _resolve_focus_child_hwnd(top_hwnd)
            sent_keys: list[str] = []
            if parsed:
                sent_keys = _post_key_chord_to_hwnd(child_hwnd, keys)
            if text:
                _post_text_to_hwnd(child_hwnd, text)
            return sent_keys, child_hwnd

        prev_fg = _get_foreground_hwnd() if restore_focus else 0
        prev_cursor = _get_cursor_pos() if restore_focus else None
        try:
            if focus_first:
                focus_target = target_hwnd or self._resolve_keypress_focus_hwnd(win, dialogs)
                if focus_target is not None:
                    self._call_focus_window(focus_target, cached_win=win)
            sent_keys = self._send_key_chord(keys) if parsed else []
            if text:
                self._send_unicode_text(text)
        finally:
            if restore_focus and prev_fg:
                _restore_user_foreground_and_cursor(prev_fg, prev_cursor, push_hwnd=top_hwnd)
        return sent_keys, top_hwnd

    def keypress(
        self,
        keys: str,
        *,
        text: str | None = None,
        dry_run: bool = False,
        focus_first: bool = True,
        confirm: bool = False,
        background: bool | None = None,
        restore_focus: bool = False,
    ) -> dict[str, Any]:
        """Dispatch a keyboard chord or Unicode string to Packet Tracer."""
        normalized_chord = keys.strip().lower()
        if normalized_chord in {"alt+f4", "ctrl+q"}:
            self.safety.require_confirmation_for_risky_action(normalized_chord, confirm=confirm)

        self.safety.check_safe_to_act(live_input=not dry_run)
        parsed = _parse_key_chord(keys) if keys.strip() else []
        use_bg = self._resolve_background(background)

        if dry_run:
            return {
                "dry_run": True,
                "background": use_bg,
                "keys": [tok for tok, _ in parsed],
                "text_length": len(text) if text else 0,
                "state_level": StateLevel.PLANNED.value,
            }

        win, dialogs = self._require_main_window()
        sent_keys, target_hwnd = self._dispatch_keypress(
            win,
            dialogs,
            keys,
            text=text,
            focus_first=focus_first,
            use_bg=use_bg,
            restore_focus=restore_focus,
        )

        return {
            "dry_run": False,
            "background": use_bg,
            "target_hwnd": target_hwnd,
            "keys": sent_keys,
            "text_length": len(text) if text else 0,
            "window_title": win.title,
            "state_level": StateLevel.EXECUTED.value,
        }

    def inspect_state(self) -> dict[str, Any]:
        """Return structured GUI state including window geometry, dialogs, and calibration."""
        detection = self.detect_application()
        profile = self.calibration.ensure_or_default()
        dialogs = [GuiDialogInfo.model_validate(d) for d in detection.get("dialogs", [])]
        win = WindowInfo.model_validate(detection["window"]) if detection.get("window") else None
        warnings: list[str] = []
        if any(d.dialog_type == DialogType.LOGIN_WALL for d in dialogs):
            warnings.append("Packet Tracer login wall is open and may block workspace automation.")
        if win and win.has_unsaved_changes:
            warnings.append("Packet Tracer window indicates unsaved project modifications ('*').")
        if win and not profile:
            warnings.append("No calibration profile saved yet; run gui_calibrate first.")

        report = GuiStateReport(
            detected=detection["detected_binary"],
            running=detection["running"],
            executable_path=detection["executable_path"],
            window=win,
            dialogs=dialogs,
            calibration_loaded=profile is not None,
            calibration_profile_id=profile.profile_id if profile else None,
            abort_armed=self.safety.is_stopped(),
            warnings=warnings,
        )
        return {
            "report": report.model_dump(mode="json"),
            "state_level": StateLevel.VERIFIED.value,
        }

    def recover(self, *, strategy: str = "dismiss_dialog", confirm: bool = False) -> dict[str, Any]:
        """Recover from modal dialogs or arm/reset emergency stop safely."""
        if strategy == "reset_abort":
            self.safety.reset()
            return {
                "strategy": strategy,
                "abort_armed": False,
                "state_level": StateLevel.EXECUTED.value,
            }

        if strategy == "emergency_stop":
            self.safety.request_stop("User/agent triggered gui_recover emergency_stop.")
            return {
                "strategy": strategy,
                "abort_armed": True,
                "state_level": StateLevel.EXECUTED.value,
            }

        if strategy in {"discard_changes", "force_close_dialogs"}:
            self.safety.require_confirmation_for_risky_action(strategy, confirm=confirm)

        self._require_windows()
        self.safety.check_safe_to_act(live_input=True)
        detection = self.detect_application()
        dialogs = [GuiDialogInfo.model_validate(d) for d in detection.get("dialogs", [])]
        if not dialogs:
            return {
                "strategy": strategy,
                "dismissed": 0,
                "message": "No unexpected Packet Tracer popup dialogs detected.",
                "state_level": StateLevel.VERIFIED.value,
            }

        import win32con  # type: ignore[import-untyped]
        import win32gui  # type: ignore[import-untyped]

        dismissed: list[dict[str, Any]] = []
        for dlg in dialogs:
            if dlg.dialog_type in {DialogType.LOGIN_WALL, DialogType.DEVICE_WINDOW} and not confirm:
                continue
            win32gui.PostMessage(dlg.hwnd, win32con.WM_CLOSE, 0, 0)
            dismissed.append({"hwnd": dlg.hwnd, "title": dlg.title, "type": dlg.dialog_type.value})

        time.sleep(0.25)
        after = self.detect_application()
        return {
            "strategy": strategy,
            "dismissed": len(dismissed),
            "dismissed_dialogs": dismissed,
            "remaining_dialogs": after.get("dialogs", []),
            "state_level": StateLevel.VERIFIED.value,
        }

    def capture_text_from_focused_window(self) -> str:
        """Select and copy text from a focused Packet Tracer CLI pane using Ctrl+A, Ctrl+C."""
        self.safety.check_safe_to_act(live_input=True)
        prev = _clipboard_read()
        self._send_key_chord("ctrl+a")
        time.sleep(0.08)
        self._send_key_chord("ctrl+c")
        time.sleep(0.12)
        captured = _clipboard_read()
        if not captured and prev:
            _clipboard_write(prev)
        return captured

    def paste_lines_to_focused_window(self, lines: list[str], *, delay_s: float = 0.08) -> None:
        """Send command lines reliably into a focused Packet Tracer CLI pane."""
        self.safety.check_safe_to_act(live_input=True)
        for line in lines:
            self.safety.check_safe_to_act(live_input=True)
            self._send_unicode_text(line)
            self._send_key_chord("enter")
            time.sleep(delay_s)

    @staticmethod
    def _find_dialog_by_title(
        dialogs: list[GuiDialogInfo], title_contains: str
    ) -> GuiDialogInfo | None:
        """Find the topmost open Packet Tracer dialog matching a title substring."""
        needle = title_contains.strip().lower()
        if not needle:
            return None
        for dlg in reversed(dialogs):
            if needle in dlg.title.lower():
                return dlg
        return None

    def _batch_step_click(self, step: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        win: WindowInfo = ctx["win"]
        dialogs: list[GuiDialogInfo] = ctx["dialogs"]
        sx, sy, source, anchor_verified = self.calibration.resolve_screen_point(
            win.client_rect,
            x=step.get("x"),
            y=step.get("y"),
            nx=step.get("nx"),
            ny=step.get("ny"),
            anchor_name=step.get("anchor_name"),
            profile=ctx["profile"],
        )
        button = str(step.get("button", "left"))
        clicks = max(1, int(step.get("clicks", 1)))
        step_bg = self._resolve_background(step.get("background", ctx["background"]))
        if ctx["dry_run"]:
            return {
                "op": "click",
                "dry_run": True,
                "screen_x": sx,
                "screen_y": sy,
                "background": step_bg,
            }
        if not step_bg:
            ctx["ensure_fg_saved"]()
        hwnd = self._dispatch_click(
            win,
            dialogs,
            sx,
            sy,
            button=button,
            clicks=clicks,
            focus_first=bool(step.get("focus_first", True)),
            use_bg=step_bg,
            restore_focus=False,
        )
        delay_ms = int(step.get("delay_ms", 18))
        if delay_ms > 0:
            time.sleep(min(delay_ms, 5000) / 1000.0)
        return {
            "op": "click",
            "screen_x": sx,
            "screen_y": sy,
            "resolution_source": source,
            "anchor_verified": anchor_verified,
            "target_hwnd": hwnd,
            "background": step_bg,
        }

    @staticmethod
    def _refresh_dialog_info(dlg: GuiDialogInfo) -> GuiDialogInfo:
        """Read live Win32 bounding rect for an open dialog to avoid stale spawn geometry."""
        if platform.system() != "Windows":
            return dlg
        try:
            import win32gui  # type: ignore[import-untyped]

            left, top, right, bottom = win32gui.GetWindowRect(int(dlg.hwnd))
            if right > left and bottom > top:
                return dlg.model_copy(
                    update={"rect": Rect(left=left, top=top, right=right, bottom=bottom)}
                )
        except Exception:
            pass
        return dlg

    def _get_fresh_batch_dialog(self, ctx: dict[str, Any], title_contains: str) -> GuiDialogInfo:
        """Locate an open batch dialog by title substring and refresh its live geometry."""
        dlg = self._find_dialog_by_title(ctx["dialogs"], title_contains)
        if dlg is None:
            ctx["refresh"]()
            dlg = self._find_dialog_by_title(ctx["dialogs"], title_contains)
        if dlg is None:
            raise ValidationError(
                f"No open dialog matching '{title_contains}' found.",
                details={"open_dialogs": [d.title for d in ctx["dialogs"]]},
            )
        fresh = self._refresh_dialog_info(dlg)
        ctx["dialogs"] = [fresh if d.hwnd == fresh.hwnd else d for d in ctx["dialogs"]]
        return fresh

    @staticmethod
    def _resolve_dialog_point(
        rect: Rect,
        *,
        offset_x: Any = None,
        offset_y: Any = None,
        nx: Any = None,
        ny: Any = None,
        default_x: int = 0,
        default_y: int = 0,
    ) -> tuple[int, int]:
        """Resolve screen `(sx, sy)` inside a dialog rect from normalized or pixel offsets."""
        if nx is not None and ny is not None:
            fnx, fny = float(nx), float(ny)
            if not (0.0 <= fnx <= 1.0 and 0.0 <= fny <= 1.0):
                raise ValidationError(
                    f"Normalized dialog coordinates ({fnx}, {fny}) must be within [0.0, 1.0].",
                    details={"nx": fnx, "ny": fny},
                )
            return (
                rect.left + int(round(fnx * rect.width)),
                rect.top + int(round(fny * rect.height)),
            )
        ox = int(default_x if offset_x is None else offset_x)
        oy = int(default_y if offset_y is None else offset_y)
        return rect.left + ox, rect.top + oy

    def _batch_step_click_dialog(self, step: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        title_contains = str(step.get("title_contains", "")).strip()
        dlg = self._get_fresh_batch_dialog(ctx, title_contains)
        sx, sy = self._resolve_dialog_point(
            dlg.rect,
            offset_x=step.get("offset_x"),
            offset_y=step.get("offset_y"),
            nx=step.get("nx"),
            ny=step.get("ny"),
        )
        button = str(step.get("button", "left"))
        clicks = max(1, int(step.get("clicks", 1)))
        step_bg = self._resolve_background(step.get("background", ctx["background"]))
        if ctx["dry_run"]:
            return {
                "op": "click_dialog",
                "dry_run": True,
                "dialog_title": dlg.title,
                "screen_x": sx,
                "screen_y": sy,
                "background": step_bg,
            }
        if not step_bg:
            ctx["ensure_fg_saved"](push_hwnd=dlg.hwnd)
        hwnd = self._dispatch_click(
            ctx["win"],
            ctx["dialogs"],
            sx,
            sy,
            button=button,
            clicks=clicks,
            focus_first=bool(step.get("focus_first", True)),
            use_bg=step_bg,
            restore_focus=False,
        )
        delay_ms = int(step.get("delay_ms", 35))
        if delay_ms > 0:
            time.sleep(min(delay_ms, 5000) / 1000.0)
        return {
            "op": "click_dialog",
            "dialog_title": dlg.title,
            "screen_x": sx,
            "screen_y": sy,
            "target_hwnd": hwnd,
            "background": step_bg,
        }

    def _batch_step_wait_dialog(self, step: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        title_contains = str(step.get("title_contains", "")).strip()
        if not title_contains:
            raise ValidationError("'wait_dialog' requires non-empty 'title_contains'.")
        if ctx["dry_run"]:
            return {"op": "wait_dialog", "dry_run": True, "title_contains": title_contains}
        step_bg = self._resolve_background(step.get("background", ctx["background"]))
        prev_fg = _get_foreground_hwnd() if step_bg and platform.system() == "Windows" else 0
        timeout_s = max(0.1, min(float(step.get("timeout_s", 4.0)), 30.0))
        poll_s = max(0.02, min(int(step.get("poll_ms", 40)) / 1000.0, 0.5))
        deadline = time.monotonic() + timeout_s
        while True:
            ctx["refresh"]()
            dlg = self._find_dialog_by_title(ctx["dialogs"], title_contains)
            if dlg is not None:
                # Allow Qt's initial work-area constraint pass (e.g. top=198 -> 131) to settle.
                prev_rect = dlg.rect
                for _ in range(3):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(0.03, remaining))
                    settled = self._refresh_dialog_info(dlg)
                    dlg = settled
                    if settled.rect == prev_rect:
                        break
                    prev_rect = settled.rect
                ctx["dialogs"] = [dlg if d.hwnd == dlg.hwnd else d for d in ctx["dialogs"]]
                if step_bg and prev_fg and platform.system() == "Windows":
                    curr_fg = _get_foreground_hwnd()
                    if curr_fg in {int(dlg.hwnd), int(ctx["win"].hwnd)}:
                        _restore_user_foreground_and_cursor(prev_fg, None, push_hwnd=int(dlg.hwnd))
                return {
                    "op": "wait_dialog",
                    "dialog_title": dlg.title,
                    "hwnd": dlg.hwnd,
                    "rect": dlg.rect.model_dump(),
                }
            if time.monotonic() >= deadline:
                raise AdapterUnavailableError(
                    f"Timed out waiting for dialog matching '{title_contains}'.",
                    details={"open_dialogs": [d.title for d in ctx["dialogs"]]},
                )
            time.sleep(poll_s)

    def _batch_step_close_dialog(self, step: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        title_contains = str(step.get("title_contains", "")).strip()
        if ctx["dry_run"]:
            return {"op": "close_dialog", "dry_run": True, "title_contains": title_contains}
        import win32con  # type: ignore[import-untyped]
        import win32gui  # type: ignore[import-untyped]

        ctx["refresh"]()
        closed: list[str] = []
        for dlg in ctx["dialogs"]:
            if not title_contains or title_contains.lower() in dlg.title.lower():
                if dlg.title.strip().lower() == "packettracer":
                    continue
                win32gui.PostMessage(dlg.hwnd, win32con.WM_CLOSE, 0, 0)
                closed.append(dlg.title)
        wait_gone_s = max(0.0, min(float(step.get("wait_gone_s", 1.5)), 10.0))
        if closed and wait_gone_s > 0:
            deadline = time.monotonic() + wait_gone_s
            while time.monotonic() < deadline:
                time.sleep(0.05)
                ctx["refresh"]()
                if (
                    not title_contains
                    or self._find_dialog_by_title(ctx["dialogs"], title_contains) is None
                ):
                    break
        return {"op": "close_dialog", "closed": closed, "count": len(closed)}

    def _batch_step_keypress(self, step: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        keys = str(step.get("keys", ""))
        text = step.get("text")
        normalized_chord = keys.strip().lower()
        if normalized_chord in {"alt+f4", "ctrl+q"}:
            self.safety.require_confirmation_for_risky_action(
                normalized_chord, confirm=bool(step.get("confirm", False))
            )
        parsed = _parse_key_chord(keys) if keys.strip() else []
        step_bg = self._resolve_background(step.get("background", ctx["background"]))
        if ctx["dry_run"]:
            return {
                "op": "keypress",
                "dry_run": True,
                "keys": [tok for tok, _ in parsed],
                "text_length": len(text) if text else 0,
                "background": step_bg,
            }
        target_hwnd: int | None = None
        if step.get("title_contains"):
            dlg = self._find_dialog_by_title(ctx["dialogs"], str(step["title_contains"]))
            if dlg is not None:
                target_hwnd = dlg.hwnd
        if not step_bg:
            ctx["ensure_fg_saved"]()
        sent_keys, used_hwnd = self._dispatch_keypress(
            ctx["win"],
            ctx["dialogs"],
            keys,
            text=text,
            focus_first=bool(step.get("focus_first", True)),
            use_bg=step_bg,
            restore_focus=False,
            target_hwnd=target_hwnd,
        )
        delay_ms = int(step.get("delay_ms", 15))
        if delay_ms > 0:
            time.sleep(min(delay_ms, 5000) / 1000.0)
        return {
            "op": "keypress",
            "keys": sent_keys,
            "text_length": len(text) if text else 0,
            "target_hwnd": used_hwnd,
            "background": step_bg,
        }

    def _batch_step_paste_lines(self, step: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        raw_lines = step.get("lines")
        if not isinstance(raw_lines, list):
            raise ValidationError("'paste_lines' requires a list of strings in 'lines'.")
        lines = [str(line) for line in raw_lines]
        step_bg = self._resolve_background(step.get("background", ctx["background"]))
        if ctx["dry_run"]:
            return {
                "op": "paste_lines",
                "dry_run": True,
                "line_count": len(lines),
                "background": step_bg,
            }

        target_hwnd: int | None = None
        if step.get("title_contains"):
            dlg = self._find_dialog_by_title(ctx["dialogs"], str(step["title_contains"]))
            if dlg is None:
                ctx["refresh"]()
                dlg = self._find_dialog_by_title(ctx["dialogs"], str(step["title_contains"]))
            if dlg is not None:
                target_hwnd = dlg.hwnd
        if not step_bg:
            ctx["ensure_fg_saved"]()
            if target_hwnd is not None:
                self._call_focus_window(target_hwnd, cached_win=ctx["win"])
            else:
                resolved = self._resolve_keypress_focus_hwnd(ctx["win"], ctx["dialogs"])
                if resolved is not None:
                    self._call_focus_window(resolved, cached_win=ctx["win"])

        delay_s = max(0.0, min(int(step.get("delay_ms", 12)), 1000) / 1000.0)
        child_hwnd: int | None = None
        if step_bg and platform.system() == "Windows":
            base_hwnd = target_hwnd or ctx["win"].hwnd
            if target_hwnd is None:
                non_main = [
                    d.hwnd
                    for d in reversed(ctx["dialogs"])
                    if d.title.strip().lower() != "packettracer"
                ]
                if non_main:
                    base_hwnd = non_main[0]
            child_hwnd = _resolve_focus_child_hwnd(base_hwnd)
            if (
                child_hwnd == base_hwnd
                and target_hwnd is not None
                and step.get("offset_x") is not None
                and step.get("offset_y") is not None
            ):
                matching_dlg = next((d for d in ctx["dialogs"] if d.hwnd == target_hwnd), None)
                if matching_dlg is not None:
                    matching_dlg = self._refresh_dialog_info(matching_dlg)
                    child_hwnd, _, _ = _resolve_child_window_at_point(
                        target_hwnd,
                        matching_dlg.rect.left + int(step["offset_x"]),
                        matching_dlg.rect.top + int(step["offset_y"]),
                    )

        for line in lines:
            self.safety.check_safe_to_act(live_input=True, count_action=False)
            if step_bg and child_hwnd is not None:
                if line:
                    _post_text_to_hwnd(child_hwnd, line)
                _post_key_chord_to_hwnd(child_hwnd, "enter")
            else:
                if line:
                    self._send_unicode_text(line)
                self._send_key_chord("enter")
            if delay_s > 0:
                time.sleep(delay_s)

        return {
            "op": "paste_lines",
            "line_count": len(lines),
            "target_hwnd": child_hwnd or target_hwnd or ctx["win"].hwnd,
            "background": step_bg,
        }

    def _batch_step_sleep(self, step: dict[str, Any], _ctx: dict[str, Any]) -> dict[str, Any]:
        ms = max(0, min(int(step.get("ms", 100)), 10000))
        if not _ctx["dry_run"] and ms > 0:
            time.sleep(ms / 1000.0)
        return {"op": "sleep", "ms": ms}

    def _batch_step_screenshot(self, step: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        if ctx["dry_run"]:
            return {
                "op": "screenshot",
                "dry_run": True,
                "dialog_title": step.get("dialog_title"),
            }
        res = self.capture_screenshot(
            output_path=step.get("output_path"),
            full_window=bool(step.get("full_window", False)),
            focus_first=bool(step.get("focus_first", False)),
            dialog_title=step.get("dialog_title"),
        )
        res["op"] = "screenshot"
        return res

    def _dispatch_drag(
        self,
        op_name: str,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        step: dict[str, Any],
        ctx: dict[str, Any],
        *,
        target_hwnd: int,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        step_bg = self._resolve_background(step.get("background", ctx["background"]))
        steps_count = max(1, min(int(step.get("steps", 12)), 60))
        duration_s = max(0.02, min(int(step.get("duration_ms", 180)) / 1000.0, 5.0))
        out: dict[str, Any] = {
            "op": op_name,
            "start": [int(start_x), int(start_y)],
            "end": [int(end_x), int(end_y)],
            "steps": steps_count,
            "target_hwnd": target_hwnd,
            "background": step_bg,
        }
        if extra:
            out.update(extra)
        if ctx["dry_run"]:
            out["dry_run"] = True
            return out
        if step_bg and platform.system() == "Windows":
            used_hwnd = _post_mouse_drag_to_hwnd(
                target_hwnd,
                start_x,
                start_y,
                end_x,
                end_y,
                steps=steps_count,
                duration_s=duration_s,
            )
            out["target_hwnd"] = used_hwnd
        else:
            ctx["ensure_fg_saved"](push_hwnd=target_hwnd)
            if bool(step.get("focus_first", True)):
                self._call_focus_window(target_hwnd, cached_win=ctx["win"])
                time.sleep(0.06)
            self.drag(
                start_x,
                start_y,
                end_x,
                end_y,
                steps=steps_count,
                duration_s=duration_s,
            )
        delay_ms = int(step.get("delay_ms", 40))
        if delay_ms > 0:
            time.sleep(min(delay_ms, 5000) / 1000.0)
        return out

    def _batch_step_drag(self, step: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        win: WindowInfo = ctx["win"]
        sx, sy, _, _ = self.calibration.resolve_screen_point(
            win.client_rect,
            x=step.get("from_x", step.get("start_x")),
            y=step.get("from_y", step.get("start_y")),
            nx=step.get("from_nx"),
            ny=step.get("from_ny"),
            anchor_name=step.get("from_anchor"),
            profile=ctx["profile"],
        )
        ex, ey, _, _ = self.calibration.resolve_screen_point(
            win.client_rect,
            x=step.get("to_x", step.get("end_x")),
            y=step.get("to_y", step.get("end_y")),
            nx=step.get("to_nx"),
            ny=step.get("to_ny"),
            anchor_name=step.get("to_anchor"),
            profile=ctx["profile"],
        )
        target_dlg = self._find_dialog_at_point(ctx["dialogs"], sx, sy)
        top_hwnd = target_dlg.hwnd if target_dlg is not None else win.hwnd
        return self._dispatch_drag("drag", sx, sy, ex, ey, step, ctx, target_hwnd=top_hwnd)

    def _batch_step_drag_dialog(self, step: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
        title_contains = str(step.get("title_contains", "")).strip()
        dlg = self._get_fresh_batch_dialog(ctx, title_contains)
        sx, sy = self._resolve_dialog_point(
            dlg.rect,
            offset_x=step.get("from_x", step.get("start_offset_x")),
            offset_y=step.get("from_y", step.get("start_offset_y")),
            nx=step.get("from_nx"),
            ny=step.get("from_ny"),
        )
        ex, ey = self._resolve_dialog_point(
            dlg.rect,
            offset_x=step.get("to_x", step.get("end_offset_x")),
            offset_y=step.get("to_y", step.get("end_offset_y")),
            nx=step.get("to_nx"),
            ny=step.get("to_ny"),
        )
        return self._dispatch_drag(
            "drag_dialog",
            sx,
            sy,
            ex,
            ey,
            step,
            ctx,
            target_hwnd=dlg.hwnd,
            extra={"dialog_title": dlg.title},
        )

    def _batch_step_click_template(
        self, step: dict[str, Any], ctx: dict[str, Any]
    ) -> dict[str, Any]:
        template_path = safe_resolve_path(str(step.get("template_path", "")))
        if not template_path.exists():
            raise ValidationError(f"Template image not found: {template_path}")
        if ctx["dry_run"]:
            return {"op": "click_template", "dry_run": True, "template_path": str(template_path)}

        import cv2  # type: ignore[import-untyped]
        import numpy as np  # type: ignore[import-untyped]

        win: WindowInfo = ctx["win"]
        img = None
        if platform.system() == "Windows":
            with suppress(Exception):
                img = _capture_window_printwindow(
                    win.hwnd, win.window_rect, win.client_rect, full_window=False
                )
        if img is None:
            if ImageGrab is None:
                raise AdapterUnavailableError(
                    "Pillow (ImageGrab) is required for template matching.",
                    remediation="Install optional GUI extras: pip install 'agenticnet[gui]'.",
                )
            rect = win.client_rect
            img = ImageGrab.grab(
                bbox=(rect.left, rect.top, rect.right, rect.bottom),
                all_screens=True,
            )

        bgr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
        tpl = cv2.imread(str(template_path))
        if tpl is None:
            raise ValidationError(f"Failed to load template image: {template_path}")

        ih, iw = bgr.shape[:2]
        region = step.get("region_nx") or [0.0, 1.0, 0.0, 1.0]
        x0 = max(0, int(iw * float(region[0])))
        x1 = min(iw, int(iw * float(region[1])))
        y0 = max(0, int(ih * float(region[2])))
        y1 = min(ih, int(ih * float(region[3])))
        roi = bgr[y0:y1, x0:x1]
        res = cv2.matchTemplate(roi, tpl, cv2.TM_CCOEFF_NORMED)
        _, max_val, _, max_loc = cv2.minMaxLoc(res)
        min_score = float(step.get("min_score", 0.85))
        if max_val < min_score:
            raise AdapterUnavailableError(
                f"Template '{template_path.name}' match score {max_val:.3f} < {min_score:.3f}.",
                details={"score": float(max_val), "min_score": min_score},
            )

        th, tw = tpl.shape[:2]
        cx = x0 + max_loc[0] + tw // 2 + int(step.get("offset_dx", 0))
        cy = y0 + max_loc[1] + th // 2 + int(step.get("offset_dy", 0))
        sx = win.client_rect.left + cx
        sy = win.client_rect.top + cy
        step_bg = self._resolve_background(step.get("background", ctx["background"]))
        if not step_bg:
            ctx["ensure_fg_saved"]()
        hwnd = self._dispatch_click(
            win,
            ctx["dialogs"],
            sx,
            sy,
            button=str(step.get("button", "left")),
            clicks=max(1, int(step.get("clicks", 1))),
            focus_first=bool(step.get("focus_first", True)),
            use_bg=step_bg,
            restore_focus=False,
        )
        delay_ms = int(step.get("delay_ms", 35))
        if delay_ms > 0:
            time.sleep(min(delay_ms, 5000) / 1000.0)
        return {
            "op": "click_template",
            "template": template_path.name,
            "score": round(float(max_val), 4),
            "screen_x": sx,
            "screen_y": sy,
            "target_hwnd": hwnd,
            "background": step_bg,
        }

    def execute_batch(
        self,
        actions: list[dict[str, Any]],
        *,
        background: bool | None = None,
        restore_focus: bool = True,
        stop_on_error: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Execute a sequence of calibrated GUI actions in one low-latency batch."""
        if not actions:
            raise ValidationError("'actions' must contain at least one batch step.")

        self.safety.check_safe_to_act(live_input=not dry_run)
        default_bg = self._resolve_background(background)
        win, dialogs = self._require_main_window()
        if not dry_run or win.is_minimized or win.client_rect.left <= -10000:
            win, dialogs = self._ensure_usable_window(win, dialogs, background=default_bg)
        profile = self.calibration.ensure_or_default()

        handlers = {
            "click": self._batch_step_click,
            "click_dialog": self._batch_step_click_dialog,
            "click_template": self._batch_step_click_template,
            "drag": self._batch_step_drag,
            "drag_dialog": self._batch_step_drag_dialog,
            "wait_dialog": self._batch_step_wait_dialog,
            "close_dialog": self._batch_step_close_dialog,
            "keypress": self._batch_step_keypress,
            "paste_lines": self._batch_step_paste_lines,
            "sleep": self._batch_step_sleep,
            "screenshot": self._batch_step_screenshot,
        }

        fg_state: dict[str, Any] = {
            "saved": False,
            "fg": 0,
            "cursor": None,
            "push_hwnd": 0,
            "initial_fg": _get_foreground_hwnd() if restore_focus and not dry_run else 0,
        }

        def _ensure_fg_saved(*, push_hwnd: int = 0) -> None:
            if push_hwnd:
                fg_state["push_hwnd"] = int(push_hwnd)
            if not restore_focus or fg_state["saved"]:
                return
            fg_state["saved"] = True
            fg_state["fg"] = _get_foreground_hwnd()
            fg_state["cursor"] = _get_cursor_pos()

        ctx: dict[str, Any] = {
            "win": win,
            "dialogs": dialogs,
            "profile": profile,
            "background": default_bg,
            "dry_run": dry_run,
            "ensure_fg_saved": _ensure_fg_saved,
        }

        def _refresh() -> None:
            fresh_win, fresh_dialogs = self._require_main_window()
            if (
                fresh_win.is_minimized
                or fresh_win.client_rect.left <= -10000
                or fresh_win.client_rect.width < 400
            ):
                fresh_win, fresh_dialogs = self._ensure_usable_window(
                    fresh_win, fresh_dialogs, background=default_bg
                )
            ctx["win"], ctx["dialogs"] = fresh_win, fresh_dialogs

        ctx["refresh"] = _refresh

        started = time.perf_counter()
        results: list[dict[str, Any]] = []
        failed_count = 0

        try:
            for idx, step in enumerate(actions):
                if not isinstance(step, dict):
                    raise ValidationError(f"Batch step {idx} must be an object/dict.")
                op = str(step.get("op", "")).strip().lower()
                handler = handlers.get(op)
                if handler is None:
                    raise ValidationError(
                        f"Unsupported batch op '{op}' at step {idx}.",
                        details={"supported_ops": sorted(handlers)},
                    )
                if not dry_run:
                    self.safety.check_safe_to_act(live_input=True)
                try:
                    if step.get("refresh"):
                        _refresh()
                    step_res = handler(step, ctx)
                    step_res["step_index"] = idx
                    step_res["ok"] = True
                    results.append(step_res)
                except Exception as exc:
                    failed_count += 1
                    err_entry = {
                        "step_index": idx,
                        "op": op,
                        "ok": False,
                        "error": str(exc),
                    }
                    results.append(err_entry)
                    if stop_on_error:
                        raise
        finally:
            if fg_state["saved"] and restore_focus:
                push = int(fg_state["push_hwnd"] or ctx["win"].hwnd) if fg_state["fg"] else 0
                _restore_user_foreground_and_cursor(
                    int(fg_state["fg"]),
                    fg_state["cursor"],
                    push_hwnd=push,
                )
            elif restore_focus and default_bg and not dry_run and fg_state["initial_fg"]:
                pt_hwnds = {int(ctx["win"].hwnd), *(int(d.hwnd) for d in ctx["dialogs"])}
                init_fg = int(fg_state["initial_fg"])
                if init_fg not in pt_hwnds and _get_foreground_hwnd() in pt_hwnds:
                    _restore_user_foreground_and_cursor(
                        init_fg, None, push_hwnd=int(ctx["win"].hwnd)
                    )

        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
        return {
            "dry_run": dry_run,
            "background": default_bg,
            "total_steps": len(actions),
            "completed_steps": len(results),
            "failed_steps": failed_count,
            "elapsed_ms": elapsed_ms,
            "results": results,
            "state_level": StateLevel.PLANNED.value if dry_run else StateLevel.EXECUTED.value,
        }

    def attach_ip_phone_power(
        self,
        *,
        device_name: str = "IP_PHONE1",
        pt_device_title: str | None = None,
        canvas_x: float = 500.0,
        canvas_y: float = 180.0,
        close_dialog: bool = True,
        restore_focus: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Drag the 7960 external AC power adapter brick onto its Physical-tab DC socket."""
        self._require_windows()
        self.safety.check_safe_to_act(live_input=not dry_run)
        win, dialogs = self._require_main_window()
        if win.client_rect.width < 400 or win.client_rect.height < 300:
            if dry_run:
                raise AdapterUnavailableError(
                    "Packet Tracer main window client bounds are too small/minimized.",
                    details={"client_rect": win.client_rect.model_dump()},
                    remediation="Restore/maximize Packet Tracer before running GUI power attach.",
                )
            win, dialogs = self._ensure_usable_window(win, dialogs, background=False)

        scale = max(1.0, float(win.scale_factor or 1.0))
        click_sx = int(win.client_rect.left + round(float(canvas_x) + 3.0 * scale))
        click_sy = int(win.client_rect.top + round(float(canvas_y) + 100.0 * scale))
        brick_rel = (0.9194, 0.8640)
        socket_rel = (0.3606, 0.3378)
        title_needle = str(pt_device_title or device_name).strip()
        if not title_needle:
            raise ValidationError("device_name / pt_device_title must not be empty.")

        if dry_run:
            return {
                "dry_run": True,
                "device_name": device_name,
                "pt_device_title": title_needle,
                "hwnd": int(win.hwnd),
                "dpi": int(win.dpi),
                "scale_factor": float(win.scale_factor),
                "canvas_xy": [float(canvas_x), float(canvas_y)],
                "planned_canvas_click": [click_sx, click_sy],
                "power_brick_rel": list(brick_rel),
                "dc_socket_rel": list(socket_rel),
                "close_dialog": bool(close_dialog),
                "state_level": StateLevel.PLANNED.value,
            }

        if platform.system() == "Windows" and int(ctypes.windll.user32.GetForegroundWindow()) == 0:
            raise AdapterUnavailableError(
                "No active foreground desktop window (GetForegroundWindow() == 0: desktop is "
                "locked, asleep, or running inside a non-interactive/isolated desktop session); "
                "Physical-tab power-adapter drag requires an unlocked interactive Windows desktop.",
                details={"hwnd": int(win.hwnd), "dpi": int(win.dpi)},
                remediation=(
                    "Run inside an unlocked interactive Windows desktop session (not a "
                    "locked screen or isolated sandbox desktop) and retry."
                ),
            )

        existing_dlg = self._find_dialog_by_title(dialogs, title_needle)
        if existing_dlg is None:
            open_res = self.execute_batch(
                [
                    {"op": "click", "x": click_sx, "y": click_sy, "background": True},
                    {"op": "wait_dialog", "title_contains": title_needle, "timeout_s": 4.0},
                ],
                background=True,
                restore_focus=restore_focus,
            )
            _ = open_res
            _, fresh_dialogs = self._require_main_window()
            existing_dlg = self._find_dialog_by_title(fresh_dialogs, title_needle)
            if existing_dlg is None:
                raise AdapterUnavailableError(
                    f"Device dialog matching '{title_needle}' did not open after canvas click.",
                    details={"click": [click_sx, click_sy]},
                )

        dlg = self._refresh_dialog_info(existing_dlg)
        if dlg.rect is None or dlg.rect.width < 200 or dlg.rect.height < 200:
            raise AdapterUnavailableError(
                f"Device dialog '{dlg.title}' lacks valid geometry.",
                details={"rect": dlg.rect.model_dump() if dlg.rect else None},
            )

        from_ox = int(round(dlg.rect.width * brick_rel[0]))
        from_oy = int(round(dlg.rect.height * brick_rel[1]))
        to_ox = int(round(dlg.rect.width * socket_rel[0]))
        to_oy = int(round(dlg.rect.height * socket_rel[1]))

        before_img = None
        with suppress(Exception):
            before_img = _capture_window_printwindow(
                int(dlg.hwnd), dlg.rect, dlg.rect, full_window=True
            )

        drag_res = self.execute_batch(
            [
                {
                    "op": "drag_dialog",
                    "title_contains": title_needle,
                    "from_x": from_ox,
                    "from_y": from_oy,
                    "to_x": to_ox,
                    "to_y": to_oy,
                    "steps": 24,
                    "duration_ms": 420,
                    "delay_ms": 250,
                    "background": False,
                },
            ],
            background=False,
            restore_focus=restore_focus,
        )

        socket_roi_diff = None
        with suppress(Exception):
            after_img = _capture_window_printwindow(
                int(dlg.hwnd), dlg.rect, dlg.rect, full_window=True
            )
            if before_img is not None and after_img is not None:
                from agenticnet.gui.vision import image_diff_ratio

                bw, bh = before_img.size
                box = (int(bw * 0.31), int(bh * 0.29), int(bw * 0.43), int(bh * 0.41))
                socket_roi_diff = image_diff_ratio(before_img.crop(box), after_img.crop(box))

        if close_dialog:
            with suppress(Exception):
                self.execute_batch(
                    [{"op": "close_dialog", "title_contains": title_needle, "background": True}],
                    background=True,
                    restore_focus=restore_focus,
                )

        return {
            "dry_run": False,
            "device_name": device_name,
            "pt_device_title": dlg.title,
            "hwnd": int(win.hwnd),
            "dialog_hwnd": int(dlg.hwnd),
            "dpi": int(win.dpi),
            "scale_factor": float(win.scale_factor),
            "canvas_click": [click_sx, click_sy],
            "dialog_rect": dlg.rect.model_dump(),
            "drag_offsets": {"from": [from_ox, from_oy], "to": [to_ox, to_oy]},
            "socket_roi_diff_ratio": socket_roi_diff,
            "closed_dialog": bool(close_dialog),
            "elapsed_ms": drag_res.get("elapsed_ms"),
            "state_level": StateLevel.EXECUTED.value,
        }
