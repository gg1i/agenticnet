"""Platform-aware Packet Tracer installation discovery helpers."""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import signal
import subprocess
import time
from collections.abc import Sequence
from contextlib import suppress
from ctypes import wintypes
from pathlib import Path
from typing import Any

from agenticnet.core.exceptions import AdapterUnavailableError

_UOI_NAME = 2
_WM_CLOSE = 0x0010


def _query_windows_desktop_name() -> str | None:
    """Return the current thread's desktop name (e.g. 'Default' or 'exebox-...')."""
    if platform.system() != "Windows":
        return None
    try:
        u32 = ctypes.windll.user32
        k32 = ctypes.windll.kernel32
        tid = int(k32.GetCurrentThreadId() or 0)
        hdesk = u32.GetThreadDesktop(tid)
        if not hdesk:
            return None
        buf = ctypes.create_unicode_buffer(256)
        needed = wintypes.DWORD(0)
        ok = u32.GetUserObjectInformationW(
            hdesk, _UOI_NAME, buf, ctypes.sizeof(buf), ctypes.byref(needed)
        )
        if not ok:
            return None
        return str(buf.value) or None
    except Exception:
        return None


def get_desktop_session_info() -> dict[str, Any]:
    """Inspect whether the current process runs on an unlocked interactive Default desktop."""
    non_interactive_raw = (
        os.environ.get("AGENTICNET_NON_INTERACTIVE")
        or os.environ.get("NETFORGE_NON_INTERACTIVE")
        or ""
    )
    force_non = non_interactive_raw.strip().lower() in {
        "1",
        "true",
        "yes",
    }
    allow_env = (
        (
            os.environ.get("AGENTICNET_ALLOW_NON_INTERACTIVE_LAUNCH")
            or os.environ.get("NETFORGE_ALLOW_NON_INTERACTIVE_LAUNCH")
            or ""
        )
        .strip()
        .lower()
    )
    allow_override = allow_env in {"1", "true", "yes"}

    if platform.system() != "Windows":
        display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
        has_gui = bool(display) or platform.system() == "Darwin"
        if force_non:
            interactive = False
            reason = "AGENTICNET_NON_INTERACTIVE environment variable is set."
        elif allow_override:
            interactive = True
            reason = "AGENTICNET_ALLOW_NON_INTERACTIVE_LAUNCH override is active."
        elif not has_gui:
            interactive = False
            reason = "No DISPLAY/WAYLAND_DISPLAY GUI session detected."
        else:
            interactive = True
            reason = "Interactive desktop session detected."
        return {
            "platform": platform.system(),
            "session_id": None,
            "active_console_session_id": None,
            "desktop_name": display,
            "interactive": interactive,
            "reason": reason,
        }

    k32 = ctypes.windll.kernel32
    pid = int(k32.GetCurrentProcessId() or 0)
    sess_id = wintypes.DWORD(0)
    has_sess = bool(k32.ProcessIdToSessionId(pid, ctypes.byref(sess_id)))
    session_id = int(sess_id.value) if has_sess else None
    active_console_raw = int(k32.WTSGetActiveConsoleSessionId())
    active_console = None if active_console_raw == 0xFFFFFFFF else active_console_raw
    desktop_name = _query_windows_desktop_name()

    if force_non:
        interactive = False
        reason = "AGENTICNET_NON_INTERACTIVE environment variable is set."
    elif allow_override:
        interactive = True
        reason = "AGENTICNET_ALLOW_NON_INTERACTIVE_LAUNCH override is active."
    elif session_id is not None and session_id == 0:
        interactive = False
        reason = "Windows Session 0 services session is non-interactive."
    elif session_id is not None and active_console is not None and session_id != active_console:
        interactive = False
        reason = f"Process session {session_id} != active console session {active_console}."
    elif desktop_name is None:
        interactive = False
        reason = "Unable to verify interactive 'Default' desktop name."
    elif desktop_name.strip().lower() != "default":
        interactive = False
        reason = f"Desktop {desktop_name!r} is non-interactive (expected 'Default')."
    else:
        interactive = True
        reason = "Interactive Windows Default desktop."

    return {
        "platform": "Windows",
        "session_id": session_id,
        "active_console_session_id": active_console,
        "desktop_name": desktop_name,
        "interactive": interactive,
        "reason": reason,
    }


def is_interactive_desktop() -> bool:
    """Return True only when executing on an interactive desktop (not exebox/Session 0/headless)."""
    return bool(get_desktop_session_info().get("interactive", False))


def require_interactive_desktop_for_launch(caller: str = "packet_tracer_launch") -> None:
    """Refuse starting PacketTracer.exe from an agent shell or non-interactive session."""
    info = get_desktop_session_info()
    if info.get("interactive"):
        return
    raise AdapterUnavailableError(
        f"Refusing to launch PacketTracer.exe from a non-interactive session ({caller}): "
        f"{info.get('reason')}",
        error_code="NON_INTERACTIVE_SESSION",
        details={**info, "caller": caller},
        remediation=(
            "Never start PacketTracer.exe from an agent shell or isolated desktop "
            "(e.g. WinSta0\\exebox-*). Launch Packet Tracer interactively on your Default desktop."
        ),
    )


def list_packet_tracer_pids() -> list[int]:
    """List currently running Packet Tracer process IDs without mutating system state."""
    if platform.system() == "Windows":

        class _ProcessEntry32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Process32FirstW.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ProcessEntry32W),
        ]
        kernel32.Process32FirstW.restype = wintypes.BOOL
        kernel32.Process32NextW.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ProcessEntry32W),
        ]
        kernel32.Process32NextW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        snap = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if snap == wintypes.HANDLE(-1).value or not snap:
            return []
        pids: list[int] = []
        try:
            entry = _ProcessEntry32W()
            entry.dwSize = ctypes.sizeof(_ProcessEntry32W)
            ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
            while ok:
                if entry.szExeFile.lower() in {"packettracer.exe", "packettracer"}:
                    pids.append(int(entry.th32ProcessID))
                ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
            return pids
        finally:
            kernel32.CloseHandle(snap)

    pgrep = shutil.which("pgrep")
    if pgrep:
        proc = subprocess.run(
            [pgrep, "-f", "PacketTracer"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            out: list[int] = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line.isdigit():
                    out.append(int(line))
            return out
    return []


def is_packet_tracer_running() -> bool:
    """Detect whether a Packet Tracer process is running without mutating system state."""
    return len(list_packet_tracer_pids()) > 0


def _post_wm_close_to_pids(target_pids: set[int]) -> list[int]:
    """Send WM_CLOSE to top-level windows owned by `target_pids` on Windows."""
    if platform.system() != "Windows" or not target_pids:
        return []
    u32 = ctypes.windll.user32
    closed_hwnds: list[int] = []
    enum_proc_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def _cb(hwnd: int, _lparam: int) -> bool:
        pid = wintypes.DWORD(0)
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if int(pid.value) in target_pids:
            u32.PostMessageW(hwnd, _WM_CLOSE, 0, 0)
            closed_hwnds.append(int(hwnd))
        return True

    u32.EnumWindows(enum_proc_type(_cb), 0)
    return closed_hwnds


def gracefully_close_packet_tracer(
    pids: Sequence[int] | None = None,
    *,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Close Packet Tracer gracefully via WM_CLOSE / SIGTERM only (no forced kills)."""
    raw_pids = pids if pids is not None else list_packet_tracer_pids()
    target_pids = list(dict.fromkeys(int(p) for p in raw_pids))
    if not target_pids:
        return {
            "attempted": False,
            "close_mode": "graceful_only",
            "forced_kill_used": False,
            "target_pids": [],
            "graceful_closed_pids": [],
            "forced_closed_pids": [],
            "remaining_pids": [],
        }

    target_set = set(target_pids)
    if platform.system() == "Windows":
        _post_wm_close_to_pids(target_set)
        for pid in target_pids:
            subprocess.run(
                ["taskkill", "/PID", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    else:
        for pid in target_pids:
            with suppress(OSError):
                os.kill(pid, signal.SIGTERM)

    deadline = time.monotonic() + max(timeout_seconds, 0.2)
    remaining = [p for p in target_pids if p in set(list_packet_tracer_pids())]
    while remaining and time.monotonic() < deadline:
        time.sleep(0.2)
        alive = set(list_packet_tracer_pids())
        remaining = [p for p in target_pids if p in alive]

    graceful_closed = [p for p in target_pids if p not in remaining]
    return {
        "attempted": True,
        "close_mode": "graceful_only",
        "forced_kill_used": False,
        "target_pids": target_pids,
        "graceful_closed_pids": graceful_closed,
        "forced_closed_pids": [],
        "remaining_pids": remaining,
    }


def _version_sort_key(path: Path) -> tuple[tuple[int, ...], str]:
    """Extract numeric version tuple from folder/app name so newer PT versions sort first."""
    import re

    nums = tuple(int(tok) for tok in re.findall(r"\d+", path.parent.parent.name or path.name))
    return (nums, str(path).lower())


def detect_packet_tracer_binary(explicit_path: str | None = None) -> str | None:
    """Locate Cisco Packet Tracer executable across versions without altering system state."""
    if explicit_path and Path(explicit_path).exists():
        return str(Path(explicit_path))

    candidates: list[Path] = []
    if platform.system() == "Windows":
        roots: list[Path] = []
        for env_key in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
            raw = os.environ.get(env_key)
            if raw:
                p = Path(raw)
                if p not in roots:
                    roots.append(p)
        if not roots:
            roots.extend([Path(r"C:\Program Files"), Path(r"C:\Program Files (x86)")])

        discovered: list[Path] = []
        for root in roots:
            if root.is_dir():
                with suppress(OSError):
                    discovered.extend(root.glob("Cisco Packet Tracer*/bin/PacketTracer.exe"))
        discovered.sort(key=_version_sort_key, reverse=True)
        candidates.extend(discovered)
        candidates.extend(
            [
                Path(r"C:\Program Files\Cisco Packet Tracer 8.2.2\bin\PacketTracer.exe"),
                Path(r"C:\Program Files\Cisco Packet Tracer 8.2.1\bin\PacketTracer.exe"),
                Path(r"C:\Program Files\Cisco Packet Tracer 8.2.0\bin\PacketTracer.exe"),
                Path(r"C:\Program Files\Cisco Packet Tracer\bin\PacketTracer.exe"),
            ]
        )
    elif platform.system() == "Linux":
        candidates.extend(
            [
                Path("/opt/pt/packettracer"),
                Path("/usr/local/bin/packettracer"),
            ]
        )
    elif platform.system() == "Darwin":
        apps_dir = Path("/Applications")
        if apps_dir.is_dir():
            with suppress(OSError):
                mac_apps = sorted(
                    apps_dir.glob("Cisco Packet Tracer*.app"),
                    key=_version_sort_key,
                    reverse=True,
                )
                candidates.extend(mac_apps)
        candidates.append(Path("/Applications/Cisco Packet Tracer.app"))

    seen: set[Path] = set()
    for cand in candidates:
        if cand in seen:
            continue
        seen.add(cand)
        if cand.exists():
            return str(cand)

    return shutil.which("PacketTracer") or shutil.which("packettracer")
