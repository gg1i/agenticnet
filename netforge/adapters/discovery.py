"""Platform-aware Packet Tracer installation discovery helpers."""

from __future__ import annotations

import ctypes
import platform
import shutil
import subprocess
from ctypes import wintypes
from pathlib import Path


def is_packet_tracer_running() -> bool:
    """Detect whether a Packet Tracer process is running without mutating system state."""
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

        kernel32 = ctypes.windll.kernel32
        snap = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if snap == wintypes.HANDLE(-1).value:
            return False
        try:
            entry = _ProcessEntry32W()
            entry.dwSize = ctypes.sizeof(_ProcessEntry32W)
            ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
            while ok:
                if entry.szExeFile.lower() in {"packettracer.exe", "packettracer"}:
                    return True
                ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
            return False
        finally:
            kernel32.CloseHandle(snap)

    pgrep = shutil.which("pgrep")
    if pgrep:
        proc = subprocess.run([pgrep, "-f", "PacketTracer"], capture_output=True, check=False)
        return proc.returncode == 0
    return False


def detect_packet_tracer_binary(explicit_path: str | None = None) -> str | None:
    """Locate Cisco Packet Tracer executable without altering system state."""
    if explicit_path and Path(explicit_path).exists():
        return str(Path(explicit_path))

    candidates: list[Path] = []
    if platform.system() == "Windows":
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
        candidates.append(Path("/Applications/Cisco Packet Tracer.app"))

    for cand in candidates:
        if cand.exists():
            return str(cand)

    return shutil.which("PacketTracer") or shutil.which("packettracer")
