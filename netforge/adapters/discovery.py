"""Platform-aware Packet Tracer installation discovery helpers."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path


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
