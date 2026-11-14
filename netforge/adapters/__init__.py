"""Backend adapter abstractions for Packet Tracer GUI, console, and simulation engines."""

from __future__ import annotations

from netforge.adapters.base import (
    AdapterConnectionState,
    BackendStatus,
    ConsoleBackend,
    GuiBackend,
    ScriptBackend,
    SimulationBackend,
)
from netforge.adapters.script_bridge import (
    HttpScriptBridgeBackend,
    HttpScriptBridgeServer,
    ScriptBridgeError,
)

__all__ = [
    "AdapterConnectionState",
    "BackendStatus",
    "ConsoleBackend",
    "GuiBackend",
    "HttpScriptBridgeBackend",
    "HttpScriptBridgeServer",
    "ScriptBackend",
    "ScriptBridgeError",
    "SimulationBackend",
]
