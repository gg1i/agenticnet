"""Backend adapter abstractions for Packet Tracer GUI, console, and simulation engines."""

from __future__ import annotations

from agenticnet.adapters.base import (
    AdapterConnectionState,
    BackendStatus,
    ConsoleBackend,
    GuiBackend,
    ScriptBackend,
    SimulationBackend,
)
from agenticnet.adapters.script_bridge import (
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
