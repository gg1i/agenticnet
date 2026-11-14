"""Device console CLI state-machine subsystem (Phase 2)."""

from netforge.console.engine import DeviceConsoleEngine
from netforge.console.models import (
    CLIPromptMode,
    CommandTranscript,
    ConsoleExecutionReport,
    ConsoleInteractionKind,
    ConsoleSessionState,
    DeviceConsoleProfile,
    ParsedPrompt,
)
from netforge.console.profiles import get_console_profile
from netforge.console.state_machine import (
    ConsoleStateMachine,
    PromptDetector,
    strip_paging_and_control,
)
from netforge.console.transport import (
    ConsoleTransport,
    SimulatedConsoleTransport,
    UnavailableConsoleTransport,
    WindowsGuiConsoleTransport,
)

__all__ = [
    "CLIPromptMode",
    "CommandTranscript",
    "ConsoleExecutionReport",
    "ConsoleInteractionKind",
    "ConsoleSessionState",
    "ConsoleStateMachine",
    "ConsoleTransport",
    "DeviceConsoleEngine",
    "DeviceConsoleProfile",
    "ParsedPrompt",
    "PromptDetector",
    "SimulatedConsoleTransport",
    "UnavailableConsoleTransport",
    "WindowsGuiConsoleTransport",
    "get_console_profile",
    "strip_paging_and_control",
]
