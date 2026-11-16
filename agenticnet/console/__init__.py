"""Device console CLI state-machine subsystem (Phase 2)."""

from agenticnet.console.engine import DeviceConsoleEngine
from agenticnet.console.models import (
    CLIPromptMode,
    CommandTranscript,
    ConsoleExecutionReport,
    ConsoleInteractionKind,
    ConsoleSessionState,
    DeviceConsoleProfile,
    ParsedPrompt,
)
from agenticnet.console.profiles import get_console_profile
from agenticnet.console.state_machine import (
    ConsoleStateMachine,
    PromptDetector,
    strip_paging_and_control,
)
from agenticnet.console.transport import (
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
