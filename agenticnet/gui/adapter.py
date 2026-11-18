"""Cross-platform factory selecting the active GuiBackend implementation."""

from __future__ import annotations

import platform
from typing import Any

from agenticnet.adapters.base import BackendStatus, GuiBackend
from agenticnet.core.exceptions import AdapterUnavailableError
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.gui.calibration import CalibrationManager
from agenticnet.gui.safety import EmergencyStopController
from agenticnet.gui.windows_backend import WindowsGuiBackend


class NullGuiBackend(GuiBackend):
    """Explicit placeholder backend on non-Windows platforms until native adapters are added."""

    def __init__(self, settings: AgenticNetSettings) -> None:
        self.settings = settings

    def is_available(self) -> bool:
        """Return False on non-Windows platforms where live GUI automation is unsupported."""
        return False

    def backend_status(self) -> BackendStatus:
        """Report unsupported desktop automation on non-Windows OS."""
        return BackendStatus(
            backend_name="NullGuiBackend",
            platform=platform.platform(),
            notes=(
                "Live Packet Tracer GUI automation currently targets Windows. "
                "See docs/cross-platform-roadmap.md for Linux/macOS plans."
            ),
        )

    def detect_application(self) -> dict[str, Any]:
        """Return safe non-running detection payload on non-Windows hosts."""
        return {
            "detected_binary": False,
            "executable_path": None,
            "running": False,
            "processes": [],
            "window": None,
            "dialogs": [],
            "calibration_loaded": False,
            "platform_supported": False,
        }

    def capture_screenshot(self, output_path: str | None = None) -> dict[str, Any]:
        """Raise AdapterUnavailableError cleanly."""
        raise AdapterUnavailableError(
            f"Live GUI capture is not implemented for {platform.system()} yet.",
            remediation=(
                "Run Packet Tracer automation on Windows or inject a mock backend in tests."
            ),
        )


def create_gui_backend(
    settings: AgenticNetSettings,
    *,
    calibration: CalibrationManager | None = None,
    safety: EmergencyStopController | None = None,
) -> GuiBackend:
    """Create the platform-appropriate GuiBackend."""
    if platform.system() == "Windows":
        return WindowsGuiBackend(settings=settings, calibration=calibration, safety=safety)
    return NullGuiBackend(settings=settings)
