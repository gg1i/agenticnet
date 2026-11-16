"""Safety guardrails, fail-safe abort mechanism, and human approval checks for GUI input."""

from __future__ import annotations

import platform
import threading
import time
from typing import Final

from agenticnet.core.exceptions import AdapterUnavailableError, ApprovalRequiredError


class AutomationStopError(AdapterUnavailableError):
    """Raised when the emergency stop, Escape fail-safe, or corner kill switch triggers."""

    error_code = "AUTOMATION_ABORTED"


_TOP_LEFT_FAILSAFE_PX: Final[int] = 2


class EmergencyStopController:
    """Thread-safe emergency stop and bounded execution guard for desktop automation."""

    def __init__(
        self,
        *,
        corner_failsafe: bool = True,
        escape_failsafe: bool = True,
        max_actions_per_minute: int = 300,
    ) -> None:
        self._stop_event = threading.Event()
        self._stop_reason: str | None = None
        self._lock = threading.Lock()
        self.corner_failsafe = corner_failsafe
        self.escape_failsafe = escape_failsafe
        self.max_actions_per_minute = max_actions_per_minute
        self._action_timestamps: list[float] = []

    @property
    def stop_reason(self) -> str | None:
        """Return reason why automation was halted, if triggered."""
        return self._stop_reason

    def is_stopped(self) -> bool:
        """Return True if an explicit emergency stop has been requested."""
        return self._stop_event.is_set()

    def request_stop(self, reason: str = "Explicit user/agent stop requested.") -> None:
        """Arm the emergency stop latch so subsequent GUI actions immediately halt."""
        with self._lock:
            self._stop_reason = reason
            self._stop_event.set()

    def reset(self) -> None:
        """Clear a previous emergency stop trigger."""
        with self._lock:
            self._stop_reason = None
            self._stop_event.clear()

    def _check_windows_hardware_failsafe(self) -> None:
        """Check Windows cursor corner fail-safe and Escape key if running on Win32."""
        if platform.system() != "Windows":
            return
        try:
            import ctypes

            import win32api  # type: ignore[import-untyped]
            import win32con  # type: ignore[import-untyped]

            if self.corner_failsafe:
                x, y = win32api.GetCursorPos()
                if x <= _TOP_LEFT_FAILSAFE_PX and y <= _TOP_LEFT_FAILSAFE_PX:
                    raise AutomationStopError(
                        "Fail-safe triggered: cursor moved to top-left corner (0, 0).",
                        details={"cursor": [x, y]},
                        remediation="Move cursor away from top-left corner and call reset.",
                    )

            if self.escape_failsafe:
                # High-order bit indicates key currently held down; do not trigger on stale bit 0.
                state = ctypes.windll.user32.GetAsyncKeyState(win32con.VK_ESCAPE)
                if state & 0x8000:
                    raise AutomationStopError(
                        "Fail-safe triggered: Escape key is held down.",
                        remediation="Release Escape key before resuming GUI automation.",
                    )
        except AutomationStopError:
            raise
        except Exception:
            # Fail closed on explicit stop flag only if Win32 API query is unavailable in session.
            return

    def check_safe_to_act(self, *, live_input: bool = True, count_action: bool = True) -> None:
        """Verify stop flag, hardware fail-safes (for live input), and action rate ceiling."""
        if self.is_stopped():
            raise AutomationStopError(
                f"GUI automation halted by emergency stop: {self._stop_reason or 'stopped'}",
                remediation="Inspect UI state via gui_state_inspect before resuming.",
            )

        if live_input:
            self._check_windows_hardware_failsafe()

        if not count_action:
            return

        now = time.monotonic()
        with self._lock:
            cutoff = now - 60.0
            self._action_timestamps = [t for t in self._action_timestamps if t >= cutoff]
            if len(self._action_timestamps) >= self.max_actions_per_minute:
                raise AutomationStopError(
                    f"GUI safety rate limit exceeded ({self.max_actions_per_minute} actions/min).",
                    details={"window_seconds": 60, "count": len(self._action_timestamps)},
                    remediation="Pause briefly or batch commands before retrying GUI input.",
                )
            self._action_timestamps.append(now)

    @staticmethod
    def require_confirmation_for_risky_action(action_label: str, *, confirm: bool) -> None:
        """Block high-risk GUI actions (closing unsaved files, discarding changes, Alt+F4)."""
        if not confirm:
            raise ApprovalRequiredError(
                f"Risky GUI operation '{action_label}' requires explicit confirmation.",
                details={"action": action_label},
                remediation="Review screen state with gui_screenshot and retry with confirm=True.",
            )
