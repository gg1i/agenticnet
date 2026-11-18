"""Abstract adapter contracts decoupling core engines from Packet Tracer backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from agenticnet.core.exceptions import AdapterUnavailableError


class AdapterConnectionState(StrEnum):
    """Runtime status of an external Packet Tracer automation adapter."""

    OFFLINE_PLANNING = "offline_planning"
    DETECTED_IDLE = "detected_idle"
    CONNECTED = "connected"
    ERROR = "error"


class BackendStatus(BaseModel):
    """Describes the currently attached Packet Tracer backend."""

    backend_name: str
    connection_state: AdapterConnectionState = AdapterConnectionState.OFFLINE_PLANNING
    platform: str
    packet_tracer_version: str | None = None
    executable_path: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    notes: str = ""


class GuiBackend(ABC):
    """Abstraction for desktop GUI automation backends (Phase 2)."""

    @abstractmethod
    def detect_application(self) -> dict[str, Any]:
        """Detect running or installed Packet Tracer window and process metadata."""

    @abstractmethod
    def capture_screenshot(self, output_path: str | None = None) -> dict[str, Any]:
        """Capture Packet Tracer window screenshot for calibration and inspection."""

    def backend_status(self) -> BackendStatus:
        """Describe backend connection status."""
        return BackendStatus(
            backend_name=self.__class__.__name__,
            platform="unknown",
        )

    def is_available(self) -> bool:
        """Return True when a live Packet Tracer GUI window is reachable."""
        try:
            det = self.detect_application()
        except Exception:
            return False
        return bool(isinstance(det, dict) and det.get("running") and det.get("window") is not None)

    def launch_application(
        self,
        executable_path: str | None = None,
        *,
        project_file: str | None = None,
        wait_seconds: float = 15.0,
    ) -> dict[str, Any]:
        """Launch Cisco Packet Tracer if supported by this backend."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement launch_application."
        )

    def inspect_state(self) -> dict[str, Any]:
        """Inspect active window, open dialogs, and calibration status."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement inspect_state."
        )

    def calibrate(self, *, profile_id: str = "default") -> dict[str, Any]:
        """Calibrate relative workspace coordinates and DPI scaling."""
        raise AdapterUnavailableError(f"{self.__class__.__name__} does not implement calibrate.")

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
    ) -> dict[str, Any]:
        """Click a calibrated pixel or normalized point inside Packet Tracer."""
        raise AdapterUnavailableError(f"{self.__class__.__name__} does not implement click.")

    def keypress(
        self,
        keys: str,
        *,
        text: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Send a key chord or text sequence to Packet Tracer."""
        raise AdapterUnavailableError(f"{self.__class__.__name__} does not implement keypress.")

    def recover(self, *, strategy: str = "dismiss_dialog", confirm: bool = False) -> dict[str, Any]:
        """Recover from unexpected Packet Tracer modal dialogs or stuck UI state."""
        raise AdapterUnavailableError(f"{self.__class__.__name__} does not implement recover.")


class ConsoleBackend(ABC):
    """Abstraction for Packet Tracer device CLI console automation (Phase 2/3)."""

    @abstractmethod
    def open_console(self, device_name: str) -> dict[str, Any]:
        """Open and focus the CLI tab for a target device."""

    @abstractmethod
    def execute_commands(self, device_name: str, commands: list[str]) -> dict[str, Any]:
        """Send IOS commands to a device console and return captured output."""

    def capture_output(self, device_name: str) -> dict[str, Any]:
        """Capture current CLI buffer output for a device."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement capture_output."
        )

    def inspect_session(self, device_name: str) -> dict[str, Any]:
        """Inspect console prompt state, hostname, and recent CLI errors."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement inspect_session."
        )


class SimulationBackend(ABC):
    """Abstraction for Packet Tracer simulation mode and connectivity verification (Phase 3)."""

    @abstractmethod
    def set_mode(self, mode: str) -> dict[str, Any]:
        """Switch between 'realtime' and 'simulation' mode."""

    @abstractmethod
    def run_connectivity_check(self, source: str, destination_ip: str) -> dict[str, Any]:
        """Run an in-simulator ping or PDU trace and return verified evidence."""

    def start_simulation(self) -> dict[str, Any]:
        """Start/capture simulation playback."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement start_simulation."
        )

    def stop_simulation(self) -> dict[str, Any]:
        """Pause or reset simulation playback."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement stop_simulation."
        )


class ScriptBackend(ABC):
    """Abstraction for Packet Tracer Script Module bridge automation (Phase 1+)."""

    @abstractmethod
    def is_connected(self) -> bool:
        """Return True if a live Packet Tracer script bridge client is attached."""

    @abstractmethod
    def ping(self) -> dict[str, Any]:
        """Perform an authenticated round-trip health check against Packet Tracer."""

    @abstractmethod
    def add_device(
        self,
        model: str,
        *,
        device_type: int | str = 0,
        x: float = 100.0,
        y: float = 100.0,
    ) -> dict[str, Any]:
        """Instantiate a device on the active Packet Tracer logical workspace."""

    @abstractmethod
    def create_link(
        self,
        device1: str,
        port1: str,
        device2: str,
        port2: str,
        *,
        conn_type: int | str = 8107,
    ) -> dict[str, Any]:
        """Connect two device ports on the active Packet Tracer logical workspace."""

    @abstractmethod
    def execute_cli(
        self,
        device_name: str,
        commands: list[str],
        *,
        wait_for_prompt: bool = True,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Run IOS CLI commands on a device TerminalLine and return raw output."""

    def read_activity_status(self) -> dict[str, Any]:
        """Read native `.pka` activity score and comparator tree (Phase 4)."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement read_activity_status."
        )

    def open_file(self, path: str, *, timeout_seconds: float = 30.0) -> dict[str, Any]:
        """Open a `.pkt` or `.pka` file in Packet Tracer."""
        raise AdapterUnavailableError(f"{self.__class__.__name__} does not implement open_file.")

    def save_file(
        self,
        path: str | None = None,
        *,
        overwrite: bool = True,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Save the active Packet Tracer file."""
        raise AdapterUnavailableError(f"{self.__class__.__name__} does not implement save_file.")

    def list_devices(self, *, timeout_seconds: float | None = None) -> dict[str, Any]:
        """List live Packet Tracer devices, links, and ports."""
        raise AdapterUnavailableError(f"{self.__class__.__name__} does not implement list_devices.")

    def attach_ip_phone_power(
        self,
        device_name: str,
        *,
        timeout_seconds: float = 25.0,
    ) -> dict[str, Any]:
        """Attach AC power adapter onto a 7960 IP Phone in Packet Tracer via ScriptBackend."""
        raise NotImplementedError("ScriptBackend does not implement 'attach_ip_phone_power'.")

    def configure_host(
        self,
        device_name: str,
        *,
        port: str = "FastEthernet0",
        dhcp: bool = False,
        ip: str | None = None,
        subnet_mask: str | None = None,
        default_gateway: str | None = None,
        dns_server: str | None = None,
        display_name: str | None = None,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Configure DHCP or static IPv4/gateway/DNS on a PT host device (`PC-PT`, `Laptop-PT`)."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement configure_host."
        )

    def remove_device(
        self,
        device_name: str,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Remove a device from the active Packet Tracer logical workspace."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement remove_device."
        )

    def move_device(
        self,
        device_name: str,
        x: float,
        y: float,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Move a device to `(x, y)` on the active Packet Tracer logical workspace."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement move_device."
        )

    def delete_link(
        self,
        device_name: str,
        port_name: str,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Delete the link attached to `device_name:port_name` in Packet Tracer."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement delete_link."
        )

    def add_module(
        self,
        device_name: str,
        slot: str | int,
        module_name: str,
        *,
        module_type: int | None = None,
        power_cycle: bool = True,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Insert a hardware module into a device slot in Packet Tracer."""
        raise AdapterUnavailableError(
            f"{self.__class__.__name__} does not implement add_module."
        )

    def batch_ops(
        self,
        ops: list[dict[str, Any]],
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Execute multiple synchronous workspace ops in one Packet Tracer RPC call."""
        raise AdapterUnavailableError(f"{self.__class__.__name__} does not implement batch_ops.")

    def backend_status(self) -> BackendStatus:
        """Describe script backend connection state and supported capabilities."""
        return BackendStatus(
            backend_name=self.__class__.__name__,
            connection_state=(
                AdapterConnectionState.CONNECTED
                if self.is_connected()
                else AdapterConnectionState.DETECTED_IDLE
            ),
            platform="unknown",
        )
