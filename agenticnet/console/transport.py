"""Console transport abstractions for Windows Packet Tracer and test harnesses."""

from __future__ import annotations

import platform
import time
from abc import ABC, abstractmethod

from agenticnet.console.models import DeviceConsoleProfile
from agenticnet.core.exceptions import AdapterUnavailableError
from agenticnet.gui.windows_backend import WindowsGuiBackend


class ConsoleTransport(ABC):
    """Transport boundary sending raw lines and reading terminal text for one device."""

    transport_name: str = "abstract"

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this transport can reach a live or simulated console."""

    def can_batch(self) -> bool:
        """Return True when this transport supports native multi-command batch execution."""
        return False

    @abstractmethod
    def open_device(self, device_name: str, profile: DeviceConsoleProfile) -> str:
        """Focus or attach to `device_name`'s console and return current buffer."""

    @abstractmethod
    def send_line(self, device_name: str, line: str, *, timeout_s: float = 5.0) -> str:
        """Send one command line + Enter and return newly observed output tail."""

    @abstractmethod
    def read_buffer(self, device_name: str) -> str:
        """Capture current visible terminal buffer for `device_name`."""


class UnavailableConsoleTransport(ConsoleTransport):
    """Explicit transport on platforms without desktop Packet Tracer CLI automation."""

    transport_name = "unavailable"

    def __init__(self, reason: str | None = None) -> None:
        self.reason = reason or (
            f"Live Packet Tracer console automation is not available on {platform.system()}."
        )

    def is_available(self) -> bool:
        return False

    def open_device(self, device_name: str, profile: DeviceConsoleProfile) -> str:
        raise AdapterUnavailableError(
            f"Cannot open console for '{device_name}': {self.reason}",
            details={"device_name": device_name, "model": profile.model},
            remediation="Use dry_run=True for offline IOS generation, or run on Windows with PT.",
        )

    def send_line(self, device_name: str, line: str, *, timeout_s: float = 5.0) -> str:
        raise AdapterUnavailableError(
            f"Cannot send CLI line to '{device_name}': {self.reason}",
            details={"device_name": device_name},
        )

    def read_buffer(self, device_name: str) -> str:
        raise AdapterUnavailableError(
            f"Cannot capture CLI buffer for '{device_name}': {self.reason}",
            details={"device_name": device_name},
        )


class WindowsGuiConsoleTransport(ConsoleTransport):
    """Interacts with an open Packet Tracer device CLI subwindow on Windows."""

    transport_name = "windows_pt_gui_clipboard"

    def __init__(self, gui_backend: WindowsGuiBackend) -> None:
        self.gui = gui_backend
        self._device_hwnds: dict[str, int] = {}

    def is_available(self) -> bool:
        if platform.system() != "Windows":
            return False
        det = self.gui.detect_application()
        return bool(det.get("running") and det.get("window") is not None)

    def _find_device_hwnd(self, device_name: str) -> int:
        det = self.gui.detect_application()
        target_low = device_name.strip().lower()
        for dlg in det.get("dialogs", []):
            title = str(dlg.get("title", "")).strip()
            low = title.lower()
            if low == target_low or low.startswith(f"{target_low} ") or f" {target_low}" in low:
                hwnd = int(dlg["hwnd"])
                self._device_hwnds[device_name] = hwnd
                return hwnd

        raise AdapterUnavailableError(
            f"No open Packet Tracer device window found matching '{device_name}'.",
            details={"device_name": device_name, "visible_dialogs": det.get("dialogs", [])},
            remediation=(
                f"Open device '{device_name}' inside Cisco Packet Tracer and select its "
                "CLI (or Command Prompt) tab, then retry."
            ),
        )

    def _focus_device_hwnd(self, hwnd: int) -> None:
        import win32con  # type: ignore[import-untyped]
        import win32gui  # type: ignore[import-untyped]

        is_iconic = bool(win32gui.IsIconic(hwnd))
        if is_iconic:
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            time.sleep(0.15)
        elif win32gui.GetForegroundWindow() == hwnd:
            return
        try:
            win32gui.SetForegroundWindow(hwnd)
        except Exception:
            win32gui.BringWindowToTop(hwnd)
        time.sleep(0.12)

    def _resolve_cached_hwnd(self, device_name: str) -> int:
        import win32gui  # type: ignore[import-untyped]

        hwnd = self._device_hwnds.get(device_name)
        if hwnd and win32gui.IsWindow(hwnd):
            return hwnd
        self._device_hwnds.pop(device_name, None)
        return self._find_device_hwnd(device_name)

    def open_device(self, device_name: str, profile: DeviceConsoleProfile) -> str:
        """Focus the PT subwindow for `device_name` and snapshot its terminal buffer."""
        hwnd = self._find_device_hwnd(device_name)
        self._focus_device_hwnd(hwnd)
        return self.gui.capture_text_from_focused_window()

    def send_line(self, device_name: str, line: str, *, timeout_s: float = 5.0) -> str:
        """Send a line + Enter into the device CLI window and return trailing output."""
        hwnd = self._resolve_cached_hwnd(device_name)
        self._focus_device_hwnd(hwnd)
        before = self.gui.capture_text_from_focused_window()
        self.gui.paste_lines_to_focused_window([line], delay_s=min(0.25, max(0.06, timeout_s / 40)))
        time.sleep(0.12)
        after = self.gui.capture_text_from_focused_window()
        if after.startswith(before):
            return after[len(before) :]
        return after

    def read_buffer(self, device_name: str) -> str:
        """Focus `device_name` window and capture terminal buffer via clipboard."""
        hwnd = self._resolve_cached_hwnd(device_name)
        self._focus_device_hwnd(hwnd)
        return self.gui.capture_text_from_focused_window()


class SimulatedConsoleTransport(ConsoleTransport):
    """Deterministic stateful IOS CLI harness for unit/integration tests (NOT live PT)."""

    transport_name = "test_ios_harness"

    def __init__(self, initial_prompt: str = "Press RETURN to get started!") -> None:
        self._buffers: dict[str, str] = {}
        self._modes: dict[str, str] = {}
        self._hostnames: dict[str, str] = {}
        self._initial_prompt = initial_prompt
        self._paged_remaining: dict[str, list[str]] = {}
        self._configs: dict[str, list[str]] = {}
        self._paging_disabled: dict[str, bool] = {}
        self._is_asa: dict[str, bool] = {}

    def is_available(self) -> bool:
        return True

    def seed_device(
        self,
        device_name: str,
        *,
        initial_output: str | None = None,
        hostname: str = "Router",
        mode: str = "user_exec",
        is_asa: bool = False,
    ) -> None:
        """Pre-seed a deterministic simulated console buffer."""
        self._hostnames[device_name] = hostname
        self._modes[device_name] = mode
        self._buffers[device_name] = initial_output or f"{hostname}>"
        self._configs.setdefault(device_name, [f"hostname {hostname}"])
        self._is_asa[device_name] = is_asa

    def _prompt_for(self, device_name: str) -> str:
        host = self._hostnames.get(device_name, "Router")
        mode = self._modes.get(device_name, "user_exec")
        return {
            "setup_dialog": "Would you like to enter the initial configuration dialog? [yes/no]:",
            "press_return": "Press RETURN to get started!",
            "password_prompt": "Password:",
            "confirm_modulus": "How many bits in the modulus [512]:",
            "confirm_clear": 'Clear "show interface" counters on all interfaces [confirm]',
            "user_exec": f"{host}>",
            "privileged_exec": f"{host}#",
            "global_config": f"{host}(config)#",
            "interface_config": f"{host}(config-if)#",
            "interface_range_config": f"{host}(config-if-range)#",
            "subinterface_config": f"{host}(config-subif)#",
            "router_config": f"{host}(config-router)#",
            "dhcp_config": f"{host}(dhcp-config)#",
            "isakmp_config": f"{host}(config-isakmp)#",
            "telephony_config": f"{host}(config-telephony)#",
            "pc_prompt": "C:\\>",
        }.get(mode, f"{host}#")

    def open_device(self, device_name: str, profile: DeviceConsoleProfile) -> str:
        if device_name not in self._buffers:
            if profile.interaction_kind == "pt_desktop_cmd":
                self._modes[device_name] = "pc_prompt"
                self._buffers[device_name] = "Packet Tracer PC Command Line 1.0\n\nC:\\>"
            elif profile.interaction_kind == "asa_cli":
                self._is_asa[device_name] = True
                self._hostnames[device_name] = "ciscoasa"
                self._modes[device_name] = "user_exec"
                self._buffers[device_name] = "ciscoasa>"
                self._configs.setdefault(device_name, ["hostname ciscoasa"])
            else:
                self._hostnames[device_name] = "Router" if "Router" in profile.model else "Switch"
                if self._initial_prompt == "Press RETURN to get started!":
                    self._modes[device_name] = "press_return"
                    self._buffers[device_name] = "Press RETURN to get started!"
                else:
                    self._modes[device_name] = "user_exec"
                    self._buffers[device_name] = self._prompt_for(device_name)
                self._configs.setdefault(device_name, [])
        return self._buffers[device_name]

    def send_line(self, device_name: str, line: str, *, timeout_s: float = 5.0) -> str:
        _ = timeout_s
        cmd = line.strip()
        mode = self._modes.get(device_name, "user_exec")
        out_lines: list[str] = []

        if self._paged_remaining.get(device_name):
            chunk = self._paged_remaining[device_name]
            if cmd == "" or line == " ":
                out_lines.extend(chunk)
                self._paged_remaining[device_name] = []
                out_lines.append(self._prompt_for(device_name))
                chunk_text = "\n".join(out_lines)
                self._buffers[device_name] = f"{self._buffers.get(device_name, '')}\n{chunk_text}"
                return chunk_text

        if mode == "setup_dialog":
            if cmd.lower() in {"no", "n"}:
                self._modes[device_name] = "press_return"
                out_lines.append("Press RETURN to get started!")
            else:
                out_lines.append(self._prompt_for(device_name))
        elif mode == "press_return":
            self._modes[device_name] = "user_exec"
            out_lines.append(self._prompt_for(device_name))
        elif mode == "password_prompt":
            self._modes[device_name] = "privileged_exec"
            out_lines.append(self._prompt_for(device_name))
        elif mode == "confirm_modulus":
            bits = cmd or "512"
            self._modes[device_name] = "global_config"
            out_lines.append(
                f"% Generating {bits} bit RSA keys, keys will be non-exportable...[OK]"
            )
            out_lines.append(self._prompt_for(device_name))
        elif mode == "confirm_clear":
            self._modes[device_name] = "privileged_exec"
            out_lines.append(self._prompt_for(device_name))
        elif cmd.endswith("?"):
            out_lines.append("Exec / configuration context help:")
            out_lines.append("  ip         Global IP configuration subcommands")
            out_lines.append("  interface  Select an interface to configure")
            out_lines.append(self._prompt_for(device_name))
        elif mode == "pc_prompt":
            if cmd.lower().startswith("ping "):
                parts = cmd.split()
                target = parts[-1] if len(parts) >= 2 else ""
                sent_count = 4
                for idx_p, tok in enumerate(parts):
                    if (
                        tok.lower() == "-n"
                        and idx_p + 1 < len(parts)
                        and parts[idx_p + 1].isdigit()
                    ):
                        sent_count = max(1, int(parts[idx_p + 1]))
                        break
                out_lines.append(f"Pinging {target} with 32 bytes of data:")
                for _ in range(sent_count):
                    out_lines.append(f"Reply from {target}: bytes=32 time=1ms TTL=128")
                out_lines.extend(
                    [
                        f"Ping statistics for {target}:",
                        (
                            f"    Packets: Sent = {sent_count}, "
                            f"Received = {sent_count}, Lost = 0 (0% loss),"
                        ),
                        "Approximate round trip times in milli-seconds:",
                        "    Minimum = 1ms, Maximum = 1ms, Average = 1ms",
                    ]
                )
            out_lines.append(self._prompt_for(device_name))
        elif cmd == "enable" and mode == "user_exec":
            if self._is_asa.get(device_name, False):
                self._modes[device_name] = "password_prompt"
            else:
                self._modes[device_name] = "privileged_exec"
            out_lines.append(self._prompt_for(device_name))
        elif cmd == "disable" and mode == "privileged_exec":
            self._modes[device_name] = "user_exec"
            out_lines.append(self._prompt_for(device_name))
        elif cmd in {"configure terminal", "conf t"} and mode == "privileged_exec":
            self._modes[device_name] = "global_config"
            out_lines.append("Enter configuration commands, one per line.  End with CNTL/Z.")
            out_lines.append(self._prompt_for(device_name))
        elif (
            cmd == "terminal length 0" and mode in {"user_exec", "privileged_exec"}
        ) or (cmd == "terminal pager 0" and mode == "privileged_exec"):
            self._paging_disabled[device_name] = True
            out_lines.append(self._prompt_for(device_name))
        elif cmd == "clear counters" and mode == "privileged_exec":
            self._modes[device_name] = "confirm_clear"
            out_lines.append(self._prompt_for(device_name))
        elif cmd == "crypto key generate rsa" and mode == "global_config":
            self._modes[device_name] = "confirm_modulus"
            out_lines.append(self._prompt_for(device_name))
        elif cmd == "end":
            self._modes[device_name] = "privileged_exec"
            out_lines.append(self._prompt_for(device_name))
        elif cmd == "exit":
            if mode in {
                "interface_config",
                "interface_range_config",
                "subinterface_config",
                "router_config",
                "dhcp_config",
                "isakmp_config",
                "telephony_config",
            }:
                self._modes[device_name] = "global_config"
            elif mode == "global_config":
                self._modes[device_name] = "privileged_exec"
            out_lines.append(self._prompt_for(device_name))
        elif cmd.startswith("hostname ") and mode == "global_config":
            new_host = cmd.split(maxsplit=1)[1]
            self._hostnames[device_name] = new_host
            self._configs[device_name].append(cmd)
            out_lines.append(self._prompt_for(device_name))
        elif cmd.startswith("interface range ") and mode in {
            "global_config",
            "interface_config",
            "interface_range_config",
        }:
            self._modes[device_name] = "interface_range_config"
            self._configs[device_name].append(cmd)
            out_lines.append(self._prompt_for(device_name))
        elif cmd.startswith("interface ") and mode in {
            "global_config",
            "interface_config",
            "subinterface_config",
        }:
            self._modes[device_name] = (
                "subinterface_config" if "." in cmd else "interface_config"
            )
            self._configs[device_name].append(cmd)
            out_lines.append(self._prompt_for(device_name))
        elif cmd.startswith("crypto isakmp policy ") and mode == "global_config":
            self._modes[device_name] = "isakmp_config"
            self._configs[device_name].append(cmd)
            out_lines.append(self._prompt_for(device_name))
        elif cmd == "telephony-service" and mode == "global_config":
            self._modes[device_name] = "telephony_config"
            self._configs[device_name].append(cmd)
            out_lines.append(self._prompt_for(device_name))
        elif cmd.startswith("router ") and mode in {"global_config", "router_config"}:
            self._modes[device_name] = "router_config"
            self._configs[device_name].append(cmd)
            out_lines.append(self._prompt_for(device_name))
        elif cmd.startswith("ip dhcp pool ") and mode in {"global_config", "dhcp_config"}:
            self._modes[device_name] = "dhcp_config"
            self._configs[device_name].append(cmd)
            out_lines.append(self._prompt_for(device_name))
        elif "invalid" in cmd.lower() or cmd == "bad command":
            out_lines.extend(["                 ^", "% Invalid input detected at '^' marker."])
            out_lines.append(self._prompt_for(device_name))
        elif cmd.startswith("show running-config") and mode == "privileged_exec":
            body = ["Building configuration...", "Current configuration : 512 bytes", "!"]
            body.extend(self._configs.get(device_name, []))
            body.append("end")
            if not self._paging_disabled.get(device_name, False):
                out_lines.extend(body[:2])
                pager = "<--- More --->" if self._is_asa.get(device_name, False) else "--More--"
                out_lines.append(pager)
                self._paged_remaining[device_name] = body[2:]
            else:
                out_lines.extend(body)
                out_lines.append(self._prompt_for(device_name))
        elif cmd.startswith("ping ") and mode in {"user_exec", "privileged_exec"}:
            target = cmd.split()[1]
            out_lines.extend(
                [
                    "Type escape sequence to abort.",
                    f"Sending 5, 100-byte ICMP Echos to {target}, timeout is 2 seconds:",
                    "!!!!!",
                    "Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms",
                    self._prompt_for(device_name),
                ]
            )
        else:
            if cmd and not cmd.startswith("show"):
                self._configs[device_name].append(cmd)
            out_lines.append(self._prompt_for(device_name))

        chunk_text = "\n".join(out_lines)
        self._buffers[device_name] = f"{self._buffers.get(device_name, '')}\n{chunk_text}"
        return chunk_text

    def read_buffer(self, device_name: str) -> str:
        return self._buffers.get(device_name, "")
