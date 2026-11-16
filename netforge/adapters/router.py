"""Hybrid execution router dispatching Packet Tracer operations script-first with GUI fallback."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from netforge.adapters.base import GuiBackend, ScriptBackend
from netforge.adapters.script_bridge import (
    ScriptBridgeError,
    resolve_connect_type,
    resolve_device_type,
)
from netforge.console.models import DeviceConsoleProfile
from netforge.console.transport import ConsoleTransport, UnavailableConsoleTransport
from netforge.core.enums import DeviceCategory
from netforge.core.exceptions import AdapterUnavailableError, ValidationError
from netforge.core.models import ExecutionBackend
from netforge.security.redaction import redact_cli_text

if TYPE_CHECKING:
    from netforge.console.engine import DeviceConsoleEngine


def transport_to_execution_backend(transport_name: str) -> ExecutionBackend:
    """Map a ConsoleTransport identifier to a canonical OperationResult provenance tag."""
    if transport_name == "script_bridge":
        return "script_backend"
    if transport_name == "windows_gui":
        return "gui_backend"
    return "offline_model"


class RoutedConsoleTransport(ConsoleTransport):
    """ConsoleTransport routing CLI lines script-first with optional fallback transport."""

    def __init__(
        self,
        router: BackendRouter,
        fallback: ConsoleTransport | None = None,
    ) -> None:
        self.router = router
        self.fallback: ConsoleTransport = fallback or UnavailableConsoleTransport()
        self._last_output: dict[str, str] = {}
        self.last_execution_backend: ExecutionBackend = "offline_model"

    @property
    def transport_name(self) -> str:  # type: ignore[override]
        if self.router.has_live_script():
            return "script_bridge"
        return self.fallback.transport_name

    def is_available(self) -> bool:
        return self.router.has_live_script() or self.fallback.is_available()

    def open_device(self, device_name: str, profile: DeviceConsoleProfile) -> str:
        if self.router.ensure_live_script() and self.router.script_backend is not None:
            pt_name = self.router.resolve_pt_device_name(device_name)
            try:
                res = self.router.script_backend.execute_cli(
                    pt_name,
                    [""],
                    timeout_seconds=25.0,
                )
                text = str(res.get("raw_output") or res.get("prompt") or "")
                self._last_output[device_name] = text
                self.last_execution_backend = "script_backend"
                return text
            except AdapterUnavailableError:
                if not self.fallback.is_available():
                    raise

        text = self.fallback.open_device(device_name, profile)
        self._last_output[device_name] = text
        self.last_execution_backend = transport_to_execution_backend(self.fallback.transport_name)
        return text

    def send_line(self, device_name: str, line: str, *, timeout_s: float = 5.0) -> str:
        if self.router.ensure_live_script() and self.router.script_backend is not None:
            pt_name = self.router.resolve_pt_device_name(device_name)
            try:
                res = self.router.script_backend.execute_cli(
                    pt_name,
                    [line],
                    timeout_seconds=max(timeout_s, 20.0),
                )
                text = str(res.get("raw_output") or res.get("prompt") or "")
                with self.router._state_lock:
                    self._last_output[device_name] = text
                    self.last_execution_backend = "script_backend"
                    cleaned_line = line.strip()
                    if cleaned_line:
                        self.router.executed_cli_log.setdefault(pt_name, []).append(cleaned_line)
                return text
            except AdapterUnavailableError:
                if not self.fallback.is_available():
                    raise

        text = self.fallback.send_line(device_name, line, timeout_s=timeout_s)
        self._last_output[device_name] = text
        self.last_execution_backend = transport_to_execution_backend(self.fallback.transport_name)
        return text

    def can_batch(self) -> bool:
        """Return True when CLI lines can be dispatched as a single ScriptBackend batch."""
        return bool(self.router.ensure_live_script() and self.router.script_backend is not None)

    def send_batch(
        self,
        device_name: str,
        lines: list[str],
        *,
        timeout_s: float = 25.0,
    ) -> dict[str, Any]:
        """Execute all CLI lines in one live ScriptBackend round-trip."""
        if not lines:
            return {"ok": True, "raw_output": "", "prompt": "", "command_statuses": []}
        if self.router.ensure_live_script() and self.router.script_backend is not None:
            pt_name = self.router.resolve_pt_device_name(device_name)
            res = dict(
                self.router.script_backend.execute_cli(
                    pt_name,
                    lines,
                    timeout_seconds=max(timeout_s, 20.0),
                )
            )
            text = str(res.get("raw_output") or res.get("prompt") or "")
            with self.router._state_lock:
                self._last_output[device_name] = text
                self.last_execution_backend = "script_backend"
                log = self.router.executed_cli_log.setdefault(pt_name, [])
                for line in lines:
                    cleaned_line = str(line).strip()
                    if cleaned_line:
                        log.append(cleaned_line)
            return res
        raise AdapterUnavailableError("Batch CLI transport requires a live ScriptBackend.")

    def read_buffer(self, device_name: str) -> str:
        if self.router.ensure_live_script() and self.router.script_backend is not None:
            if device_name in self._last_output:
                self.last_execution_backend = "script_backend"
                return self._last_output[device_name]
            pt_name = self.router.resolve_pt_device_name(device_name)
            try:
                res = self.router.script_backend.execute_cli(
                    pt_name,
                    [""],
                    timeout_seconds=25.0,
                )
                text = str(res.get("raw_output") or res.get("prompt") or "")
                self._last_output[device_name] = text
                self.last_execution_backend = "script_backend"
                return text
            except AdapterUnavailableError:
                if not self.fallback.is_available():
                    raise

        text = self.fallback.read_buffer(device_name)
        self._last_output[device_name] = text
        self.last_execution_backend = transport_to_execution_backend(self.fallback.transport_name)
        return text


class BackendRouter:
    """Routes scripting-capable operations to ScriptBackend, else GUI or offline model."""

    def __init__(
        self,
        *,
        script_backend: ScriptBackend | None = None,
        gui_backend: GuiBackend | None = None,
        fallback_console: ConsoleTransport | None = None,
        add_device_retry_delays: Sequence[float] = (0.5, 1.0, 2.0),
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.script_backend = script_backend
        self.gui_backend = gui_backend
        self.console_transport = RoutedConsoleTransport(self, fallback=fallback_console)
        self._state_lock = threading.RLock()
        self.device_aliases: dict[str, str] = {}
        self.add_device_retry_delays = tuple(float(d) for d in add_device_retry_delays)
        self._sleep = sleep_fn
        self.watch_mode: bool = False
        self.watch_pace_seconds: float = 0.15
        self.narration_log: list[str] = []
        self.executed_cli_log: dict[str, list[str]] = {}
        self.active_original_path: str | None = None
        self.active_working_path: str | None = None
        self.active_backup_path: str | None = None
        self.active_is_activity: bool | None = None
        self.paging_disabled_devices: set[str] = set()
        self.initial_snapshot: dict[str, Any] | None = None
        self.latest_snapshot: dict[str, Any] | None = None

    def clear_aliases(self) -> None:
        """Reset logical->PT device aliases and per-file session caches for a new lab."""
        with self._state_lock:
            self.device_aliases.clear()
            self.paging_disabled_devices.clear()
            self.console_transport._last_output.clear()

    def configure_watch_mode(self, *, enabled: bool = True, pace_seconds: float = 0.15) -> None:
        """Configure watch-mode pacing and narration for live interactive walkthroughs."""
        self.watch_mode = bool(enabled)
        self.watch_pace_seconds = max(0.0, float(pace_seconds))

    def record_watch_action(
        self,
        action: str,
        summary: str,
        *,
        data: dict[str, Any] | None = None,
        evidence: list[str] | None = None,
        pace: bool = True,
    ) -> str:
        """Append a one-line narration step and apply watch-mode pacing when enabled."""
        with self._state_lock:
            step_num = len(self.narration_log) + 1
            line = f"[Watch #{step_num}] {action}: {summary}"
            self.narration_log.append(line)
        if isinstance(data, dict):
            data["narration"] = line
            data["watch_mode"] = self.watch_mode
        if isinstance(evidence, list):
            evidence.append(line)
        if self.watch_mode and pace and self.watch_pace_seconds > 0:
            self._sleep(self.watch_pace_seconds)
        return line

    def has_live_script(self) -> bool:
        """Return True when a ScriptBackend is attached and actively connected to PT."""
        return self.script_backend is not None and self.script_backend.is_connected()

    def ensure_live_script(self) -> bool:
        """Return True if ScriptBackend is live, auto-launching Packet Tracer when configured."""
        if self.has_live_script():
            return True
        if self.script_backend is not None:
            ensure_fn = getattr(self.script_backend, "ensure_connected", None)
            if callable(ensure_fn):
                ensure_fn()
        return self.has_live_script()

    def has_live_gui(self) -> bool:
        """Return True when a live GuiBackend is available."""
        return self.gui_backend is not None and self.gui_backend.is_available()

    def resolve_pt_device_name(self, device_name: str) -> str:
        """Translate a topology device name to Packet Tracer's live device name if mapped."""
        with self._state_lock:
            return self.device_aliases.get(device_name, device_name)

    def add_device(
        self,
        name: str,
        model: str,
        *,
        category: str | DeviceCategory = DeviceCategory.ROUTER,
        x: float = 100.0,
        y: float = 100.0,
        dry_run: bool = False,
    ) -> tuple[ExecutionBackend, dict[str, Any], list[str], list[str]]:
        """Dispatch live device creation via ScriptBackend when connected."""
        if dry_run:
            return (
                "offline_model",
                {},
                ["Dry-run: recorded device in topology model without live PT dispatch."],
                [],
            )
        if not self.ensure_live_script() or self.script_backend is None:
            return ("offline_model", {}, [], [])

        cat_str = category.value if isinstance(category, DeviceCategory) else str(category)
        model_key = model.strip().lower()
        if model_key in {"7960", "ip_phone", "cisco ip phone"}:
            cat_str = "ip_phone"
        elif model_key.startswith("laptop"):
            cat_str = "laptop"
        elif model_key.startswith("server"):
            cat_str = "server"
        elif model_key.startswith("printer"):
            cat_str = "printer"
        try:
            dev_type = resolve_device_type(cat_str)
        except Exception:
            dev_type = 0
        delays = (0.0, *self.add_device_retry_delays)
        attempts = 0
        last_res: dict[str, Any] = {}
        for attempt_idx, delay_s in enumerate(delays, start=1):
            if attempt_idx > 1 and delay_s > 0:
                self._sleep(delay_s)
            attempts = attempt_idx
            try:
                res = self.script_backend.add_device(model, device_type=dev_type, x=x, y=y)
            except ScriptBridgeError as exc:
                msg_low = str(exc).lower()
                if "empty name" in msg_low or "adddevice" in msg_low:
                    last_res = {"ok": False, "device_name": "", "model": model, "error": str(exc)}
                    continue
                return (
                    "offline_model",
                    {},
                    [],
                    [f"ScriptBackend add_device unavailable ({exc}); kept offline topology only."],
                )
            except AdapterUnavailableError as exc:
                return (
                    "offline_model",
                    {},
                    [],
                    [f"ScriptBackend add_device unavailable ({exc}); kept offline topology only."],
                )
            last_res = dict(res)
            pt_name = str(last_res.get("device_name", "")).strip()
            if pt_name:
                with self._state_lock:
                    self.device_aliases[name] = pt_name
                last_res["attempts"] = attempts
                evidence = [f"Created '{pt_name}' ({model}) in Packet Tracer via ScriptBackend."]
                if attempts > 1:
                    evidence.append(f"Succeeded after {attempts} attempts (warm-up retry).")
                if self.watch_mode:
                    self.record_watch_action(
                        "add_device",
                        f"Added {model} as '{pt_name}' at ({x:.0f}, {y:.0f}).",
                        data=last_res,
                        evidence=evidence,
                    )
                return ("script_backend", last_res, evidence, [])

        # Never store or alias an empty PT device name; fail explicitly after bounded backoff.
        last_res["ok"] = False
        last_res["device_name"] = ""
        last_res["attempts"] = attempts
        last_res["error"] = (
            f"Packet Tracer addDevice('{model}') returned an empty device name "
            f"after {attempts} attempt(s)."
        )
        return ("script_backend", last_res, [], [last_res["error"]])

    def create_link(
        self,
        source_device: str,
        source_interface: str,
        target_device: str,
        target_interface: str,
        *,
        cable_type: str = "auto",
        dry_run: bool = False,
    ) -> tuple[ExecutionBackend, dict[str, Any], list[str], list[str]]:
        """Dispatch live cable creation via ScriptBackend when connected."""
        if dry_run:
            return (
                "offline_model",
                {},
                ["Dry-run: recorded link in topology model without live PT dispatch."],
                [],
            )
        if not self.ensure_live_script() or self.script_backend is None:
            return ("offline_model", {}, [], [])

        pt_d1 = self.resolve_pt_device_name(source_device)
        pt_d2 = self.resolve_pt_device_name(target_device)
        try:
            conn_code = resolve_connect_type(cable_type)
        except Exception:
            conn_code = 8107
        try:
            res = self.script_backend.create_link(
                pt_d1,
                source_interface,
                pt_d2,
                target_interface,
                conn_type=conn_code,
            )
        except ScriptBridgeError as exc:
            err_msg = str(exc)
            if "createlink" in err_msg.lower() or "false" in err_msg.lower():
                return (
                    "script_backend",
                    {"ok": False, "error": err_msg},
                    [],
                    [
                        f"Packet Tracer rejected link {pt_d1}:{source_interface} <-> "
                        f"{pt_d2}:{target_interface}: {err_msg}"
                    ],
                )
            return (
                "offline_model",
                {},
                [],
                [f"ScriptBackend create_link unavailable ({exc}); kept offline topology only."],
            )
        except AdapterUnavailableError as exc:
            return (
                "offline_model",
                {},
                [],
                [f"ScriptBackend create_link unavailable ({exc}); kept offline topology only."],
            )
        if not res.get("ok", False):
            return (
                "script_backend",
                {**res, "ok": False},
                [],
                [
                    f"Packet Tracer rejected link {pt_d1}:{source_interface} <-> "
                    f"{pt_d2}:{target_interface}."
                ],
            )
        evidence = [
            f"Linked {pt_d1}:{source_interface} <-> {pt_d2}:{target_interface} "
            "in Packet Tracer via ScriptBackend.",
        ]
        if self.watch_mode:
            self.record_watch_action(
                "create_link",
                f"Connected {pt_d1}:{source_interface} <-> {pt_d2}:{target_interface}.",
                data=res,
                evidence=evidence,
            )
        return ("script_backend", res, evidence, [])

    def configure_host(
        self,
        device_name: str,
        *,
        port: str = "FastEthernet0",
        dhcp: bool = False,
        ip: str | None = None,
        subnet_mask: str | None = None,
        default_gateway: str | None = None,
        console_engine: DeviceConsoleEngine | None = None,
        dry_run: bool = False,
    ) -> tuple[ExecutionBackend, dict[str, Any], list[str], list[str]]:
        """Configure DHCP or static IPv4 on a PT host via IPC or `ipconfig` CLI fallback."""
        if dry_run:
            return (
                "offline_model",
                {"device_name": device_name, "dhcp": dhcp, "ip": ip, "subnet_mask": subnet_mask},
                [f"Dry-run: planned host configuration for '{device_name}'."],
                [],
            )
        if not self.ensure_live_script() or self.script_backend is None:
            return ("offline_model", {}, [], [])

        pt_name = self.resolve_pt_device_name(device_name)
        cfg_fn = getattr(self.script_backend, "configure_host", None)
        if callable(cfg_fn):
            try:
                res = dict(
                    cfg_fn(
                        pt_name,
                        port=port,
                        dhcp=dhcp,
                        ip=ip,
                        subnet_mask=subnet_mask,
                        default_gateway=default_gateway,
                    )
                )
                desc = "DHCP" if dhcp else f"{ip}/{subnet_mask}"
                ev = [f"Configured host '{pt_name}' ({port}) via ScriptBackend ({desc})."]
                if self.watch_mode:
                    self.record_watch_action(
                        "configure_host",
                        f"Configured {pt_name} ({desc}).",
                        data=res,
                        evidence=ev,
                    )
                return ("script_backend", res, ev, [])
            except ScriptBridgeError as exc:
                if "unsupported opcode" not in str(exc).lower():
                    raise
            except AdapterUnavailableError:
                pass

        # Fallback to Packet Tracer PC Command Prompt when older `.pts` lacks configure_host.
        if console_engine is not None:
            if dhcp:
                cmds = ["ipconfig /renew"]
            elif ip and subnet_mask:
                gw_part = f" {default_gateway}" if default_gateway else ""
                cmds = [f"ipconfig {ip} {subnet_mask}{gw_part}"]
            else:
                return ("offline_model", {}, [], ["Missing DHCP flag or static IP/mask for host."])
            rep = console_engine.execute_commands(
                device_name, cmds, model="PC-PT", target_mode="preserve"
            )
            ev = list(rep.get("evidence", []))
            return ("script_backend", rep, ev, list(rep.get("warnings", [])))

        return ("offline_model", {}, [], [])

    def batch_ops(
        self,
        ops: list[dict[str, Any]],
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any] | None:
        """Dispatch synchronous workspace ops in one bridge round-trip when supported."""
        if not ops or not self.ensure_live_script() or self.script_backend is None:
            return None
        batch_fn = getattr(self.script_backend, "batch_ops", None)
        if not callable(batch_fn):
            return None
        try:
            res = dict(batch_fn(ops, timeout_seconds=timeout_seconds))
        except ScriptBridgeError as exc:
            if "unsupported opcode" in str(exc).lower():
                return None
            raise
        except AdapterUnavailableError:
            return None
        aliases = res.get("aliases")
        if isinstance(aliases, dict):
            with self._state_lock:
                for k, v in aliases.items():
                    if k and v:
                        self.device_aliases[str(k)] = str(v)
        return res

    def read_show_output(
        self,
        device_name: str,
        command: str = "show running-config",
        *,
        console_engine: DeviceConsoleEngine | None = None,
    ) -> tuple[ExecutionBackend, str, list[str], list[str]]:
        """Read running-config or a show command live via ScriptBackend or console fallback."""
        pt_name = self.resolve_pt_device_name(device_name)
        if self.ensure_live_script() and self.script_backend is not None:
            res = self.script_backend.execute_cli(
                pt_name,
                ["terminal length 0", command],
                timeout_seconds=25.0,
            )
            cleaned = redact_cli_text(str(res.get("raw_output", "")))
            warnings: list[str] = []
            if res.get("timed_out"):
                warnings.append(f"Timed out waiting for prompt after '{command}' on '{pt_name}'.")
            return (
                "script_backend",
                cleaned,
                [f"Captured '{command}' on '{pt_name}' via ScriptBackend."],
                warnings,
            )

        if console_engine is not None and console_engine.transport.is_available():
            report = console_engine.execute_commands(
                device_name,
                ["terminal length 0", command],
                target_mode="privileged_exec",
            )
            backend = transport_to_execution_backend(console_engine.transport.transport_name)
            transcripts = report.get("transcripts", [])
            raw = transcripts[-1].get("raw_output", "") if transcripts else ""
            cleaned = redact_cli_text(str(raw))
            return (
                backend,
                cleaned,
                [f"Captured '{command}' on '{device_name}' via {backend}."],
                list(report.get("warnings", [])),
            )

        raise AdapterUnavailableError(
            f"No live script or console backend available to read '{command}' on '{device_name}'.",
            remediation="Connect Packet Tracer Script Module bridge or provide config_text.",
        )

    def read_activity_status(self) -> dict[str, Any]:
        """Read .pka grader state fail-closed: never attempt password or lock bypass."""
        if not self.ensure_live_script() or self.script_backend is None:
            return {
                "state": "unavailable",
                "readable": False,
                "locked": False,
                "score": None,
                "fallback": "cli_verification",
                "reason": "No live ScriptBackend connected.",
                "execution_backend": "offline_model",
            }
        try:
            raw = dict(self.script_backend.read_activity_status())
        except Exception as exc:
            return {
                "state": "unavailable",
                "readable": False,
                "locked": False,
                "score": None,
                "fallback": "cli_verification",
                "reason": f"Grader probe error (fail-closed): {exc}",
                "execution_backend": "script_backend",
            }

        locked = bool(
            raw.get("locked")
            or raw.get("password_locked")
            or raw.get("assessment_mode")
        )
        score = raw.get("score")
        readable = (
            not locked
            and raw.get("state") != "unavailable"
            and raw.get("readable", score is not None)
        )
        if not readable:
            return {
                **raw,
                "state": "unavailable",
                "readable": False,
                "locked": locked,
                "score": None,
                "fallback": "cli_verification",
                "reason": raw.get("reason") or (
                    "Activity is password-locked or in Assessment mode; never bypassing locks."
                    if locked
                    else "Activity completion status is unavailable."
                ),
                "execution_backend": "script_backend",
            }
        return {
            **raw,
            "state": raw.get("state", "available"),
            "readable": True,
            "locked": False,
            "execution_backend": "script_backend",
        }

    def open_file(
        self,
        path: str,
        *,
        timeout_seconds: float = 30.0,
    ) -> tuple[ExecutionBackend, dict[str, Any], list[str], list[str]]:
        """Open a `.pkt`/`.pka` lab inside live Packet Tracer through `ScriptBackend`."""
        cleaned = str(path or "").strip()
        if not cleaned:
            raise ValidationError("Lab file path must not be empty.")
        if self.ensure_live_script() and self.script_backend is not None:
            open_fn = getattr(self.script_backend, "open_file", None)
            if not callable(open_fn):
                raise AdapterUnavailableError(
                    "Connected ScriptBackend does not implement 'open_file'.",
                    remediation="Update netforge_bridge.pts to expose the 'open_file' opcode.",
                )
            data = dict(open_fn(cleaned, timeout_seconds=timeout_seconds))
            evidence = [f"Opened '{cleaned}' inside Packet Tracer via script_backend (fileOpen)."]
            if self.watch_mode:
                self.record_watch_action(
                    "open_file",
                    f"Opened lab '{cleaned}' in Packet Tracer.",
                    data=data,
                    evidence=evidence,
                )
            return ("script_backend", data, evidence, [])
        raise AdapterUnavailableError(
            f"Cannot open '{cleaned}' in Packet Tracer: no live ScriptBackend connected.",
            remediation="Ensure Packet Tracer is running with netforge_bridge.pts connected.",
        )

    def save_file(
        self,
        path: str | None = None,
        *,
        overwrite: bool = True,
        timeout_seconds: float = 30.0,
    ) -> tuple[ExecutionBackend, dict[str, Any], list[str], list[str]]:
        """Save the active Packet Tracer lab through `ScriptBackend`."""
        cleaned = str(path).strip() if path is not None else None
        if path is not None and not cleaned:
            raise ValidationError("Destination path must not be blank when provided.")
        if self.ensure_live_script() and self.script_backend is not None:
            save_fn = getattr(self.script_backend, "save_file", None)
            if not callable(save_fn):
                raise AdapterUnavailableError(
                    "Connected ScriptBackend does not implement 'save_file'.",
                    remediation="Update netforge_bridge.pts with the 'save_file' opcode.",
                )
            data = dict(save_fn(cleaned, overwrite=overwrite, timeout_seconds=timeout_seconds))
            if data.get("ok") is False:
                raise AdapterUnavailableError(
                    str(data.get("error") or "Packet Tracer save_file reported failure."),
                    details=data,
                    remediation="Verify destination path permissions and active PT file state.",
                )
            target_desc = cleaned or str(data.get("saved_filename") or "active file")
            evidence = [f"Saved Packet Tracer workspace to '{target_desc}' via script_backend."]
            if self.watch_mode:
                self.record_watch_action(
                    "save_file",
                    f"Saved lab to '{target_desc}'.",
                    data=data,
                    evidence=evidence,
                    pace=False,
                )
            return ("script_backend", data, evidence, [])
        raise AdapterUnavailableError(
            "Cannot save Packet Tracer workspace: no live ScriptBackend connected.",
            remediation="Ensure Packet Tracer is running with netforge_bridge.pts connected.",
        )

    def list_devices(
        self,
        *,
        timeout_seconds: float = 30.0,
    ) -> tuple[ExecutionBackend, dict[str, Any], list[str], list[str]]:
        """Query live Packet Tracer devices, links, and interface statuses through ScriptBackend."""
        if self.ensure_live_script() and self.script_backend is not None:
            list_fn = getattr(self.script_backend, "list_devices", None)
            if not callable(list_fn):
                raise AdapterUnavailableError(
                    "Connected ScriptBackend does not implement 'list_devices'.",
                    remediation="Update netforge_bridge.pts with the 'list_devices' opcode.",
                )
            data = dict(list_fn(timeout_seconds=timeout_seconds))
            if data.get("ok") is False:
                raise AdapterUnavailableError(
                    str(data.get("error") or "Packet Tracer list_devices reported failure."),
                    details=data,
                )
            dev_cnt = len(data.get("devices", []))
            link_cnt = len(data.get("links", []))
            return (
                "script_backend",
                data,
                [f"Read {dev_cnt} devices and {link_cnt} links live from Packet Tracer."],
                [],
            )
        raise AdapterUnavailableError(
            "Cannot inspect live devices: no live ScriptBackend connected.",
            remediation="Ensure Packet Tracer is running with netforge_bridge.pts connected.",
        )

    def attach_ip_phone_power(
        self,
        device_name: str,
        *,
        timeout_seconds: float = 25.0,
    ) -> tuple[ExecutionBackend, dict[str, Any], list[str], list[str]]:
        """Attach AC power adapter onto a 7960 IP Phone via live ScriptBackend."""
        if self.ensure_live_script() and self.script_backend is not None:
            pt_name = self.resolve_pt_device_name(device_name)
            data = dict(
                self.script_backend.attach_ip_phone_power(
                    pt_name,
                    timeout_seconds=timeout_seconds,
                )
            )
            powered = bool(data.get("powered", False))
            method = str(data.get("method_used") or "script_bridge")
            evidence = [
                f"Attached 7960 power adapter on '{pt_name}' via {method} (powered={powered})."
            ]
            if self.watch_mode:
                self.record_watch_action(
                    "attach_ip_phone_power",
                    f"Powered 7960 IP Phone '{pt_name}' (powered={powered}).",
                    data=data,
                    evidence=evidence,
                )
            return ("script_backend", data, evidence, [])
        raise AdapterUnavailableError(
            f"Cannot attach 7960 power adapter on '{device_name}': "
            "no live ScriptBackend connected.",
            remediation="Ensure Packet Tracer is running with netforge_bridge.pts connected.",
        )
