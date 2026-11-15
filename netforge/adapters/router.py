"""Hybrid execution router dispatching Packet Tracer operations script-first with GUI fallback."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from netforge.adapters.base import GuiBackend, ScriptBackend
from netforge.adapters.script_bridge import resolve_connect_type, resolve_device_type
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
        if self.router.has_live_script() and self.router.script_backend is not None:
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
        if self.router.has_live_script() and self.router.script_backend is not None:
            pt_name = self.router.resolve_pt_device_name(device_name)
            try:
                res = self.router.script_backend.execute_cli(
                    pt_name,
                    [line],
                    timeout_seconds=max(timeout_s, 20.0),
                )
                text = str(res.get("raw_output") or res.get("prompt") or "")
                self._last_output[device_name] = text
                self.last_execution_backend = "script_backend"
                return text
            except AdapterUnavailableError:
                if not self.fallback.is_available():
                    raise

        text = self.fallback.send_line(device_name, line, timeout_s=timeout_s)
        self._last_output[device_name] = text
        self.last_execution_backend = transport_to_execution_backend(self.fallback.transport_name)
        return text

    def read_buffer(self, device_name: str) -> str:
        if self.router.has_live_script() and self.router.script_backend is not None:
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
        self.device_aliases: dict[str, str] = {}
        self.add_device_retry_delays = tuple(float(d) for d in add_device_retry_delays)
        self._sleep = sleep_fn

    def has_live_script(self) -> bool:
        """Return True when a ScriptBackend is attached and actively connected to PT."""
        return self.script_backend is not None and self.script_backend.is_connected()

    def has_live_gui(self) -> bool:
        """Return True when a live GuiBackend is available."""
        return self.gui_backend is not None and self.gui_backend.is_available()

    def resolve_pt_device_name(self, device_name: str) -> str:
        """Translate a topology device name to Packet Tracer's live device name if mapped."""
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
        if not self.has_live_script() or self.script_backend is None:
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
                self.device_aliases[name] = pt_name
                last_res["attempts"] = attempts
                evidence = [f"Created '{pt_name}' ({model}) in Packet Tracer via ScriptBackend."]
                if attempts > 1:
                    evidence.append(f"Succeeded after {attempts} attempts (warm-up retry).")
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
        if not self.has_live_script() or self.script_backend is None:
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
        except AdapterUnavailableError as exc:
            return (
                "offline_model",
                {},
                [],
                [f"ScriptBackend create_link unavailable ({exc}); kept offline topology only."],
            )
        if not res.get("ok", False):
            return (
                "offline_model",
                res,
                [],
                [
                    f"Packet Tracer rejected link {pt_d1}:{source_interface} <-> "
                    f"{pt_d2}:{target_interface}; kept offline topology only."
                ],
            )
        evidence = [
            f"Linked {pt_d1}:{source_interface} <-> {pt_d2}:{target_interface} "
            "in Packet Tracer via ScriptBackend.",
        ]
        return ("script_backend", res, evidence, [])

    def read_show_output(
        self,
        device_name: str,
        command: str = "show running-config",
        *,
        console_engine: DeviceConsoleEngine | None = None,
    ) -> tuple[ExecutionBackend, str, list[str], list[str]]:
        """Read running-config or a show command live via ScriptBackend or console fallback."""
        pt_name = self.resolve_pt_device_name(device_name)
        if self.has_live_script() and self.script_backend is not None:
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
        if not self.has_live_script() or self.script_backend is None:
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
        if self.has_live_script() and self.script_backend is not None:
            open_fn = getattr(self.script_backend, "open_file", None)
            if not callable(open_fn):
                raise AdapterUnavailableError(
                    "Connected ScriptBackend does not implement 'open_file'.",
                    remediation="Update netforge_bridge.pts to expose the 'open_file' opcode.",
                )
            data = dict(open_fn(cleaned, timeout_seconds=timeout_seconds))
            return (
                "script_backend",
                data,
                [f"Opened '{cleaned}' inside Packet Tracer via script_backend (fileOpen)."],
                [],
            )
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
        if self.has_live_script() and self.script_backend is not None:
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
            return (
                "script_backend",
                data,
                [f"Saved Packet Tracer workspace to '{target_desc}' via script_backend."],
                [],
            )
        raise AdapterUnavailableError(
            "Cannot save Packet Tracer workspace: no live ScriptBackend connected.",
            remediation="Ensure Packet Tracer is running with netforge_bridge.pts connected.",
        )
