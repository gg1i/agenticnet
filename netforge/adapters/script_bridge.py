"""Localhost HTTP + token-authenticated Script Module bridge for Packet Tracer 8.2.2."""

from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from netforge.adapters.base import AdapterConnectionState, BackendStatus, ScriptBackend
from netforge.adapters.discovery import (
    detect_packet_tracer_binary,
    is_packet_tracer_running,
    require_interactive_desktop_for_launch,
)
from netforge.core.exceptions import AdapterUnavailableError, ValidationError
from netforge.gui.safety import EmergencyStopController

ALLOWED_OPCODES: frozenset[str] = frozenset(
    {
        "ping",
        "add_device",
        "create_link",
        "cli_exec",
        "get_activity_status",
        "open_file",
        "save_file",
        "list_devices",
        "attach_ip_phone_power",
        "configure_host",
        "batch_ops",
    }
)

# Verified verbatim from PT 8.2.2 IpcAPI (`class_logical_workspace.html`).
PT_DEVICE_TYPES: dict[str, int] = {
    "router": 0,
    "l2_switch": 1,
    "switch": 1,
    "cloud": 2,
    "bridge": 3,
    "hub": 4,
    "repeater": 5,
    "access_point": 7,
    "pc": 8,
    "server": 9,
    "printer": 10,
    "wireless_router": 11,
    "ip_phone": 12,
    "l3_switch": 16,
    "multilayer_switch": 16,
    "laptop": 17,
    "home_voip": 23,
    "analog_phone": 24,
}

# Verified verbatim from PT 8.2.2 IpcAPI (`class_logical_workspace.html`).
PT_CONNECT_TYPES: dict[str, int] = {
    "straight_through": 8100,
    "straight": 8100,
    "crossover": 8101,
    "cross": 8101,
    "rollover": 8102,
    "fiber": 8103,
    "phone": 8104,
    "cable": 8105,
    "serial": 8106,
    "serial_dce": 8106,
    "serial_dte": 8106,
    "auto": 8107,
    "console": 8108,
    "wireless": 8109,
    "coaxial": 8110,
    "octal": 8111,
    "usb": 8113,
}


class ScriptBridgeError(AdapterUnavailableError):
    """Raised when the Packet Tracer Script Module bridge fails or times out."""

    error_code = "SCRIPT_BRIDGE_ERROR"


def resolve_device_type(device_type: int | str) -> int:
    """Resolve a NetForge category name or integer into a Packet Tracer DeviceType ID."""
    if isinstance(device_type, bool):
        raise ValidationError("device_type must be an integer or category string.")
    if isinstance(device_type, int):
        if device_type < 0:
            raise ValidationError("device_type must be non-negative.")
        return device_type
    key = device_type.strip().lower().replace("-", "_").replace(" ", "_")
    if key in PT_DEVICE_TYPES:
        return PT_DEVICE_TYPES[key]
    raise ValidationError(
        f"Unsupported device_type '{device_type}'.",
        details={"supported_categories": sorted(PT_DEVICE_TYPES)},
    )


def resolve_connect_type(conn_type: int | str) -> int:
    """Resolve a cable name or integer into a Packet Tracer CONNECT_TYPES constant."""
    if isinstance(conn_type, bool):
        raise ValidationError("conn_type must be an integer or cable type string.")
    if isinstance(conn_type, int):
        if conn_type < 8100 or conn_type > 8114:
            raise ValidationError(f"Unsupported PT connection type code: {conn_type}")
        return conn_type
    key = conn_type.strip().lower().replace("-", "_").replace(" ", "_")
    if key in PT_CONNECT_TYPES:
        return PT_CONNECT_TYPES[key]
    raise ValidationError(
        f"Unsupported conn_type '{conn_type}'.",
        details={"supported_cables": sorted(PT_CONNECT_TYPES)},
    )


def is_allowed_bridge_origin(origin: str) -> bool:
    """Allow requests only from PT Script Module WebViews or explicit loopback origins."""
    cleaned = origin.strip()
    if not cleaned or cleaned == "null":
        return True
    # PT 8.2.2 WebViews send the opaque origin "pt-sm:" (observed live, no "//").
    if cleaned.startswith("pt-sm:") or cleaned.startswith("file://"):
        return True
    parsed = urlparse(cleaned)
    return parsed.scheme in {"http", "https"} and parsed.hostname in {"127.0.0.1", "localhost"}


def _require_non_empty(value: str, field_name: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValidationError(f"{field_name} must not be empty.")
    return cleaned


@dataclass
class _PendingCommand:
    """Tracks one queued Script Module command waiting for a result callback."""

    request_id: str
    opcode: str
    params: dict[str, Any]
    event: threading.Event = field(default_factory=threading.Event)
    result_payload: dict[str, Any] | None = None

    def to_wire_dict(self) -> dict[str, Any]:
        """Serialize command for the PT WebView poller."""
        return {
            "request_id": self.request_id,
            "opcode": self.opcode,
            "params": self.params,
        }


class HttpScriptBridgeServer:
    """Loopback-only authenticated HTTP RPC bridge consumed by PT's WebView extension."""

    MODULE_ID: str = "com.netforge.bridge"
    SESSION_TTL_MS: int = 60_000

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        auth_token: str | None = None,
        session_file: Path | None = None,
        mirror_session_files: Sequence[Path] | None = None,
        connection_ttl_seconds: float = 10.0,
        heartbeat_interval_seconds: float = 15.0,
    ) -> None:
        if host != "127.0.0.1":
            raise ValidationError(
                "Script bridge must bind to 127.0.0.1 only.",
                details={"requested_host": host},
                remediation="Use 127.0.0.1 to prevent remote network exposure.",
            )
        self.host = host
        self._requested_port = port
        self._token = auth_token or secrets.token_hex(24)
        self.session_file = session_file
        self.mirror_session_files: tuple[Path, ...] = tuple(
            Path(p) for p in (mirror_session_files or ())
        )
        self.connection_ttl_seconds = connection_ttl_seconds
        self.heartbeat_interval_seconds = heartbeat_interval_seconds

        self._cond = threading.Condition()
        self._descriptor_lock = threading.Lock()
        self._queue: list[_PendingCommand] = []
        self._inflight: dict[str, _PendingCommand] = {}
        self._last_seen_monotonic: float | None = None
        self._last_origin: str | None = None
        self._stopped = False
        self._session_id: str | None = None
        self._created_at_ms: int | None = None

        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        """Return the bound localhost TCP port (raises if not started)."""
        if self._httpd is None:
            raise ScriptBridgeError("HttpScriptBridgeServer has not been started.")
        return int(self._httpd.server_address[1])

    @property
    def base_url(self) -> str:
        """Return the loopback HTTP URL for the active bridge."""
        return f"http://{self.host}:{self.port}"

    def token_matches(self, candidate: str) -> bool:
        """Constant-time validation against the ephemeral bridge auth token."""
        if not candidate:
            return False
        return secrets.compare_digest(candidate, self._token)

    def start(self) -> None:
        """Start the 127.0.0.1 HTTP server in a daemon thread and emit session descriptor."""
        if self._httpd is not None:
            return
        with self._cond:
            self._stopped = False
        self._session_id = f"sess_{uuid4().hex[:16]}"
        self._created_at_ms = int(time.time() * 1000)
        self._heartbeat_stop.clear()

        bridge = self

        class _BridgeHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def _origin_header(self) -> str:
                return str(self.headers.get("Origin", "")).strip()

            def _write_cors_headers(self) -> bool:
                origin = self._origin_header()
                if not is_allowed_bridge_origin(origin):
                    return False
                if origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-NetForge-Token")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                return True

            def _send_json(self, status: int, body: dict[str, Any] | None = None) -> None:
                raw = json.dumps(body).encode("utf-8") if body is not None else b""
                try:
                    self.send_response(status)
                    if not self._write_cors_headers():
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", "0")
                        self.send_header("Connection", "close")
                        self.close_connection = True
                        self.end_headers()
                        return
                    if status == 204:
                        self.send_header("Connection", "keep-alive")
                        self.end_headers()
                        return
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    if raw:
                        self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return

            def _authorize(self) -> bool:
                origin = self._origin_header()
                if not is_allowed_bridge_origin(origin):
                    self._send_json(403, {"ok": False, "error": "origin_forbidden"})
                    return False
                token = str(self.headers.get("X-NetForge-Token", ""))
                if not bridge.token_matches(token):
                    self._send_json(401, {"ok": False, "error": "unauthorized"})
                    return False
                return True

            def do_OPTIONS(self) -> None:  # noqa: N802
                origin = self._origin_header()
                if not is_allowed_bridge_origin(origin):
                    self.send_response(403)
                    self.end_headers()
                    return
                self.send_response(204)
                self._write_cors_headers()
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                if not self._authorize():
                    return
                parsed = urlparse(self.path)
                if parsed.path == "/v1/health":
                    self._send_json(
                        200,
                        {
                            "ok": True,
                            "connected": bridge.is_connected(),
                            "bridge_version": "1",
                        },
                    )
                    return

                if parsed.path == "/v1/commands/next":
                    qs = parse_qs(parsed.query)
                    try:
                        wait_ms = int(qs.get("wait_ms", ["0"])[0])
                    except ValueError:
                        wait_ms = 0
                    wait_sec = min(max(wait_ms, 0), 2000) / 1000.0
                    cmd = bridge._pop_next_command(
                        wait_seconds=wait_sec,
                        client_origin=self._origin_header() or None,
                    )
                    if cmd is None:
                        self._send_json(204, None)
                    else:
                        self._send_json(200, {"ok": True, "command": cmd.to_wire_dict()})
                    return

                self._send_json(404, {"ok": False, "error": "not_found"})

            def _drain_post_body(self) -> None:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if 0 < length <= 4 * 1024 * 1024:
                    self.rfile.read(length)

            def do_POST(self) -> None:  # noqa: N802
                if not self._authorize():
                    self._drain_post_body()
                    return
                parsed = urlparse(self.path)
                if parsed.path != "/v1/commands/result":
                    self._send_json(404, {"ok": False, "error": "not_found"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if length <= 0 or length > 4 * 1024 * 1024:
                    self._send_json(400, {"ok": False, "error": "invalid_content_length"})
                    return
                raw = self.rfile.read(length).decode("utf-8", errors="replace")
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    self._send_json(400, {"ok": False, "error": "invalid_json"})
                    return
                if not isinstance(payload, dict) or not isinstance(
                    payload.get("request_id"), str
                ):
                    self._send_json(400, {"ok": False, "error": "missing_request_id"})
                    return
                matched = bridge._complete_command(
                    payload,
                    client_origin=self._origin_header() or None,
                )
                if not matched:
                    self._send_json(404, {"ok": False, "error": "unknown_request_id"})
                    return
                self._send_json(200, {"ok": True})

        class _NoDelayHTTPServer(ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

            def finish_request(self, request: Any, client_address: Any) -> None:
                with suppress(OSError):
                    request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                super().finish_request(request, client_address)

        self._httpd = _NoDelayHTTPServer((self.host, self._requested_port), _BridgeHandler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="netforge-script-bridge",
            daemon=True,
        )
        self._thread.start()
        self._write_session_descriptor()
        if self.session_file is not None and self.heartbeat_interval_seconds > 0:
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                name="netforge-script-bridge-heartbeat",
                daemon=True,
            )
            self._heartbeat_thread.start()

    def stop(self) -> None:
        """Stop the HTTP server cleanly and remove ephemeral session descriptor."""
        self._heartbeat_stop.set()
        with self._cond:
            self._stopped = True
            for pending in list(self._queue) + list(self._inflight.values()):
                pending.result_payload = {
                    "request_id": pending.request_id,
                    "ok": False,
                    "data": {},
                    "error": "Script bridge server stopped.",
                }
                pending.event.set()
            self._queue.clear()
            self._inflight.clear()
            self._cond.notify_all()

        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=2.0)
            self._heartbeat_thread = None
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._remove_session_descriptor()

    def is_connected(self, *, max_idle_seconds: float | None = None) -> bool:
        """Return True if a PT Script Module polled recently while the bridge is running."""
        if self._httpd is None or self._stopped:
            return False
        limit = (
            max_idle_seconds if max_idle_seconds is not None else self.connection_ttl_seconds
        )
        with self._cond:
            if self._last_seen_monotonic is None:
                return False
            return (time.monotonic() - self._last_seen_monotonic) <= limit

    def enqueue_command(
        self,
        opcode: str,
        params: dict[str, Any] | None = None,
        *,
        timeout_seconds: float = 15.0,
    ) -> dict[str, Any]:
        """Queue a typed opcode for Packet Tracer and wait synchronously for its result."""
        if opcode not in ALLOWED_OPCODES:
            raise ValidationError(
                f"Disallowed script opcode '{opcode}'.",
                details={"allowed_opcodes": sorted(ALLOWED_OPCODES)},
            )
        if self._httpd is None:
            raise ScriptBridgeError(
                "Script bridge HTTP server is not running.",
                remediation="Start HttpScriptBridgeServer before dispatching PT script calls.",
            )

        pending = _PendingCommand(
            request_id=f"req_{uuid4().hex[:12]}",
            opcode=opcode,
            params=dict(params or {}),
        )
        with self._cond:
            if self._stopped:
                raise ScriptBridgeError("Script bridge server is stopping.")
            self._queue.append(pending)
            self._inflight[pending.request_id] = pending
            self._cond.notify_all()

        if not pending.event.wait(timeout=timeout_seconds):
            with self._cond:
                if pending in self._queue:
                    self._queue.remove(pending)
                self._inflight.pop(pending.request_id, None)
            raise ScriptBridgeError(
                f"Timed out waiting for Packet Tracer Script Module response ({opcode}).",
                details={"opcode": opcode, "timeout_seconds": timeout_seconds},
                remediation="Ensure Packet Tracer is running with the NetForge bridge active.",
            )

        payload = pending.result_payload or {}
        if not payload.get("ok"):
            raise ScriptBridgeError(
                str(payload.get("error") or f"Script opcode '{opcode}' failed in Packet Tracer."),
                details={"opcode": opcode, "data": payload.get("data", {})},
            )
        data = payload.get("data", {})
        return dict(data) if isinstance(data, dict) else {"value": data}

    def _pop_next_command(
        self,
        *,
        wait_seconds: float = 0.0,
        client_origin: str | None = None,
    ) -> _PendingCommand | None:
        deadline = time.monotonic() + wait_seconds
        with self._cond:
            self._last_seen_monotonic = time.monotonic()
            if client_origin:
                self._last_origin = client_origin
            while not self._queue and not self._stopped:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(timeout=remaining)
            if self._stopped or not self._queue:
                return None
            self._last_seen_monotonic = time.monotonic()
            return self._queue.pop(0)

    def _complete_command(
        self,
        payload: dict[str, Any],
        *,
        client_origin: str | None = None,
    ) -> bool:
        request_id = str(payload["request_id"])
        with self._cond:
            self._last_seen_monotonic = time.monotonic()
            if client_origin:
                self._last_origin = client_origin
            pending = self._inflight.pop(request_id, None)
            if pending is None:
                return False
            pending.result_payload = payload
            pending.event.set()
            return True

    def _heartbeat_loop(self) -> None:
        interval = max(float(self.heartbeat_interval_seconds), 0.1)
        while not self._heartbeat_stop.wait(timeout=interval):
            if self._stopped or self._httpd is None:
                break
            try:
                self._write_session_descriptor()
            except OSError:
                continue

    def _write_session_descriptor(self) -> None:
        targets = [p for p in [self.session_file, *self.mirror_session_files] if p is not None]
        if not targets or self._stopped or self._httpd is None:
            return
        now_ms = int(time.time() * 1000)
        descriptor = {
            "session_id": self._session_id or f"sess_{uuid4().hex[:16]}",
            "url": self.base_url,
            "token": self._token,
            "server_pid": os.getpid(),
            "pid": os.getpid(),
            "created_at": self._created_at_ms or now_ms,
            "heartbeat_at": now_ms,
            "ttl_ms": self.SESSION_TTL_MS,
            "module_id": self.MODULE_ID,
            "bridge_version": "1",
        }
        raw_text = json.dumps(descriptor, indent=2)
        with self._descriptor_lock:
            if self._stopped or self._httpd is None:
                return
            for target in targets:
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp = target.with_suffix(".tmp")
                tmp.write_text(raw_text, encoding="utf-8")
                tmp.replace(target)
                if os.name == "posix":
                    os.chmod(target, 0o600)

    def _remove_session_descriptor(self) -> None:
        targets = [p for p in [self.session_file, *self.mirror_session_files] if p is not None]
        with self._descriptor_lock:
            for target in targets:
                if not target.exists():
                    continue
                # Never unlink a descriptor owned by another live server process.
                try:
                    existing = json.loads(target.read_text(encoding="utf-8"))
                    owner_sid = existing.get("session_id") if isinstance(existing, dict) else None
                    if self._session_id and owner_sid and owner_sid != self._session_id:
                        continue
                except (OSError, json.JSONDecodeError):
                    pass
                with suppress(OSError):
                    target.unlink()


class HttpScriptBridgeBackend(ScriptBackend):
    """Concrete `ScriptBackend` executing typed opcodes via `HttpScriptBridgeServer`."""

    def __init__(
        self,
        server: HttpScriptBridgeServer | None = None,
        *,
        safety: EmergencyStopController | None = None,
        default_timeout_seconds: float = 25.0,
        auto_launch_pt: bool = False,
        packet_tracer_path: str | None = None,
    ) -> None:
        self._owns_server = server is None
        self.server = server or HttpScriptBridgeServer()
        self.safety = safety or EmergencyStopController(
            corner_failsafe=False,
            escape_failsafe=False,
            max_actions_per_minute=300,
        )
        self.default_timeout_seconds = default_timeout_seconds
        self.auto_launch_pt = auto_launch_pt
        self.packet_tracer_path = packet_tracer_path
        self._launch_lock = threading.Lock()

    def _ensure_installed_pts(self) -> None:
        """Ensure the bundled `netforge_bridge.pts` is present alongside the session file."""
        if self.server.session_file is None:
            return
        try:
            asset = resources.files("netforge.adapters.assets").joinpath("netforge_bridge.pts")
            if not asset.is_file():
                return
            expected_bytes = asset.read_bytes()
            dest = self.server.session_file.parent / "netforge_bridge.pts"
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists() or dest.read_bytes() != expected_bytes:
                dest.write_bytes(expected_bytes)
        except OSError:
            return

    def start(self) -> None:
        """Start the underlying HTTP bridge server."""
        self._ensure_installed_pts()
        self.server.start()

    def stop(self) -> None:
        """Stop the underlying HTTP bridge server."""
        self.server.stop()

    def is_connected(self) -> bool:
        """Return True if a live Packet Tracer extension client is connected."""
        return self.server.is_connected()

    def ensure_connected(self, *, timeout_seconds: float = 40.0) -> bool:
        """Auto-launch Packet Tracer if needed and wait until the Script Module connects."""
        if self.is_connected():
            return True
        if not self.auto_launch_pt or self.server._httpd is None:
            return False
        require_interactive_desktop_for_launch("HttpScriptBridgeBackend.ensure_connected")
        pt_exe = detect_packet_tracer_binary(self.packet_tracer_path)
        if pt_exe is None:
            return False
        with self._launch_lock:
            if self.is_connected():
                return True
            if not is_packet_tracer_running():
                subprocess.Popen([str(pt_exe)])
            deadline = time.monotonic() + max(timeout_seconds, 1.0)
            while time.monotonic() < deadline:
                if self.is_connected():
                    return True
                time.sleep(0.15)
        return self.is_connected()

    def ping(self) -> dict[str, Any]:
        """Run an authenticated end-to-end ping through Packet Tracer's Script Module."""
        self.safety.check_safe_to_act(live_input=False, count_action=False)
        data = self.server.enqueue_command(
            "ping",
            {},
            timeout_seconds=min(self.default_timeout_seconds, 5.0),
        )
        return {"ok": True, "backend": "script_http", "response": data}

    def add_device(
        self,
        model: str,
        *,
        device_type: int | str = 0,
        x: float = 100.0,
        y: float = 100.0,
    ) -> dict[str, Any]:
        """Create a device on the active Packet Tracer logical workspace."""
        cleaned_model = _require_non_empty(model, "model")
        resolved_type = resolve_device_type(device_type)
        self.safety.check_safe_to_act(live_input=False, count_action=True)
        data = self.server.enqueue_command(
            "add_device",
            {
                "device_type": resolved_type,
                "model": cleaned_model,
                "x": float(x),
                "y": float(y),
            },
            timeout_seconds=self.default_timeout_seconds,
        )
        out: dict[str, Any] = {
            "ok": True,
            "backend": "script_http",
            "device_name": str(data.get("device_name", "")),
            "model": cleaned_model,
            "device_type": resolved_type,
            "x": float(x),
            "y": float(y),
        }
        if "auto_powered" in data:
            out["auto_powered"] = bool(data["auto_powered"])
        if "power_details" in data:
            out["power_details"] = data["power_details"]
        return out

    def create_link(
        self,
        device1: str,
        port1: str,
        device2: str,
        port2: str,
        *,
        conn_type: int | str = 8107,
    ) -> dict[str, Any]:
        """Link two device interfaces in Packet Tracer's logical workspace."""
        d1 = _require_non_empty(device1, "device1")
        p1 = _require_non_empty(port1, "port1")
        d2 = _require_non_empty(device2, "device2")
        p2 = _require_non_empty(port2, "port2")
        resolved_conn = resolve_connect_type(conn_type)
        self.safety.check_safe_to_act(live_input=False, count_action=True)
        data = self.server.enqueue_command(
            "create_link",
            {
                "device1": d1,
                "port1": p1,
                "device2": d2,
                "port2": p2,
                "conn_type": resolved_conn,
            },
            timeout_seconds=self.default_timeout_seconds,
        )
        return {
            "ok": bool(data.get("linked", True)),
            "backend": "script_http",
            "device1": d1,
            "port1": p1,
            "device2": d2,
            "port2": p2,
            "conn_type": resolved_conn,
        }

    def execute_cli(
        self,
        device_name: str,
        commands: list[str],
        *,
        wait_for_prompt: bool = True,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Run IOS CLI commands via PT TerminalLine and return captured raw output."""
        dev = _require_non_empty(device_name, "device_name")
        if not commands:
            raise ValidationError("commands must contain at least one CLI command string.")
        normalized_cmds = [str(cmd) for cmd in commands]
        effective_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else max(float(self.default_timeout_seconds), 25.0)
        )
        self.safety.check_safe_to_act(live_input=False, count_action=True)
        data = self.server.enqueue_command(
            "cli_exec",
            {
                "device_name": dev,
                "commands": normalized_cmds,
                "wait_for_prompt": bool(wait_for_prompt),
                "timeout_ms": int(max(effective_timeout, 1.0) * 1000),
            },
            timeout_seconds=effective_timeout + 2.0,
        )
        statuses = list(data.get("command_statuses", []))
        non_fatal_commands = list(data.get("non_fatal_commands", []))
        if not non_fatal_commands:
            non_fatal_commands = [
                str(entry.get("command", ""))
                for entry in statuses
                if isinstance(entry, dict)
                and entry.get("status", 0) != 0
                and str(entry.get("command", "")).strip().lower().startswith("terminal length 0")
            ]
        return {
            "ok": True,
            "backend": "script_http",
            "device_name": dev,
            "commands": normalized_cmds,
            "raw_output": str(data.get("raw_output", "")),
            "prompt": str(data.get("prompt", "")),
            "mode": str(data.get("mode", "")),
            "command_statuses": statuses,
            "non_fatal_commands": non_fatal_commands,
            "more_pages_advanced": int(data.get("more_pages_advanced", 0)),
            "timed_out": bool(data.get("timed_out", False)),
        }

    def read_activity_status(self) -> dict[str, Any]:
        """Read `.pka` score and comparator tree without bypassing locks/passwords."""
        self.safety.check_safe_to_act(live_input=False, count_action=False)
        data = self.server.enqueue_command(
            "get_activity_status",
            {},
            timeout_seconds=self.default_timeout_seconds,
        )
        is_act = bool(data.get("is_activity_file", False))
        pct = data.get("percentage_complete")
        raw_state = data.get("state")
        if not is_act:
            return {
                "ok": True,
                "backend": "script_http",
                **data,
                "state": str(raw_state or "not_activity"),
                "readable": False,
                "fallback": "cli_verification",
            }
        pct_valid = isinstance(pct, (int, float)) and not isinstance(pct, bool) and pct >= 0
        if raw_state == "unavailable" or not pct_valid:
            return {
                "ok": True,
                "backend": "script_http",
                **data,
                "is_activity_file": True,
                "state": "unavailable",
                "readable": False,
                "fallback": "cli_verification",
                "reason": str(
                    data.get("reason")
                    or "Activity completion score is unreadable, locked, or Assessment-restricted."
                ),
            }
        return {
            "ok": True,
            "backend": "script_http",
            **data,
            "state": "available",
            "readable": True,
        }

    def open_file(
        self,
        path: str,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Open a `.pkt`/`.pka` file inside PT via `ipc.appWindow().fileOpen()`."""
        self.safety.check_safe_to_act(live_input=False, count_action=False)
        data = self.server.enqueue_command(
            "open_file",
            {"path": str(path)},
            timeout_seconds=timeout_seconds or self.default_timeout_seconds,
        )
        return {
            "ok": True,
            "backend": "script_http",
            **data,
        }

    def save_file(
        self,
        path: str | None = None,
        *,
        overwrite: bool = True,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Save the active PT file via `fileSave()` or `fileSaveAsNoPrompt()`."""
        self.safety.check_safe_to_act(live_input=False, count_action=False)
        payload: dict[str, Any] = {"overwrite": bool(overwrite)}
        if path is not None:
            payload["path"] = str(path)
        data = self.server.enqueue_command(
            "save_file",
            payload,
            timeout_seconds=timeout_seconds or self.default_timeout_seconds,
        )
        return {
            "ok": True,
            "backend": "script_http",
            **data,
        }

    def list_devices(
        self,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Query live Packet Tracer canvas devices, models, hostnames, ports, and links."""
        self.safety.check_safe_to_act(live_input=False, count_action=False)
        data = self.server.enqueue_command(
            "list_devices",
            {},
            timeout_seconds=timeout_seconds or self.default_timeout_seconds,
        )
        return {
            "ok": True,
            "backend": "script_http",
            **data,
        }

    def attach_ip_phone_power(
        self,
        device_name: str,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Attach the AC power adapter onto a 7960 IP Phone via PT's Script Module IPC."""
        dev = _require_non_empty(device_name, "device_name")
        self.safety.check_safe_to_act(live_input=False, count_action=True)
        data = self.server.enqueue_command(
            "attach_ip_phone_power",
            {"device_name": dev},
            timeout_seconds=timeout_seconds or self.default_timeout_seconds,
        )
        return {
            "ok": True,
            "backend": "script_http",
            **data,
        }

    def configure_host(
        self,
        device_name: str,
        *,
        port: str = "FastEthernet0",
        dhcp: bool = False,
        ip: str | None = None,
        subnet_mask: str | None = None,
        default_gateway: str | None = None,
        display_name: str | None = None,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Configure DHCP or static IPv4/mask/gateway on a PT host via Script Module IPC."""
        dev = _require_non_empty(device_name, "device_name")
        self.safety.check_safe_to_act(live_input=False, count_action=True)
        payload: dict[str, Any] = {
            "device_name": dev,
            "port": port or "FastEthernet0",
            "dhcp": bool(dhcp),
        }
        if ip:
            payload["ip"] = str(ip)
        if subnet_mask:
            payload["subnet_mask"] = str(subnet_mask)
        if default_gateway:
            payload["default_gateway"] = str(default_gateway)
        if display_name:
            payload["display_name"] = str(display_name)
        data = self.server.enqueue_command(
            "configure_host",
            payload,
            timeout_seconds=timeout_seconds or self.default_timeout_seconds,
        )
        return {
            "ok": True,
            "backend": "script_http",
            **data,
        }

    def batch_ops(
        self,
        ops: list[dict[str, Any]],
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Execute multiple synchronous workspace ops in one Packet Tracer RPC call."""
        if not ops:
            return {"ok": True, "backend": "script_http", "results": [], "aliases": {}}
        self.safety.check_safe_to_act(live_input=False, count_action=True)
        effective = timeout_seconds or max(self.default_timeout_seconds, 10.0 + len(ops) * 0.5)
        data = self.server.enqueue_command(
            "batch_ops",
            {"ops": ops},
            timeout_seconds=effective,
        )
        return {
            "ok": True,
            "backend": "script_http",
            **data,
        }

    def backend_status(self) -> BackendStatus:
        """Describe HTTP script bridge status and verified PT 8.2.2 capabilities."""
        return BackendStatus(
            backend_name="HttpScriptBridgeBackend",
            connection_state=(
                AdapterConnectionState.CONNECTED
                if self.is_connected()
                else AdapterConnectionState.DETECTED_IDLE
            ),
            platform="loopback_http",
            capabilities=[
                "ping",
                "add_device",
                "create_link",
                "cli_exec",
                "get_activity_status",
                "open_file",
                "save_file",
                "list_devices",
                "attach_ip_phone_power",
                "configure_host",
                "batch_ops",
            ],
            notes="127.0.0.1 token-authenticated WebView HTTP bridge.",
        )


def read_bridge_session_descriptor(session_file: Path) -> dict[str, Any] | None:
    """Read an ephemeral runtime bridge session descriptor if present and valid."""
    if not session_file.exists():
        return None
    try:
        payload = json.loads(session_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    url = payload.get("url")
    token = payload.get("token")
    if not isinstance(url, str) or not isinstance(token, str):
        return None
    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        return None
    return payload


def probe_bridge_health(
    session_file: Path,
    *,
    timeout_seconds: float = 0.5,
) -> dict[str, Any]:
    """Probe the local script bridge `/v1/health` endpoint without exposing its secret token."""
    desc = read_bridge_session_descriptor(session_file)
    if desc is None:
        return {
            "session_descriptor_present": session_file.exists(),
            "reachable": False,
            "connected": False,
            "state": "offline",
            "error": None,
        }

    url = f"{desc['url'].rstrip('/')}/v1/health"
    req = urllib.request.Request(
        url,
        headers={"X-NetForge-Token": str(desc["token"])},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:  # noqa: S310
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return {
            "session_descriptor_present": True,
            "reachable": False,
            "connected": False,
            "state": "stale_descriptor",
            "error": str(exc),
        }

    connected = bool(body.get("connected", False))
    return {
        "session_descriptor_present": True,
        "reachable": True,
        "connected": connected,
        "state": "connected" if connected else "bridge_listening_pt_idle",
        "bridge_version": body.get("bridge_version"),
        "error": None,
    }


def render_script_module_sources(
    output_dir: Path,
    *,
    session_file: Path | None = None,
) -> dict[str, Path]:
    """Write configured non-secret Script Module JS and HTML files for Packet Tracer export."""
    output_dir.mkdir(parents=True, exist_ok=True)
    assets_pkg = resources.files("netforge.adapters.assets")
    js_template = (assets_pkg / "netforge_bridge.js").read_text(encoding="utf-8")
    html_text = (assets_pkg / "bridge.html").read_text(encoding="utf-8")

    js_path = output_dir / "netforge_bridge.js"
    html_path = output_dir / "bridge.html"
    js_rendered = js_template
    if session_file is not None:
        session_slash = str(session_file.resolve()).replace("\\", "/")
        js_rendered = js_template.replace("__NETFORGE_SESSION_FILE__", session_slash)
    js_path.write_text(js_rendered, encoding="utf-8")
    html_path.write_text(html_text, encoding="utf-8")
    return {"js": js_path, "html": html_path}
