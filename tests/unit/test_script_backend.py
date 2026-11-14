"""Offline unit tests for ScriptBackend ABC and 127.0.0.1 authenticated HTTP bridge."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from netforge.adapters import (
    AdapterConnectionState,
    HttpScriptBridgeBackend,
    HttpScriptBridgeServer,
    ScriptBackend,
    ScriptBridgeError,
)
from netforge.adapters.script_bridge import (
    is_allowed_bridge_origin,
    render_script_module_sources,
    resolve_connect_type,
    resolve_device_type,
)
from netforge.core.exceptions import ValidationError
from netforge.gui.safety import AutomationStopError, EmergencyStopController


class _FakePtBridgeClient:
    """Offline stand-in for PT's headless QWebEngine script module client."""

    def __init__(self, base_url: str, token: str, handlers: dict[str, Any]) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.handlers = handlers
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            req = urllib.request.Request(
                f"{self.base_url}/v1/commands/next?wait_ms=250",
                headers={
                    "X-NetForge-Token": self.token,
                    "Origin": "pt-sm://com.netforge.bridge/bridge.html",
                },
                method="GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    if resp.status == 204:
                        continue
                    payload = json.loads(resp.read().decode("utf-8"))
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
                time.sleep(0.05)
                continue

            cmd = payload.get("command")
            if not isinstance(cmd, dict):
                continue
            handler = self.handlers.get(cmd["opcode"])
            try:
                data = handler(cmd["params"]) if handler else {}
                body = {"request_id": cmd["request_id"], "ok": True, "data": data, "error": None}
            except Exception as exc:  # noqa: BLE001
                body = {
                    "request_id": cmd["request_id"],
                    "ok": False,
                    "data": {},
                    "error": str(exc),
                }

            post_req = urllib.request.Request(
                f"{self.base_url}/v1/commands/result",
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-NetForge-Token": self.token,
                    "Origin": "pt-sm://com.netforge.bridge/bridge.html",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(post_req, timeout=2.0):
                    pass
            except (urllib.error.URLError, OSError):
                pass


@pytest.mark.unit
def test_script_backend_abc_and_type_resolvers() -> None:
    with pytest.raises(TypeError):
        ScriptBackend()  # type: ignore[abstract]

    assert resolve_device_type("router") == 0
    assert resolve_device_type("L2-Switch") == 1
    assert resolve_device_type(8) == 8
    with pytest.raises(ValidationError):
        resolve_device_type(True)
    with pytest.raises(ValidationError):
        resolve_device_type("toaster_9000")

    assert resolve_connect_type("straight_through") == 8100
    assert resolve_connect_type("crossover") == 8101
    assert resolve_connect_type(8107) == 8107
    with pytest.raises(ValidationError):
        resolve_connect_type(9999)
    with pytest.raises(ValidationError):
        resolve_connect_type("laser_beam")


@pytest.mark.unit
def test_origin_allowlist_and_loopback_enforcement() -> None:
    assert is_allowed_bridge_origin("pt-sm://com.netforge.bridge/bridge.html")
    assert is_allowed_bridge_origin("pt-sm:")  # origin observed live in PT 8.2.2
    assert is_allowed_bridge_origin("http://127.0.0.1:5000")
    assert is_allowed_bridge_origin("null")
    assert not is_allowed_bridge_origin("https://attacker.example")

    with pytest.raises(ValidationError):
        HttpScriptBridgeServer(host="0.0.0.0")


@pytest.mark.unit
def test_http_bridge_auth_and_session_descriptor(tmp_path: Path) -> None:
    session_file = tmp_path / "bridge_session.json"
    server = HttpScriptBridgeServer(session_file=session_file)
    server.start()
    try:
        assert session_file.exists()
        desc = json.loads(session_file.read_text(encoding="utf-8"))
        assert desc["url"].startswith("http://127.0.0.1:")
        assert len(desc["token"]) >= 32

        # Missing token -> 401
        with pytest.raises(urllib.error.HTTPError) as missing_exc:
            urllib.request.urlopen(f"{server.base_url}/v1/health", timeout=2.0)
        assert missing_exc.value.code == 401

        # Disallowed external origin -> 403
        bad_origin_req = urllib.request.Request(
            f"{server.base_url}/v1/health",
            headers={"X-NetForge-Token": desc["token"], "Origin": "https://evil.example"},
        )
        with pytest.raises(urllib.error.HTTPError) as origin_exc:
            urllib.request.urlopen(bad_origin_req, timeout=2.0)
        assert origin_exc.value.code == 403

        # Valid token & PT origin -> 200 without leaking token
        ok_req = urllib.request.Request(
            f"{server.base_url}/v1/health",
            headers={
                "X-NetForge-Token": desc["token"],
                "Origin": "pt-sm://com.netforge.bridge/bridge.html",
            },
        )
        with urllib.request.urlopen(ok_req, timeout=2.0) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert payload["ok"] is True
        assert payload["connected"] is False
        assert desc["token"] not in json.dumps(payload)
    finally:
        server.stop()

    assert not session_file.exists()


@pytest.mark.unit
def test_mocked_bridge_core_spike_roundtrip_and_safety(tmp_path: Path) -> None:
    session_file = tmp_path / "bridge_session.json"
    server = HttpScriptBridgeServer(session_file=session_file)
    safety = EmergencyStopController(
        corner_failsafe=False,
        escape_failsafe=False,
        max_actions_per_minute=3,
    )
    backend = HttpScriptBridgeBackend(server, safety=safety, default_timeout_seconds=3.0)
    backend.start()

    desc = json.loads(session_file.read_text(encoding="utf-8"))
    handlers = {
        "ping": lambda _p: {"pong": True, "bridge": "mock_pt"},
        "add_device": lambda p: {
            "device_name": "Router0" if p["device_type"] == 0 else "Switch0",
            "model": p["model"],
            "device_type": p["device_type"],
        },
        "create_link": lambda p: {"linked": True, **p},
        "cli_exec": lambda p: {
            "device_name": p["device_name"],
            "prompt": "Router#",
            "mode": "enable",
            "raw_output": (
                "Router#show ip interface brief\n"
                "GigabitEthernet0/0 unassigned YES unset down"
            ),
            "command_statuses": [{"command": c, "status": 0} for c in p["commands"]],
            "timed_out": False,
        },
        "get_activity_status": lambda _p: {"is_activity_file": True, "percentage_complete": 12.5},
    }
    client = _FakePtBridgeClient(desc["url"], desc["token"], handlers)
    client.start()
    try:
        # Wait briefly for poller heartbeat
        deadline = time.monotonic() + 2.0
        while not backend.is_connected() and time.monotonic() < deadline:
            time.sleep(0.05)

        assert backend.is_connected() is True
        assert backend.backend_status().connection_state == AdapterConnectionState.CONNECTED

        assert backend.ping()["response"]["pong"] is True
        dev = backend.add_device("2911", device_type="router", x=150, y=150)
        assert dev["device_name"] == "Router0"

        link = backend.create_link(
            "Router0",
            "GigabitEthernet0/0",
            "Switch0",
            "FastEthernet0/1",
            conn_type="straight_through",
        )
        assert link["ok"] is True
        assert link["conn_type"] == 8100

        cli = backend.execute_cli("Router0", ["show ip interface brief"])
        assert cli["prompt"] == "Router#"
        assert "GigabitEthernet0/0" in cli["raw_output"]
        assert cli["command_statuses"] == [{"command": "show ip interface brief", "status": 0}]

        # 4th mutating action hits max_actions_per_minute=3 rate limit before dispatch
        with pytest.raises(AutomationStopError):
            backend.add_device("2960-24TT", device_type="switch")

        # Reading activity doesn't count against action budget unless stopped
        safety.max_actions_per_minute = 20
        activity = backend.read_activity_status()
        assert activity["percentage_complete"] == 12.5

        # Explicit emergency stop halts further calls immediately
        safety.request_stop("test abort")
        with pytest.raises(AutomationStopError):
            backend.execute_cli("Router0", ["show version"])
    finally:
        client.stop()
        backend.stop()


@pytest.mark.unit
def test_bridge_error_propagation_and_timeout(tmp_path: Path) -> None:
    server = HttpScriptBridgeServer(session_file=tmp_path / "bridge_session.json")
    backend = HttpScriptBridgeBackend(server, default_timeout_seconds=0.3)
    backend.start()
    try:
        with pytest.raises(ValidationError):
            server.enqueue_command("eval_js", {"code": "1+1"})

        with pytest.raises(ScriptBridgeError):
            backend.ping()

        desc = json.loads((tmp_path / "bridge_session.json").read_text(encoding="utf-8"))

        def _fail(_params: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("createLink returned false")

        client = _FakePtBridgeClient(desc["url"], desc["token"], {"create_link": _fail})
        client.start()
        try:
            with pytest.raises(ScriptBridgeError, match="createLink returned false"):
                backend.create_link("R1", "Gi0/0", "SW1", "Fa0/1")
        finally:
            client.stop()
    finally:
        backend.stop()


@pytest.mark.unit
def test_render_script_module_sources_has_no_embedded_secret(tmp_path: Path) -> None:
    out = render_script_module_sources(
        tmp_path / "rendered",
        session_file=tmp_path / "netforge_data" / "bridge_session.json",
    )
    js_text = out["js"].read_text(encoding="utf-8")
    html_text = out["html"].read_text(encoding="utf-8")
    assert "__NETFORGE_SESSION_FILE__" not in js_text
    assert "bridge_session.json" in js_text
    assert "new Function" not in js_text
    assert "/v1/commands/next" in html_text
    assert "moreDisplayed" in js_text
    assert "isStarted" in js_text

    portable = render_script_module_sources(tmp_path / "portable", session_file=None)
    portable_js = portable["js"].read_text(encoding="utf-8")
    assert "__NETFORGE_SESSION_FILE__" in portable_js
    assert "getUserFolder" in portable_js
    assert "getTempFileLocation" in portable_js
    home_slash = str(Path.home()).replace("\\", "/")
    assert home_slash not in portable_js
    assert ":".join(["C", "/Users/"]) not in portable_js


@pytest.mark.unit
def test_bridge_idempotent_start_stop_and_cli_hardening(tmp_path: Path) -> None:
    session_file = tmp_path / "bridge_session.json"
    server = HttpScriptBridgeServer(session_file=session_file)
    backend = HttpScriptBridgeBackend(server, default_timeout_seconds=10.0)
    backend.start()
    port_first = server.port
    backend.start()  # idempotent double-start
    assert server.port == port_first
    assert session_file.exists()

    seen_timeouts: list[int] = []
    desc = json.loads(session_file.read_text(encoding="utf-8"))

    def _cli_handler(p: dict[str, Any]) -> dict[str, Any]:
        seen_timeouts.append(int(p["timeout_ms"]))
        return {
            "device_name": p["device_name"],
            "prompt": "Router#",
            "mode": "enable",
            "raw_output": "Router#show running-config\n! ... \nend\nRouter#",
            "command_statuses": [
                {"command": "terminal length 0", "status": 2, "non_fatal": True},
                {"command": "show running-config", "status": 0, "non_fatal": False},
            ],
            "non_fatal_commands": ["terminal length 0"],
            "more_pages_advanced": 3,
            "timed_out": False,
        }

    client = _FakePtBridgeClient(
        desc["url"],
        desc["token"],
        {
            "cli_exec": _cli_handler,
            "get_activity_status": lambda _p: {
                "is_activity_file": True,
                "state": "unavailable",
                "percentage_complete": -1,
                "reason": "Assessment lock active.",
            },
        },
    )
    client.start()
    try:
        res = backend.execute_cli("Router0", ["terminal length 0", "show running-config"])
        assert res["ok"] is True
        assert seen_timeouts == [25000]  # enforces >= 20s budget even if default=10s
        assert res["non_fatal_commands"] == ["terminal length 0"]
        assert res["more_pages_advanced"] == 3

        locked_grade = backend.read_activity_status()
        assert locked_grade["state"] == "unavailable"
        assert locked_grade["readable"] is False
        assert locked_grade["fallback"] == "cli_verification"
    finally:
        client.stop()
        backend.stop()
        backend.stop()  # idempotent double-stop
    assert not session_file.exists()


def test_bridge_js_sends_cli_commands_sequentially() -> None:
    js = (
        Path(__file__).resolve().parents[2]
        / "netforge/adapters/assets/netforge_bridge.js"
    ).read_text(encoding="utf-8")
    assert "nextIdx" in js
    batch = "for (var i = 0; i < commands.length; i++) {"
    assert batch not in js


@pytest.mark.unit
def test_http_bridge_security_origin_and_token_matrix(tmp_path: Path) -> None:
    session_file = tmp_path / "bridge_session.json"
    server = HttpScriptBridgeServer(session_file=session_file)
    server.start()
    try:
        desc = json.loads(session_file.read_text(encoding="utf-8"))
        url = desc["url"]
        token = desc["token"]

        # 1. Origin http://evil.example with valid token -> 403 (GET, POST, OPTIONS)
        for method, path, body in [
            ("GET", "/v1/commands/next?wait_ms=10", None),
            ("POST", "/v1/commands/result", b"{}"),
            ("OPTIONS", "/v1/commands/next", None),
        ]:
            req = urllib.request.Request(
                f"{url}{path}",
                data=body,
                method=method,
                headers={"Origin": "http://evil.example", "X-NetForge-Token": token},
            )
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req, timeout=2.0)
            assert exc.value.code == 403

        # 2. Valid PT origin (pt-sm:) with NO token -> 401
        no_tok_req = urllib.request.Request(
            f"{url}/v1/commands/next?wait_ms=10",
            headers={"Origin": "pt-sm:"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_missing:
            urllib.request.urlopen(no_tok_req, timeout=2.0)
        assert exc_missing.value.code == 401

        # 3. Valid PT origin (pt-sm:) with WRONG token -> 401
        wrong_tok_req = urllib.request.Request(
            f"{url}/v1/commands/next?wait_ms=10",
            headers={"Origin": "pt-sm:", "X-NetForge-Token": "wrong-token-value"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_wrong:
            urllib.request.urlopen(wrong_tok_req, timeout=2.0)
        assert exc_wrong.value.code == 401

        # 4. Only PT origin (pt-sm:) + valid token is accepted -> 204 / 200
        ok_poll = urllib.request.Request(
            f"{url}/v1/commands/next?wait_ms=10",
            headers={"Origin": "pt-sm:", "X-NetForge-Token": token},
        )
        with urllib.request.urlopen(ok_poll, timeout=2.0) as resp:
            assert resp.status == 204
    finally:
        server.stop()
