"""Unit tests for ScriptBridge, BackendRouter, and DeviceConsoleEngine latency optimizations."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from agenticnet.adapters.base import ScriptBackend
from agenticnet.adapters.router import BackendRouter, RoutedConsoleTransport
from agenticnet.adapters.script_bridge import HttpScriptBridgeBackend, HttpScriptBridgeServer
from agenticnet.console.engine import DeviceConsoleEngine
from agenticnet.console.models import CLIPromptMode, DeviceConsoleProfile
from agenticnet.console.transport import ConsoleTransport


@pytest.mark.unit
def test_http_bridge_wait_until_connected_wakes_immediately(tmp_path: Path) -> None:
    session_file = tmp_path / "bridge_session.json"
    server = HttpScriptBridgeServer(session_file=session_file)
    backend = HttpScriptBridgeBackend(server)
    backend.start()
    try:
        assert backend.wait_for_connection(timeout_seconds=0.04) is False

        desc = json.loads(session_file.read_text(encoding="utf-8"))
        stop_evt = threading.Event()
        errors: list[str] = []

        def _delayed_client() -> None:
            time.sleep(0.05)
            req = urllib.request.Request(
                f"{desc['url']}/v1/commands/next?wait_ms=300",
                headers={"Origin": "pt-sm:", "X-NetForge-Token": desc["token"]},
                method="GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    _ = resp.read()
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                if not stop_evt.is_set():
                    errors.append(str(exc))

        t = threading.Thread(target=_delayed_client, daemon=True)
        t.start()
        t0 = time.monotonic()
        connected = backend.wait_for_connection(timeout_seconds=3.0)
        elapsed = time.monotonic() - t0
        stop_evt.set()
        assert connected is True
        assert elapsed < 0.6
        # Active long-poll keeps is_connected() True even before 204 returns
        assert server.is_connected() is True
        t.join(timeout=2.0)
        assert errors == []
    finally:
        backend.stop()

    assert backend.wait_for_connection(timeout_seconds=0.5) is False


@pytest.mark.unit
def test_router_ensure_live_script_avoids_40s_hang_and_uses_cooldown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agenticnet.adapters.router as router_mod

    server = HttpScriptBridgeServer(session_file=tmp_path / "bridge_session.json")
    backend = HttpScriptBridgeBackend(server, auto_launch_pt=True)
    router = BackendRouter(script_backend=backend)

    # Unstarted server fails fast without even probing PT PIDs.
    monkeypatch.setattr(
        router_mod,
        "is_packet_tracer_running",
        lambda: (_ for _ in ()).throw(AssertionError("should not check PT when httpd stopped")),
    )
    assert router.ensure_live_script() is False

    backend.start()
    try:
        monkeypatch.setattr(router_mod, "is_packet_tracer_running", lambda: True)
        wait_calls: list[float] = []
        ensure_calls: list[bool] = []

        def _fake_wait(*, timeout_seconds: float = 15.0) -> bool:
            wait_calls.append(timeout_seconds)
            return False

        def _fake_ensure(*, timeout_seconds: float = 40.0) -> bool:
            _ = timeout_seconds
            ensure_calls.append(True)
            return False

        monkeypatch.setattr(backend, "wait_for_connection", _fake_wait)
        monkeypatch.setattr(backend, "ensure_connected", _fake_ensure)

        assert router.ensure_live_script() is False
        assert len(wait_calls) == 1
        assert wait_calls[0] >= 8.0
        # When PT is already running, ensure_connected() must NOT run redundantly
        assert ensure_calls == []

        # Immediate second call uses cooldown instead of blocking again
        assert router.ensure_live_script() is False
        assert len(wait_calls) == 1

        # Once bridge actually connects, fast path returns True despite cooldown
        monkeypatch.setattr(backend, "is_connected", lambda: True)
        assert router.ensure_live_script() is True
    finally:
        backend.stop()


@pytest.mark.unit
def test_router_defaults_paging_and_unsupported_command_caches() -> None:
    sleeps: list[float] = []

    class _RecordingScriptBackend(ScriptBackend):
        def __init__(self) -> None:
            self.cli_calls: list[tuple[str, list[str], bool]] = []
            self.opened_files: list[str] = []
            self.removed: list[str] = []

        def is_connected(self) -> bool:
            return True

        def ping(self) -> dict[str, Any]:
            return {"ok": True}

        def add_device(
            self,
            model: str,
            *,
            device_type: int | str = 0,
            x: float = 100.0,
            y: float = 100.0,
        ) -> dict[str, Any]:
            return {"ok": True, "device_name": "Router0", "model": model}

        def create_link(
            self,
            device1: str,
            port1: str,
            device2: str,
            port2: str,
            *,
            conn_type: int | str = 8107,
        ) -> dict[str, Any]:
            return {"ok": True}

        def execute_cli(
            self,
            device_name: str,
            commands: list[str],
            *,
            wait_for_prompt: bool = True,
            stop_on_error: bool = False,
            timeout_seconds: float | None = None,
        ) -> dict[str, Any]:
            _ = (wait_for_prompt, timeout_seconds)
            self.cli_calls.append((device_name, list(commands), stop_on_error))
            outputs = [f"OUT:{c}" for c in commands]
            return {
                "ok": True,
                "device_name": device_name,
                "commands": list(commands),
                "raw_output": "\n".join(outputs),
                "command_outputs": outputs,
                "command_statuses": [{"command": c, "status": 0} for c in commands],
                "prompt": "R1#",
                "timed_out": False,
            }

        def open_file(self, path: str, *, timeout_seconds: float = 30.0) -> dict[str, Any]:
            _ = timeout_seconds
            self.opened_files.append(path)
            return {"ok": True, "path": path, "is_activity_file": False}

        def remove_device(
            self, device_name: str, *, timeout_seconds: float | None = None
        ) -> dict[str, Any]:
            _ = timeout_seconds
            self.removed.append(device_name)
            return {"ok": True, "removed": True, "device_name": device_name}

    sb = _RecordingScriptBackend()
    router = BackendRouter(script_backend=sb, sleep_fn=sleeps.append)

    assert router.watch_pace_seconds == 0.0
    assert router.add_device_retry_delays == (0.1, 0.25)

    router.configure_watch_mode(enabled=True)
    assert router.watch_mode is True
    assert router.watch_pace_seconds == 0.0
    router.add_device("R1", "2911")
    assert sleeps == []
    assert router.narration_log

    # First read_show_output disables paging; second skips `terminal length 0`
    _, out1, _, _ = router.read_show_output("R1", "show running-config")
    _, out2, _, _ = router.read_show_output("R1", "show ip route")
    assert out1 == "OUT:show running-config"
    assert out2 == "OUT:show ip route"
    assert sb.cli_calls[0][1] == ["terminal length 0", "show running-config"]
    assert sb.cli_calls[1][1] == ["show ip route"]
    assert "Router0" in router.paging_disabled_devices

    # Unsupported command cache + execute_cli_batch resolve aliases cleanly
    router.mark_cli_command_unsupported("R1", "show telephony-service")
    assert router.is_cli_command_unsupported("R1", "  SHOW TELEPHONY-SERVICE ") is True
    batch_res = router.execute_cli_batch("R1", ["show version", "show ip route"])
    assert batch_res["ok"] is True
    assert sb.cli_calls[-1] == ("Router0", ["show version", "show ip route"], False)

    # remove_device cleans per-device state; open_file clears session caches
    router.remove_device("R1")
    assert "Router0" not in router.paging_disabled_devices
    assert router.is_cli_command_unsupported("Router0", "show telephony-service") is False

    router.mark_cli_command_unsupported("Router0", "show ephone")
    router.open_file("next.pkt")
    assert router.paging_disabled_devices == set()
    assert router.unsupported_cli_commands == {}


@pytest.mark.unit
def test_router_batch_ops_resolves_aliases_and_records_new_ones() -> None:
    class _BatchOpsBackend(ScriptBackend):
        def __init__(self) -> None:
            self.seen_ops: list[list[dict[str, Any]]] = []

        def is_connected(self) -> bool:
            return True

        def ping(self) -> dict[str, Any]:
            return {"ok": True}

        def add_device(
            self, model: str, *, device_type: int | str = 0, x: float = 100.0, y: float = 100.0
        ) -> dict[str, Any]:
            return {"ok": True, "device_name": model}

        def create_link(
            self,
            device1: str,
            port1: str,
            device2: str,
            port2: str,
            *,
            conn_type: int | str = 8107,
        ) -> dict[str, Any]:
            return {"ok": True}

        def execute_cli(
            self,
            device_name: str,
            commands: list[str],
            *,
            wait_for_prompt: bool = True,
            timeout_seconds: float | None = None,
        ) -> dict[str, Any]:
            return {"ok": True, "raw_output": "", "prompt": f"{device_name}#"}

        def batch_ops(
            self, ops: list[dict[str, Any]], *, timeout_seconds: float | None = None
        ) -> dict[str, Any]:
            _ = timeout_seconds
            self.seen_ops.append(ops)
            return {
                "ok": True,
                "results": [
                    {
                        "index": 0,
                        "op": "add_device",
                        "ok": True,
                        "data": {"device_name": "Router1"},
                    },
                    {"index": 1, "op": "create_link", "ok": True, "data": {"linked": True}},
                ],
                "aliases": {},
            }

    sb = _BatchOpsBackend()
    router = BackendRouter(script_backend=sb)
    router.device_aliases["SW_EXIST"] = "Switch9"

    res = router.batch_ops(
        [
            {
                "op": "add_device",
                "params": {"model": "2911", "display_name": "R_NEW", "alias": "R_NEW"},
            },
            {
                "op": "create_link",
                "params": {
                    "device1": "R_NEW",
                    "port1": "Gi0/0",
                    "device2": "SW_EXIST",
                    "port2": "Fa0/1",
                },
            },
        ]
    )
    assert res is not None
    # Top-level alias promoted for PT bridge & pre-existing alias translated
    assert sb.seen_ops[0][0]["alias"] == "R_NEW"
    assert sb.seen_ops[0][1]["params"]["device1"] == "R_NEW"
    assert sb.seen_ops[0][1]["params"]["device2"] == "Switch9"
    assert router.resolve_pt_device_name("R_NEW") == "Router1"


@pytest.mark.unit
def test_routed_transport_preserves_prompt_without_extra_recovery_roundtrips() -> None:
    class _PromptSplitBackend(ScriptBackend):
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def is_connected(self) -> bool:
            return True

        def ping(self) -> dict[str, Any]:
            return {"ok": True}

        def add_device(
            self, model: str, *, device_type: int | str = 0, x: float = 100.0, y: float = 100.0
        ) -> dict[str, Any]:
            return {"ok": True, "device_name": "R1"}

        def create_link(
            self,
            device1: str,
            port1: str,
            device2: str,
            port2: str,
            *,
            conn_type: int | str = 8107,
        ) -> dict[str, Any]:
            return {"ok": True}

        def execute_cli(
            self,
            device_name: str,
            commands: list[str],
            *,
            wait_for_prompt: bool = True,
            timeout_seconds: float | None = None,
        ) -> dict[str, Any]:
            _ = (device_name, wait_for_prompt, timeout_seconds)
            self.calls.append(list(commands))
            return {
                "ok": True,
                "raw_output": "Banner text without trailing prompt",
                "prompt": "R1#",
                "command_statuses": [],
                "timed_out": False,
            }

    sb = _PromptSplitBackend()
    router = BackendRouter(script_backend=sb)
    engine = DeviceConsoleEngine(transport=RoutedConsoleTransport(router))

    opened = engine.open_console("R1", model="2911")
    assert opened["session"]["current_mode"] == CLIPromptMode.PRIVILEGED_EXEC.value
    assert opened["session"]["recoveries_performed"] == 0
    assert len(sb.calls) == 1


@pytest.mark.unit
def test_console_engine_batches_verification_commands_in_single_roundtrip() -> None:
    class _BatchVerifyTransport(ConsoleTransport):
        transport_name = "script_bridge"

        def __init__(self) -> None:
            self.batch_calls: list[tuple[list[str], bool, str | None]] = []

        def is_available(self) -> bool:
            return True

        def can_batch(self) -> bool:
            return True

        def open_device(self, device_name: str, profile: DeviceConsoleProfile) -> str:
            _ = (device_name, profile)
            return "R1>"

        def send_line(self, device_name: str, line: str, *, timeout_s: float = 5.0) -> str:
            _ = (device_name, line, timeout_s)
            return "R1#"

        def read_buffer(self, device_name: str) -> str:
            _ = device_name
            return "R1#"

        def send_batch(
            self,
            device_name: str,
            lines: list[str],
            *,
            stop_on_error: bool = True,
            timeout_s: float = 25.0,
            enable_password: str | None = None,
        ) -> dict[str, Any]:
            _ = (device_name, timeout_s)
            self.batch_calls.append((list(lines), stop_on_error, enable_password))
            if "show ip route" in lines:
                return {
                    "ok": True,
                    "prompt": "R1#",
                    "raw_output": (
                        "R1#end\nR1#show ip int brief\nGi0/0 up\n"
                        "R1#show ip route\nC 10.0.0.0/24\nR1#"
                    ),
                    "command_outputs": ["", "Gi0/0 up\n", "C 10.0.0.0/24\n"],
                    "command_statuses": [{"command": c, "status": 0} for c in lines],
                    "timed_out": False,
                }
            return {
                "ok": True,
                "prompt": "R1(config)#",
                "raw_output": "R1(config)#",
                "command_outputs": ["" for _ in lines],
                "command_statuses": [{"command": c, "status": 0} for c in lines],
                "timed_out": False,
            }

    tr = _BatchVerifyTransport()
    engine = DeviceConsoleEngine(transport=tr)
    rep = engine.execute_commands(
        "R1",
        ["hostname R1"],
        model="2911",
        target_mode="global_config",
        verification_commands=["show ip interface brief", "show ip route"],
        enable_password="cisco",
    )
    assert rep["all_commands_succeeded"] is True
    assert len(tr.batch_calls) == 2
    assert tr.batch_calls[0] == (["enable", "configure terminal", "hostname R1"], True, "cisco")
    assert tr.batch_calls[1] == (
        ["end", "show ip interface brief", "show ip route"],
        False,
        None,
    )
    assert rep["verification_output"]["show ip interface brief"].strip() == "Gi0/0 up"
    assert rep["verification_output"]["show ip route"].strip() == "C 10.0.0.0/24"


@pytest.mark.unit
def test_bridge_js_and_html_optimizations_keep_protocol_invariants() -> None:
    root = Path(__file__).resolve().parents[2]
    js_text = (root / "agenticnet" / "adapters" / "assets" / "netforge_bridge.js").read_text(
        encoding="utf-8"
    )
    html_text = (root / "agenticnet" / "adapters" / "assets" / "bridge.html").read_text(
        encoding="utf-8"
    )

    assert "var IDLE_POLL_INTERVAL_MS = 5000;" in js_text
    assert "setInterval(stepCli, 10)" in js_text
    assert "var stepping = false;" in js_text
    assert "enableRetried" in js_text
    assert "var doneAt = 0;" in js_text
    assert "trailingSlice" in js_text
    assert "opParams.alias" in js_text
    assert "wait_ms=2000" in html_text
    assert "setTimeout(function () { pollOnce(gen); }, 0)" in html_text


class _ColdSwitchScriptBackend(ScriptBackend):
    def __init__(self, *, succeed_on_attempt: int | None) -> None:
        self.succeed_on_attempt = succeed_on_attempt
        self.enable_attempts = 0
        self.cli_calls: list[tuple[str, list[str], bool]] = []

    def is_connected(self) -> bool:
        return True

    def ping(self) -> dict[str, Any]:
        return {"ok": True}

    def add_device(
        self,
        model: str,
        *,
        device_type: int | str = 1,
        x: float = 100.0,
        y: float = 100.0,
    ) -> dict[str, Any]:
        return {"ok": True, "device_name": "Switch0", "model": model}

    def create_link(
        self,
        device1: str,
        port1: str,
        device2: str,
        port2: str,
        *,
        conn_type: int | str = 8107,
    ) -> dict[str, Any]:
        return {"ok": True}

    def execute_cli(
        self,
        device_name: str,
        commands: list[str],
        *,
        wait_for_prompt: bool = True,
        stop_on_error: bool = False,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        _ = (wait_for_prompt, timeout_seconds)
        self.cli_calls.append((device_name, list(commands), stop_on_error))
        if commands == ["enable"] or commands[-1:] == ["enable"]:
            self.enable_attempts += 1
            if (
                self.succeed_on_attempt is not None
                and self.enable_attempts >= self.succeed_on_attempt
            ):
                return {
                    "ok": True,
                    "device_name": device_name,
                    "commands": list(commands),
                    "raw_output": "Switch>enable\nSwitch#",
                    "command_outputs": ["Switch#" if c == "enable" else "" for c in commands],
                    "command_statuses": [{"command": c, "status": 0} for c in commands],
                    "prompt": "Switch#",
                    "timed_out": False,
                }
            return {
                "ok": True,
                "device_name": device_name,
                "commands": list(commands),
                "raw_output": "Press RETURN to get started.\n\nSwitch>",
                "command_outputs": [
                    "Press RETURN to get started.\nSwitch>" if c == "enable" else ""
                    for c in commands
                ],
                "command_statuses": [{"command": c, "status": 0} for c in commands],
                "prompt": "Switch>",
                "timed_out": False,
            }

        outputs = ["Switch(config)#" for _ in commands]
        return {
            "ok": True,
            "device_name": device_name,
            "commands": list(commands),
            "raw_output": "\n".join(outputs),
            "command_outputs": outputs,
            "command_statuses": [{"command": c, "status": 0} for c in commands],
            "prompt": "Switch(config)#",
            "timed_out": False,
        }

    def open_file(self, path: str, *, timeout_seconds: float = 30.0) -> dict[str, Any]:
        _ = (path, timeout_seconds)
        return {"ok": True}

    def remove_device(
        self, device_name: str, *, timeout_seconds: float | None = None
    ) -> dict[str, Any]:
        _ = (device_name, timeout_seconds)
        return {"ok": True}


@pytest.mark.unit
def test_console_engine_preflight_recovers_cold_switch_press_return_before_config() -> None:
    sb = _ColdSwitchScriptBackend(succeed_on_attempt=2)
    router = BackendRouter(script_backend=sb)
    transport = RoutedConsoleTransport(router)
    engine = DeviceConsoleEngine(transport=transport)

    rep = engine.execute_commands(
        "Switch0",
        ["vlan 10", "no shutdown"],
        model="2960-24TT",
        target_mode="global_config",
    )
    assert rep["all_commands_succeeded"] is True
    assert rep["session"]["recoveries_performed"] >= 1
    assert sb.enable_attempts == 2
    assert len(sb.cli_calls) == 3
    assert sb.cli_calls[0][1] == ["enable"]
    assert sb.cli_calls[1][1] == ["", "enable"]
    assert sb.cli_calls[2] == ("Switch0", ["configure terminal", "vlan 10", "no shutdown"], True)
    # Config commands must never be dispatched during preflight while still at Switch>
    assert all(
        "vlan 10" not in cmds and "no shutdown" not in cmds
        for _, cmds, _ in sb.cli_calls[:2]
    )

    # Subsequent execution on the already-open Switch0 skips redundant preflight
    rep2 = engine.execute_commands(
        "Switch0",
        ["interface vlan 10", "no shutdown"],
        model="2960-24TT",
        target_mode="global_config",
    )
    assert rep2["all_commands_succeeded"] is True
    assert len(sb.cli_calls) == 4
    assert sb.cli_calls[3][1] == ["interface vlan 10", "no shutdown"]


@pytest.mark.unit
def test_console_engine_preflight_aborts_cleanly_if_stuck_in_user_exec() -> None:
    sb = _ColdSwitchScriptBackend(succeed_on_attempt=None)
    router = BackendRouter(script_backend=sb)
    transport = RoutedConsoleTransport(router)
    engine = DeviceConsoleEngine(transport=transport)

    rep = engine.execute_commands(
        "Switch0",
        ["no shutdown"],
        model="2960-24TT",
        target_mode="global_config",
    )
    assert rep["all_commands_succeeded"] is False
    assert rep["failed_commands"] == ["enable"]
    assert any(
        d["code"] == "PRIVILEGE_ESCALATION_FAILED"
        for t in rep["transcripts"]
        for d in t["diagnostics"]
    )
    assert sb.enable_attempts == 3
    # Dangerous config line must never be sent to PT when Switch> cannot elevate
    assert all("no shutdown" not in cmds for _, cmds, _ in sb.cli_calls)


@pytest.mark.unit
def test_console_engine_does_not_revert_mode_on_empty_prompt_and_empty_trailing_output() -> None:
    class _EmptyTrailingOutputBackend(_ColdSwitchScriptBackend):
        def execute_cli(
            self,
            device_name: str,
            commands: list[str],
            *,
            wait_for_prompt: bool = True,
            stop_on_error: bool = False,
            timeout_seconds: float | None = None,
        ) -> dict[str, Any]:
            _ = (wait_for_prompt, timeout_seconds)
            self.cli_calls.append((device_name, list(commands), stop_on_error))
            if commands == ["enable"]:
                return {
                    "ok": True,
                    "device_name": device_name,
                    "commands": ["enable"],
                    "raw_output": "Router0#",
                    "command_outputs": ["Router0#"],
                    "command_statuses": [{"command": "enable", "status": 0}],
                    "prompt": "Router0#",
                    "timed_out": False,
                }
            if commands == ["exit", "end", "write memory"]:
                # Simulate PT bridge returning empty prompt and trailing `end`/`write memory`
                # with empty slices while `cleaned_out` ends at earlier `Router0(config)#`.
                return {
                    "ok": True,
                    "device_name": device_name,
                    "commands": list(commands),
                    "raw_output": "exit\nRouter0(config)#",
                    "command_outputs": ["exit\nRouter0(config)#", "", ""],
                    "command_statuses": [{"command": c, "status": 0} for c in commands],
                    "prompt": "",
                    "timed_out": False,
                }
            if commands == ["show ip interface brief"]:
                return {
                    "ok": True,
                    "device_name": device_name,
                    "commands": list(commands),
                    "raw_output": "Gi0/0 10.0.0.1 up",
                    "command_outputs": ["Gi0/0 10.0.0.1 up"],
                    "command_statuses": [{"command": c, "status": 0} for c in commands],
                    "prompt": "Router0#",
                    "timed_out": False,
                }
            return super().execute_cli(
                device_name,
                commands,
                wait_for_prompt=wait_for_prompt,
                stop_on_error=stop_on_error,
                timeout_seconds=timeout_seconds,
            )

    sb = _EmptyTrailingOutputBackend(succeed_on_attempt=1)
    router = BackendRouter(script_backend=sb)
    engine = DeviceConsoleEngine(transport=RoutedConsoleTransport(router))

    # Enter global_config cleanly via preflight + first batch
    assert engine.execute_commands(
        "Router0", ["interface Gi0/0"], model="2911", target_mode="global_config"
    )["all_commands_succeeded"] is True

    # Now `exit` -> `end` -> `write memory` returns empty prompt + empty trailing outputs.
    # Session and last transcript MUST stay `privileged_exec`, not revert to `global_config`!
    rep = engine.execute_commands(
        "Router0",
        ["exit", "end", "write memory"],
        model="2911",
        target_mode="preserve",
    )
    assert rep["all_commands_succeeded"] is True
    assert rep["session"]["current_mode"] == "privileged_exec"
    assert rep["transcripts"][-1]["command"] == "write memory"
    assert rep["transcripts"][-1]["mode_after"] == "privileged_exec"

    # Very next `privileged_exec` call must NOT prepend `end` (avoids 60s DNS translate hang)
    sb.cli_calls.clear()
    show_rep = engine.execute_commands(
        "Router0",
        ["show ip interface brief"],
        model="2911",
        target_mode="privileged_exec",
    )
    assert show_rep["all_commands_succeeded"] is True
    assert sb.cli_calls == [("Router0", ["show ip interface brief"], True)]


@pytest.mark.unit
def test_console_engine_splits_large_switch_no_shutdown_burst_into_micro_batches() -> None:
    class _BurstSwitchBackend(_ColdSwitchScriptBackend):
        def __init__(self, *, fail_cmd: str | None = None) -> None:
            super().__init__(succeed_on_attempt=1)
            self.fail_cmd = fail_cmd

        def execute_cli(
            self,
            device_name: str,
            commands: list[str],
            *,
            wait_for_prompt: bool = True,
            stop_on_error: bool = False,
            timeout_seconds: float | None = None,
        ) -> dict[str, Any]:
            _ = (wait_for_prompt, timeout_seconds)
            self.cli_calls.append((device_name, list(commands), stop_on_error))
            if commands == ["enable"]:
                return {
                    "ok": True,
                    "device_name": device_name,
                    "commands": ["enable"],
                    "raw_output": "Switch0#",
                    "command_outputs": ["Switch0#"],
                    "command_statuses": [{"command": "enable", "status": 0}],
                    "prompt": "Switch0#",
                    "timed_out": False,
                }
            if self.fail_cmd and self.fail_cmd in commands:
                idx_fail = commands.index(self.fail_cmd)
                kept = commands[: idx_fail + 1]
                return {
                    "ok": True,
                    "device_name": device_name,
                    "commands": list(commands),
                    "raw_output": "% Invalid input detected at '^' marker.",
                    "command_outputs": [""] * idx_fail + ["% Invalid input"],
                    "command_statuses": [
                        {"command": c, "status": 2 if i == idx_fail else 0}
                        for i, c in enumerate(kept)
                    ],
                    "stopped_on_error": stop_on_error,
                    "prompt": "Switch0(config)#",
                    "timed_out": False,
                }
            prompt = "" if commands[-1] == "write memory" else "Switch0(config)#"
            outs = ["" if c in {"end", "write memory"} else f"{prompt} {c}" for c in commands]
            return {
                "ok": True,
                "device_name": device_name,
                "commands": list(commands),
                "raw_output": "Switch0(config)#" if not prompt else "\n".join(outs),
                "command_outputs": outs,
                "command_statuses": [{"command": c, "status": 0} for c in commands],
                "prompt": prompt,
                "timed_out": False,
            }

    sleeps: list[float] = []
    sb = _BurstSwitchBackend()
    router = BackendRouter(script_backend=sb, sleep_fn=sleeps.append)
    engine = DeviceConsoleEngine(transport=RoutedConsoleTransport(router))

    switch_cmds = [
        "vlan 10",
        "name DATA",
        "exit",
        "vlan 20",
        "name VOICE",
        "exit",
        "interface FastEthernet0/1",
        "switchport mode trunk",
        "no shutdown",
        "exit",
        "interface range FastEthernet0/2-3",
        "switchport mode access",
        "switchport access vlan 10",
        "switchport voice vlan 20",
        "spanning-tree portfast",
        "no shutdown",
        "exit",
        "interface range FastEthernet0/4-5",
        "switchport mode access",
        "switchport access vlan 10",
        "switchport voice vlan 20",
        "spanning-tree portfast",
        "no shutdown",
        "exit",
        "end",
        "write memory",
    ]

    rep = engine.execute_commands(
        "Switch0",
        switch_cmds,
        model="2960-24TT",
        target_mode="global_config",
    )
    assert rep["all_commands_succeeded"] is True
    assert rep["session"]["current_mode"] == "privileged_exec"
    assert sb.cli_calls[0][1] == ["enable"]
    config_batches = [cmds for _, cmds, _ in sb.cli_calls[1:]]
    assert len(config_batches) == 4
    assert config_batches[0][-2:] == ["no shutdown", "exit"]
    assert config_batches[1][0] == "interface range FastEthernet0/2-3"
    assert config_batches[2][0] == "interface range FastEthernet0/4-5"
    assert config_batches[3] == ["end", "write memory"]
    assert all(len(b) <= 12 for b in config_batches)
    assert len(sleeps) == 3

    # If a sub-chunk fails with stop_on_error=True, later micro-batches are skipped, not sent
    sleeps.clear()
    sb_err = _BurstSwitchBackend(fail_cmd="switchport mode trunk")
    router_err = BackendRouter(script_backend=sb_err, sleep_fn=sleeps.append)
    eng_err = DeviceConsoleEngine(transport=RoutedConsoleTransport(router_err))
    err_rep = eng_err.execute_commands(
        "Switch0",
        switch_cmds,
        model="2960-24TT",
        target_mode="global_config",
        stop_on_error=True,
    )
    assert err_rep["all_commands_succeeded"] is False
    assert err_rep["failed_commands"] == ["switchport mode trunk"]
    # Preflight + chunk 0 only; chunks 1..3 must NOT be sent
    assert len(sb_err.cli_calls) == 2
    assert err_rep["transcripts"][-1]["command"] == "write memory"
    assert err_rep["transcripts"][-1]["diagnostics"][0]["code"] == "SKIPPED_AFTER_ERROR"
