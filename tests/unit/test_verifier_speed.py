"""Unit tests for verifier, lab_runner, and connectivity_test latency optimizations."""

from __future__ import annotations

import asyncio
import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from agenticnet.adapters.router import BackendRouter, RoutedConsoleTransport
from agenticnet.adapters.script_bridge import HttpScriptBridgeBackend, HttpScriptBridgeServer
from agenticnet.console.engine import DeviceConsoleEngine
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.diagnostics.lab_runner import (
    _apply_batch_build,
    evaluate_lab_status,
    start_lab_session,
)
from agenticnet.diagnostics.verifier import LabVerifier
from agenticnet.mcp.server import create_mcp_server
from agenticnet.simulation.parsers import parse_ipconfig_all


def _call_tool_sync(server: Any, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    res = asyncio.run(server.call_tool(name, args or {}))
    assert res.structured_content is not None
    return dict(res.structured_content)


class _BridgeHarness:
    """In-process Packet Tracer HTTP bridge client for testing batching & timings."""

    def __init__(
        self,
        tmp_path: Path,
        cli_handler: Callable[[str, list[str], dict[str, Any]], dict[str, Any]],
    ) -> None:
        self.session_file = tmp_path / "bridge_session.json"
        self.bridge_server = HttpScriptBridgeServer(session_file=self.session_file)
        self.backend = HttpScriptBridgeBackend(self.bridge_server)
        self.cli_handler = cli_handler
        self.stop_evt = threading.Event()
        self.poller: threading.Thread | None = None
        self.cli_calls: list[dict[str, Any]] = []
        self.activity_calls = 0
        self._lock = threading.Lock()
        self._active_per_device: dict[str, int] = {}
        self.concurrent_collisions: list[str] = []

    def __enter__(self) -> _BridgeHarness:
        self.backend.start()
        desc = json.loads(self.session_file.read_text(encoding="utf-8"))
        url = desc["url"]
        token = desc["token"]
        headers = {
            "Origin": "pt-sm:",
            "X-NetForge-Token": token,
            "Content-Type": "application/json",
        }

        def _poll() -> None:
            while not self.stop_evt.is_set():
                try:
                    req = urllib.request.Request(
                        f"{url}/v1/commands/next?wait_ms=80",
                        headers={"Origin": "pt-sm:", "X-NetForge-Token": token},
                    )
                    with urllib.request.urlopen(req, timeout=2.0) as resp:
                        if resp.status == 204:
                            continue
                        wire = json.loads(resp.read().decode("utf-8"))
                        cmd = wire["command"]
                except (
                    urllib.error.URLError,
                    TimeoutError,
                    OSError,
                    json.JSONDecodeError,
                    KeyError,
                ):
                    continue

                op = cmd["opcode"]
                params = cmd.get("params", {})
                ok = True
                err: str | None = None
                data: dict[str, Any] = {}
                if op == "cli_exec":
                    dev = str(params["device_name"])
                    cmds = [str(c) for c in params["commands"]]
                    with self._lock:
                        cur = self._active_per_device.get(dev, 0) + 1
                        self._active_per_device[dev] = cur
                        if cur > 1:
                            self.concurrent_collisions.append(dev)
                        self.cli_calls.append(
                            {
                                "device": dev,
                                "commands": cmds,
                                "stop_on_error": params.get("stop_on_error"),
                            }
                        )
                    try:
                        out = self.cli_handler(dev, cmds, params)
                        ok = bool(out.pop("_ok", True))
                        err = out.pop("_error", None)
                        data = out
                    finally:
                        with self._lock:
                            self._active_per_device[dev] -= 1
                elif op == "get_activity_status":
                    self.activity_calls += 1
                    data = {
                        "is_activity_file": False,
                        "state": "not_activity",
                        "readable": False,
                    }
                elif op == "list_devices":
                    data = {"device_count": 0, "link_count": 0, "devices": [], "links": []}
                elif op == "batch_ops":
                    results = []
                    aliases = {}
                    for oi, item in enumerate(params.get("ops", [])):
                        if item["op"] == "add_device":
                            alias = item["alias"]
                            aliases[alias] = alias
                            results.append(
                                {
                                    "index": oi,
                                    "op": "add_device",
                                    "alias": alias,
                                    "ok": True,
                                    "data": {"device_name": alias},
                                    "error": None,
                                }
                            )
                        else:
                            results.append(
                                {
                                    "index": oi,
                                    "op": item["op"],
                                    "alias": None,
                                    "ok": True,
                                    "data": {"ok": True},
                                    "error": None,
                                }
                            )
                    data = {"results": results, "aliases": aliases}

                payload = json.dumps(
                    {"request_id": cmd["request_id"], "ok": ok, "data": data, "error": err}
                ).encode("utf-8")
                post = urllib.request.Request(
                    f"{url}/v1/commands/result",
                    data=payload,
                    headers=headers,
                    method="POST",
                )
                with suppress(Exception):
                    urllib.request.urlopen(post, timeout=2.0).close()

        self.poller = threading.Thread(target=_poll, daemon=True)
        self.poller.start()
        deadline = time.monotonic() + 3.0
        while not self.backend.is_connected() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert self.backend.is_connected()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop_evt.set()
        if self.poller is not None:
            self.poller.join(timeout=2.0)
        self.backend.stop()


@pytest.mark.unit
def test_verifier_batches_per_device_via_command_outputs(tmp_path: Path) -> None:
    def _cli(dev: str, cmds: list[str], _params: dict[str, Any]) -> dict[str, Any]:
        canned = {
            ("Router0", "show ip interface brief"): (
                "Interface              IP-Address      OK? Method Status                Protocol\n"
                "GigabitEthernet0/0     10.0.0.1        YES manual up                    up\n"
            ),
            ("Router0", "show ip route"): "S    10.20.0.0/24 [1/0] via 10.0.0.2\n",
            ("Router0", "show ip dhcp binding"): (
                "IP address       Client-ID/              Lease expiration        Type\n"
                "192.168.10.11    0001.4255.89A1          --                      Automatic\n"
            ),
            ("Router0", "show running-config"): (
                "hostname Router0\n!\ninterface GigabitEthernet0/0\n"
                " ip address 10.0.0.1 255.255.255.0\n!\n"
            ),
            ("Router0", "show ephone"): (
                "ephone-1 Mac:0001.64A1.2233 REGISTERED\n"
                "IP:192.168.10.11 * 1024 7960\n"
                "button 1: dn 1 number 1001 CH1 IDLE\n"
            ),
            ("Router0", "ping 192.168.10.11"): (
                "Sending 5, 100-byte ICMP Echos to 192.168.10.11:\n"
                "!!!!!\nSuccess rate is 100 percent (5/5)\n"
            ),
            ("Switch0", "show vlan brief"): (
                "VLAN Name                             Status    Ports\n"
                "---- -------------------------------- --------- -------------------------------\n"
                "10   VOICE                            active    Fa0/2\n"
            ),
            ("Switch0", "show interfaces trunk"): (
                "Port        Mode         Encapsulation  Status        Native vlan\n"
                "Fa0/1       on           802.1q         trunking      1\n\n"
                "Port        Vlans allowed on trunk\n"
                "Fa0/1       1,10,20\n"
            ),
            ("Switch0", "show spanning-tree"): (
                "VLAN0010\n  Spanning tree enabled protocol rstp\n"
                "  Root ID    Priority    24586\n"
                "             Address     0001.42AA.1111\n"
                "             This bridge is the root\n"
            ),
        }
        outputs = [canned.get((dev, c), "% Invalid input detected\n") for c in cmds]
        statuses = [{"command": c, "status": 0, "non_fatal": False} for c in cmds]
        return {
            "device_name": dev,
            "prompt": f"{dev}#",
            "mode": "enable",
            "raw_output": "\n".join(outputs),
            "command_outputs": outputs,
            "command_statuses": statuses,
            "timed_out": False,
        }

    with _BridgeHarness(tmp_path, _cli) as h:
        router = BackendRouter(script_backend=h.backend)
        reqs = [
            {"type": "interface_up", "device": "Router0", "interface": "Gi0/0"},
            {"type": "ip_assigned", "device": "Router0", "interface": "Gi0/0", "ip": "10.0.0.1"},
            {"type": "route_exists", "device": "Router0", "network": "10.20.0.0/24"},
            {"type": "dhcp_binding", "device": "Router0", "ip": "192.168.10.11"},
            {
                "type": "config_contains",
                "device": "Router0",
                "section": "interface GigabitEthernet0/0",
                "contains": ["ip address 10.0.0.1 255.255.255.0"],
            },
            {"type": "ephone_registered", "device": "Router0", "ephone_id": 1, "number": "1001"},
            {"type": "reachable", "from": "Router0", "to": "192.168.10.11"},
            {"type": "vlan_exists", "device": "Switch0", "vlan_id": 10, "ports": ["Fa0/2"]},
            {
                "type": "trunk_exists",
                "device": "Switch0",
                "interface": "Fa0/1",
                "allowed_vlans": [10, 20],
            },
            {"type": "stp_root", "device": "Switch0", "vlan_id": 10, "expect_root": True},
        ]
        rep = LabVerifier(router).verify(reqs, include_activity_grade=True)
        assert rep["passed"] is True
        assert rep["verified_live"] is True
        assert rep["state_level"] == "verified"
        assert rep["summary"] == {"total": 10, "passed": 10, "failed": 0, "errors": 0}
        # Only 1 HTTP cli_exec round-trip per device!
        rtr_calls = [c for c in h.cli_calls if c["device"] == "Router0"]
        sw_calls = [c for c in h.cli_calls if c["device"] == "Switch0"]
        assert len(rtr_calls) == 1
        assert len(sw_calls) == 1
        assert rtr_calls[0]["stop_on_error"] is not True
        assert rtr_calls[0]["commands"].count("show ip interface brief") == 1
        assert h.activity_calls == 1
        assert router.active_is_activity is False

        # Second verify_lab skips activity probe since active_is_activity is cached False.
        rep2 = LabVerifier(router).verify(reqs[:2], include_activity_grade=True)
        assert rep2["passed"] is True
        assert h.activity_calls == 1


@pytest.mark.unit
def test_verifier_remembers_unsupported_telephony_service(tmp_path: Path) -> None:
    state = {"ephone_calls": 0, "telephony_calls": 0}

    def _cli(dev: str, cmds: list[str], _params: dict[str, Any]) -> dict[str, Any]:
        outputs: list[str] = []
        statuses: list[dict[str, Any]] = []
        for c in cmds:
            if c == "show telephony-service":
                state["telephony_calls"] += 1
                outputs.append(
                    "show telephony-service\n^\n% Invalid input detected at '^' marker.\nR1#"
                )
                statuses.append({"command": c, "status": 2, "non_fatal": False})
            elif c == "show running-config":
                outputs.append(
                    "hostname R1\n!\ntelephony-service\n max-ephones 5\n max-dn 10\n"
                    " ip source-address 10.50.100.1 port 2000\n!\n"
                )
                statuses.append({"command": c, "status": 0, "non_fatal": False})
            elif c == "show ephone":
                state["ephone_calls"] += 1
                if state["ephone_calls"] < 2:
                    outputs.append("ephone-1 UNREGISTERED\n")
                else:
                    outputs.append(
                        "ephone-1 Mac:0001.64A1.2233 REGISTERED\nbutton 1: dn 1 number 1001\n"
                    )
                statuses.append({"command": c, "status": 0, "non_fatal": False})
            else:
                outputs.append("")
                statuses.append({"command": c, "status": 0, "non_fatal": False})
        return {
            "device_name": dev,
            "prompt": f"{dev}#",
            "raw_output": "\n".join(outputs),
            "command_outputs": outputs,
            "command_statuses": statuses,
            "timed_out": False,
        }

    with _BridgeHarness(tmp_path, _cli) as h:
        router = BackendRouter(script_backend=h.backend)
        router.latest_snapshot = {"devices": [{"name": "R1", "model": "2811", "type": "router"}]}
        verifier = LabVerifier(router)
        reqs = [
            {
                "type": "telephony_service",
                "device": "R1",
                "source_address": "10.50.100.1",
                "source_port": 2000,
            },
            {"type": "ephone_registered", "device": "R1", "ephone_id": 1, "number": "1001"},
        ]
        rep1 = verifier.verify(reqs, poll_interval_seconds=0.02, include_activity_grade=False)
        assert rep1["passed"] is True
        assert state["telephony_calls"] == 1
        assert state["ephone_calls"] == 2
        assert "show running-config" in rep1["results"][0]["command"]

        # Subsequent call on same router skips show telephony-service altogether!
        rep2 = LabVerifier(router).verify([reqs[0]], include_activity_grade=False)
        assert rep2["passed"] is True
        assert state["telephony_calls"] == 1
        assert "show running-config" in rep2["results"][0]["command"]


@pytest.mark.unit
def test_verifier_fails_fast_on_unconvergeable_errors_and_static_config(tmp_path: Path) -> None:
    def _cli(dev: str, cmds: list[str], _params: dict[str, Any]) -> dict[str, Any]:
        if dev == "GhostDevice":
            return {"_ok": False, "_error": f"Device not found: {dev}"}
        outputs = []
        statuses = []
        for c in cmds:
            if c == "show running-config":
                outputs.append("hostname R1\n!\n")
                statuses.append({"command": c, "status": 0, "non_fatal": False})
            else:
                outputs.append("% Invalid input detected at '^' marker.\n")
                statuses.append({"command": c, "status": 2, "non_fatal": False})
        return {
            "device_name": dev,
            "prompt": f"{dev}#",
            "raw_output": "\n".join(outputs),
            "command_outputs": outputs,
            "command_statuses": statuses,
            "timed_out": False,
        }

    with _BridgeHarness(tmp_path, _cli) as h:
        router = BackendRouter(script_backend=h.backend)
        t0 = time.monotonic()
        rep_err = LabVerifier(router).verify(
            [{"type": "interface_up", "device": "GhostDevice", "interface": "Gi0/0"}],
            include_activity_grade=False,
        )
        elapsed_err = time.monotonic() - t0
        assert rep_err["passed"] is False
        assert rep_err["verified_live"] is False
        assert rep_err["results"][0]["status"] == "error"
        assert len(h.cli_calls) == 1  # No retry and no poll loop!
        assert elapsed_err < 1.5

        h.cli_calls.clear()
        t1 = time.monotonic()
        rep_cfg = LabVerifier(router).verify(
            [{"type": "config_contains", "device": "R1", "contains": ["ip routing"]}],
            include_activity_grade=False,
        )
        elapsed_cfg = time.monotonic() - t1
        assert rep_cfg["passed"] is False
        assert rep_cfg["verified_live"] is True
        assert rep_cfg["results"][0]["status"] == "fail"
        assert len(h.cli_calls) == 1  # Static config mismatch did not poll!
        assert elapsed_cfg < 1.5


@pytest.mark.unit
def test_verifier_uses_concise_pc_ping_count(tmp_path: Path) -> None:
    def _cli(dev: str, cmds: list[str], _params: dict[str, Any]) -> dict[str, Any]:
        outputs = [
            "Pinging 10.10.20.1 with 32 bytes of data:\n"
            "Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\n"
            for _ in cmds
        ]
        return {
            "device_name": dev,
            "prompt": "C:\\>",
            "raw_output": "\n".join(outputs),
            "command_outputs": outputs,
            "command_statuses": [{"command": c, "status": 0} for c in cmds],
            "timed_out": False,
        }

    with _BridgeHarness(tmp_path, _cli) as h:
        router = BackendRouter(script_backend=h.backend)
        router.latest_snapshot = {"devices": [{"name": "PC1", "model": "PC-PT", "type": "pc"}]}
        rep = LabVerifier(router).verify(
            [{"type": "reachable", "from": "PC1", "to": "10.10.20.1"}],
            include_activity_grade=False,
        )
        assert rep["passed"] is True
        assert h.cli_calls[0]["commands"] == ["ping -n 2 10.10.20.1"]


@pytest.mark.unit
def test_lab_runner_fast_defaults_and_no_watch_sleeps(tmp_path: Path) -> None:
    def _cli(dev: str, cmds: list[str], _params: dict[str, Any]) -> dict[str, Any]:
        return {
            "device_name": dev,
            "prompt": f"{dev}#",
            "raw_output": "",
            "command_outputs": ["" for _ in cmds],
            "command_statuses": [{"command": c, "status": 0} for c in cmds],
            "timed_out": False,
        }

    with _BridgeHarness(tmp_path, _cli) as h:
        settings = AgenticNetSettings(data_dir=tmp_path / ".nf", tool_profile="solve_lab")
        server, runtime = create_mcp_server(settings, script_backend=h.backend)
        sleeps: list[float] = []
        runtime.router._sleep = lambda sec: sleeps.append(sec)
        _call_tool_sync(server, "project_create", {"name": "fast-runner"})

        started = start_lab_session(
            runtime,
            "Build R1 and SW1 VLAN lab",
            auto_approve=True,
            devices=[
                {"name": "R1", "model": "2811", "x": 100, "y": 100},
                {"name": "SW1", "model": "2960-24TT", "x": 200, "y": 100},
            ],
            links=[
                {
                    "source_device": "R1",
                    "source_interface": "Fa0/0",
                    "target_device": "SW1",
                    "target_interface": "Fa0/1",
                }
            ],
            configs={"R1": ["hostname R1"], "SW1": ["hostname SW1"]},
        )
        assert started["ready"] is True
        assert started["watch_mode"] is True
        assert started["watch_pace_seconds"] == 0.0
        assert sleeps == []

        # evaluate_lab_status skips activity probe when active_is_activity is already False.
        runtime.router.active_is_activity = False
        status = evaluate_lab_status(runtime.router, include_activity_grade=True)
        assert status["grade"]["raw_state"] == "not_activity"
        assert h.activity_calls == 0

        # _apply_batch_build with watch_pace_seconds > 0 still does not pace per device.
        runtime.router.configure_watch_mode(enabled=True, pace_seconds=0.25)
        _apply_batch_build(
            runtime,
            runtime.router,
            configs={"R1": ["end"], "SW1": ["end"]},
        )
        assert sleeps == []


@pytest.mark.unit
def test_connectivity_test_batches_per_source_and_deduplicates(tmp_path: Path) -> None:
    def _cli(dev: str, cmds: list[str], _params: dict[str, Any]) -> dict[str, Any]:
        outputs: list[str] = []
        for c in cmds:
            target = c.split()[-1]
            if dev == "PC1":
                outputs.append(
                    f"Pinging {target} with 32 bytes of data:\n"
                    f"Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\n"
                )
            else:
                outputs.append(
                    f"Sending 5, 100-byte ICMP Echos to {target}:\n"
                    "!!!!!\nSuccess rate is 100 percent (5/5)\n"
                )
        return {
            "device_name": dev,
            "prompt": "C:\\>" if dev == "PC1" else f"{dev}#",
            "raw_output": "\n".join(outputs),
            "command_outputs": outputs,
            "command_statuses": [{"command": c, "status": 0} for c in cmds],
            "timed_out": False,
        }

    with _BridgeHarness(tmp_path, _cli) as h:
        settings = AgenticNetSettings(data_dir=tmp_path / ".nf", tool_profile="solve_lab")
        server, runtime = create_mcp_server(settings, script_backend=h.backend)
        runtime.console = DeviceConsoleEngine(
            transport=RoutedConsoleTransport(runtime.router)
        )
        _call_tool_sync(server, "project_create", {"name": "ping-batch-test"})
        _, topo, _, _ = runtime.manager.require_active()
        topo.add_device("Router0", "2811")
        topo.add_device("PC1", "PC-PT")

        res = _call_tool_sync(
            server,
            "connectivity_test",
            {
                "count": 2,
                "checks": [
                    {"source_device": "Router0", "destination_ip": "192.168.1.2"},
                    {"source_device": "Router0", "destination_ip": "192.168.1.3"},
                    {"source_device": "Router0", "destination_ip": "192.168.1.2"},
                    {"source_device": "PC1", "destination_ip": "192.168.1.1"},
                    {"source_device": "PC1", "destination_ip": "192.168.2.1"},
                ],
            },
        )
        assert res["success"] is True
        assert res["state_level"] == "verified"
        assert res["data"]["total"] == 5
        assert res["data"]["reachable_count"] == 5
        assert res["data"]["all_reachable"] is True
        assert h.concurrent_collisions == []
        rtr_calls = [c for c in h.cli_calls if c["device"] == "Router0"]
        pc_calls = [c for c in h.cli_calls if c["device"] == "PC1"]
        assert len(rtr_calls) == 1
        assert rtr_calls[0]["commands"] == ["ping 192.168.1.2", "ping 192.168.1.3"]
        assert len(pc_calls) == 1
        assert pc_calls[0]["commands"] == ["ping -n 2 192.168.1.1", "ping -n 2 192.168.2.1"]


@pytest.mark.unit
def test_parse_ipconfig_all_handles_pt822_indented_continuations() -> None:
    dual_stack = (
        "FastEthernet0 Connection:(default port)\n\n"
        "   Connection-specific DNS Suffix..:\n"
        "   Physical Address................: 0001.4259.E48E\n"
        "   Link-local IPv6 Address.........: FE80::201:42FF:FE59:E48E\n"
        "   IPv6 Address....................: ::\n"
        "   IPv4 Address....................: 192.168.100.10\n"
        "   Subnet Mask.....................: 255.255.255.0\n"
        "   Default Gateway.................: ::\n"
        "                                     192.168.100.1\n"
        "   DHCP Servers....................: 0.0.0.0\n"
        "   DNS Servers.....................: ::\n"
        "                                     8.8.8.8\n"
        "                                     1.1.1.1\n"
    )
    parsed = parse_ipconfig_all(dual_stack)
    assert len(parsed) == 1
    assert parsed[0].ipv4_address == "192.168.100.10"
    assert parsed[0].subnet_mask == "255.255.255.0"
    assert parsed[0].default_gateway == "192.168.100.1"
    assert parsed[0].dns_servers == ["8.8.8.8", "1.1.1.1"]

    v6_only_gw = (
        "FastEthernet0 Connection:(default port)\n"
        "   Default Gateway.................: 2001:db8::1\n"
        "                                     0.0.0.0\n"
        "   DNS Servers.....................: ::\n"
        "                                     0.0.0.0\n"
    )
    parsed_v6 = parse_ipconfig_all(v6_only_gw)
    assert len(parsed_v6) == 1
    assert parsed_v6[0].default_gateway == "2001:db8::1"
    assert parsed_v6[0].dns_servers == ["::", "0.0.0.0"]
