"""Targeted offline tests for stability bugfixes and latency optimizations."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from agenticnet.adapters.base import ScriptBackend
from agenticnet.adapters.router import BackendRouter, RoutedConsoleTransport
from agenticnet.adapters.script_bridge import (
    HttpScriptBridgeBackend,
    HttpScriptBridgeServer,
    ScriptBridgeError,
)
from agenticnet.console.engine import DeviceConsoleEngine, _compute_batch_timeout
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.diagnostics.rules import check_missing_default_gateways
from agenticnet.diagnostics.verifier import LabVerifier
from agenticnet.mcp.server import create_mcp_server
from agenticnet.topology.engine import TopologyEngine


def _call_tool_sync(server: Any, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    res = asyncio.run(server.call_tool(name, args or {}))
    assert res.structured_content is not None
    return dict(res.structured_content)


class _FlakyDeviceAndLinkBackend(ScriptBackend):
    def __init__(self) -> None:
        self.add_calls = 0
        self.reject_link = True
        self.host_calls: list[dict[str, Any]] = []
        self.cli_calls: list[tuple[str, list[str]]] = []
        self.unsupported_configure_host = False
        self.activity_calls = 0

    def is_connected(self) -> bool:
        return True

    def ping(self) -> dict[str, Any]:
        return {"ok": True}

    def capabilities(self) -> set[str]:
        return {
            "add_device",
            "create_link",
            "configure_host",
            "execute_cli",
            "open_file",
            "save_file",
            "list_devices",
            "read_activity_status",
        }

    def add_device(
        self, model: str, *, device_type: int = 0, x: float = 100.0, y: float = 100.0
    ) -> dict[str, Any]:
        self.add_calls += 1
        raise ScriptBridgeError("addDevice returned empty name for Laptop-PT")

    def create_link(
        self,
        device1: str,
        port1: str,
        device2: str,
        port2: str,
        *,
        conn_type: int = 8106,
    ) -> dict[str, Any]:
        if self.reject_link:
            return {"ok": False, "error": "createLink returned false"}
        return {"ok": True}

    def configure_host(
        self,
        device_name: str,
        *,
        port: str = "FastEthernet0",
        dhcp: bool = False,
        ip: str | None = None,
        subnet_mask: str | None = None,
        default_gateway: str | None = None,
    ) -> dict[str, Any]:
        self.host_calls.append(
            {
                "device_name": device_name,
                "port": port,
                "dhcp": dhcp,
                "ip": ip,
                "subnet_mask": subnet_mask,
                "default_gateway": default_gateway,
            }
        )
        if self.unsupported_configure_host:
            raise ScriptBridgeError("Unsupported opcode: configure_host")
        return {"ok": True, "device_name": device_name, "dhcp": dhcp, "ip": ip}

    def execute_cli(
        self, device_name: str, commands: list[str], *, timeout_seconds: float = 25.0
    ) -> dict[str, Any]:
        self.cli_calls.append((device_name, list(commands)))
        return {
            "ok": True,
            "device_name": device_name,
            "prompt": "C:\\>" if any("ipconfig" in c for c in commands) else "R1#",
            "mode": "pc" if any("ipconfig" in c for c in commands) else "enable",
            "raw_output": (
                "Interface              IP-Address      OK? Method Status                Protocol\n"
                "GigabitEthernet0/0     10.0.0.1        YES manual up                    up\n"
            ),
            "command_statuses": [
                {"command": c, "status": 0, "non_fatal": False} for c in commands
            ],
            "timed_out": False,
        }

    def open_file(self, path: str, *, timeout_seconds: float = 30.0) -> dict[str, Any]:
        return {"ok": True, "path": path, "is_activity_file": False}

    def save_file(
        self, path: str | None = None, *, overwrite: bool = True, timeout_seconds: float = 30.0
    ) -> dict[str, Any]:
        return {"ok": True, "saved_filename": path or "lab.pkt"}

    def list_devices(self, *, timeout_seconds: float = 30.0) -> dict[str, Any]:
        return {"ok": True, "devices": [], "links": []}

    def read_activity_status(self) -> dict[str, Any]:
        self.activity_calls += 1
        return {"ok": True, "state": "available", "readable": True, "percentage_complete": 0.0}


def _make_runtime_server(tmp_path: Path, backend: ScriptBackend) -> tuple[Any, Any]:
    settings = AgenticNetSettings(data_dir=tmp_path / "data", tool_profile="advanced")
    server, runtime = create_mcp_server(settings)
    runtime.router = BackendRouter(
        script_backend=backend,
        add_device_retry_delays=(0.0, 0.0),
        sleep_fn=lambda _s: None,
    )
    runtime.console = DeviceConsoleEngine(transport=RoutedConsoleTransport(runtime.router))
    _call_tool_sync(server, "project_create", {"name": "bugfix-test"})
    return server, runtime


@pytest.mark.unit
def test_device_add_retries_and_rolls_back_offline_topology_on_pt_failure(tmp_path: Path) -> None:
    backend = _FlakyDeviceAndLinkBackend()
    server, runtime = _make_runtime_server(tmp_path, backend)

    res = _call_tool_sync(
        server, "device_add", {"name": "Laptop0", "model": "Laptop-PT", "x": 100, "y": 200}
    )
    assert res["success"] is False
    assert res["errors"][0]["error_code"] == "PT_EMPTY_DEVICE_NAME"
    assert backend.add_calls == 3  # initial + 2 retries
    assert "Laptop0" not in runtime.router.device_aliases

    _, topo, _, _ = runtime.manager.require_active()
    assert "Laptop0" not in topo.model.devices


@pytest.mark.unit
def test_connection_create_rolls_back_offline_link_on_pt_rejection(tmp_path: Path) -> None:
    backend = _FlakyDeviceAndLinkBackend()
    server, runtime = _make_runtime_server(tmp_path, backend)
    _, topo, _, _ = runtime.manager.require_active()
    topo.add_device("R1", "2911")
    topo.add_device("SW1", "2960-24TT")

    res = _call_tool_sync(
        server,
        "connection_create",
        {
            "source_device": "R1",
            "source_interface": "GigabitEthernet0/0",
            "target_device": "SW1",
            "target_interface": "FastEthernet0/1",
        },
    )
    assert res["success"] is False
    assert res["errors"][0]["error_code"] == "PT_LINK_FAILED"
    assert len(topo.model.connections) == 0


@pytest.mark.unit
def test_host_configure_ipc_and_ipconfig_cli_fallback(tmp_path: Path) -> None:
    backend = _FlakyDeviceAndLinkBackend()
    server, runtime = _make_runtime_server(tmp_path, backend)
    _, topo, _, _ = runtime.manager.require_active()
    topo.add_device("PC0", "PC-PT")

    res_ipc = _call_tool_sync(
        server,
        "host_configure",
        {
            "device_name": "PC0",
            "ip_address": "12.0.0.2",
            "subnet_mask": "255.0.0.0",
            "default_gateway": "12.0.0.1",
        },
    )
    assert res_ipc["success"] is True
    assert backend.host_calls[-1]["ip"] == "12.0.0.2"
    assert topo.model.devices["PC0"].interfaces["FastEthernet0"].ip_address == "12.0.0.2"
    assert topo.model.devices["PC0"].interfaces["FastEthernet0"].default_gateway == "12.0.0.1"

    # Simulate older .pts lacking configure_host -> falls back to `ipconfig /renew`.
    backend.unsupported_configure_host = True
    res_fb = _call_tool_sync(
        server, "host_configure", {"device_name": "PC0", "dhcp": True}
    )
    assert res_fb["success"] is True
    assert any("ipconfig /renew" in cmds for _dev, cmds in backend.cli_calls)


@pytest.mark.unit
def test_batch_timeout_scales_and_gateway_repair_uses_valid_pt_syntax() -> None:
    fast_budget = _compute_batch_timeout(20.0, ["show ip route", "show version"])
    ping_budget = _compute_batch_timeout(
        20.0,
        ["ping 192.168.1.2", "ping 192.168.2.2", "ipconfig /renew"],
    )
    assert ping_budget >= fast_budget + 29.0

    topo = TopologyEngine()
    pc = topo.add_device("PC0", "PC-PT")
    pc.interfaces["FastEthernet0"].ip_address = "192.168.1.10"
    pc.interfaces["FastEthernet0"].subnet_mask = "255.255.255.0"
    pc.interfaces["FastEthernet0"].default_gateway = None

    findings = check_missing_default_gateways(topo)
    assert len(findings) == 1
    _finding, repair = findings[0]
    cmd = repair.actions[0].command_sequence[0]
    assert "/gateway" not in cmd
    assert cmd == "ipconfig 192.168.1.10 255.255.255.0 192.168.1.1"


@pytest.mark.unit
def test_open_clears_aliases_and_skips_activity_probe_on_non_pka_verify(tmp_path: Path) -> None:
    backend = _FlakyDeviceAndLinkBackend()
    server, runtime = _make_runtime_server(tmp_path, backend)
    runtime.router.device_aliases["R1"] = "OldRouter0"
    runtime.router.initial_snapshot = {
        "device_count": 0,
        "link_count": 0,
        "devices": [],
        "links": [],
        "cli_log": {},
    }

    opened = _call_tool_sync(server, "lab_open", {"path": str(tmp_path / "sample.pkt")})
    assert opened["success"] is True
    assert runtime.router.device_aliases == {}
    assert runtime.router.active_is_activity is False

    report = LabVerifier(runtime.router).verify(
        {
            "lab_name": "pkt-only",
            "requirements": [
                {"type": "interface_up", "device": "R1", "interface": "GigabitEthernet0/0"}
            ],
        },
        include_activity_grade=True,
    )
    assert report["passed"] is True
    assert backend.activity_calls == 0
    assert report["activity_grade"]["is_activity"] is False

    saved_fast = _call_tool_sync(
        server, "lab_save", {"path": str(tmp_path / "out.pkt"), "include_diff": False}
    )
    assert saved_fast["success"] is True
    assert "lab_diff" not in saved_fast["data"]


@pytest.mark.unit
def test_parallel_batch_cli_batch_build_and_verifier_over_http_bridge(tmp_path: Path) -> None:
    import json
    import threading
    import urllib.error
    import urllib.request
    from contextlib import suppress

    from agenticnet.diagnostics.lab_runner import _apply_batch_build

    session_file = tmp_path / "bridge_session.json"
    bridge_server = HttpScriptBridgeServer(session_file=session_file)
    bridge_backend = HttpScriptBridgeBackend(bridge_server)
    bridge_backend.start()

    stop_evt = threading.Event()
    seen_opcodes: list[str] = []
    seen_conn_types: list[int] = []

    def _poll_loop() -> None:
        desc = json.loads(session_file.read_text(encoding="utf-8"))
        url = desc["url"]
        token = desc["token"]
        headers = {
            "Origin": "pt-sm:",
            "X-NetForge-Token": token,
            "Content-Type": "application/json",
        }
        while not stop_evt.is_set():
            try:
                req = urllib.request.Request(
                    f"{url}/v1/commands/next?wait_ms=100",
                    headers={"Origin": "pt-sm:", "X-NetForge-Token": token},
                )
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    if resp.status == 204:
                        continue
                    wire = json.loads(resp.read().decode("utf-8"))
                    cmd = wire["command"]
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, KeyError):
                continue

            op = cmd["opcode"]
            seen_opcodes.append(op)
            params = cmd.get("params", {})
            data: dict[str, Any] = {}
            if op == "batch_ops":
                results = []
                aliases = {}
                for oi, item in enumerate(params.get("ops", [])):
                    if item["op"] == "add_device":
                        alias = item["alias"]
                        pt_name = f"Router{oi}"
                        aliases[alias] = pt_name
                        results.append(
                            {
                                "index": oi,
                                "op": "add_device",
                                "alias": alias,
                                "ok": True,
                                "data": {"device_name": pt_name},
                                "error": None,
                            }
                        )
                    else:
                        if item["op"] == "create_link":
                            seen_conn_types.append(int(item["params"]["conn_type"]))
                        results.append(
                            {
                                "index": oi,
                                "op": item["op"],
                                "alias": None,
                                "ok": True,
                                "data": {"linked": True},
                                "error": None,
                            }
                        )
                data = {"results": results, "aliases": aliases}
            elif op == "cli_exec":
                dev = params["device_name"]
                cmds = params["commands"]
                data = {
                    "device_name": dev,
                    "prompt": f"{dev}#",
                    "mode": "enable",
                    "raw_output": (
                        f"{dev}#show ip interface brief\n"
                        "Interface              IP-Address      OK? Method Status"
                        "                Protocol\n"
                        "GigabitEthernet0/0     10.0.0.1        YES manual up"
                        "                    up\n"
                        f"{dev}#"
                    ),
                    "command_statuses": [
                        {"command": c, "status": 0, "non_fatal": False} for c in cmds
                    ],
                    "timed_out": False,
                }
            payload = json.dumps(
                {"request_id": cmd["request_id"], "ok": True, "data": data, "error": None}
            ).encode("utf-8")
            post = urllib.request.Request(
                f"{url}/v1/commands/result",
                data=payload,
                headers=headers,
                method="POST",
            )
            with suppress(Exception):
                urllib.request.urlopen(post, timeout=2.0).close()

    poller = threading.Thread(target=_poll_loop, daemon=True)
    poller.start()
    try:
        # Wait briefly until poller registers heartbeat on /v1/commands/next.
        import time

        deadline = time.monotonic() + 3.0
        while not bridge_backend.is_connected() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert bridge_backend.is_connected()

        server, runtime = _make_runtime_server(tmp_path, bridge_backend)
        build_res = _apply_batch_build(
            runtime,
            runtime.router,
            devices=[
                {"name": "R1", "model": "2911", "x": 100, "y": 100},
                {"name": "R2", "model": "2911", "x": 300, "y": 100},
            ],
            links=[
                {
                    "source_device": "R1",
                    "source_interface": "GigabitEthernet0/0",
                    "target_device": "R2",
                    "target_interface": "GigabitEthernet0/0",
                }
            ],
            configs={"R1": ["hostname R1"], "R2": ["hostname R2"]},
        )
        assert "batch_ops" in seen_opcodes
        assert seen_conn_types == [8101]
        assert [d["name"] for d in build_res["devices"]] == ["R1", "R2"]
        assert [d["pt_name"] for d in build_res["devices"]] == ["Router0", "Router1"]
        assert all(not d["errors"] for d in build_res["devices"])
        assert len(build_res["links"]) == 1
        assert not build_res["links"][0]["errors"]
        assert list(build_res["configs"].keys()) == ["R1", "R2"]

        batch_cli = _call_tool_sync(
            server,
            "console_execute",
            {
                "batch_configs": {
                    "R1": ["interface gi0/0", "no shutdown"],
                    "R2": ["interface gi0/0", "no shutdown"],
                }
            },
        )
        assert batch_cli["success"] is True
        assert batch_cli["data"]["devices"] == ["R1", "R2"]

        runtime.router.active_is_activity = False
        ver = LabVerifier(runtime.router).verify(
            {
                "lab_name": "parallel-http-check",
                "requirements": [
                    {"type": "interface_up", "device": "R1", "interface": "GigabitEthernet0/0"},
                    {"type": "interface_up", "device": "R2", "interface": "GigabitEthernet0/0"},
                ],
            },
            poll_wait_seconds=0.0,
        )
        assert ver["passed"] is True
        assert len(ver["results"]) == 2
    finally:
        stop_evt.set()
        poller.join(timeout=2.0)
        bridge_backend.stop()


@pytest.mark.unit
def test_windows_toolhelp_does_not_collide_across_modules() -> None:
    import platform

    from agenticnet.adapters.discovery import list_packet_tracer_pids

    if platform.system() == "Windows":
        from agenticnet.gui.windows_backend import _snapshot_pt_processes

        snap = _snapshot_pt_processes()
        assert snap is None or isinstance(snap, list)

    pids = list_packet_tracer_pids()
    assert isinstance(pids, list)


@pytest.mark.unit
def test_core_imports_without_optional_gui_deps() -> None:
    import subprocess
    import sys

    code = "\n".join(
        [
            "import sys",
            "for mod in ('psutil', 'cv2', 'numpy', 'PIL', 'PIL.Image', 'PIL.ImageGrab'):",
            "    sys.modules[mod] = None",
            "from agenticnet.mcp.server import create_mcp_server",
            "from agenticnet.gui.vision import compute_image_stats",
            "from agenticnet.gui.windows_backend import WindowsGuiBackend",
            "from agenticnet.core.exceptions import AdapterUnavailableError",
            "try:",
            "    compute_image_stats(None)",
            "except AdapterUnavailableError as exc:",
            "    assert 'agenticnet[gui]' in str(exc.remediation)",
            "else:",
            "    raise AssertionError('Expected AdapterUnavailableError')",
        ]
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr or proc.stdout


@pytest.mark.unit
def test_cable_type_aliases_normalize_cleanly() -> None:
    from agenticnet.adapters.script_bridge import resolve_connect_type
    from agenticnet.core.enums import CableType, parse_cable_type
    from agenticnet.core.exceptions import ValidationError

    assert parse_cable_type("copper_straight") == CableType.STRAIGHT_THROUGH
    assert parse_cable_type("copper-cross") == CableType.CROSSOVER
    assert resolve_connect_type("copper_straight") == 8100
    assert resolve_connect_type("copper_cross") == 8101

    topo = TopologyEngine()
    topo.add_device("R1", "2911")
    topo.add_device("SW1", "2960-24TT")
    link = topo.connect(
        "R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1", cable_type="copper_straight"
    )
    assert link.cable_type == CableType.STRAIGHT_THROUGH

    topo.add_device("SW2", "2960-24TT")
    with pytest.raises(ValidationError):
        topo.connect("SW1", "FastEthernet0/1", "SW2", "FastEthernet0/1", cable_type="quantum_cable")


@pytest.mark.unit
def test_pc_connectivity_test_uses_dash_n_and_ios_avoids_repeat() -> None:
    from agenticnet.console.transport import SimulatedConsoleTransport
    from agenticnet.simulation.engine import SimulationEngine

    transport = SimulatedConsoleTransport()
    transport.seed_device("R1", hostname="R1", mode="privileged_exec")
    sent_log: list[tuple[str, str]] = []
    orig_send = transport.send_line

    def _recording_send(dev: str, line: str, *, timeout_s: float = 5.0) -> str:
        sent_log.append((dev, line))
        return orig_send(dev, line, timeout_s=timeout_s)

    transport.send_line = _recording_send  # type: ignore[method-assign]
    console = DeviceConsoleEngine(transport=transport)
    sim = SimulationEngine(console_engine=console)

    topo = TopologyEngine()
    topo.add_device("PC-A1", "PC-PT")
    topo.add_device("R1", "2911")

    res_pc = sim.run_connectivity_check("PC-A1", "10.10.10.1", topology=topo, count=2)
    assert res_pc["reachable"] is True
    assert any(dev == "PC-A1" and line == "ping -n 2 10.10.10.1" for dev, line in sent_log)

    res_ios = sim.run_connectivity_check("R1", "10.0.0.2", topology=topo, count=2)
    assert res_ios["reachable"] is True
    assert any(dev == "R1" and line == "ping 10.0.0.2" for dev, line in sent_log)
    assert not any("repeat" in line for _, line in sent_log)


@pytest.mark.unit
def test_batch_connectivity_test_tool(tmp_path: Path) -> None:
    from agenticnet.console.transport import SimulatedConsoleTransport

    transport = SimulatedConsoleTransport()
    transport.seed_device("R1", hostname="R1", mode="privileged_exec")
    settings = AgenticNetSettings(data_dir=tmp_path / "data", tool_profile="advanced")
    server, _ = create_mcp_server(settings, console_transport=transport)
    _call_tool_sync(server, "project_create", {"name": "batch-ping-test"})
    _call_tool_sync(server, "device_add", {"name": "PC-1", "model": "PC-PT"})
    _call_tool_sync(server, "device_add", {"name": "R1", "model": "2911"})

    res = _call_tool_sync(
        server,
        "connectivity_test",
        {
            "checks": [
                {"source_device": "PC-1", "destination_ip": "10.10.10.1"},
                {"source_device": "R1", "destination_ip": "10.0.0.2"},
            ],
            "count": 2,
        },
    )
    assert res["success"] is True
    assert res["data"]["total"] == 2
    assert res["data"]["reachable_count"] == 2
    assert res["data"]["all_reachable"] is True


@pytest.mark.unit
def test_split_batch_output_prevents_n_times_duplication() -> None:
    from agenticnet.console.engine import _split_batch_output

    raw = (
        "show ip interface brief\n"
        "Gi0/0 10.0.0.1 up up\n"
        "R1#show ip route\n"
        "C 10.0.0.0/30 is directly connected\n"
        "R1#show ip ospf neighbor\n"
        "2.2.2.2 FULL/DR\n"
        "R1#"
    )
    slices = _split_batch_output(
        raw, ["show ip interface brief", "show ip route", "show ip ospf neighbor"]
    )
    assert len(slices) == 3
    assert "Gi0/0 10.0.0.1" in slices[0] and "2.2.2.2" not in slices[0]
    assert "10.0.0.0/30" in slices[1] and "Gi0/0 10.0.0.1" not in slices[1]
    assert "2.2.2.2 FULL/DR" in slices[2] and "10.0.0.0/30" not in slices[2]


@pytest.mark.unit
def test_bridge_js_ping_recovery_more_dedupe_and_dhcp_toggle() -> None:
    js_path = (
        Path(__file__).resolve().parents[2]
        / "agenticnet"
        / "adapters"
        / "assets"
        / "netforge_bridge.js"
    )
    js_text = js_path.read_text(encoding="utf-8")
    assert "hasPingOrTraceFinished" in js_text
    assert "advancePagerOnce" in js_text
    assert "hPort.setDhcpClientFlag(false)" in js_text
    assert "applied_ip" in js_text



