"""Unit tests for fast `solve_lab` batching, instructions, prompts, and defaults."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import pytest

from agenticnet.adapters.router import BackendRouter, RoutedConsoleTransport
from agenticnet.adapters.script_bridge import HttpScriptBridgeBackend
from agenticnet.console.engine import DeviceConsoleEngine
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.mcp.profiles import RAW_GUI_INPUT_TOOLS, SOLVE_LAB_TOOLS
from agenticnet.mcp.server import create_mcp_server


def _call_tool_sync(server: Any, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    res = asyncio.run(server.call_tool(name, args or {}))
    assert res.structured_content is not None
    return dict(res.structured_content)


class _BatchBridgeBackend(HttpScriptBridgeBackend):
    """Test double inheriting `HttpScriptBridgeBackend` without starting a live socket."""

    def __init__(self) -> None:
        super().__init__()
        self.connected = True
        self.batch_calls: list[list[dict[str, Any]]] = []
        self.cli_calls: list[tuple[str, list[str]]] = []
        self.fail_device: str | None = None
        self.fail_link_index: int | None = None

    def is_connected(self) -> bool:
        return self.connected

    def batch_ops(
        self,
        ops: list[dict[str, Any]],
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        self.batch_calls.append(list(ops))
        results: list[dict[str, Any]] = []
        aliases: dict[str, str] = {}
        link_idx = 0
        for idx, item in enumerate(ops):
            op_name = item["op"]
            params = item.get("params", {})
            if op_name == "add_device":
                alias = item.get("alias")
                if self.fail_device and alias == self.fail_device:
                    results.append(
                        {
                            "index": idx,
                            "op": "add_device",
                            "alias": alias,
                            "ok": False,
                            "data": {},
                            "error": f"Simulated failure for {alias}",
                        }
                    )
                    continue
                pt_name = str(params.get("display_name") or alias or f"Dev{idx}")
                if alias:
                    aliases[str(alias)] = pt_name
                results.append(
                    {
                        "index": idx,
                        "op": "add_device",
                        "alias": alias,
                        "ok": True,
                        "data": {"device_name": pt_name},
                        "error": None,
                    }
                )
            elif op_name == "create_link":
                should_fail = self.fail_link_index is not None and link_idx == self.fail_link_index
                link_idx += 1
                results.append(
                    {
                        "index": idx,
                        "op": "create_link",
                        "alias": None,
                        "ok": not should_fail,
                        "data": {"linked": not should_fail},
                        "error": "createLink returned false" if should_fail else None,
                    }
                )
            else:
                results.append(
                    {
                        "index": idx,
                        "op": op_name,
                        "alias": None,
                        "ok": True,
                        "data": {"ok": True},
                        "error": None,
                    }
                )
        return {"ok": True, "backend": "script_http", "results": results, "aliases": aliases}

    def execute_cli(
        self,
        device_name: str,
        commands: list[str],
        *,
        wait_for_prompt: bool = True,
        timeout_seconds: float | None = None,
        stop_on_error: bool = True,
    ) -> dict[str, Any]:
        self.cli_calls.append((device_name, list(commands)))
        cmd_outputs = [f"{device_name}# {c}\nok" for c in commands]
        return {
            "ok": True,
            "device_name": device_name,
            "prompt": f"{device_name}#",
            "mode": "privileged_exec",
            "raw_output": "\n".join(cmd_outputs),
            "command_outputs": cmd_outputs,
            "command_statuses": [{"command": c, "status": 0, "non_fatal": False} for c in commands],
            "timed_out": False,
        }

    def list_devices(self, *, timeout_seconds: float = 30.0) -> dict[str, Any]:
        return {"ok": True, "device_count": 0, "link_count": 0, "devices": [], "links": []}


@pytest.mark.unit
def test_solve_lab_exposes_topology_create_and_excludes_raw_gui(tmp_path: Path) -> None:
    assert "topology_create" in SOLVE_LAB_TOOLS
    assert len(SOLVE_LAB_TOOLS) == 27
    assert SOLVE_LAB_TOOLS.isdisjoint(RAW_GUI_INPUT_TOOLS)

    srv, _ = create_mcp_server(AgenticNetSettings(data_dir=tmp_path / ".nf_fast"))
    tool_names = {t.name for t in asyncio.run(srv.list_tools())}
    assert "topology_create" in tool_names
    assert tool_names.isdisjoint(RAW_GUI_INPUT_TOOLS)
    assert "configure_ospf" not in tool_names

    inst = srv.instructions or ""
    assert "topology_create" in inst
    assert "batch_configs" in inst
    assert "lab_start" in inst
    assert "verify_lab" in inst
    assert "lab_save" in inst

    adv_srv, _ = create_mcp_server(
        AgenticNetSettings(data_dir=tmp_path / ".nf_adv", tool_profile="advanced")
    )
    adv_only = {t.name for t in asyncio.run(adv_srv.list_tools())} - SOLVE_LAB_TOOLS
    backticked_inst = set(re.findall(r"`([a-z0-9_]+)`", inst))
    assert not (backticked_inst & adv_only)


@pytest.mark.unit
def test_topology_create_one_shot_batch_ops_and_inline_hosts(tmp_path: Path) -> None:
    backend = _BatchBridgeBackend()
    settings = AgenticNetSettings(data_dir=tmp_path / ".nf_batch")
    srv, rt = create_mcp_server(settings, script_backend=backend)
    _call_tool_sync(srv, "project_create", {"name": "TP4 Fast Build"})

    res = _call_tool_sync(
        srv,
        "topology_create",
        {
            "devices": [
                {"name": "R1", "model": "2811", "x": 111.0, "y": 222.0},
                {"name": "SW1", "model": "2960-24TT"},
                {"name": "PC1", "model": "PC-PT", "dhcp": True},
                {
                    "name": "SRV1",
                    "model": "Server-PT",
                    "ip_address": "192.168.10.10",
                    "subnet_mask": "255.255.255.0",
                    "default_gateway": "192.168.10.1",
                },
                {"name": "Phone1", "model": "7960"},
            ],
            "connections": [
                {
                    "source_device": "R1",
                    "source_interface": "Fa0/0",
                    "target_device": "SW1",
                    "target_interface": "Gi0/1",
                },
                {
                    "source_device": "SW1",
                    "source_interface": "Fa0/1",
                    "target_device": "PC1",
                    "target_interface": "Fa0",
                },
                {
                    "source_device": "SW1",
                    "source_interface": "Fa0/2",
                    "target_device": "SRV1",
                    "target_interface": "Fa0",
                },
                {
                    "source_device": "SW1",
                    "source_interface": "Fa0/3",
                    "target_device": "Phone1",
                    "target_interface": "Switch",
                },
            ],
        },
    )
    assert res["success"] is True
    assert res["state_level"] == "executed"
    assert res["execution_backend"] == "script_backend"
    assert len(backend.batch_calls) == 1

    ops = backend.batch_calls[0]
    add_ops = [op for op in ops if op["op"] == "add_device"]
    link_ops = [op for op in ops if op["op"] == "create_link"]
    host_ops = [op for op in ops if op["op"] == "configure_host"]
    assert len(add_ops) == 5
    assert len(link_ops) == 4
    assert len(host_ops) == 2

    # Top-level `alias` must be present for netforge_bridge.js batch_ops aliasMap resolution
    assert all(op.get("alias") == op["params"]["display_name"] for op in add_ops)
    phone_op = next(op for op in add_ops if op["alias"] == "Phone1")
    assert phone_op["params"]["device_type"] == 12
    r1_op = next(op for op in add_ops if op["alias"] == "R1")
    assert r1_op["params"]["x"] == 111.0 and r1_op["params"]["y"] == 222.0

    _, topo, ipam, _ = rt.manager.require_active()
    assert topo.model.devices["SRV1"].interfaces["FastEthernet0"].ip_address == "192.168.10.10"
    assert any(a.ip_address == "192.168.10.10" for a in ipam.state.allocations.values())


@pytest.mark.unit
def test_topology_create_dry_run_offline_and_partial_rollback(tmp_path: Path) -> None:
    backend = _BatchBridgeBackend()
    settings = AgenticNetSettings(data_dir=tmp_path / ".nf_rb")
    srv, rt = create_mcp_server(settings, script_backend=backend)
    _call_tool_sync(srv, "project_create", {"name": "Rollback Test"})

    # replace_existing=True + dry_run=True on a brand-new empty project succeeds without confirm
    dry = _call_tool_sync(
        srv,
        "topology_create",
        {
            "replace_existing": True,
            "devices": [{"name": "R1", "model": "2911"}],
            "dry_run": True,
        },
    )
    assert dry["success"] is True
    assert dry["execution_backend"] == "offline_model"
    assert dry["state_level"] == "planned"
    assert backend.batch_calls == []

    # replace_existing=True on a fresh empty project also succeeds live without confirm=True
    _call_tool_sync(srv, "project_create", {"name": "Empty Live"})
    empty_replace = _call_tool_sync(
        srv,
        "topology_create",
        {
            "replace_existing": True,
            "devices": [{"name": "SeedR", "model": "2911"}],
        },
    )
    assert empty_replace["success"] is True
    assert empty_replace["execution_backend"] == "script_backend"

    # replace_existing=True on a non-empty project without confirm=True requires approval
    blocked_replace = _call_tool_sync(
        srv,
        "topology_create",
        {
            "replace_existing": True,
            "devices": [{"name": "NewR", "model": "2911"}],
        },
    )
    assert blocked_replace["success"] is False
    assert blocked_replace["status"] == "approval_required"

    # Simulate partial batch failure in PT -> failed device & dependent link rolled back
    backend.fail_device = "SW1"
    fail_res = _call_tool_sync(
        srv,
        "topology_create",
        {
            "replace_existing": True,
            "confirm": True,
            "devices": [
                {"name": "R1", "model": "2911"},
                {"name": "SW1", "model": "2960-24TT"},
            ],
            "connections": [
                {
                    "source_device": "R1",
                    "source_interface": "Gi0/0",
                    "target_device": "SW1",
                    "target_interface": "Gi0/1",
                }
            ],
        },
    )
    assert fail_res["success"] is False
    assert fail_res["errors"][0]["error_code"] == "PT_BATCH_FAILED"
    _, topo, _, _ = rt.manager.require_active()
    assert "R1" in topo.model.devices
    assert "SW1" not in topo.model.devices
    assert len(topo.model.connections) == 0


@pytest.mark.unit
def test_fast_defaults_skip_watch_sleeps_and_redundant_cli_reads(tmp_path: Path) -> None:
    backend = _BatchBridgeBackend()
    settings = AgenticNetSettings(data_dir=tmp_path / ".nf_cli")
    srv, rt = create_mcp_server(settings, script_backend=backend)
    sleep_calls: list[float] = []
    rt.router = BackendRouter(script_backend=backend, sleep_fn=sleep_calls.append)
    rt.console = DeviceConsoleEngine(transport=RoutedConsoleTransport(rt.router))

    _call_tool_sync(srv, "project_create", {"name": "Speed Defaults"})
    started = _call_tool_sync(
        srv,
        "lab_start",
        {"input_target": "Build a 2-router OSPF lab", "auto_approve": True},
    )
    assert started["success"] is True
    assert started["data"]["watch_pace_seconds"] == 0.0

    # Default console_execute with batch_configs skips before/after snapshot reads
    cli_res = _call_tool_sync(
        srv,
        "console_execute",
        {
            "batch_configs": {
                "R1": ["hostname R1", "interface Gi0/0", "no shutdown"],
                "R2": ["hostname R2", "interface Gi0/0", "no shutdown"],
            },
            "target_mode": "global_config",
        },
    )
    assert cli_res["success"] is True
    assert sleep_calls == []
    assert not any("show ip interface brief" in cmds for _dev, cmds in backend.cli_calls)
    assert [
        (dev, cmds)
        for dev, cmds in backend.cli_calls
        if "hostname R1" in cmds or "hostname R2" in cmds
    ] == [
        ("R1", ["configure terminal", "hostname R1", "interface Gi0/0", "no shutdown"]),
        ("R2", ["configure terminal", "hostname R2", "interface Gi0/0", "no shutdown"]),
    ]

    # Once warm, subsequent batch_configs executes 1 CLI call per device (no extra preflight/reads)
    backend.cli_calls.clear()
    warm_res = _call_tool_sync(
        srv,
        "console_execute",
        {
            "batch_configs": {
                "R1": ["logging synchronous"],
                "R2": ["logging synchronous"],
            },
            "target_mode": "global_config",
        },
    )
    assert warm_res["success"] is True
    assert len(backend.cli_calls) == 2

    # When capture_before_after=True with multiple verification_commands, snapshots run in 1 batch
    backend.cli_calls.clear()
    diff_res = _call_tool_sync(
        srv,
        "console_execute",
        {
            "device_name": "R1",
            "commands": ["hostname R1-NEW"],
            "target_mode": "global_config",
            "verification_commands": ["show ip interface brief", "show ip route"],
            "capture_before_after": True,
        },
    )
    assert diff_res["success"] is True
    # Before snapshot: 1 batched call (2 cmds); config + verification: batched; no per-command loop
    assert any(
        "show ip interface brief" in cmds and "show ip route" in cmds
        for _dev, cmds in backend.cli_calls
    )


@pytest.mark.unit
def test_router_multi_interface_no_shutdown_executes_in_single_batch(tmp_path: Path) -> None:
    backend = _BatchBridgeBackend()
    settings = AgenticNetSettings(data_dir=tmp_path / ".nf_rtr_batch")
    srv, rt = create_mcp_server(settings, script_backend=backend)
    sleep_calls: list[float] = []
    rt.router = BackendRouter(script_backend=backend, sleep_fn=sleep_calls.append)
    rt.console = DeviceConsoleEngine(transport=RoutedConsoleTransport(rt.router))

    _call_tool_sync(srv, "project_create", {"name": "Router Single Batch"})
    _, topo, _, _ = rt.manager.require_active()
    topo.add_device("R0", "2811")

    cmds: list[str] = ["configure terminal"]
    for idx in range(4):
        cmds.extend(
            [
                f"interface Serial0/{idx // 2}/{idx % 2}",
                f"ip address 10.0.{idx}.1 255.255.255.252",
                "clock rate 64000",
                "no shutdown",
                "exit",
            ]
        )
    cmds.extend(["router ospf 1", "network 10.0.0.0 0.0.255.255 area 0", "end", "write memory"])

    res = _call_tool_sync(
        srv,
        "console_execute",
        {"device_name": "R0", "commands": cmds, "target_mode": "preserve"},
    )
    assert res["success"] is True
    assert sleep_calls == []
    cfg_calls = [c for c in backend.cli_calls if any("router ospf 1" in x for x in c[1])]
    assert len(cfg_calls) == 1


@pytest.mark.unit
def test_router_catalog_exposes_dual_hwic_serial_ports(tmp_path: Path) -> None:
    backend = _BatchBridgeBackend()
    settings = AgenticNetSettings(data_dir=tmp_path / ".nf_serial_cat")
    srv, rt = create_mcp_server(settings, script_backend=backend)
    _call_tool_sync(srv, "project_create", {"name": "Dual HWIC Serial"})

    for model in ("2811", "2911", "1941"):
        profile = rt.catalog.get_profile(model)
        iface_names = {iface.name for iface in profile.interfaces}
        for port in ("Serial0/0/0", "Serial0/0/1", "Serial0/1/0", "Serial0/1/1"):
            assert port in iface_names, f"{model} missing {port}"
            assert rt.catalog.normalize_interface_name(model, port) == port
        assert rt.catalog.normalize_interface_name(model, "Se0/1/0") == "Serial0/1/0"

    res = _call_tool_sync(
        srv,
        "topology_create",
        {
            "replace_existing": True,
            "devices": [
                {"name": "R1", "model": "2811"},
                {"name": "R2", "model": "2811"},
            ],
            "connections": [
                {
                    "source_device": "R1",
                    "source_interface": "Serial0/1/0",
                    "target_device": "R2",
                    "target_interface": "Se0/1/1",
                }
            ],
        },
    )
    assert res["success"] is True
    _, topo, _, _ = rt.manager.require_active()
    assert len(topo.model.connections) == 1
    conn = next(iter(topo.model.connections.values()))
    assert conn.source_interface == "Serial0/1/0"
    assert conn.target_interface == "Serial0/1/1"
