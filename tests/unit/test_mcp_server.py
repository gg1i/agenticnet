"""End-to-end unit tests for AgenticNet tools, permissions, resources, and prompts."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from agenticnet.core.settings import AgenticNetSettings
from agenticnet.mcp.server import create_mcp_server
from agenticnet.security.permissions import PermissionPolicy


def _decode_tool_result(call_result) -> dict:
    assert call_result.structured_content is not None
    return dict(call_result.structured_content)


@pytest.mark.unit
def test_mcp_tool_resource_prompt_discovery_and_manifest(mcp_bundle) -> None:
    server, runtime = mcp_bundle

    tools = asyncio.run(server.list_tools())
    resources = asyncio.run(server.list_resources())
    prompts = asyncio.run(server.list_prompts())

    tool_names = {t.name for t in tools}
    manifest = runtime.build_manifest()
    assert len(tool_names) == manifest["tool_count"]
    assert len(tool_names) == 94
    assert manifest["platform_core"]["default_target_mode"] == "packet_tracer"
    assert len(manifest["adapters"]) == 1
    assert manifest["adapters"][0]["adapter_id"] == "cisco_packet_tracer"
    assert manifest["adapters"][0]["supported_modes"] == ["packet_tracer"]
    assert {
        "configure_hsrp",
        "configure_bgp",
        "configure_dhcp_snooping",
        "configure_dai",
        "configure_services",
        "configure_voip_cme",
        "configure_asa",
        "stored_config_manage",
        "topology_merge",
        "topology_diff",
        "lab_failure_drill",
        "workspace_preferences",
    } <= tool_names
    assert "grade_lab" in tool_names
    assert "lab_start" in tool_names
    assert "lab_open" in tool_names
    assert "lab_save" in tool_names
    assert "lab_status" in tool_names
    assert "list_devices" in tool_names
    assert "lab_snapshot" in tool_names
    assert "lab_diff" in tool_names
    assert "gui_attach_ip_phone_power" in tool_names
    assert {
        "project_create",
        "topology_create",
        "device_capabilities",
        "connection_create",
        "vlsm_plan",
        "configure_ospf",
        "configure_nat",
        "configure_acl",
        "configure_ssh",
        "command_validate",
        "console_open",
        "console_execute",
        "packet_tracer_detect",
        "gui_calibrate",
        "gui_recover",
        "simulation_mode",
        "simulation_start",
        "connectivity_test",
        "network_diagnose",
        "network_repair_propose",
        "network_repair_execute",
        "network_verify",
        "verify_requirements_schema",
        "verify_lab",
        "lab_open",
        "lab_save",
        "lab_status",
    } <= tool_names
    assert len(resources) == 7
    assert len(prompts) == 6
    assert {str(r.uri) for r in resources} >= {
        "agenticnet://manifest",
        "agenticnet://workflows/solve_lab",
        "agenticnet://devices/catalog",
    }
    assert {p.name for p in prompts} >= {
        "start_lab",
        "solve_lab",
        "plan_network_architecture",
        "design_campus_vlan_network",
    }


@pytest.mark.unit
def test_end_to_end_enterprise_workflow_via_mcp_tools(mcp_bundle) -> None:
    server, runtime = mcp_bundle

    async def _run_workflow() -> None:
        r = _decode_tool_result(
            await server.call_tool(
                "project_create",
                {"name": "Enterprise HQ", "project_id": "enterprise-hq"},
            )
        )
        assert r["success"] is True
        assert r["state_level"] == "planned"

        vlsm = _decode_tool_result(
            await server.call_tool(
                "vlsm_plan",
                {
                    "base_cidr": "10.20.0.0/16",
                    "requirements": [
                        {"name": "Users-VLAN10", "required_hosts": 50, "vlan_id": 10},
                        {"name": "Servers-VLAN20", "required_hosts": 15, "vlan_id": 20},
                        {"name": "R1-SWCore-Transit", "required_hosts": 2},
                    ],
                    "register_pools": True,
                },
            )
        )
        assert vlsm["success"] is True
        assert len(vlsm["data"]["registered_pool_ids"]) == 3

        topo = _decode_tool_result(
            await server.call_tool(
                "topology_create",
                {
                    "devices": [
                        {"name": "R1", "model": "2911", "role": "Edge Router"},
                        {"name": "SW-CORE", "model": "3560-24PS", "role": "Core L3 Switch"},
                        {"name": "SW-ACC", "model": "2960-24TT", "role": "Access Switch"},
                        {"name": "SRV1", "model": "Server-PT", "role": "App Server"},
                        {"name": "PC1", "model": "PC-PT", "role": "User PC"},
                    ],
                    "connections": [
                        {
                            "source_device": "R1",
                            "source_interface": "Gi0/0",
                            "target_device": "SW-CORE",
                            "target_interface": "Gi0/1",
                        },
                        {
                            "source_device": "SW-CORE",
                            "source_interface": "Gi0/2",
                            "target_device": "SW-ACC",
                            "target_interface": "Gi0/1",
                        },
                        {
                            "source_device": "SW-ACC",
                            "source_interface": "Fa0/1",
                            "target_device": "PC1",
                            "target_interface": "Fa0",
                        },
                        {
                            "source_device": "SW-CORE",
                            "source_interface": "Fa0/1",
                            "target_device": "SRV1",
                            "target_interface": "Fa0",
                        },
                    ],
                },
            )
        )
        assert topo["success"] is True

        vlan_res = _decode_tool_result(
            await server.call_tool(
                "configure_vlan",
                {
                    "device_name": "SW-ACC",
                    "vlans": [
                        {"vlan_id": 10, "name": "Users"},
                        {"vlan_id": 20, "name": "Servers"},
                    ],
                    "access_ports": [{"interface": "Fa0/1", "vlan_id": 10}],
                },
            )
        )
        assert vlan_res["success"] is True

        trunk_res = _decode_tool_result(
            await server.call_tool(
                "configure_trunk",
                {"device_name": "SW-CORE", "interface": "Gi0/2", "allowed_vlans": [10, 20]},
            )
        )
        assert " switchport trunk encapsulation dot1q" in trunk_res["data"]["commands"]

        iface_res = _decode_tool_result(
            await server.call_tool(
                "configure_interface",
                {
                    "device_name": "SW-CORE",
                    "interface": "Vlan10",
                    "ipv4_address": "10.20.0.1/26",
                },
            )
        )
        assert iface_res["success"] is True

        ospf_res = _decode_tool_result(
            await server.call_tool(
                "configure_ospf",
                {
                    "device_name": "R1",
                    "process_id": 1,
                    "router_id": "1.1.1.1",
                    "networks": [{"network": "10.20.0.0/16", "area": 0}],
                },
            )
        )
        assert ospf_res["success"] is True

        ssh_res = _decode_tool_result(
            await server.call_tool(
                "configure_ssh",
                {
                    "device_name": "R1",
                    "domain_name": "hq.example",
                    "username": "netadmin",
                    "secret": "SecretPass2026!",
                },
            )
        )
        assert ssh_res["success"] is True
        assert all("SecretPass2026!" not in c for c in ssh_res["data"]["commands_redacted"])

        blocked_rm = _decode_tool_result(
            await server.call_tool("device_remove", {"name": "PC1", "confirm": False})
        )
        assert blocked_rm["success"] is False
        assert blocked_rm["status"] == "approval_required"

        vis = _decode_tool_result(await server.call_tool("topology_visualize", {}))
        assert "flowchart LR" in vis["data"]["mermaid"]

        report = _decode_tool_result(
            await server.call_tool("ipam_report", {"table_format": "markdown"})
        )
        assert report["success"] is True

        saved = _decode_tool_result(await server.call_tool("project_save", {"create_backup": True}))
        assert saved["success"] is True

        logs = runtime.manager.store.list_execution_logs(project_id="enterprise-hq", limit=50)
        assert len(logs) >= 8
        assert "SecretPass2026!" not in json.dumps(logs)

    asyncio.run(_run_workflow())


@pytest.mark.unit
def test_read_only_permission_profile_blocks_mutations(tmp_path: Path) -> None:
    ro_settings = AgenticNetSettings(
        data_dir=tmp_path / ".netforge_ro",
        permission_profile="read-only",
        allowed_tiers=PermissionPolicy.from_profile("read-only").allowed_tiers,
    )
    server, _ = create_mcp_server(ro_settings)

    res = _decode_tool_result(asyncio.run(server.call_tool("project_create", {"name": "Blocked"})))
    assert res["success"] is False
    assert res["status"] == "blocked"
    assert res["errors"][0]["error_code"] == "PERMISSION_DENIED"


@pytest.mark.unit
def test_dynamic_instructions_and_all_prompts_respect_solve_lab_profile(tmp_path: Path) -> None:
    import re

    from agenticnet.mcp.profiles import SOLVE_LAB_TOOLS

    solve_srv, _ = create_mcp_server(AgenticNetSettings(data_dir=tmp_path / ".nf_solve"))
    adv_srv, _ = create_mcp_server(
        AgenticNetSettings(data_dir=tmp_path / ".nf_adv", tool_profile="advanced")
    )
    all_adv_tools = {t.name for t in asyncio.run(adv_srv.list_tools())}
    adv_only_tools = all_adv_tools - set(SOLVE_LAB_TOOLS)

    solve_inst = solve_srv.instructions or ""
    inst_tokens = set(re.findall(r"`([a-z0-9_]+)`", solve_inst))
    assert not (inst_tokens & adv_only_tools), (
        f"solve_lab instructions leaked advanced tools: {inst_tokens & adv_only_tools}"
    )
    assert "project_save" in SOLVE_LAB_TOOLS
    assert len(SOLVE_LAB_TOOLS) == 26

    prompts = asyncio.run(solve_srv.list_prompts())
    assert len(prompts) == 6
    sample_args: dict[str, dict[str, str]] = {
        "start_lab": {"lab_input": "demo"},
        "solve_lab": {"lab_goal": "solve demo"},
        "plan_network_architecture": {"requirement": "2-VLAN branch"},
        "design_campus_vlan_network": {},
        "review_network_configurations": {},
        "troubleshoot_network_workflow": {"symptom": "PC1 cannot ping gateway"},
    }
    for p in prompts:
        out = asyncio.run(solve_srv.get_prompt(p.name, arguments=sample_args.get(p.name, {})))
        body = str(out.messages[0].content.text)
        cited = set(re.findall(r"`([a-z0-9_]+)`", body))
        leaked = cited & adv_only_tools
        assert not leaked, f"Prompt '{p.name}' leaked advanced-only tools in solve_lab: {leaked}"


@pytest.mark.unit
def test_cold_start_resources_and_builtin_pt_guides(tmp_path: Path) -> None:
    data_dir = tmp_path / ".nf_res"
    srv_empty, _ = create_mcp_server(
        AgenticNetSettings(data_dir=data_dir, tool_profile="advanced")
    )

    # 1. Static resource list stays 7; template list exposes agenticnet://guides/{topic}
    static_res = asyncio.run(srv_empty.list_resources())
    templates = asyncio.run(srv_empty.list_resource_templates())
    assert len(static_res) == 7
    assert any("agenticnet://guides/{topic}" in str(t.uri_template) for t in templates)

    # 2. Empty cold-start topology/ipam resources return non-null structured JSON without writing DB
    topo_empty = json.loads(
        "".join(
            str(getattr(c, "content", c))
            for c in asyncio.run(srv_empty.read_resource("agenticnet://project/topology"))
        )
    )
    ipam_empty = json.loads(
        "".join(
            str(getattr(c, "content", c))
            for c in asyncio.run(srv_empty.read_resource("agenticnet://project/ipam"))
        )
    )
    assert topo_empty["status"] == "no_active_project"
    assert topo_empty.get("active_project", "absent") is not None
    assert ipam_empty["status"] == "no_active_project"

    # 3. Create + save a project, then cold-start a brand-new server and read persisted state
    _decode_tool_result(
        asyncio.run(srv_empty.call_tool("project_create", {"name": "ColdStartNet"}))
    )
    _decode_tool_result(
        asyncio.run(srv_empty.call_tool("device_add", {"name": "R1", "model": "2911"}))
    )
    _decode_tool_result(asyncio.run(srv_empty.call_tool("project_save", {"create_backup": False})))

    srv_restarted, rt_restarted = create_mcp_server(
        AgenticNetSettings(data_dir=data_dir, tool_profile="advanced")
    )
    assert rt_restarted.manager.has_active_project is False
    topo_loaded = json.loads(
        "".join(
            str(getattr(c, "content", c))
            for c in asyncio.run(srv_restarted.read_resource("agenticnet://project/topology"))
        )
    )
    assert "R1" in topo_loaded["devices"]

    # 4. Read all 7 built-in Packet Tracer reference guides
    expected_snippets = {
        "master": "AC-POWER-SUPPLY",
        "l2-l3": "encapsulation dot1q",
        "hosts": "host_configure",
        "asa": "5506-X",
        "wireless": "CAPWAP",
        "iot": "HomeGateway-PT",
        "voip": "option 150",
        "index": "agenticnet://guides/master",
    }
    for topic, snippet in expected_snippets.items():
        chunks = asyncio.run(srv_empty.read_resource(f"agenticnet://guides/{topic}"))
        text = "".join(str(getattr(c, "content", c)) for c in chunks)
        assert snippet in text, f"Expected {snippet!r} in guide topic {topic!r}"


@pytest.mark.unit
def test_lab_open_hydrates_topology_and_wires_tools_and_lab_save_guard(tmp_path: Path) -> None:
    from agenticnet.adapters.base import ScriptBackend

    class _HydrationBackend(ScriptBackend):
        def __init__(self) -> None:
            self.host_calls: list[dict] = []
            self.link_calls: list[tuple] = []
            self.saved_paths: list[str | None] = []

        def is_connected(self) -> bool:
            return True

        def ping(self) -> dict:
            return {"ok": True}

        def open_file(self, path: str, *, timeout_seconds: float = 30.0) -> dict:
            return {"ok": True, "path": path, "is_activity_file": False}

        def save_file(
            self, path: str | None = None, *, overwrite: bool = True, timeout_seconds: float = 30.0
        ) -> dict:
            self.saved_paths.append(path)
            return {"ok": True, "saved": True, "path": path or "active.pkt"}

        def list_devices(self, *, timeout_seconds: float = 30.0) -> dict:
            return {
                "ok": True,
                "devices": [
                    {
                        "name": "Router0",
                        "model": "2911",
                        "type": "router",
                        "hostname": "HQ_RTR",
                        "x": 160,
                        "y": 110,
                        "ports": [
                            {
                                "name": "GigabitEthernet0/0",
                                "ip_address": "10.10.1.1",
                                "subnet_mask": "255.255.255.0",
                                "port_up": False,
                                "has_link": True,
                            }
                        ],
                    },
                    {
                        "name": "Switch0",
                        "model": "2960-24TT",
                        "type": "switch",
                        "hostname": "SW_ACC",
                        "ports": [
                            {
                                "name": "FastEthernet0/1",
                                "ip_address": "",
                                "subnet_mask": "",
                                "port_up": True,
                                "has_link": True,
                            },
                            {
                                "name": "FastEthernet0/2",
                                "ip_address": "",
                                "subnet_mask": "",
                                "port_up": True,
                                "has_link": True,
                            },
                        ],
                    },
                    {
                        "name": "PC0",
                        "model": "PC-PT",
                        "type": "pc",
                        "hostname": "PC0",
                        "ports": [
                            {
                                "name": "FastEthernet0",
                                "ip_address": "10.10.1.50",
                                "subnet_mask": "255.255.255.0",
                                "port_up": True,
                                "has_link": True,
                            }
                        ],
                    },
                ],
                "links": [
                    {
                        "device1": "Router0",
                        "port1": "GigabitEthernet0/0",
                        "device2": "Switch0",
                        "port2": "FastEthernet0/1",
                    },
                    {
                        "device1": "Switch0",
                        "port1": "FastEthernet0/2",
                        "device2": "PC0",
                        "port2": "FastEthernet0",
                    },
                ],
            }

        def add_device(
            self, model: str, *, device_type: int | str = 0, x: float = 100.0, y: float = 100.0
        ) -> dict:
            return {"ok": True, "device_name": "PC1"}

        def create_link(
            self,
            device1: str,
            port1: str,
            device2: str,
            port2: str,
            *,
            conn_type: int | str = 8107,
        ) -> dict:
            self.link_calls.append((device1, port1, device2, port2))
            return {"ok": True}

        def configure_host(
            self,
            device_name: str,
            *,
            dns_server: str | None = None,
            **kwargs,
        ) -> dict:
            self.host_calls.append(
                {"device_name": device_name, "dns_server": dns_server, **kwargs}
            )
            return {"ok": True, "device_name": device_name}

        def move_device(self, name: str, x: float, y: float) -> dict:
            return {"ok": True, "device_name": name, "x": x, "y": y}

        def delete_link(self, device_name: str, port_name: str) -> dict:
            return {"ok": True, "device_name": device_name, "port_name": port_name}

        def remove_device(self, name: str) -> dict:
            return {"ok": True, "device_name": name}

        def execute_cli(self, device_name: str, commands: list[str], **kwargs) -> dict:
            return {
                "ok": True,
                "raw_output": "hostname HQ_RTR\nenable secret 5 $1$secret\nend",
                "prompt": "HQ_RTR#",
                "command_statuses": [{"command": c, "status": 0} for c in commands],
            }

        def read_activity_status(self) -> dict:
            return {"ok": True, "is_activity_file": False, "state": "not_activity"}

    backend = _HydrationBackend()
    srv, rt = create_mcp_server(
        AgenticNetSettings(data_dir=tmp_path / ".nf_hyd", tool_profile="advanced"),
        script_backend=backend,
    )

    async def _exercise() -> None:
        opened = _decode_tool_result(
            await srv.call_tool("lab_open", {"path": str(tmp_path / "campus.pkt")})
        )
        assert opened["success"] is True
        assert opened["data"]["topology_hydration"]["hydrated_devices"] == 3
        assert opened["data"]["topology_hydration"]["hydrated_connections"] == 2
        assert rt.router.device_aliases.get("HQ_RTR") == "Router0"

        # 1. topology_inspect sees hydrated devices & links immediately
        ti = _decode_tool_result(
            await srv.call_tool("topology_inspect", {"include_interfaces": True})
        )
        assert len(ti["data"]["devices"]) == 3
        assert len(ti["data"]["connections"]) == 2

        # 2. device_inspect works by both PT canvas name AND IOS hostname alias
        di_canvas = _decode_tool_result(await srv.call_tool("device_inspect", {"name": "Router0"}))
        di_alias = _decode_tool_result(await srv.call_tool("device_inspect", {"name": "HQ_RTR"}))
        assert di_canvas["success"] is True
        assert di_alias["success"] is True
        assert di_alias["data"]["device"]["name"] == "Router0"

        # 3. host_configure works on hydrated PC0 (including optional dns_server)
        hc = _decode_tool_result(
            await srv.call_tool(
                "host_configure",
                {
                    "device_name": "PC0",
                    "ip_address": "10.10.1.50",
                    "subnet_mask": "255.255.255.0",
                    "default_gateway": "10.10.1.1",
                    "dns_server": "8.8.8.8",
                },
            )
        )
        assert hc["success"] is True
        assert backend.host_calls[-1]["default_gateway"] == "10.10.1.1"
        assert backend.host_calls[-1]["dns_server"] == "8.8.8.8"

        # 4. connection_create links newly added PC1 to hydrated Switch0 free port Fa0/3
        _decode_tool_result(await srv.call_tool("device_add", {"name": "PC1", "model": "PC-PT"}))
        cc = _decode_tool_result(
            await srv.call_tool(
                "connection_create",
                {
                    "source_device": "SW_ACC",
                    "source_interface": "FastEthernet0/3",
                    "target_device": "PC1",
                    "target_interface": "FastEthernet0",
                },
            )
        )
        assert cc["success"] is True
        assert backend.link_calls[-1][0] == "Switch0"
        conn_id = cc["data"]["connection_id"]

        # 4b. device_move, connection_remove, and device_remove dispatch live via BackendRouter
        mv = _decode_tool_result(
            await srv.call_tool("device_move", {"name": "PC1", "x": 320.0, "y": 410.0})
        )
        assert mv["success"] is True
        assert mv["execution_backend"] == "script_backend"

        cr = _decode_tool_result(
            await srv.call_tool("connection_remove", {"connection_id": conn_id, "confirm": True})
        )
        assert cr["success"] is True
        assert cr["execution_backend"] == "script_backend"

        dr = _decode_tool_result(
            await srv.call_tool("device_remove", {"name": "PC1", "confirm": True})
        )
        assert dr["success"] is True
        assert dr["execution_backend"] == "script_backend"

        # 5. configuration_backup works on hydrated alias HQ_RTR
        cb = _decode_tool_result(
            await srv.call_tool(
                "configuration_backup",
                {"device_name": "HQ_RTR", "fetch_live": True},
            )
        )
        assert cb["success"] is True
        assert cb["state_level"] == "verified"

        # 6. network_diagnose detects admin-down Gi0/0 on hydrated Router0
        nd = _decode_tool_result(await srv.call_tool("network_diagnose", {}))
        assert nd["success"] is True
        finding_codes = {f["code"] for f in nd["data"]["findings"]}
        assert "INTERFACE_ADMIN_DOWN_WITH_IP" in finding_codes

        # 7. lab_save guards overwriting an existing custom .pkt file unless confirm=True
        existing_other = tmp_path / "other_existing.pkt"
        existing_other.write_bytes(b"PREEXISTING")
        blocked_save = _decode_tool_result(
            await srv.call_tool("lab_save", {"path": str(existing_other), "overwrite": True})
        )
        assert blocked_save["success"] is False
        assert blocked_save["status"] == "approval_required"

        confirmed_save = _decode_tool_result(
            await srv.call_tool(
                "lab_save",
                {"path": str(existing_other), "overwrite": True, "confirm": True},
            )
        )
        assert confirmed_save["success"] is True
        assert backend.saved_paths[-1] == str(existing_other)

    asyncio.run(_exercise())


@pytest.mark.unit
def test_configure_trunk_sets_diagnostic_flags_and_provenance_tags(tmp_path: Path) -> None:
    srv, rt = create_mcp_server(
        AgenticNetSettings(data_dir=tmp_path / ".nf_trk", tool_profile="advanced")
    )

    async def _run() -> None:
        _decode_tool_result(await srv.call_tool("project_create", {"name": "TrunkDiag"}))
        _decode_tool_result(
            await srv.call_tool("device_add", {"name": "SW1", "model": "2960-24TT"})
        )
        _decode_tool_result(
            await srv.call_tool("device_add", {"name": "SW2", "model": "3560-24PS"})
        )
        _decode_tool_result(
            await srv.call_tool(
                "connection_create",
                {
                    "source_device": "SW1",
                    "source_interface": "Gi0/1",
                    "target_device": "SW2",
                    "target_interface": "Gi0/1",
                },
            )
        )
        # Configure only SW1 as trunk with native VLAN 10 -> triggers TRUNK_MODE_MISMATCH on SW2
        _decode_tool_result(
            await srv.call_tool(
                "configure_trunk",
                {"device_name": "SW1", "interface": "Gi0/1", "native_vlan": 10},
            )
        )
        d1 = _decode_tool_result(await srv.call_tool("vlan_diagnose", {}))
        assert "TRUNK_MODE_MISMATCH" in {f["code"] for f in d1["data"]["findings"]}

        # Configure SW2 as trunk with native VLAN 20 -> triggers NATIVE_VLAN_MISMATCH
        _decode_tool_result(
            await srv.call_tool(
                "configure_trunk",
                {"device_name": "SW2", "interface": "Gi0/1", "native_vlan": 20},
            )
        )
        d2 = _decode_tool_result(await srv.call_tool("vlan_diagnose", {}))
        assert "NATIVE_VLAN_MISMATCH" in {f["code"] for f in d2["data"]["findings"]}

        # Simulation mode provenance: offline -> offline_model; GUI click -> gui_backend
        sim_off = _decode_tool_result(
            await srv.call_tool("simulation_mode", {"mode": "simulation"})
        )
        assert sim_off["execution_backend"] == "offline_model"

        rt.simulation.set_mode = lambda mode: {  # type: ignore[method-assign]
            "mode": mode,
            "dispatched_to_gui": True,
            "state_level": "executed",
        }
        sim_gui = _decode_tool_result(await srv.call_tool("simulation_start", {}))
        assert sim_gui["execution_backend"] == "gui_backend"

    asyncio.run(_run())


@pytest.mark.unit
def test_stage_1c_enterprise_tools_stored_configs_topology_prefs_and_drills(
    tmp_path: Path,
) -> None:
    from agenticnet.adapters.base import ScriptBackend

    class _ApplyBackend(ScriptBackend):
        def __init__(self) -> None:
            self.cli_batches: list[tuple[str, list[str]]] = []

        def is_connected(self) -> bool:
            return True

        def ping(self) -> dict:
            return {"ok": True}

        def add_device(
            self,
            model: str,
            *,
            device_type: int | str = 0,
            x: float = 100.0,
            y: float = 100.0,
            display_name: str | None = None,
        ) -> dict:
            return {"ok": True, "device_name": display_name or model}

        def create_link(
            self,
            device1: str,
            port1: str,
            device2: str,
            port2: str,
            *,
            conn_type: int | str = 8107,
        ) -> dict:
            return {"ok": True}

        def execute_cli(self, device_name: str, commands: list[str], **kwargs) -> dict:
            self.cli_batches.append((device_name, list(commands)))
            return {
                "ok": True,
                "raw_output": "R2(config)#",
                "prompt": "R2(config)#",
                "command_statuses": [{"command": c, "status": 0} for c in commands],
            }

    backend = _ApplyBackend()
    srv, _ = create_mcp_server(
        AgenticNetSettings(data_dir=tmp_path / ".nf_1c", tool_profile="advanced"),
        script_backend=backend,
    )

    async def _run() -> None:
        # 1. workspace_preferences CRUD
        wp_set = _decode_tool_result(
            await srv.call_tool(
                "workspace_preferences",
                {"action": "set", "key": "default_ospf_area", "value": 0},
            )
        )
        assert wp_set["success"] is True
        wp_get = _decode_tool_result(
            await srv.call_tool(
                "workspace_preferences",
                {"action": "get", "key": "default_ospf_area"},
            )
        )
        assert wp_get["data"]["found"] is True
        assert wp_get["data"]["value"] == 0
        wp_list = _decode_tool_result(
            await srv.call_tool("workspace_preferences", {"action": "list"})
        )
        assert wp_list["data"]["count"] == 1

        # 2. Baseline project + active project + topology_merge + topology_diff
        _decode_tool_result(
            await srv.call_tool("project_create", {"name": "Base", "project_id": "base-proj"})
        )
        _decode_tool_result(
            await srv.call_tool(
                "topology_create",
                {
                    "devices": [
                        {"name": "R1", "model": "2811"},
                        {"name": "SW1", "model": "3560-24PS"},
                        {"name": "FW1", "model": "5506-X"},
                    ],
                },
            )
        )
        _decode_tool_result(await srv.call_tool("project_save", {"create_backup": False}))

        _decode_tool_result(
            await srv.call_tool("project_create", {"name": "Target", "project_id": "target-proj"})
        )
        _decode_tool_result(
            await srv.call_tool(
                "topology_create",
                {
                    "devices": [
                        {"name": "R1", "model": "2811"},
                        {"name": "SW1", "model": "3560-24PS"},
                        {"name": "FW1", "model": "5506-X"},
                    ],
                },
            )
        )
        merged = _decode_tool_result(
            await srv.call_tool(
                "topology_merge",
                {
                    "devices": [{"name": "R2", "model": "2911"}],
                    "connections": [
                        {
                            "source_device": "R1",
                            "source_interface": "Fa0/0",
                            "target_device": "R2",
                            "target_interface": "Gi0/0",
                        }
                    ],
                    "push_live": True,
                },
            )
        )
        assert merged["success"] is True
        assert merged["execution_backend"] == "script_backend"
        assert merged["data"]["devices_added"] == ["R2"]
        assert len(merged["data"]["connections_added"]) == 1

        tdiff = _decode_tool_result(
            await srv.call_tool("topology_diff", {"other_project_id": "base-proj"})
        )
        assert tdiff["success"] is True
        assert tdiff["data"]["devices_removed"] == ["R2"]

        # 3. Exercise all 7 new enterprise/PT structured generator tools
        hsrp = _decode_tool_result(
            await srv.call_tool(
                "configure_hsrp",
                {"device_name": "R1", "interface": "Fa0/0", "virtual_ip": "10.10.0.254"},
            )
        )
        assert hsrp["success"] is True
        assert any("standby 1 ip 10.10.0.254" in c for c in hsrp["data"]["commands"])

        bgp = _decode_tool_result(
            await srv.call_tool(
                "configure_bgp",
                {
                    "device_name": "R1",
                    "local_as": 65001,
                    "neighbors": [{"peer_ip": "10.10.0.2", "remote_as": 65002}],
                    "networks": ["192.168.100.0/24"],
                },
            )
        )
        assert bgp["success"] is True
        assert "router bgp 65001" in bgp["data"]["commands"]

        snoop = _decode_tool_result(
            await srv.call_tool(
                "configure_dhcp_snooping",
                {"device_name": "SW1", "vlans": [10, 20], "trusted_interfaces": ["Gi0/1"]},
            )
        )
        assert snoop["success"] is True
        assert "ip dhcp snooping" in snoop["data"]["commands"]

        dai = _decode_tool_result(
            await srv.call_tool(
                "configure_dai",
                {"device_name": "SW1", "vlans": [10], "trusted_interfaces": ["Gi0/1"]},
            )
        )
        assert dai["success"] is True
        assert "ip arp inspection vlan 10" in dai["data"]["commands"]

        svcs = _decode_tool_result(
            await srv.call_tool(
                "configure_services",
                {
                    "device_name": "R1",
                    "ntp_servers": ["10.0.0.10"],
                    "snmp_ro_community": "SuperSecretRO",
                    "aaa_new_model": True,
                    "radius_server_ip": "10.0.0.11",
                    "radius_key": "RadPass99!",
                },
            )
        )
        assert svcs["success"] is True
        assert all("SuperSecretRO" not in c for c in svcs["data"]["commands_redacted"])
        assert all("RadPass99!" not in c for c in svcs["data"]["commands_redacted"])

        cme = _decode_tool_result(
            await srv.call_tool(
                "configure_voip_cme",
                {
                    "device_name": "R1",
                    "source_address": "10.10.0.1",
                    "dns": [{"dn_id": 1, "number": "1001"}],
                    "ephones": [{"ephone_id": 1, "button_mapping": "1:1"}],
                },
            )
        )
        assert cme["success"] is True
        assert "telephony-service" in cme["data"]["commands"]

        asa = _decode_tool_result(
            await srv.call_tool(
                "configure_asa",
                {
                    "device_name": "FW1",
                    "hostname": "EDGE-FW",
                    "interfaces": [
                        {
                            "interface": "Gi1/1",
                            "nameif": "inside",
                            "security_level": 100,
                            "ip_address": "10.20.0.1/24",
                        }
                    ],
                },
            )
        )
        assert asa["success"] is True
        assert " nameif inside" in asa["data"]["commands"]

        # 4. Blocking validate_pre_apply + live apply=True on configure_*
        _decode_tool_result(
            await srv.call_tool(
                "configure_interface",
                {"device_name": "R1", "interface": "Fa0/0", "ipv4_address": "10.99.0.1/24"},
            )
        )
        dup_blocked = _decode_tool_result(
            await srv.call_tool(
                "configure_interface",
                {
                    "device_name": "R2",
                    "interface": "Gi0/0",
                    "ipv4_address": "10.99.0.1/24",
                    "apply": True,
                },
            )
        )
        assert dup_blocked["success"] is False
        assert dup_blocked["errors"][0]["error_code"] == "IOS_CONFIG_ERROR"

        applied_ok = _decode_tool_result(
            await srv.call_tool(
                "configure_interface",
                {
                    "device_name": "R2",
                    "interface": "Gi0/0",
                    "ipv4_address": "10.99.0.2/24",
                    "apply": True,
                },
            )
        )
        assert applied_ok["success"] is True
        assert applied_ok["data"]["applied"] is True
        assert applied_ok["execution_backend"] == "script_backend"
        assert backend.cli_batches[-1][0] == "R2"

        # 5. stored_config_manage lifecycle (upsert -> read -> merge -> validate -> delete)
        up = _decode_tool_result(
            await srv.call_tool(
                "stored_config_manage",
                {
                    "action": "upsert",
                    "device_name": "R2",
                    "config_text": "hostname R2\ninterface GigabitEthernet0/1\n no shutdown",
                },
            )
        )
        assert up["success"] is True
        rd = _decode_tool_result(
            await srv.call_tool(
                "stored_config_manage",
                {"action": "read", "device_name": "R2", "start_line": 1, "end_line": 2},
            )
        )
        assert rd["data"]["lines"][0] == {"line": 1, "text": "hostname R2"}

        mg = _decode_tool_result(
            await srv.call_tool(
                "stored_config_manage",
                {
                    "action": "merge",
                    "device_name": "R2",
                    "start_line": 1,
                    "end_line": 1,
                    "new_lines": ["hostname R2-CORE"],
                },
            )
        )
        assert "hostname R2-CORE" in mg["data"]["config_text"]

        val_ok = _decode_tool_result(
            await srv.call_tool(
                "stored_config_manage",
                {"action": "validate", "device_name": "R2", "strict": True},
            )
        )
        assert val_ok["data"]["valid"] is True

        val_bad = _decode_tool_result(
            await srv.call_tool(
                "stored_config_manage",
                {
                    "action": "validate",
                    "device_name": "SW1",
                    "config_text": "ip nat inside source static 10.0.0.1 203.0.113.1",
                    "strict": True,
                },
            )
        )
        assert val_bad["success"] is False

        dl = _decode_tool_result(
            await srv.call_tool(
                "stored_config_manage",
                {"action": "delete", "device_name": "R2", "state_level": "planned"},
            )
        )
        assert dl["data"]["deleted_count"] >= 1

        # 6. lab_failure_drill dry_run=True
        drill = _decode_tool_result(
            await srv.call_tool(
                "lab_failure_drill",
                {
                    "requirements": {
                        "reachable": [
                            {"source": "R1", "destination_ip": "10.99.0.2", "id": "R1_R2"}
                        ]
                    },
                    "break_step": {
                        "device": "R2",
                        "commands": ["interface Gi0/0", "shutdown"],
                        "expected_failing_ids": ["R1_R2"],
                    },
                    "fix_step": {
                        "device": "R2",
                        "commands": ["interface Gi0/0", "no shutdown"],
                    },
                    "dry_run": True,
                },
            )
        )
        assert drill["success"] is True
        assert drill["data"]["dry_run"] is True
        assert drill["state_level"] == "planned"

    asyncio.run(_run())
