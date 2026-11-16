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
    assert len(tool_names) == 82
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
