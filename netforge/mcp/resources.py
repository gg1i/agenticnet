"""MCP resources exposing NetForge capability manifest, project state, IPAM, and logs."""

from __future__ import annotations

import json

from mcp.server.mcpserver import MCPServer

from netforge.mcp.registry import NetForgeRuntime


def register_resources(server: MCPServer, runtime: NetForgeRuntime) -> None:
    """Register read-only MCP resources on the MCPServer."""

    uris = [
        "netforge://manifest",
        "netforge://project/current",
        "netforge://project/topology",
        "netforge://project/ipam",
        "netforge://devices/catalog",
        "netforge://logs/recent",
    ]
    runtime.registry.resource_uris.extend(uris)

    @server.resource(
        "netforge://manifest",
        name="manifest",
        description="Machine-readable NetForge MCP capability manifest, tools, and device support.",
        mime_type="application/json",
    )
    def resource_manifest() -> str:
        return json.dumps(runtime.build_manifest(), indent=2)

    @server.resource(
        "netforge://project/current",
        name="current_project",
        description="Active project status with Planned vs Executed vs Verified state counts.",
        mime_type="application/json",
    )
    def resource_current_project() -> str:
        return json.dumps(runtime.manager.status_summary(), indent=2)

    @server.resource(
        "netforge://project/topology",
        name="project_topology",
        description="Current normalized topology JSON for the active NetForge project.",
        mime_type="application/json",
    )
    def resource_project_topology() -> str:
        if not runtime.manager.has_active_project:
            return json.dumps({"active_project": None, "devices": {}, "connections": {}}, indent=2)
        _, topo, _, _ = runtime.manager.require_active()
        return topo.export_data(fmt="json")

    @server.resource(
        "netforge://project/ipam",
        name="project_ipam",
        description="Current IPAM pools, allocations, utilization, and validation checks.",
        mime_type="application/json",
    )
    def resource_project_ipam() -> str:
        if not runtime.manager.has_active_project:
            return json.dumps({"active_project": None, "pools": [], "allocations": []}, indent=2)
        _, _, ipam, _ = runtime.manager.require_active()
        return ipam.utilization_report().model_dump_json(indent=2)

    @server.resource(
        "netforge://devices/catalog",
        name="device_catalog",
        description="Verified Packet Tracer device profiles, ports, and protocol capabilities.",
        mime_type="application/json",
    )
    def resource_device_catalog() -> str:
        reports = [
            runtime.catalog.capability_report(p.model).model_dump(mode="json")
            for p in runtime.catalog.list_profiles()
        ]
        return json.dumps({"models": reports}, indent=2)

    @server.resource(
        "netforge://logs/recent",
        name="recent_logs",
        description="Recent redacted execution audit log entries from SQLite.",
        mime_type="application/json",
    )
    def resource_recent_logs() -> str:
        logs = runtime.manager.store.list_execution_logs(
            project_id=runtime.manager.active_project_id,
            limit=50,
        )
        return json.dumps({"logs": logs}, indent=2)
