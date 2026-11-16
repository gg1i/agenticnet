"""MCP tools for topology construction, validation, analysis, export, and visualization."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, Field

from agenticnet.core.enums import PermissionTier, StateLevel
from agenticnet.core.exceptions import ValidationError
from agenticnet.core.models import OperationResult
from agenticnet.mcp.registry import AgenticNetRuntime


class TopologyDeviceSpec(BaseModel):
    """Device entry inside a batch topology_create call."""

    name: str
    model: str
    role: str = ""
    x: float | None = None
    y: float | None = None


class TopologyLinkSpec(BaseModel):
    """Link entry inside a batch topology_create call."""

    source_device: str
    source_interface: str
    target_device: str
    target_interface: str
    cable_type: str = "auto"
    clock_rate: int | None = None


def register_topology_tools(server: MCPServer, runtime: AgenticNetRuntime) -> None:
    """Register topology_* tools onto the MCPServer."""

    def topology_create(
        devices: list[TopologyDeviceSpec],
        connections: list[TopologyLinkSpec] = Field(default_factory=list),
        auto_layout: bool = True,
        layout_strategy: Literal["hierarchical", "grid"] = "hierarchical",
        replace_existing: bool = False,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Build a multi-device topology atomically from device and connection lists."""
        params = {
            "device_count": len(devices),
            "connection_count": len(connections),
            "auto_layout": auto_layout,
            "layout_strategy": layout_strategy,
            "replace_existing": replace_existing,
            "confirm": confirm,
        }
        tier = PermissionTier.DESTRUCTIVE if replace_existing else PermissionTier.PLANNING

        def _run() -> OperationResult:
            _, topo, ipam, _ = runtime.manager.require_active()
            total_devices = len(devices) + (0 if replace_existing else len(topo.model.devices))
            if total_devices > runtime.settings.max_devices_per_project:
                raise ValidationError(
                    "Topology would exceed max_devices_per_project "
                    f"({runtime.settings.max_devices_per_project})."
                )

            # Build in a staged copy so failed links never leave partial corrupt state
            from agenticnet.topology.engine import TopologyEngine
            from agenticnet.topology.models import TopologyModel

            staged = TopologyEngine(
                model=TopologyModel() if replace_existing else topo.model,
                catalog=runtime.catalog,
            )
            for dev in devices:
                staged.add_device(dev.name, dev.model, x=dev.x, y=dev.y, role=dev.role)
            for link in connections:
                staged.connect(
                    link.source_device,
                    link.source_interface,
                    link.target_device,
                    link.target_interface,
                    cable_type=link.cable_type,
                    clock_rate=link.clock_rate,
                )
            if auto_layout:
                staged.auto_layout(strategy=layout_strategy)

            # Commit staged topology
            if replace_existing:
                for dev_name in list(topo.model.devices):
                    ipam.remove_device_allocations(dev_name)
            topo.model = staged.model
            topo._rebuild_graph()
            issues = topo.validate()

            return OperationResult.ok(
                "topology_create",
                f"Built topology with {len(topo.model.devices)} devices and "
                f"{len(topo.model.connections)} links.",
                data={
                    "devices": sorted(topo.model.devices.keys()),
                    "connections": [
                        c.model_dump(mode="json") for c in topo.model.connections.values()
                    ],
                    "validation_issues": [i.model_dump(mode="json") for i in issues],
                },
                state_level=StateLevel.PLANNED,
                warnings=[i.message for i in issues if i.severity == "warning"],
                evidence=[
                    "Validated device models, interfaces, and cable rules in TopologyEngine."
                ],
            )

        return runtime.execute(
            "topology_create",
            tier,
            params,
            _run,
            confirm=confirm,
            destructive_reason=(
                "Replacing an existing topology clears current devices and links; "
                "pass confirm=True."
            ),
        )

    def topology_inspect(include_interfaces: bool = False) -> dict[str, Any]:
        """Inspect all devices, links, coordinates, and state levels in the topology."""

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            devices_out = []
            for name in sorted(topo.model.devices):
                dev = topo.model.devices[name]
                entry: dict[str, Any] = {
                    "name": dev.name,
                    "model": dev.model,
                    "category": dev.category.value,
                    "role": dev.role,
                    "position": dev.position.model_dump(),
                    "state_level": dev.state_level.value,
                    "connected_interfaces": sum(
                        1 for i in dev.interfaces.values() if i.connected_to_connection_id
                    ),
                    "total_interfaces": len(dev.interfaces),
                }
                if include_interfaces:
                    entry["interfaces"] = {
                        k: v.model_dump(mode="json") for k, v in dev.interfaces.items()
                    }
                devices_out.append(entry)

            return OperationResult.ok(
                "topology_inspect",
                f"Topology has {len(devices_out)} devices and "
                f"{len(topo.model.connections)} connections.",
                data={
                    "devices": devices_out,
                    "connections": [
                        c.model_dump(mode="json") for c in topo.model.connections.values()
                    ],
                },
                state_level=StateLevel.PLANNED,
                evidence=["Inspected active TopologyModel."],
            )

        return runtime.execute(
            "topology_inspect",
            PermissionTier.READ_ONLY,
            {"include_interfaces": include_interfaces},
            _run,
        )

    def topology_validate() -> dict[str, Any]:
        """Validate topology graph integrity, serial clocking, link media, and switching loops."""

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            issues = topo.validate()
            errors = [i for i in issues if i.severity == "error"]
            return OperationResult.ok(
                "topology_validate",
                f"Validation found {len(errors)} error(s) and "
                f"{len(issues) - len(errors)} warning/info item(s).",
                data={
                    "valid": len(errors) == 0,
                    "issue_count": len(issues),
                    "issues": [i.model_dump(mode="json") for i in issues],
                },
                state_level=StateLevel.PLANNED,
                warnings=[i.message for i in issues if i.severity == "warning"],
                evidence=["Executed full graph and media consistency checks."],
            )

        return runtime.execute("topology_validate", PermissionTier.READ_ONLY, {}, _run)

    def topology_export(fmt: Literal["json", "yaml"] = "json") -> dict[str, Any]:
        """Export the active topology graph (devices, interfaces, connections) as JSON or YAML."""

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            content = topo.export_data(fmt=fmt)
            return OperationResult.ok(
                "topology_export",
                f"Exported topology as {fmt.upper()}.",
                data={"format": fmt, "content": content},
                state_level=StateLevel.PLANNED,
                evidence=[f"Serialized topology into {fmt}."],
            )

        return runtime.execute("topology_export", PermissionTier.READ_ONLY, {"fmt": fmt}, _run)

    def topology_visualize(
        include_mermaid: bool = True,
        include_ascii: bool = True,
    ) -> dict[str, Any]:
        """Generate Mermaid diagram and ASCII adjacency summary of the active topology."""

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            payload: dict[str, Any] = {
                "device_count": len(topo.model.devices),
                "connection_count": len(topo.model.connections),
            }
            if include_mermaid:
                payload["mermaid"] = topo.to_mermaid()
            if include_ascii:
                payload["ascii"] = topo.to_ascii()
            return OperationResult.ok(
                "topology_visualize",
                f"Generated visualization for {len(topo.model.devices)} devices.",
                data=payload,
                state_level=StateLevel.PLANNED,
                evidence=["Rendered topology visualization from TopologyEngine."],
            )

        return runtime.execute(
            "topology_visualize",
            PermissionTier.READ_ONLY,
            {"include_mermaid": include_mermaid, "include_ascii": include_ascii},
            _run,
        )

    def topology_analyze(
        source_device: str | None = None,
        target_device: str | None = None,
    ) -> dict[str, Any]:
        """Analyze topology with NetworkX: components, SPOFs/bridges, STP cycles, shortest path."""
        params = {"source_device": source_device, "target_device": target_device}

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            analysis = topo.analyze(source=source_device, target=target_device)
            return OperationResult.ok(
                "topology_analyze",
                f"Analyzed topology: {analysis.connected_components} component(s), "
                f"{len(analysis.bridges)} bridge(s), "
                f"{len(analysis.switching_cycles)} L2 cycle(s).",
                data=analysis.model_dump(mode="json"),
                state_level=StateLevel.PLANNED,
                evidence=["Computed graph properties via NetworkX."],
            )

        return runtime.execute("topology_analyze", PermissionTier.READ_ONLY, params, _run)

    specs = [
        (
            "topology_create",
            PermissionTier.PLANNING,
            topology_create.__doc__ or "",
            topology_create,
            False,
            False,
        ),
        (
            "topology_inspect",
            PermissionTier.READ_ONLY,
            topology_inspect.__doc__ or "",
            topology_inspect,
            True,
            False,
        ),
        (
            "topology_validate",
            PermissionTier.READ_ONLY,
            topology_validate.__doc__ or "",
            topology_validate,
            True,
            False,
        ),
        (
            "topology_export",
            PermissionTier.READ_ONLY,
            topology_export.__doc__ or "",
            topology_export,
            True,
            False,
        ),
        (
            "topology_visualize",
            PermissionTier.READ_ONLY,
            topology_visualize.__doc__ or "",
            topology_visualize,
            True,
            False,
        ),
        (
            "topology_analyze",
            PermissionTier.READ_ONLY,
            topology_analyze.__doc__ or "",
            topology_analyze,
            True,
            False,
        ),
    ]
    for name, tier, desc, fn, ro, dest in specs:
        runtime.registry.register_tool(
            server,
            name=name,
            category="topology",
            permission_tier=tier,
            description=desc,
            fn=fn,
            read_only=ro,
            destructive=dest,
        )
