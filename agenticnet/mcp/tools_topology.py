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
        apply_live: bool = False,
    ) -> dict[str, Any]:
        """Build a multi-device topology; set apply_live=True to push to PT in 1 batch."""
        params = {
            "device_count": len(devices),
            "connection_count": len(connections),
            "auto_layout": auto_layout,
            "layout_strategy": layout_strategy,
            "replace_existing": replace_existing,
            "confirm": confirm,
            "apply_live": apply_live,
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
            added_dev_names: list[str] = []
            for dev in devices:
                staged.add_device(dev.name, dev.model, x=dev.x, y=dev.y, role=dev.role)
                added_dev_names.append(dev.name)
            added_links = []
            for link in connections:
                edge = staged.connect(
                    link.source_device,
                    link.source_interface,
                    link.target_device,
                    link.target_interface,
                    cable_type=link.cable_type,
                    clock_rate=link.clock_rate,
                )
                added_links.append(edge)
            if auto_layout:
                staged.auto_layout(strategy=layout_strategy)

            # Commit staged topology
            if replace_existing:
                for dev_name in list(topo.model.devices):
                    ipam.remove_device_allocations(dev_name)
            topo.model = staged.model
            topo._rebuild_graph()
            issues = topo.validate()

            live_backend_name = "offline_model"
            live_state = StateLevel.PLANNED
            live_ev: list[str] = []
            live_warnings = [i.message for i in issues if i.severity == "warning"]
            live_payload: dict[str, Any] = {}

            if apply_live and runtime.router.ensure_live_script():
                from agenticnet.adapters.script_bridge import (
                    resolve_connect_type,
                    resolve_device_type,
                )

                ops: list[dict[str, Any]] = []
                for d_name in added_dev_names:
                    node = topo.model.devices[d_name]
                    try:
                        dtype = resolve_device_type(node.category.value)
                    except Exception:
                        dtype = 0
                    ops.append(
                        {
                            "op": "add_device",
                            "params": {
                                "model": node.model,
                                "device_type": dtype,
                                "x": node.position.x,
                                "y": node.position.y,
                                "display_name": node.name,
                                "alias": node.name,
                            },
                        }
                    )
                for edge in added_links:
                    try:
                        ctype = resolve_connect_type(edge.cable_type.value)
                    except Exception:
                        ctype = 8107
                    d1, p1 = edge.source_device, edge.source_interface
                    d2, p2 = edge.target_device, edge.target_interface
                    if edge.cable_type.value == "serial_dte":
                        d1, p1, d2, p2 = d2, p2, d1, p1
                    ops.append(
                        {
                            "op": "create_link",
                            "params": {
                                "device1": d1,
                                "port1": p1,
                                "device2": d2,
                                "port2": p2,
                                "conn_type": ctype,
                            },
                        }
                    )

                batch_res = runtime.router.batch_ops(ops)
                if batch_res is not None:
                    live_backend_name = "script_backend"
                    live_state = StateLevel.EXECUTED
                    live_payload = batch_res
                    live_ev.append(
                        f"Deployed {len(added_dev_names)} device(s) and {len(added_links)} link(s) "
                        "to Packet Tracer in 1 batch_ops round-trip."
                    )
                else:
                    # Fallback when running an older bridge without batch_ops
                    for d_name in added_dev_names:
                        node = topo.model.devices[d_name]
                        b, _, ev, w = runtime.router.add_device(
                            node.name,
                            node.model,
                            category=node.category,
                            x=node.position.x,
                            y=node.position.y,
                        )
                        if b == "script_backend":
                            live_backend_name = "script_backend"
                            live_state = StateLevel.EXECUTED
                        live_ev.extend(ev)
                        live_warnings.extend(w)
                    for edge in added_links:
                        b, _, ev, w = runtime.router.create_link(
                            edge.source_device,
                            edge.source_interface,
                            edge.target_device,
                            edge.target_interface,
                            cable_type=edge.cable_type.value,
                        )
                        live_ev.extend(ev)
                        live_warnings.extend(w)

            out_data: dict[str, Any] = {
                "devices": sorted(topo.model.devices.keys()),
                "connections": [
                    c.model_dump(mode="json") for c in topo.model.connections.values()
                ],
                "validation_issues": [i.model_dump(mode="json") for i in issues],
            }
            if live_payload:
                out_data["live_backend"] = live_payload

            return OperationResult.ok(
                "topology_create",
                f"Built topology with {len(topo.model.devices)} devices and "
                f"{len(topo.model.connections)} links.",
                data=out_data,
                state_level=live_state,
                execution_backend=live_backend_name,  # type: ignore[arg-type]
                warnings=live_warnings,
                evidence=[
                    "Validated device models, interfaces, and cable rules in TopologyEngine.",
                    *live_ev,
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

    def topology_merge(
        devices: list[TopologyDeviceSpec] = Field(default_factory=list),
        connections: list[TopologyLinkSpec] = Field(default_factory=list),
        topology_payload: dict[str, Any] | None = None,
        overwrite_interfaces: bool = True,
        push_live: bool = False,
    ) -> dict[str, Any]:
        """Incrementally merge devices, interfaces, and links into the active topology."""
        params = {
            "device_count": len(devices),
            "connection_count": len(connections),
            "has_payload": topology_payload is not None,
            "overwrite_interfaces": overwrite_interfaces,
            "push_live": push_live,
        }

        def _run() -> OperationResult:
            from agenticnet.core.models import ExecutionBackend
            from agenticnet.topology.engine import TopologyEngine
            from agenticnet.topology.models import TopologyModel

            _, topo, _, _ = runtime.manager.require_active()
            staged = TopologyEngine(
                model=topo.model.model_copy(deep=True),
                catalog=runtime.catalog,
            )

            merged_summary: dict[str, list[str]] = {
                "devices_added": [],
                "devices_updated": [],
                "connections_added": [],
            }
            if topology_payload is not None:
                incoming_model = TopologyModel.model_validate(topology_payload)
                res_payload = staged.merge_topology(
                    incoming_model, overwrite_interfaces=overwrite_interfaces
                )
                merged_summary["devices_added"].extend(res_payload["devices_added"])
                merged_summary["devices_updated"].extend(res_payload["devices_updated"])
                merged_summary["connections_added"].extend(res_payload["connections_added"])

            if devices:
                dev_engine = TopologyEngine(
                    model=TopologyModel(target_mode=staged.model.target_mode),
                    catalog=runtime.catalog,
                )
                for d_spec in devices:
                    dev_engine.add_device(
                        d_spec.name, d_spec.model, x=d_spec.x, y=d_spec.y, role=d_spec.role
                    )
                res_devs = staged.merge_topology(
                    dev_engine.model, overwrite_interfaces=overwrite_interfaces
                )
                for name in res_devs["devices_added"]:
                    if name not in merged_summary["devices_added"]:
                        merged_summary["devices_added"].append(name)
                for name in res_devs["devices_updated"]:
                    if name not in merged_summary["devices_updated"]:
                        merged_summary["devices_updated"].append(name)

            existing_pairs = {
                tuple(
                    sorted(
                        (
                            (lnk.source_device, lnk.source_interface),
                            (lnk.target_device, lnk.target_interface),
                        )
                    )
                )
                for lnk in staged.model.connections.values()
            }
            for link in connections:
                src_dev = staged.get_device(link.source_device)
                dst_dev = staged.get_device(link.target_device)
                src_if = runtime.catalog.normalize_interface_name(
                    src_dev.model, link.source_interface, allow_logical=False
                )
                dst_if = runtime.catalog.normalize_interface_name(
                    dst_dev.model, link.target_interface, allow_logical=False
                )
                pair_key = tuple(sorted(((src_dev.name, src_if), (dst_dev.name, dst_if))))
                if pair_key in existing_pairs:
                    continue
                edge = staged.connect(
                    src_dev.name,
                    src_if,
                    dst_dev.name,
                    dst_if,
                    cable_type=link.cable_type,
                    clock_rate=link.clock_rate,
                )
                existing_pairs.add(pair_key)
                merged_summary["connections_added"].append(edge.connection_id)

            if len(staged.model.devices) > runtime.settings.max_devices_per_project:
                raise ValidationError(
                    "Merged topology would exceed max_devices_per_project "
                    f"({runtime.settings.max_devices_per_project})."
                )
            if len(staged.model.connections) > runtime.settings.max_links_per_project:
                raise ValidationError(
                    "Merged topology would exceed max_links_per_project "
                    f"({runtime.settings.max_links_per_project})."
                )

            topo.model = staged.model
            topo._rebuild_graph()

            backend: ExecutionBackend = "offline_model"
            lvl = StateLevel.PLANNED
            evidence = [
                f"Merged +{len(merged_summary['devices_added'])} device(s), "
                f"~{len(merged_summary['devices_updated'])} updated, "
                f"+{len(merged_summary['connections_added'])} link(s)."
            ]
            warnings: list[str] = []

            if push_live:
                for d_name in merged_summary["devices_added"]:
                    node = topo.get_device(d_name)
                    b_dev, _, ev_d, w_d = runtime.router.add_device(
                        node.name,
                        node.model,
                        category=node.category,
                        x=node.position.x,
                        y=node.position.y,
                    )
                    if b_dev == "script_backend":
                        backend = "script_backend"
                        lvl = StateLevel.EXECUTED
                    evidence.extend(ev_d)
                    warnings.extend(w_d)
                for conn_id in merged_summary["connections_added"]:
                    lnk = topo.model.connections[conn_id]
                    b_lnk, _, ev_l, w_l = runtime.router.create_link(
                        lnk.source_device,
                        lnk.source_interface,
                        lnk.target_device,
                        lnk.target_interface,
                        cable_type=lnk.cable_type.value,
                    )
                    if b_lnk == "script_backend":
                        backend = "script_backend"
                        lvl = StateLevel.EXECUTED
                    evidence.extend(ev_l)
                    warnings.extend(w_l)

            return OperationResult.ok(
                "topology_merge",
                (
                    f"Merged topology: +{len(merged_summary['devices_added'])} device(s), "
                    f"+{len(merged_summary['connections_added'])} connection(s)."
                ),
                data={
                    **merged_summary,
                    "total_devices": len(topo.model.devices),
                    "total_connections": len(topo.model.connections),
                },
                state_level=lvl,
                execution_backend=backend,
                warnings=warnings,
                evidence=evidence,
            )

        return runtime.execute("topology_merge", PermissionTier.PLANNING, params, _run)

    def topology_diff(
        other_topology: dict[str, Any] | None = None,
        other_project_id: str | None = None,
    ) -> dict[str, Any]:
        """Compute structural device, interface, and link differences against another topology."""
        params = {
            "has_other_topology": other_topology is not None,
            "other_project_id": other_project_id,
        }

        def _run() -> OperationResult:
            from agenticnet.topology.models import TopologyModel

            _, topo, _, _ = runtime.manager.require_active()
            if other_topology is not None:
                target_model = TopologyModel.model_validate(other_topology)
            elif other_project_id is not None:
                other_bundle = runtime.manager.store.load_bundle(other_project_id)
                target_model = other_bundle.topology
            else:
                raise ValidationError(
                    "Provide either other_topology (TopologyModel dict) or other_project_id."
                )
            diff = topo.diff_topology(target_model)
            msg = (
                "Topologies are structurally identical."
                if diff["identical"]
                else (
                    f"Topology diff: +{len(diff['devices_added'])}/-{len(diff['devices_removed'])} "
                    f"device(s), +{len(diff['links_added'])}/-{len(diff['links_removed'])} link(s)."
                )
            )
            return OperationResult.ok(
                "topology_diff",
                msg,
                data=diff,
                state_level=StateLevel.PLANNED,
                evidence=["Computed structural diff via TopologyEngine.diff_topology."],
            )

        return runtime.execute("topology_diff", PermissionTier.READ_ONLY, params, _run)

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
            "topology_merge",
            PermissionTier.PLANNING,
            topology_merge.__doc__ or "",
            topology_merge,
            False,
            False,
        ),
        (
            "topology_diff",
            PermissionTier.READ_ONLY,
            topology_diff.__doc__ or "",
            topology_diff,
            True,
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
