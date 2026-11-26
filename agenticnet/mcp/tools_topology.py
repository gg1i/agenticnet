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
    """Device entry inside a batch topology_create call (with optional host IP/DHCP config)."""

    name: str
    model: str
    role: str = ""
    x: float | None = None
    y: float | None = None
    port: str = "FastEthernet0"
    dhcp: bool = False
    ip_address: str | None = None
    subnet_mask: str | None = None
    default_gateway: str | None = None
    dns_server: str | None = None


class TopologyLinkSpec(BaseModel):
    """Link entry inside a batch topology_create call."""

    source_device: str
    source_interface: str
    target_device: str
    target_interface: str
    cable_type: str = "auto"
    clock_rate: int | None = None


def _resolve_pt_device_type(model: str, category: Any) -> int:
    """Resolve Packet Tracer DeviceType integer accurately for special models like 7960/3650."""
    from agenticnet.adapters.script_bridge import resolve_device_type

    cat_str = category.value if hasattr(category, "value") else str(category)
    model_key = str(model).strip().lower()
    if model_key in {"7960", "ip_phone", "cisco ip phone", "ip phone", "ipphone"}:
        cat_str = "ip_phone"
    elif model_key.startswith("3650"):
        cat_str = "switch_3650"
    elif model_key in {"lap-pt", "lap", "3702i", "air-cap3702i", "cap3702i", "lightweight_ap"}:
        cat_str = "lap"
    elif model_key in {
        "5505",
        "asa 5505",
        "asa5505",
        "5506",
        "5506-x",
        "asa 5506",
        "asa5506",
        "asa 5506-x",
    }:
        cat_str = "asa"
    elif model_key in {"2504", "3504"} or model_key.startswith("wlc"):
        cat_str = "wlc"
    elif model_key.startswith("cloud"):
        cat_str = "cloud"
    elif model_key == "ata" or model_key.startswith(("home-voip", "home_voip", "home voip")):
        cat_str = "home_voip"
    elif model_key.startswith(("analog-phone", "analog_phone", "analog phone")):
        cat_str = "analog_phone"
    elif model_key.startswith("laptop"):
        cat_str = "laptop"
    elif model_key.startswith("tablet"):
        cat_str = "tablet_pc"
    elif model_key.startswith("smartphone"):
        cat_str = "smartphone"
    elif model_key == "dlc100" or model_key.startswith(
        ("homegateway", "home-gateway", "home_gateway", "home gateway")
    ):
        cat_str = "home_gateway"
    elif model_key.startswith("server"):
        cat_str = "server"
    elif model_key.startswith("printer"):
        cat_str = "printer"
    try:
        return resolve_device_type(cat_str)
    except Exception:
        return 0


def register_topology_tools(server: MCPServer, runtime: AgenticNetRuntime) -> None:
    """Register topology_* tools onto the MCPServer."""

    def topology_create(
        devices: list[TopologyDeviceSpec],
        connections: list[TopologyLinkSpec] = Field(default_factory=list),
        auto_layout: bool = True,
        layout_strategy: Literal["hierarchical", "grid"] = "hierarchical",
        replace_existing: bool = False,
        confirm: bool = False,
        apply_live: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Build a multi-device topology and push devices, links, and host configs in 1 batch."""
        params = {
            "device_count": len(devices),
            "connection_count": len(connections),
            "auto_layout": auto_layout,
            "layout_strategy": layout_strategy,
            "replace_existing": replace_existing,
            "confirm": confirm,
            "apply_live": apply_live,
            "dry_run": dry_run,
        }
        has_existing_items = False
        if replace_existing and runtime.manager.has_active_project:
            _, current_topo, _, _ = runtime.manager.require_active()
            has_existing_items = bool(
                current_topo.model.devices or current_topo.model.connections
            )
        tier = (
            PermissionTier.DESTRUCTIVE
            if (replace_existing and has_existing_items)
            else PermissionTier.PLANNING
        )

        def _run() -> OperationResult:
            from contextlib import suppress

            from agenticnet.core.enums import DeviceCategory
            from agenticnet.ipam.engine import IPAMEngine
            from agenticnet.topology.engine import TopologyEngine
            from agenticnet.topology.models import TopologyModel

            _, topo, ipam, _ = runtime.manager.require_active()
            total_devices = len(devices) + (0 if replace_existing else len(topo.model.devices))
            if total_devices > runtime.settings.max_devices_per_project:
                raise ValidationError(
                    "Topology would exceed max_devices_per_project "
                    f"({runtime.settings.max_devices_per_project})."
                )
            total_links = len(connections) + (
                0 if replace_existing else len(topo.model.connections)
            )
            if total_links > runtime.settings.max_links_per_project:
                raise ValidationError(
                    "Topology would exceed max_links_per_project "
                    f"({runtime.settings.max_links_per_project})."
                )

            staged_model = (
                TopologyModel() if replace_existing else topo.model.model_copy(deep=True)
            )
            staged = TopologyEngine(model=staged_model, catalog=runtime.catalog)
            staged_ipam = IPAMEngine(
                state=ipam.state.model_copy(deep=True) if not replace_existing else None
            )
            if replace_existing:
                for dev_name in list(topo.model.devices):
                    staged_ipam.remove_device_allocations(dev_name)

            explicit_positions: dict[str, tuple[float, float]] = {}
            added_dev_names: list[str] = []
            host_specs: dict[str, tuple[TopologyDeviceSpec, str]] = {}
            host_categories = {
                DeviceCategory.PC,
                DeviceCategory.LAPTOP,
                DeviceCategory.SERVER,
                DeviceCategory.PRINTER,
            }

            for dev in devices:
                node = staged.add_device(dev.name, dev.model, x=dev.x, y=dev.y, role=dev.role)
                added_dev_names.append(node.name)
                if dev.x is not None and dev.y is not None:
                    explicit_positions[node.name] = (float(dev.x), float(dev.y))

                has_host_cfg = bool(
                    dev.dhcp
                    or dev.ip_address
                    or dev.subnet_mask
                    or dev.default_gateway
                    or dev.dns_server
                )
                if has_host_cfg:
                    if node.category not in host_categories or node.model == "7960":
                        raise ValidationError(
                            f"Inline host IP/DHCP fields on '{node.name}' ({node.model}) are only "
                            "supported on PC/Laptop/Server/Printer end devices."
                        )
                    if not dev.dhcp and (not dev.ip_address or not dev.subnet_mask):
                        raise ValidationError(
                            f"Host '{node.name}' requires dhcp=True or both ip_address and "
                            "subnet_mask."
                        )
                    canon_port = runtime.catalog.normalize_interface_name(node.model, dev.port)
                    if not dev.dhcp and dev.ip_address and dev.subnet_mask:
                        alloc = staged_ipam.allocate_address(
                            node.name,
                            canon_port,
                            dev.ip_address,
                            subnet_mask=dev.subnet_mask,
                            gateway=dev.default_gateway,
                            allocation_type="static",
                        )
                        if canon_port in node.interfaces:
                            node.interfaces[canon_port].ip_address = alloc.ip_address
                            node.interfaces[canon_port].subnet_mask = alloc.subnet_mask
                            node.interfaces[canon_port].default_gateway = dev.default_gateway
                    elif dev.dhcp and canon_port in node.interfaces:
                        node.interfaces[canon_port].default_gateway = (
                            dev.default_gateway or node.interfaces[canon_port].default_gateway
                        )
                    host_specs[node.name] = (dev, canon_port)

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
                for dev_name, (ex, ey) in explicit_positions.items():
                    staged.move_device(dev_name, ex, ey)

            # Commit staged topology + IPAM atomically
            if replace_existing:
                runtime.router.clear_aliases()
            topo.model = staged.model
            topo._rebuild_graph()
            ipam.state = staged_ipam.state
            issues = topo.validate()

            live_backend_name = "offline_model"
            live_state = StateLevel.PLANNED
            live_ev: list[str] = []
            live_warnings = [i.message for i in issues if i.severity == "warning"]
            live_payload: dict[str, Any] = {}
            batch_errors: list[str] = []

            if apply_live and not dry_run and runtime.router.ensure_live_script():
                from agenticnet.adapters.script_bridge import resolve_connect_type

                ops: list[dict[str, Any]] = []
                op_meta: list[tuple[str, str]] = []

                for d_name in added_dev_names:
                    node = topo.model.devices[d_name]
                    dtype = _resolve_pt_device_type(node.model, node.category)
                    ops.append(
                        {
                            "op": "add_device",
                            "alias": node.name,
                            "params": {
                                "model": node.model,
                                "device_type": dtype,
                                "x": float(node.position.x),
                                "y": float(node.position.y),
                                "display_name": node.name,
                            },
                        }
                    )
                    op_meta.append(("dev", node.name))

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
                    op_meta.append(("link", edge.connection_id))

                for h_name, (h_spec, canon_port) in host_specs.items():
                    ops.append(
                        {
                            "op": "configure_host",
                            "params": {
                                "device_name": h_name,
                                "port": canon_port,
                                "dhcp": bool(h_spec.dhcp),
                                "ip": h_spec.ip_address or "",
                                "subnet_mask": h_spec.subnet_mask or "",
                                "default_gateway": h_spec.default_gateway or "",
                                "dns_server": h_spec.dns_server or "",
                            },
                        }
                    )
                    op_meta.append(("host", h_name))

                batch_res = runtime.router.batch_ops(
                    ops,
                    timeout_seconds=max(25.0, len(ops) * 1.5),
                )
                if batch_res is not None:
                    live_backend_name = "script_backend"
                    live_state = StateLevel.EXECUTED
                    live_payload = batch_res
                    raw_results = batch_res.get("results")
                    failed_devs: set[str] = set()
                    if isinstance(raw_results, list):
                        for idx, (kind_tag, item_id) in enumerate(op_meta):
                            res_item = raw_results[idx] if idx < len(raw_results) else {}
                            if not isinstance(res_item, dict):
                                continue
                            if kind_tag == "dev":
                                res_data = (
                                    res_item.get("data")
                                    if isinstance(res_item.get("data"), dict)
                                    else {}
                                )
                                pt_name = str(
                                    res_item.get("device_name")
                                    or res_data.get("device_name")
                                    or ""
                                ).strip()
                                if res_item.get("ok") is False or not pt_name:
                                    failed_devs.add(item_id)
                                    err = str(
                                        res_item.get("error")
                                        or f"Packet Tracer failed to create device '{item_id}'."
                                    )
                                    batch_errors.append(err)
                                    with suppress(Exception):
                                        topo.remove_device(item_id)
                                        ipam.remove_device_allocations(item_id)
                            elif kind_tag == "link":
                                lnk = topo.model.connections.get(item_id)
                                if lnk is None or (
                                    lnk.source_device in failed_devs
                                    or lnk.target_device in failed_devs
                                ):
                                    with suppress(Exception):
                                        topo.remove_connection(item_id)
                                elif res_item.get("ok") is False:
                                    err = str(
                                        res_item.get("error")
                                        or f"Packet Tracer rejected link '{item_id}'."
                                    )
                                    batch_errors.append(err)
                                    with suppress(Exception):
                                        topo.remove_connection(item_id)
                            elif kind_tag == "host" and res_item.get("ok") is False:
                                err = str(
                                    res_item.get("error")
                                    or f"Packet Tracer failed host config on '{item_id}'."
                                )
                                live_warnings.append(err)

                    live_ev.append(
                        f"Deployed {len(added_dev_names) - len(failed_devs)} device(s), "
                        f"{len(topo.model.connections)} link(s), and {len(host_specs)} host(s) "
                        "to Packet Tracer in 1 batch_ops round-trip."
                    )
                    if runtime.router.watch_mode:
                        runtime.router.record_watch_action(
                            "topology_create",
                            (
                                f"Batch-created {len(added_dev_names)} device(s) and "
                                f"{len(added_links)} link(s)."
                            ),
                            data=live_payload,
                            evidence=live_ev,
                        )
                else:
                    # Fallback when running an older bridge without batch_ops
                    failed_devs = set()
                    for d_name in added_dev_names:
                        node = topo.model.devices[d_name]
                        b, add_res, ev, w = runtime.router.add_device(
                            node.name,
                            node.model,
                            category=node.category,
                            x=node.position.x,
                            y=node.position.y,
                        )
                        if b == "script_backend":
                            live_backend_name = "script_backend"
                            live_state = StateLevel.EXECUTED
                        if add_res.get("ok") is False or (
                            b == "script_backend"
                            and not str(add_res.get("device_name", "")).strip()
                        ):
                            failed_devs.add(d_name)
                            batch_errors.append(
                                str(add_res.get("error") or f"Failed to add '{d_name}' in PT.")
                            )
                            with suppress(Exception):
                                topo.remove_device(d_name)
                                ipam.remove_device_allocations(d_name)
                        live_ev.extend(ev)
                        live_warnings.extend(w)
                    for edge in added_links:
                        if edge.source_device in failed_devs or edge.target_device in failed_devs:
                            with suppress(Exception):
                                topo.remove_connection(edge.connection_id)
                            continue
                        b, lnk_res, ev, w = runtime.router.create_link(
                            edge.source_device,
                            edge.source_interface,
                            edge.target_device,
                            edge.target_interface,
                            cable_type=edge.cable_type.value,
                        )
                        if lnk_res.get("ok") is False:
                            batch_errors.append(
                                str(
                                    lnk_res.get("error")
                                    or f"Failed link '{edge.connection_id}' in PT."
                                )
                            )
                            with suppress(Exception):
                                topo.remove_connection(edge.connection_id)
                        live_ev.extend(ev)
                        live_warnings.extend(w)
                    for h_name, (h_spec, canon_port) in host_specs.items():
                        if h_name in failed_devs:
                            continue
                        _, _, ev, w = runtime.router.configure_host(
                            h_name,
                            port=canon_port,
                            dhcp=bool(h_spec.dhcp),
                            ip=h_spec.ip_address,
                            subnet_mask=h_spec.subnet_mask,
                            default_gateway=h_spec.default_gateway,
                            dns_server=h_spec.dns_server,
                            console_engine=runtime.console,
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

            if batch_errors:
                return OperationResult.fail(
                    "topology_create",
                    f"Live batch topology deployment encountered {len(batch_errors)} error(s): "
                    + "; ".join(batch_errors[:5]),
                    error_code="PT_BATCH_FAILED",
                    details=out_data,
                    remediation=(
                        "Verify device models, free port names, and PT readiness, then retry."
                    ),
                    state_level=live_state,
                    execution_backend=live_backend_name,  # type: ignore[arg-type]
                )

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
