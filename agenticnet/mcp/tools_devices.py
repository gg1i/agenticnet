"""MCP tools for device lifecycle and capability queries (category: devices)."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from agenticnet.core.enums import DeviceCategory, PermissionTier, StateLevel
from agenticnet.core.exceptions import ValidationError
from agenticnet.core.models import OperationResult
from agenticnet.mcp.registry import AgenticNetRuntime


def register_device_tools(server: MCPServer, runtime: AgenticNetRuntime) -> None:
    """Register device_* tools onto the MCPServer."""

    def device_add(
        name: str,
        model: str,
        role: str = "",
        x: float | None = None,
        y: float | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Add a network device using a verified Packet Tracer model from the DeviceCatalog."""
        params = {"name": name, "model": model, "role": role, "x": x, "y": y, "dry_run": dry_run}

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            if len(topo.model.devices) >= runtime.settings.max_devices_per_project:
                raise ValidationError(
                    f"Device limit reached ({runtime.settings.max_devices_per_project})."
                )
            node = topo.add_device(name, model, x=x, y=y, role=role)
            backend, live_res, live_ev, warnings = runtime.router.add_device(
                node.name,
                node.model,
                category=node.category,
                x=node.position.x,
                y=node.position.y,
                dry_run=dry_run,
            )
            if live_res.get("ok") is False or (
                backend == "script_backend" and not str(live_res.get("device_name", "")).strip()
            ):
                topo.remove_device(node.name)
                return OperationResult.fail(
                    "device_add",
                    str(live_res.get("error") or f"Failed to add '{node.model}' in Packet Tracer."),
                    error_code="PT_EMPTY_DEVICE_NAME",
                    details=live_res,
                    remediation=(
                        "Verify the Packet Tracer model name and ensure Packet Tracer workspace "
                        "finished initializing before retrying."
                    ),
                    state_level=StateLevel.PLANNED,
                    execution_backend="script_backend",
                )
            payload = node.model_dump(mode="json")
            if live_res:
                payload["live_backend"] = live_res
            lvl = StateLevel.EXECUTED if backend == "script_backend" else StateLevel.PLANNED
            evidence = [
                f"Verified model '{node.model}' in DeviceCatalog and added to TopologyEngine.",
                *live_ev,
            ]
            return OperationResult.ok(
                "device_add",
                f"Added '{node.name}' ({node.model}) with {len(node.interfaces)} port(s).",
                data=payload,
                state_level=lvl,
                execution_backend=backend,
                warnings=warnings,
                evidence=evidence,
            )

        return runtime.execute("device_add", PermissionTier.PLANNING, params, _run)

    def device_remove(name: str, confirm: bool = False) -> dict[str, Any]:
        """Remove a device, its links, and its IPAM allocations from the active topology."""
        params = {"name": name, "confirm": confirm}

        def _run() -> OperationResult:
            _, topo, ipam, _ = runtime.manager.require_active()
            removed = topo.remove_device(name)
            removed_ips = ipam.remove_device_allocations(name)
            return OperationResult.ok(
                "device_remove",
                f"Removed device '{name}', {len(removed['removed_connections'])} link(s), "
                f"and {removed_ips} IP allocation(s).",
                data={**removed, "removed_ip_allocations": removed_ips},
                state_level=StateLevel.PLANNED,
                evidence=[f"Removed '{name}' from TopologyEngine and IPAMEngine."],
            )

        return runtime.execute(
            "device_remove",
            PermissionTier.DESTRUCTIVE,
            params,
            _run,
            confirm=confirm,
            destructive_reason=(
                f"Removing device '{name}' deletes all attached links and IP bindings; "
                "pass confirm=True."
            ),
        )

    def device_inspect(name: str) -> dict[str, Any]:
        """Inspect a device's interfaces, IP allocations, capabilities, and config snapshots."""

        def _run() -> OperationResult:
            _, topo, ipam, history = runtime.manager.require_active()
            node = topo.get_device(name)
            cap = runtime.catalog.capability_report(node.model)
            ips = [
                a.model_dump(mode="json")
                for a in ipam.state.allocations.values()
                if a.device_name == node.name
            ]
            snaps = [
                {
                    "snapshot_id": s.snapshot_id,
                    "state_level": s.state_level.value,
                    "source": s.source,
                    "note": s.note,
                    "created_at": s.created_at.isoformat(),
                }
                for s in history.list_snapshots(node.name)
            ]
            return OperationResult.ok(
                "device_inspect",
                f"Inspected '{node.name}' ({node.model}).",
                data={
                    "device": node.model_dump(mode="json"),
                    "capabilities": cap.model_dump(mode="json"),
                    "ip_allocations": ips,
                    "config_snapshots": snaps,
                },
                state_level=node.state_level,
                evidence=[
                    f"Inspected '{node.name}' across Topology, IPAM, Catalog, and ConfigHistory."
                ],
            )

        return runtime.execute("device_inspect", PermissionTier.READ_ONLY, {"name": name}, _run)

    def device_move(
        name: str | None = None,
        x: float | None = None,
        y: float | None = None,
        auto_layout_strategy: Literal["hierarchical", "grid"] | None = None,
    ) -> dict[str, Any]:
        """Move a specific device to (x, y) or run auto-layout on the whole topology."""
        params = {"name": name, "x": x, "y": y, "auto_layout_strategy": auto_layout_strategy}

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            if auto_layout_strategy is not None:
                positions = topo.auto_layout(strategy=auto_layout_strategy)
                return OperationResult.ok(
                    "device_move",
                    f"Applied '{auto_layout_strategy}' layout to {len(positions)} devices.",
                    data={"positions": {k: v.model_dump() for k, v in positions.items()}},
                    state_level=StateLevel.PLANNED,
                    evidence=[f"Computed '{auto_layout_strategy}' layout coordinates."],
                )

            if name is None or x is None or y is None:
                raise ValidationError(
                    "Provide either (name, x, y) to move one device or auto_layout_strategy."
                )
            node = topo.move_device(name, x, y)
            return OperationResult.ok(
                "device_move",
                f"Moved '{node.name}' to ({node.position.x}, {node.position.y}).",
                data={"name": node.name, "position": node.position.model_dump()},
                state_level=StateLevel.PLANNED,
                evidence=[f"Updated coordinates of '{node.name}'."],
            )

        return runtime.execute("device_move", PermissionTier.PLANNING, params, _run)

    def device_list(category: str | None = None) -> dict[str, Any]:
        """List devices in the active project, optionally filtered by category."""

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            cat_filter = DeviceCategory(category) if category else None
            devices = [
                {
                    "name": d.name,
                    "model": d.model,
                    "category": d.category.value,
                    "role": d.role,
                    "position": d.position.model_dump(),
                    "state_level": d.state_level.value,
                }
                for d in sorted(topo.model.devices.values(), key=lambda x: x.name)
                if cat_filter is None or d.category == cat_filter
            ]
            return OperationResult.ok(
                "device_list",
                f"Found {len(devices)} device(s).",
                data={"devices": devices, "count": len(devices)},
                state_level=StateLevel.PLANNED,
                evidence=["Listed devices from TopologyEngine."],
            )

        return runtime.execute(
            "device_list", PermissionTier.READ_ONLY, {"category": category}, _run
        )

    def device_capabilities(
        model: str | None = None,
        category: str | None = None,
    ) -> dict[str, Any]:
        """Query verified Packet Tracer models, interfaces, capabilities, and restrictions."""
        params = {"model": model, "category": category}

        def _run() -> OperationResult:
            if model is not None:
                report = runtime.catalog.capability_report(model)
                return OperationResult.ok(
                    "device_capabilities",
                    f"Capability report for '{report.model}' ({report.display_name}).",
                    data=report.model_dump(mode="json"),
                    state_level=StateLevel.VERIFIED,
                    evidence=[f"Read verified DeviceCatalog profile for '{report.model}'."],
                )

            cat_filter = DeviceCategory(category) if category else None
            reports = [
                runtime.catalog.capability_report(p.model).model_dump(mode="json")
                for p in runtime.catalog.list_profiles(category=cat_filter)
            ]
            return OperationResult.ok(
                "device_capabilities",
                f"Returned {len(reports)} verified Packet Tracer device model(s).",
                data={"models": reports, "count": len(reports)},
                state_level=StateLevel.VERIFIED,
                evidence=["Read verified DeviceCatalog registry."],
            )

        return runtime.execute("device_capabilities", PermissionTier.READ_ONLY, params, _run)

    def host_configure(
        device_name: str,
        port: str = "FastEthernet0",
        dhcp: bool = False,
        ip_address: str | None = None,
        subnet_mask: str | None = None,
        default_gateway: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Configure DHCP or static IPv4/mask/gateway on a PC/Laptop/Server in PT & topology."""
        params = {
            "device_name": device_name,
            "port": port,
            "dhcp": dhcp,
            "ip_address": ip_address,
            "subnet_mask": subnet_mask,
            "default_gateway": default_gateway,
            "dry_run": dry_run,
        }

        def _run() -> OperationResult:
            if not dhcp and (not ip_address or not subnet_mask):
                raise ValidationError(
                    "Provide dhcp=True, or both ip_address and subnet_mask for static host setup."
                )
            _, topo, ipam, _ = runtime.manager.require_active()
            dev = topo.get_device(device_name)
            canon_port = runtime.catalog.normalize_interface_name(dev.model, port)
            backend, live_res, ev, warnings = runtime.router.configure_host(
                dev.name,
                port=canon_port,
                dhcp=dhcp,
                ip=ip_address,
                subnet_mask=subnet_mask,
                default_gateway=default_gateway,
                console_engine=runtime.console,
                dry_run=dry_run,
            )
            if not dry_run and canon_port in dev.interfaces:
                iface = dev.interfaces[canon_port]
                if not dhcp and ip_address and subnet_mask:
                    alloc = ipam.allocate_address(
                        dev.name,
                        canon_port,
                        ip_address,
                        subnet_mask=subnet_mask,
                        gateway=default_gateway,
                        allocation_type="static",
                    )
                    iface.ip_address = alloc.ip_address
                    iface.subnet_mask = alloc.subnet_mask
                    iface.default_gateway = default_gateway
                elif dhcp:
                    iface.default_gateway = default_gateway or iface.default_gateway
            lvl = StateLevel.EXECUTED if backend == "script_backend" else StateLevel.PLANNED
            mode_label = "DHCP" if dhcp else f"{ip_address}/{subnet_mask}"
            return OperationResult.ok(
                "host_configure",
                f"Configured host '{dev.name}' ({canon_port}) via {mode_label}.",
                data={"device_name": dev.name, "port": canon_port, "live_backend": live_res},
                state_level=lvl,
                execution_backend=backend,
                warnings=warnings,
                evidence=ev or [f"Updated host '{dev.name}:{canon_port}' configuration."],
            )

        return runtime.execute("host_configure", PermissionTier.CONFIGURATION, params, _run)

    specs = [
        ("device_add", PermissionTier.PLANNING, device_add.__doc__ or "", device_add, False, False),
        (
            "host_configure",
            PermissionTier.CONFIGURATION,
            host_configure.__doc__ or "",
            host_configure,
            False,
            False,
        ),
        (
            "device_remove",
            PermissionTier.DESTRUCTIVE,
            device_remove.__doc__ or "",
            device_remove,
            False,
            True,
        ),
        (
            "device_inspect",
            PermissionTier.READ_ONLY,
            device_inspect.__doc__ or "",
            device_inspect,
            True,
            False,
        ),
        (
            "device_move",
            PermissionTier.PLANNING,
            device_move.__doc__ or "",
            device_move,
            False,
            False,
        ),
        (
            "device_list",
            PermissionTier.READ_ONLY,
            device_list.__doc__ or "",
            device_list,
            True,
            False,
        ),
        (
            "device_capabilities",
            PermissionTier.READ_ONLY,
            device_capabilities.__doc__ or "",
            device_capabilities,
            True,
            False,
        ),
    ]
    for name, tier, desc, fn, ro, dest in specs:
        runtime.registry.register_tool(
            server,
            name=name,
            category="devices",
            permission_tier=tier,
            description=desc,
            fn=fn,
            read_only=ro,
            destructive=dest,
        )
