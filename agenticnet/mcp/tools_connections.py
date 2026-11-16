"""MCP tools for link connections and interface inspection (category: connections)."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from agenticnet.core.enums import PermissionTier, StateLevel
from agenticnet.core.exceptions import InterfaceError, ValidationError
from agenticnet.core.models import OperationResult
from agenticnet.mcp.registry import AgenticNetRuntime


def register_connection_tools(server: MCPServer, runtime: AgenticNetRuntime) -> None:
    """Register connection_* and interface_* tools onto the MCPServer."""

    def connection_create(
        source_device: str,
        source_interface: str,
        target_device: str,
        target_interface: str,
        cable_type: str = "auto",
        clock_rate: int | None = None,
        notes: str = "",
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Connect two device interfaces with media validation and automatic cable selection."""
        params = {
            "source_device": source_device,
            "source_interface": source_interface,
            "target_device": target_device,
            "target_interface": target_interface,
            "cable_type": cable_type,
            "clock_rate": clock_rate,
            "notes": notes,
            "dry_run": dry_run,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            if len(topo.model.connections) >= runtime.settings.max_links_per_project:
                raise ValidationError(
                    f"Link limit reached ({runtime.settings.max_links_per_project})."
                )
            link = topo.connect(
                source_device,
                source_interface,
                target_device,
                target_interface,
                cable_type=cable_type,
                clock_rate=clock_rate,
                notes=notes,
            )
            backend, live_res, live_ev, warnings = runtime.router.create_link(
                link.source_device,
                link.source_interface,
                link.target_device,
                link.target_interface,
                cable_type=link.cable_type.value,
                dry_run=dry_run,
            )
            if live_res.get("ok") is False or (
                backend == "script_backend" and warnings and not live_ev
            ):
                topo.remove_connection(link.connection_id)
                return OperationResult.fail(
                    "connection_create",
                    str(
                        live_res.get("error")
                        or (warnings[0] if warnings else "Packet Tracer rejected link creation.")
                    ),
                    error_code="PT_LINK_FAILED",
                    details=live_res,
                    remediation=(
                        "Verify both device names and interface names exist and are free in PT."
                    ),
                    state_level=StateLevel.PLANNED,
                    execution_backend=backend,
                )
            payload = link.model_dump(mode="json")
            if live_res:
                payload["live_backend"] = live_res
            lvl = StateLevel.EXECUTED if backend == "script_backend" else StateLevel.PLANNED
            return OperationResult.ok(
                "connection_create",
                f"Connected {link.source_device}:{link.source_interface} <-> "
                f"{link.target_device}:{link.target_interface} ({link.cable_type.value}).",
                data=payload,
                state_level=lvl,
                execution_backend=backend,
                warnings=warnings,
                evidence=[
                    "Validated port availability, media match, and MDI/MDI-X cable rule.",
                    *live_ev,
                ],
            )

        return runtime.execute("connection_create", PermissionTier.PLANNING, params, _run)

    def connection_remove(connection_id: str, confirm: bool = False) -> dict[str, Any]:
        """Disconnect a link by connection_id and free both endpoint interfaces."""
        params = {"connection_id": connection_id, "confirm": confirm}

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            removed = topo.remove_connection(connection_id)
            return OperationResult.ok(
                "connection_remove",
                f"Removed connection '{connection_id}' "
                f"({removed.source_device}:{removed.source_interface} <-> "
                f"{removed.target_device}:{removed.target_interface}).",
                data=removed.model_dump(mode="json"),
                state_level=StateLevel.PLANNED,
                evidence=[f"Removed link '{connection_id}' and freed endpoint ports."],
            )

        return runtime.execute(
            "connection_remove",
            PermissionTier.DESTRUCTIVE,
            params,
            _run,
            confirm=confirm,
            destructive_reason=(
                f"Removing connection '{connection_id}' breaks network topology link; "
                "pass confirm=True."
            ),
        )

    def connection_inspect(connection_id: str | None = None) -> dict[str, Any]:
        """Inspect one connection by ID or list all connections in the active topology."""

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            if connection_id is not None:
                link = topo.model.connections.get(connection_id)
                if link is None:
                    raise ValidationError(f"Connection '{connection_id}' not found.")
                return OperationResult.ok(
                    "connection_inspect",
                    f"Inspected connection '{connection_id}'.",
                    data=link.model_dump(mode="json"),
                    state_level=link.state_level,
                    evidence=[f"Inspected link '{connection_id}'."],
                )
            links = [c.model_dump(mode="json") for c in topo.model.connections.values()]
            return OperationResult.ok(
                "connection_inspect",
                f"Found {len(links)} connection(s).",
                data={"connections": links, "count": len(links)},
                state_level=StateLevel.PLANNED,
                evidence=["Listed all connections from TopologyEngine."],
            )

        return runtime.execute(
            "connection_inspect",
            PermissionTier.READ_ONLY,
            {"connection_id": connection_id},
            _run,
        )

    def interface_list(device_name: str, only_free: bool = False) -> dict[str, Any]:
        """List physical interfaces of a device with occupancy, peer, and IP status."""
        params = {"device_name": device_name, "only_free": only_free}

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(device_name)
            ifaces = [
                iface.model_dump(mode="json")
                for iface in dev.interfaces.values()
                if not only_free or iface.connected_to_connection_id is None
            ]
            return OperationResult.ok(
                "interface_list",
                f"Listed {len(ifaces)} interface(s) on '{dev.name}'.",
                data={"device": dev.name, "model": dev.model, "interfaces": ifaces},
                state_level=StateLevel.PLANNED,
                evidence=[f"Inspected interface inventory of '{dev.name}'."],
            )

        return runtime.execute("interface_list", PermissionTier.READ_ONLY, params, _run)

    def interface_status(
        device_name: str,
        interface_name: str,
        admin_up: bool | None = None,
        description: str | None = None,
        live: bool = False,
    ) -> dict[str, Any]:
        """Inspect or update interface status (supports live show interfaces when live=True)."""
        params = {
            "device_name": device_name,
            "interface_name": interface_name,
            "admin_up": admin_up,
            "description": description,
            "live": live,
        }
        tier = (
            PermissionTier.CONFIGURATION
            if (admin_up is not None or description is not None)
            else PermissionTier.READ_ONLY
        )

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(device_name)
            canon = runtime.catalog.normalize_interface_name(dev.model, interface_name)
            iface = dev.interfaces.get(canon)
            if iface is None:
                raise InterfaceError(
                    f"Logical interface '{canon}' is not a tracked physical port on '{dev.name}'.",
                    details={"device": dev.name, "interface": canon},
                )
            if admin_up is not None:
                iface.admin_up = admin_up
            if description is not None:
                iface.description = description
            payload = iface.model_dump(mode="json")
            backend = "offline_model"
            lvl = iface.state_level
            evidence = [f"Checked interface state on '{dev.name}:{iface.name}'."]
            warnings: list[str] = []
            if live:
                backend, raw_out, ev, warnings = runtime.router.read_show_output(
                    dev.name,
                    f"show interfaces {canon}",
                    console_engine=runtime.console,
                )
                payload["live_show_output"] = raw_out
                lvl = StateLevel.VERIFIED
                evidence.extend(ev)
            return OperationResult.ok(
                "interface_status",
                f"Interface {dev.name}:{iface.name} admin_up={iface.admin_up}.",
                data=payload,
                state_level=lvl,
                execution_backend=backend,
                warnings=warnings,
                evidence=evidence,
            )

        return runtime.execute("interface_status", tier, params, _run)

    specs = [
        (
            "connection_create",
            PermissionTier.PLANNING,
            connection_create.__doc__ or "",
            connection_create,
            False,
            False,
        ),
        (
            "connection_remove",
            PermissionTier.DESTRUCTIVE,
            connection_remove.__doc__ or "",
            connection_remove,
            False,
            True,
        ),
        (
            "connection_inspect",
            PermissionTier.READ_ONLY,
            connection_inspect.__doc__ or "",
            connection_inspect,
            True,
            False,
        ),
        (
            "interface_list",
            PermissionTier.READ_ONLY,
            interface_list.__doc__ or "",
            interface_list,
            True,
            False,
        ),
        (
            "interface_status",
            PermissionTier.READ_ONLY,
            interface_status.__doc__ or "",
            interface_status,
            False,
            False,
        ),
    ]
    for name, tier, desc, fn, ro, dest in specs:
        runtime.registry.register_tool(
            server,
            name=name,
            category="connections",
            permission_tier=tier,
            description=desc,
            fn=fn,
            read_only=ro,
            destructive=dest,
        )
