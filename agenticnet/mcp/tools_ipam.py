"""MCP tools for IP Address Management (category: ipam)."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from agenticnet.core.enums import PermissionTier, StateLevel
from agenticnet.core.models import OperationResult
from agenticnet.ipam.engine import calculate_subnet, plan_vlsm
from agenticnet.ipam.models import SubnetRequirement
from agenticnet.mcp.registry import AgenticNetRuntime


def register_ipam_tools(server: MCPServer, runtime: AgenticNetRuntime) -> None:
    """Register subnet_*, vlsm_plan, address_*, and ipam_report tools."""

    def subnet_calculate(cidr: str) -> dict[str, Any]:
        """Calculate IPv4 or IPv6 subnet metrics (network, netmask, wildcard, usable range)."""

        def _run() -> OperationResult:
            calc = calculate_subnet(cidr)
            return OperationResult.ok(
                "subnet_calculate",
                f"Calculated subnet {calc.cidr}: {calc.usable_hosts} usable host(s).",
                data=calc.model_dump(mode="json"),
                state_level=StateLevel.VERIFIED,
                evidence=[f"Computed deterministic CIDR parameters via ipaddress for {calc.cidr}."],
            )

        return runtime.execute("subnet_calculate", PermissionTier.READ_ONLY, {"cidr": cidr}, _run)

    def vlsm_plan(
        base_cidr: str,
        requirements: list[SubnetRequirement],
        allow_slash31: bool = False,
        register_pools: bool = False,
    ) -> dict[str, Any]:
        """Design a non-overlapping VLSM plan and optionally register pools in the project."""
        params = {
            "base_cidr": base_cidr,
            "requirement_count": len(requirements),
            "allow_slash31": allow_slash31,
            "register_pools": register_pools,
        }
        tier = PermissionTier.PLANNING if register_pools else PermissionTier.READ_ONLY

        def _run() -> OperationResult:
            plan = plan_vlsm(base_cidr, requirements, allow_slash31=allow_slash31)
            registered_ids: list[str] = []
            if register_pools:
                _, _, ipam, _ = runtime.manager.require_active()
                for entry in plan.allocations:
                    pool = ipam.register_pool(
                        entry.name,
                        entry.allocated_cidr,
                        vlan_id=entry.vlan_id,
                        gateway=entry.gateway,
                        description=f"VLSM allocation ({entry.required_hosts} required hosts)",
                    )
                    registered_ids.append(pool.pool_id)

            return OperationResult.ok(
                "vlsm_plan",
                f"Planned {len(plan.allocations)} VLSM subnet(s) in {plan.base_cidr} "
                f"({plan.utilization_percent}% allocated).",
                data={
                    "plan": plan.model_dump(mode="json"),
                    "registered_pool_ids": registered_ids,
                },
                state_level=StateLevel.PLANNED if register_pools else StateLevel.VERIFIED,
                evidence=["Computed non-overlapping largest-first VLSM blocks."],
            )

        return runtime.execute("vlsm_plan", tier, params, _run)

    def address_allocate(
        device_name: str,
        interface_name: str,
        cidr_or_ip: str,
        subnet_mask: str | None = None,
        gateway: str | None = None,
        vlan_id: int | None = None,
        allocation_type: Literal["static", "svi", "loopback", "dhcp_reserved"] = "static",
    ) -> dict[str, Any]:
        """Allocate and validate an IP address for a device interface in project IPAM."""
        params = {
            "device_name": device_name,
            "interface_name": interface_name,
            "cidr_or_ip": cidr_or_ip,
            "subnet_mask": subnet_mask,
            "gateway": gateway,
            "vlan_id": vlan_id,
            "allocation_type": allocation_type,
        }

        def _run() -> OperationResult:
            _, topo, ipam, _ = runtime.manager.require_active()
            dev = topo.get_device(device_name)
            canon_iface = runtime.catalog.normalize_interface_name(dev.model, interface_name)
            alloc = ipam.allocate_address(
                dev.name,
                canon_iface,
                cidr_or_ip,
                subnet_mask=subnet_mask,
                gateway=gateway,
                vlan_id=vlan_id,
                allocation_type=allocation_type,
            )
            # Sync planned IP into physical interface state if tracked
            if canon_iface in dev.interfaces:
                dev.interfaces[canon_iface].ip_address = alloc.ip_address
                dev.interfaces[canon_iface].subnet_mask = alloc.subnet_mask

            return OperationResult.ok(
                "address_allocate",
                f"Allocated {alloc.ip_address}/{alloc.prefix_length} to {dev.name}:{canon_iface}.",
                data=alloc.model_dump(mode="json"),
                state_level=StateLevel.PLANNED,
                evidence=[
                    "Validated uniqueness, host range, and gateway consistency in IPAMEngine."
                ],
            )

        return runtime.execute("address_allocate", PermissionTier.PLANNING, params, _run)

    def address_validate() -> dict[str, Any]:
        """Validate all IPAM pools and allocations for conflicts, overlaps, and gateway errors."""

        def _run() -> OperationResult:
            _, _, ipam, _ = runtime.manager.require_active()
            issues = ipam.validate_all()
            errors = [i for i in issues if i.severity == "error"]
            return OperationResult.ok(
                "address_validate",
                f"IPAM check complete: {len(errors)} error(s), "
                f"{len(issues) - len(errors)} warning(s).",
                data={
                    "valid": len(errors) == 0,
                    "issues": [i.model_dump(mode="json") for i in issues],
                },
                state_level=StateLevel.PLANNED,
                warnings=[i.message for i in issues if i.severity == "warning"],
                evidence=["Audited all registered pools and host IP allocations."],
            )

        return runtime.execute("address_validate", PermissionTier.READ_ONLY, {}, _run)

    def ipam_report(
        table_format: Literal["markdown", "json", "csv"] = "markdown",
    ) -> dict[str, Any]:
        """Generate IPAM utilization summary and exportable addressing table."""

        def _run() -> OperationResult:
            _, _, ipam, _ = runtime.manager.require_active()
            report = ipam.utilization_report()
            table = ipam.export_addressing_table(fmt=table_format)
            return OperationResult.ok(
                "ipam_report",
                f"Generated IPAM report ({report.total_pools} pools, "
                f"{report.total_allocations} allocations).",
                data={
                    "report": report.model_dump(mode="json"),
                    "table_format": table_format,
                    "addressing_table": table,
                },
                state_level=StateLevel.PLANNED,
                evidence=["Generated utilization stats and addressing table from IPAMEngine."],
            )

        return runtime.execute(
            "ipam_report", PermissionTier.READ_ONLY, {"table_format": table_format}, _run
        )

    specs = [
        (
            "subnet_calculate",
            PermissionTier.READ_ONLY,
            subnet_calculate.__doc__ or "",
            subnet_calculate,
            True,
            False,
        ),
        ("vlsm_plan", PermissionTier.READ_ONLY, vlsm_plan.__doc__ or "", vlsm_plan, False, False),
        (
            "address_allocate",
            PermissionTier.PLANNING,
            address_allocate.__doc__ or "",
            address_allocate,
            False,
            False,
        ),
        (
            "address_validate",
            PermissionTier.READ_ONLY,
            address_validate.__doc__ or "",
            address_validate,
            True,
            False,
        ),
        (
            "ipam_report",
            PermissionTier.READ_ONLY,
            ipam_report.__doc__ or "",
            ipam_report,
            True,
            False,
        ),
    ]
    for name, tier, desc, fn, ro, dest in specs:
        runtime.registry.register_tool(
            server,
            name=name,
            category="ipam",
            permission_tier=tier,
            description=desc,
            fn=fn,
            read_only=ro,
            destructive=dest,
        )
