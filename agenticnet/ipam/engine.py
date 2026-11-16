"""Full IPAM subsystem: CIDR math, VLSM planning, conflict detection, and addressing tables."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import math
from uuid import uuid4

from agenticnet.core.exceptions import IPAMConflictError, ValidationError
from agenticnet.ipam.models import (
    IPAllocation,
    IPAMState,
    IPAMUtilizationReport,
    IPAMValidationIssue,
    SubnetCalculation,
    SubnetPool,
    SubnetRequirement,
    SubnetUtilizationEntry,
    VLSMAllocationEntry,
    VLSMPlanResult,
)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _parse_network(cidr: str) -> IPNetwork:
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise ValidationError(
            f"Invalid CIDR network {cidr!r}: {exc}",
            details={"cidr": cidr},
            remediation=("Provide valid CIDR such as '192.168.10.0/24' or '2001:db8:1::/64'."),
        ) from exc


def _parse_address(address: str) -> IPAddress:
    try:
        return ipaddress.ip_address(address.strip())
    except ValueError as exc:
        raise ValidationError(
            f"Invalid IP address {address!r}: {exc}",
            details={"ip_address": address},
        ) from exc


def calculate_subnet(cidr: str) -> SubnetCalculation:
    """Compute complete subnet details for an IPv4 or IPv6 CIDR network."""
    net = _parse_network(cidr)
    total = int(net.num_addresses)

    if isinstance(net, ipaddress.IPv4Network):
        if net.prefixlen == 32:
            usable = 1
            first_usable = str(net.network_address)
            last_usable = str(net.network_address)
        elif net.prefixlen == 31:
            usable = 2
            first_usable = str(net.network_address)
            last_usable = str(net.broadcast_address)
        else:
            usable = max(0, total - 2)
            first_usable = str(net.network_address + 1)
            last_usable = str(net.broadcast_address - 1)
        return SubnetCalculation(
            cidr=str(net),
            ip_version=4,
            network_address=str(net.network_address),
            broadcast_address=str(net.broadcast_address),
            netmask=str(net.netmask),
            wildcard_mask=str(net.hostmask),
            prefix_length=net.prefixlen,
            total_addresses=total,
            usable_hosts=usable,
            first_usable=first_usable,
            last_usable=last_usable,
            is_private=net.is_private,
        )

    # IPv6
    if net.prefixlen == 128:
        usable = 1
        first_usable = str(net.network_address)
        last_usable = str(net.network_address)
    elif net.prefixlen == 127:
        usable = 2
        first_usable = str(net.network_address)
        last_usable = str(net.broadcast_address)
    else:
        usable = max(0, total - 1)  # subnet-router anycast at network_address
        first_usable = str(net.network_address + 1)
        last_usable = str(net.broadcast_address)
    return SubnetCalculation(
        cidr=str(net),
        ip_version=6,
        network_address=str(net.network_address),
        broadcast_address=None,
        netmask=f"/{net.prefixlen}",
        wildcard_mask=None,
        prefix_length=net.prefixlen,
        total_addresses=total,
        usable_hosts=usable,
        first_usable=first_usable,
        last_usable=last_usable,
        is_private=net.is_private,
    )


def _prefix_for_hosts(required_hosts: int, *, ip_version: int, allow_slash31: bool) -> int:
    if ip_version == 6:
        if required_hosts <= 2 and allow_slash31:
            return 127
        host_bits = max(2, math.ceil(math.log2(required_hosts + 2)))
        if host_bits >= 64:
            return 64
        return 128 - host_bits

    if required_hosts == 1:
        return 30 if not allow_slash31 else 31
    if required_hosts == 2:
        return 31 if allow_slash31 else 30
    host_bits = math.ceil(math.log2(required_hosts + 2))
    return 32 - host_bits


def plan_vlsm(
    base_cidr: str,
    requirements: list[SubnetRequirement],
    *,
    allow_slash31: bool = False,
) -> VLSMPlanResult:
    """Compute a non-overlapping VLSM subnet plan sorted largest-first."""
    if not requirements:
        raise ValidationError("VLSM planning requires at least one subnet requirement.")

    base_net = _parse_network(base_cidr)
    sorted_reqs = sorted(requirements, key=lambda r: r.required_hosts, reverse=True)

    # Maintain sorted list of free candidate blocks starting with [base_net]
    free_blocks: list[IPNetwork] = [base_net]
    allocations: list[VLSMAllocationEntry] = []
    allocated_total = 0

    for req in sorted_reqs:
        target_prefix = _prefix_for_hosts(
            req.required_hosts, ip_version=base_net.version, allow_slash31=allow_slash31
        )
        if target_prefix < base_net.prefixlen:
            raise IPAMConflictError(
                f"Requirement '{req.name}' ({req.required_hosts} hosts, needs /{target_prefix}) "
                f"exceeds base block {base_net}.",
                details={
                    "requirement": req.model_dump(),
                    "needed_prefix": target_prefix,
                    "base_cidr": str(base_net),
                },
                remediation="Provide a larger base CIDR block or reduce required host count.",
            )

        # Find smallest free block whose prefix <= target_prefix
        candidate_idx: int | None = None
        for idx, blk in enumerate(free_blocks):
            if blk.prefixlen <= target_prefix and (
                candidate_idx is None or blk.prefixlen > free_blocks[candidate_idx].prefixlen
            ):
                candidate_idx = idx

        if candidate_idx is None:
            raise IPAMConflictError(
                f"Insufficient contiguous space in {base_net} to allocate '{req.name}' "
                f"(needs /{target_prefix} for {req.required_hosts} hosts).",
                details={
                    "requirement": req.model_dump(),
                    "needed_prefix": target_prefix,
                    "base_cidr": str(base_net),
                    "allocated_so_far": [a.allocated_cidr for a in allocations],
                },
                remediation=(
                    "Use a larger supernet (e.g. /16 instead of /24) or consolidate subnets."
                ),
            )

        block = free_blocks.pop(candidate_idx)
        while block.prefixlen < target_prefix:
            left, right = list(block.subnets(prefixlen_diff=1))
            free_blocks.append(right)
            block = left

        # Keep free_blocks sorted by network address
        free_blocks.sort(key=lambda b: int(b.network_address))

        calc = calculate_subnet(str(block))
        gateway: str | None = None
        dhcp_start = calc.first_usable
        dhcp_end = calc.last_usable

        if req.reserve_gateway == "first" and calc.first_usable:
            gateway = calc.first_usable
            if isinstance(block, ipaddress.IPv4Network) and calc.usable_hosts >= 2:
                dhcp_start = str(ipaddress.IPv4Address(calc.first_usable) + 1)
            elif isinstance(block, ipaddress.IPv6Network) and calc.usable_hosts >= 2:
                dhcp_start = str(ipaddress.IPv6Address(calc.first_usable) + 1)
        elif req.reserve_gateway == "last" and calc.last_usable:
            gateway = calc.last_usable
            if isinstance(block, ipaddress.IPv4Network) and calc.usable_hosts >= 2:
                dhcp_end = str(ipaddress.IPv4Address(calc.last_usable) - 1)
            elif isinstance(block, ipaddress.IPv6Network) and calc.usable_hosts >= 2:
                dhcp_end = str(ipaddress.IPv6Address(calc.last_usable) - 1)

        if calc.usable_hosts <= 1:
            dhcp_start = None
            dhcp_end = None

        allocated_total += int(block.num_addresses)
        allocations.append(
            VLSMAllocationEntry(
                name=req.name,
                vlan_id=req.vlan_id,
                required_hosts=req.required_hosts,
                allocated_cidr=calc.cidr,
                network_address=calc.network_address,
                netmask=calc.netmask,
                wildcard_mask=calc.wildcard_mask,
                broadcast_address=calc.broadcast_address,
                gateway=gateway,
                usable_hosts=calc.usable_hosts,
                first_usable=calc.first_usable,
                last_usable=calc.last_usable,
                dhcp_range_start=dhcp_start,
                dhcp_range_end=dhcp_end,
                wasted_hosts=max(0, calc.usable_hosts - req.required_hosts),
            )
        )

    utilization = round((allocated_total / int(base_net.num_addresses)) * 100.0, 2)
    return VLSMPlanResult(
        base_cidr=str(base_net),
        total_base_addresses=int(base_net.num_addresses),
        total_allocated_addresses=allocated_total,
        utilization_percent=utilization,
        allocations=allocations,
    )


class IPAMEngine:
    """Manages project subnet pools, host IP allocations, conflict detection, and reports."""

    def __init__(self, state: IPAMState | None = None) -> None:
        self.state = state.model_copy(deep=True) if state else IPAMState()

    def register_pool(
        self,
        name: str,
        cidr: str,
        *,
        vlan_id: int | None = None,
        gateway: str | None = None,
        default_gateway: str | None = None,
        dns_servers: list[str] | None = None,
        dhcp_pool_name: str | None = None,
        description: str = "",
    ) -> SubnetPool:
        """Register a subnet pool while rejecting overlapping CIDR ranges."""
        net = _parse_network(cidr)
        calc = calculate_subnet(str(net))

        for existing in self.state.pools.values():
            existing_net = _parse_network(existing.cidr)
            if existing_net.version == net.version and existing_net.overlaps(net):
                raise IPAMConflictError(
                    f"Subnet {net} overlaps pool '{existing.name}' ({existing.cidr}).",
                    details={"new_cidr": str(net), "existing_pool": existing.model_dump()},
                    remediation="Choose a non-overlapping subnet block.",
                )

        resolved_gateway = gateway if gateway is not None else default_gateway
        if resolved_gateway is not None:
            gw_addr = _parse_address(resolved_gateway)
            if gw_addr.version != net.version or gw_addr not in net:
                raise IPAMConflictError(
                    f"Gateway '{resolved_gateway}' is outside subnet {net}.",
                    details={"gateway": resolved_gateway, "cidr": str(net)},
                )
            if (
                isinstance(net, ipaddress.IPv4Network)
                and net.prefixlen < 31
                and gw_addr
                in {
                    net.network_address,
                    net.broadcast_address,
                }
            ):
                raise IPAMConflictError(
                    f"Gateway '{resolved_gateway}' cannot be network or broadcast of {net}.",
                )
        elif calc.first_usable:
            resolved_gateway = calc.first_usable

        excluded: list[tuple[str, str]] = []
        if resolved_gateway and isinstance(net, ipaddress.IPv4Network):
            excluded.append((resolved_gateway, resolved_gateway))

        pool_id = f"pool_{uuid4().hex[:8]}"
        pool = SubnetPool(
            pool_id=pool_id,
            name=name,
            cidr=calc.cidr,
            ip_version=calc.ip_version,
            vlan_id=vlan_id,
            gateway=resolved_gateway,
            netmask=calc.netmask,
            wildcard_mask=calc.wildcard_mask,
            first_usable=calc.first_usable,
            last_usable=calc.last_usable,
            usable_hosts=calc.usable_hosts,
            dns_servers=dns_servers or [],
            dhcp_pool_name=dhcp_pool_name,
            excluded_ranges=excluded,
            description=description,
        )
        self.state.pools[pool_id] = pool
        return pool

    def _find_matching_pool(self, addr: IPAddress) -> SubnetPool | None:
        matches: list[tuple[int, SubnetPool]] = []
        for pool in self.state.pools.values():
            net = _parse_network(pool.cidr)
            if addr.version == net.version and addr in net:
                matches.append((net.prefixlen, pool))
        if not matches:
            return None
        matches.sort(key=lambda item: item[0], reverse=True)
        return matches[0][1]

    def allocate_address(
        self,
        device_name: str,
        interface_name: str,
        cidr_or_ip: str,
        *,
        subnet_mask: str | None = None,
        gateway: str | None = None,
        vlan_id: int | None = None,
        allocation_type: str = "static",
    ) -> IPAllocation:
        """Allocate and validate an IP address for a device interface."""
        if "/" in cidr_or_ip:
            iface_obj = ipaddress.ip_interface(cidr_or_ip.strip())
            addr = iface_obj.ip
            net = iface_obj.network
        elif subnet_mask:
            addr = _parse_address(cidr_or_ip)
            net = ipaddress.ip_network(f"{addr}/{subnet_mask}", strict=False)
        else:
            addr = _parse_address(cidr_or_ip)
            matched = self._find_matching_pool(addr)
            if matched is None:
                raise ValidationError(
                    f"Cannot infer prefix length for IP '{cidr_or_ip}' with no matching pool.",
                    remediation="Pass CIDR notation (e.g. '192.168.10.10/24') or subnet_mask.",
                )
            net = _parse_network(matched.cidr)

        # Reject network/broadcast address unless point-to-point /31 or /32 host
        if (
            isinstance(net, ipaddress.IPv4Network)
            and net.prefixlen < 31
            and addr
            in {
                net.network_address,
                net.broadcast_address,
            }
        ):
            raise IPAMConflictError(
                f"IP '{addr}' is the network or broadcast address of {net}.",
                details={"ip_address": str(addr), "cidr": str(net)},
                remediation="Assign a usable host address within the subnet range.",
            )

        # Check duplicate IP across other device interfaces
        for existing in self.state.allocations.values():
            if existing.ip_address == str(addr) and not (
                existing.device_name == device_name and existing.interface_name == interface_name
            ):
                raise IPAMConflictError(
                    f"IP address '{addr}' is already assigned to "
                    f"{existing.device_name}:{existing.interface_name}.",
                    details={"ip_address": str(addr), "existing": existing.model_dump()},
                    remediation="Select an unused host address in the subnet.",
                )

        matched_pool = self._find_matching_pool(addr)
        resolved_gw = (
            gateway if gateway is not None else (matched_pool.gateway if matched_pool else None)
        )
        if resolved_gw is not None:
            gw_addr = _parse_address(resolved_gw)
            if gw_addr.version != net.version or gw_addr not in net:
                raise IPAMConflictError(
                    f"Gateway '{resolved_gw}' is not within subnet {net} for "
                    f"{device_name}:{interface_name}.",
                    details={"gateway": resolved_gw, "subnet": str(net)},
                )

        # Replace existing allocation for same (device_name, interface_name) if updating
        existing_key = next(
            (
                k
                for k, v in self.state.allocations.items()
                if v.device_name == device_name and v.interface_name == interface_name
            ),
            None,
        )
        alloc_id = existing_key or f"ip_{uuid4().hex[:8]}"
        mask_str = (
            str(net.netmask) if isinstance(net, ipaddress.IPv4Network) else f"/{net.prefixlen}"
        )
        alloc = IPAllocation(
            allocation_id=alloc_id,
            device_name=device_name,
            interface_name=interface_name,
            ip_address=str(addr),
            prefix_length=net.prefixlen,
            subnet_mask=mask_str,
            cidr=str(net),
            pool_id=matched_pool.pool_id if matched_pool else None,
            gateway=resolved_gw,
            vlan_id=vlan_id
            if vlan_id is not None
            else (matched_pool.vlan_id if matched_pool else None),
            allocation_type=allocation_type,
        )
        self.state.allocations[alloc_id] = alloc
        return alloc

    def remove_device_allocations(self, device_name: str) -> int:
        """Delete all IP allocations associated with a removed device."""
        keys = [k for k, v in self.state.allocations.items() if v.device_name == device_name]
        for k in keys:
            del self.state.allocations[k]
        return len(keys)

    def validate_all(self) -> list[IPAMValidationIssue]:
        """Validate all pools and host allocations for overlaps, duplicates, and gateway errors."""
        issues: list[IPAMValidationIssue] = []

        # Pool overlaps
        pools = list(self.state.pools.values())
        for i in range(len(pools)):
            net_i = _parse_network(pools[i].cidr)
            for j in range(i + 1, len(pools)):
                net_j = _parse_network(pools[j].cidr)
                if net_i.version == net_j.version and net_i.overlaps(net_j):
                    issues.append(
                        IPAMValidationIssue(
                            severity="error",
                            code="OVERLAPPING_POOLS",
                            message=f"Pools '{pools[i].name}' ({pools[i].cidr}) and "
                            f"'{pools[j].name}' ({pools[j].cidr}) overlap.",
                        )
                    )

        # Duplicate IPs & gateway checks
        seen_ips: dict[str, IPAllocation] = {}
        for alloc in self.state.allocations.values():
            if alloc.ip_address in seen_ips:
                prev = seen_ips[alloc.ip_address]
                issues.append(
                    IPAMValidationIssue(
                        severity="error",
                        code="DUPLICATE_IP",
                        message=(
                            f"Duplicate IP {alloc.ip_address} on "
                            f"{prev.device_name}:{prev.interface_name} and "
                            f"{alloc.device_name}:{alloc.interface_name}."
                        ),
                        affected_devices=[prev.device_name, alloc.device_name],
                    )
                )
            else:
                seen_ips[alloc.ip_address] = alloc

            if alloc.pool_id and alloc.pool_id in self.state.pools:
                pool = self.state.pools[alloc.pool_id]
                if pool.gateway and alloc.gateway and alloc.gateway != pool.gateway:
                    issues.append(
                        IPAMValidationIssue(
                            severity="warning",
                            code="GATEWAY_MISMATCH",
                            message=(
                                f"{alloc.device_name}:{alloc.interface_name} uses gateway "
                                f"{alloc.gateway}, while pool '{pool.name}' expects {pool.gateway}."
                            ),
                            affected_devices=[alloc.device_name],
                        )
                    )

        return issues

    def utilization_report(self) -> IPAMUtilizationReport:
        """Compute per-pool IP utilization and summarize any validation issues."""
        pool_entries: list[SubnetUtilizationEntry] = []
        unpooled: list[IPAllocation] = []

        alloc_by_pool: dict[str, int] = {}
        for alloc in self.state.allocations.values():
            if alloc.pool_id and alloc.pool_id in self.state.pools:
                alloc_by_pool[alloc.pool_id] = alloc_by_pool.get(alloc.pool_id, 0) + 1
            else:
                unpooled.append(alloc)

        for pool_id, pool in sorted(self.state.pools.items(), key=lambda kv: kv[1].name):
            used = alloc_by_pool.get(pool_id, 0)
            avail = max(0, pool.usable_hosts - used)
            pct = round((used / pool.usable_hosts) * 100.0, 2) if pool.usable_hosts > 0 else 0.0
            pool_entries.append(
                SubnetUtilizationEntry(
                    pool_id=pool_id,
                    name=pool.name,
                    cidr=pool.cidr,
                    vlan_id=pool.vlan_id,
                    usable_hosts=pool.usable_hosts,
                    allocated_hosts=used,
                    available_hosts=avail,
                    utilization_percent=pct,
                )
            )

        return IPAMUtilizationReport(
            total_pools=len(self.state.pools),
            total_allocations=len(self.state.allocations),
            pools=pool_entries,
            unpooled_allocations=unpooled,
            issues=self.validate_all(),
        )

    def export_addressing_table(self, fmt: str = "markdown") -> str:
        """Export allocated device addressing table in Markdown, JSON, or CSV."""
        rows = sorted(
            self.state.allocations.values(),
            key=lambda a: (a.device_name, a.interface_name),
        )
        fmt_lower = fmt.strip().lower()
        if fmt_lower == "json":
            return json.dumps([r.model_dump() for r in rows], indent=2)

        if fmt_lower == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(
                [
                    "Device",
                    "Interface",
                    "IP Address",
                    "Subnet Mask",
                    "CIDR",
                    "Gateway",
                    "VLAN",
                    "Type",
                ]
            )
            for r in rows:
                writer.writerow(
                    [
                        r.device_name,
                        r.interface_name,
                        r.ip_address,
                        r.subnet_mask,
                        r.cidr,
                        r.gateway or "",
                        r.vlan_id if r.vlan_id is not None else "",
                        r.allocation_type,
                    ]
                )
            return buf.getvalue()

        if fmt_lower == "markdown":
            lines = [
                "| Device | Interface | IP Address | Subnet Mask | Gateway | VLAN | Type |",
                "|---|---|---|---|---|---|---|",
            ]
            for r in rows:
                vlan_str = str(r.vlan_id) if r.vlan_id is not None else "-"
                lines.append(
                    f"| {r.device_name} | {r.interface_name} | {r.ip_address} | "
                    f"{r.subnet_mask} | {r.gateway or '-'} | {vlan_str} | {r.allocation_type} |"
                )
            return "\n".join(lines)

        raise ValidationError(
            f"Unsupported addressing table format {fmt!r}. Use markdown, json, or csv."
        )
