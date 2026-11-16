"""Diagnostic rule evaluators detecting addressing, interface, VLAN, and routing issues."""

from __future__ import annotations

import ipaddress

from netforge.core.enums import DeviceCategory
from netforge.diagnostics.models import (
    DiagnosticCategory,
    DiagnosticFinding,
    DiagnosticSeverity,
    RepairAction,
    RepairProposal,
)
from netforge.ipam.engine import IPAMEngine
from netforge.topology.engine import TopologyEngine


def check_disabled_interfaces_with_ip(
    topology: TopologyEngine,
) -> list[tuple[DiagnosticFinding, RepairProposal]]:
    """Flag interfaces with assigned IP addresses that remain administratively down."""
    results: list[tuple[DiagnosticFinding, RepairProposal]] = []
    for d_name, dev in topology.model.devices.items():
        for if_name, iface in dev.interfaces.items():
            if iface.ipv4_address and not iface.admin_up:
                finding = DiagnosticFinding(
                    category=DiagnosticCategory.INTERFACE_PHYSICAL,
                    severity=DiagnosticSeverity.ERROR,
                    code="INTERFACE_ADMIN_DOWN_WITH_IP",
                    target_device=d_name,
                    target_interface=if_name,
                    summary=(
                        f"Interface {d_name} {if_name} has IP {iface.ipv4_address} but is shutdown."
                    ),
                    evidence=[
                        f"Device: {d_name}, Interface: {if_name}",
                        f"Configured IP: {iface.ipv4_address}, Admin Status: DOWN (shutdown)",
                    ],
                    probable_causes=[
                        "Missing 'no shutdown' command during interface configuration.",
                        "Default administrative state on Cisco IOS router interfaces.",
                    ],
                    recommended_fix=f"Issue 'no shutdown' under interface {if_name}.",
                )
                repair = RepairProposal(
                    finding_id=finding.finding_id,
                    target_device=d_name,
                    summary=f"Bring up {if_name} on {d_name} via 'no shutdown'.",
                    actions=[
                        RepairAction(
                            target_device=d_name,
                            target_interface=if_name,
                            command_sequence=[
                                f"interface {if_name}",
                                "no shutdown",
                                "exit",
                            ],
                            description=f"Enable interface {if_name} on {d_name}.",
                            is_disruptive=False,
                            verification_commands=[f"show ip interface brief {if_name}"],
                        )
                    ],
                )
                results.append((finding, repair))
    return results


def check_missing_default_gateways(
    topology: TopologyEngine,
    ipam: IPAMEngine | None = None,
) -> list[tuple[DiagnosticFinding, RepairProposal]]:
    """Flag end devices (PC, Laptop, Server, Printer) missing default gateways."""
    results: list[tuple[DiagnosticFinding, RepairProposal]] = []
    host_categories = {
        DeviceCategory.PC,
        DeviceCategory.LAPTOP,
        DeviceCategory.SERVER,
        DeviceCategory.PRINTER,
    }

    for d_name, dev in topology.model.devices.items():
        if dev.category in host_categories:
            for if_name, iface in dev.interfaces.items():
                if iface.ipv4_address and not iface.default_gateway:
                    finding = DiagnosticFinding(
                        category=DiagnosticCategory.ADDRESSING_IPAM,
                        severity=DiagnosticSeverity.WARNING,
                        code="HOST_MISSING_DEFAULT_GATEWAY",
                        target_device=d_name,
                        target_interface=if_name,
                        summary=(
                            f"Host {d_name} ({if_name}) has IP {iface.ipv4_address} "
                            "but no default gateway."
                        ),
                        evidence=[
                            f"Host: {d_name} ({dev.category.value})",
                            f"Interface: {if_name}, IP: {iface.ipv4_address}",
                            "Default Gateway: [UNSET]",
                        ],
                        probable_causes=[
                            "Static IP configured without default gateway field.",
                            "DHCP option 3 (router) not received or unassigned.",
                        ],
                        recommended_fix=(
                            "Assign default gateway corresponding to local subnet router."
                        ),
                    )
                    gw_suggestion = "192.168.1.1"
                    if ipam is not None:
                        for pool in ipam.state.pools:
                            try:
                                net = ipaddress.IPv4Network(pool.cidr, strict=False)
                                if ipaddress.IPv4Address(iface.ipv4_address) in net:
                                    gw_suggestion = pool.default_gateway or str(
                                        list(net.hosts())[0]
                                    )
                                    break
                            except Exception:
                                continue

                    host_mask = iface.subnet_mask or "255.255.255.0"
                    repair = RepairProposal(
                        finding_id=finding.finding_id,
                        target_device=d_name,
                        summary=f"Set default gateway {gw_suggestion} for {d_name}.",
                        actions=[
                            RepairAction(
                                target_device=d_name,
                                target_interface=if_name,
                                command_sequence=[
                                    f"ipconfig {iface.ipv4_address} {host_mask} {gw_suggestion}"
                                ],
                                description=(
                                    f"Configure default gateway {gw_suggestion} on {d_name}."
                                ),
                                is_disruptive=False,
                            )
                        ],
                    )
                    results.append((finding, repair))
    return results


def check_link_subnet_mismatch(
    topology: TopologyEngine,
) -> list[tuple[DiagnosticFinding, RepairProposal]]:
    """Flag connected links where both endpoints have IPs configured in differing subnets."""
    results: list[tuple[DiagnosticFinding, RepairProposal]] = []
    for _link_id, conn in topology.model.connections.items():
        dev_a = topology.model.devices.get(conn.device_a)
        dev_b = topology.model.devices.get(conn.device_b)
        if not dev_a or not dev_b:
            continue

        if_a = dev_a.interfaces.get(conn.interface_a)
        if_b = dev_b.interfaces.get(conn.interface_b)
        if not if_a or not if_b:
            continue

        ip_a, mask_a = if_a.ipv4_address, if_a.subnet_mask
        ip_b, mask_b = if_b.ipv4_address, if_b.subnet_mask

        if ip_a and ip_b and mask_a and mask_b:
            try:
                net_a = ipaddress.IPv4Network(f"{ip_a}/{mask_a}", strict=False)
                net_b = ipaddress.IPv4Network(f"{ip_b}/{mask_b}", strict=False)
                if net_a != net_b:
                    finding = DiagnosticFinding(
                        category=DiagnosticCategory.ADDRESSING_IPAM,
                        severity=DiagnosticSeverity.ERROR,
                        code="LINK_SUBNET_MISMATCH",
                        target_device=conn.device_a,
                        target_interface=conn.interface_a,
                        summary=(
                            f"Link {conn.device_a}:{conn.interface_a} ({net_a}) connects to "
                            f"{conn.device_b}:{conn.interface_b} in different subnet ({net_b})."
                        ),
                        evidence=[
                            f"Endpoint A: {conn.device_a} {conn.interface_a} -> "
                            f"{ip_a}/{mask_a} (Net: {net_a})",
                            f"Endpoint B: {conn.device_b} {conn.interface_b} -> "
                            f"{ip_b}/{mask_b} (Net: {net_b})",
                        ],
                        probable_causes=[
                            "Subnet mask mismatch or wrong IP entered during provisioning.",
                            "Cable plugged into wrong port.",
                        ],
                        recommended_fix=(
                            f"Align {conn.device_b} interface to {net_a} or re-address link."
                        ),
                    )
                    repair = RepairProposal(
                        finding_id=finding.finding_id,
                        target_device=conn.device_b,
                        summary=f"Re-address {conn.device_b} {conn.interface_b} into {net_a}.",
                        actions=[
                            RepairAction(
                                target_device=conn.device_b,
                                target_interface=conn.interface_b,
                                command_sequence=[
                                    f"interface {conn.interface_b}",
                                    f"ip address {list(net_a.hosts())[-1]} {mask_a}",
                                    "exit",
                                ],
                                description=(
                                    f"Update IP on {conn.device_b} to match link subnet {net_a}."
                                ),
                                is_disruptive=True,
                            )
                        ],
                        requires_approval=True,
                        approval_reason=(
                            "Modifying IP address on connected link is potentially disruptive."
                        ),
                    )
                    results.append((finding, repair))
            except Exception:
                continue
    return results


def check_vlan_trunk_native_mismatch(
    topology: TopologyEngine,
) -> list[tuple[DiagnosticFinding, RepairProposal]]:
    """Flag trunk links with native VLAN mismatches."""
    results: list[tuple[DiagnosticFinding, RepairProposal]] = []
    for _link_id, conn in topology.model.connections.items():
        dev_a = topology.model.devices.get(conn.device_a)
        dev_b = topology.model.devices.get(conn.device_b)
        if not dev_a or not dev_b:
            continue

        if_a = dev_a.interfaces.get(conn.interface_a)
        if_b = dev_b.interfaces.get(conn.interface_b)
        if not if_a or not if_b:
            continue

        if if_a.is_trunk and if_b.is_trunk:
            vlan_a = if_a.vlan_id or 1
            vlan_b = if_b.vlan_id or 1
            if vlan_a != vlan_b:
                finding = DiagnosticFinding(
                    category=DiagnosticCategory.VLAN_TRUNKING,
                    severity=DiagnosticSeverity.ERROR,
                    code="NATIVE_VLAN_MISMATCH",
                    target_device=conn.device_b,
                    target_interface=conn.interface_b,
                    summary=(
                        f"Native VLAN mismatch on trunk {conn.device_a}:{conn.interface_a} "
                        f"(VLAN {vlan_a}) <-> {conn.device_b}:{conn.interface_b} (VLAN {vlan_b})."
                    ),
                    evidence=[
                        f"Switch A: {conn.device_a} {conn.interface_a} native VLAN={vlan_a}",
                        f"Switch B: {conn.device_b} {conn.interface_b} native VLAN={vlan_b}",
                    ],
                    probable_causes=[
                        "Trunk native VLAN configured on one switch but not its peer.",
                    ],
                    recommended_fix=(
                        f"Align native VLAN on {conn.device_b}:{conn.interface_b} to {vlan_a}."
                    ),
                )
                repair = RepairProposal(
                    finding_id=finding.finding_id,
                    target_device=conn.device_b,
                    summary=f"Set switchport trunk native vlan {vlan_a} on {conn.device_b}.",
                    actions=[
                        RepairAction(
                            target_device=conn.device_b,
                            target_interface=conn.interface_b,
                            command_sequence=[
                                f"interface {conn.interface_b}",
                                f"switchport trunk native vlan {vlan_a}",
                                "exit",
                            ],
                            description=f"Align trunk native VLAN to {vlan_a}.",
                            is_disruptive=False,
                            verification_commands=[
                                f"show interfaces {conn.interface_b} switchport"
                            ],
                        )
                    ],
                )
                results.append((finding, repair))
    return results
