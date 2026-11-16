"""Diagnostic rule evaluators detecting addressing, interface, VLAN, and routing issues."""

from __future__ import annotations

import ipaddress

from agenticnet.core.enums import ConfigCapability, DeviceCategory
from agenticnet.diagnostics.models import (
    DiagnosticCategory,
    DiagnosticFinding,
    DiagnosticSeverity,
    RepairAction,
    RepairProposal,
)
from agenticnet.ipam.engine import IPAMEngine
from agenticnet.topology.engine import TopologyEngine


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


def _suggest_gateway_for_host(
    ip_addr: str,
    subnet_mask: str | None,
    ipam: IPAMEngine | None,
) -> str:
    """Resolve the best default gateway suggestion from IPAM pools or host subnet."""
    if ipam is not None:
        for pool in ipam.state.pools.values():
            try:
                net = ipaddress.IPv4Network(pool.cidr, strict=False)
                if ipaddress.IPv4Address(ip_addr) in net:
                    return pool.default_gateway or str(list(net.hosts())[0])
            except Exception:
                continue
    if subnet_mask:
        try:
            net = ipaddress.IPv4Network(f"{ip_addr}/{subnet_mask}", strict=False)
            hosts = list(net.hosts())
            if hosts:
                return str(hosts[0])
        except Exception:
            pass
    return "192.168.1.1"


def check_missing_default_gateways(
    topology: TopologyEngine,
    ipam: IPAMEngine | None = None,
) -> list[tuple[DiagnosticFinding, RepairProposal]]:
    """Flag end devices with missing or out-of-subnet default gateways."""
    results: list[tuple[DiagnosticFinding, RepairProposal]] = []
    host_categories = {
        DeviceCategory.PC,
        DeviceCategory.LAPTOP,
        DeviceCategory.SERVER,
        DeviceCategory.PRINTER,
    }

    for d_name, dev in topology.model.devices.items():
        if dev.category not in host_categories:
            continue
        for if_name, iface in dev.interfaces.items():
            if not iface.ipv4_address:
                continue
            host_mask = iface.subnet_mask or "255.255.255.0"
            if not iface.default_gateway:
                gw_suggestion = _suggest_gateway_for_host(
                    iface.ipv4_address, iface.subnet_mask, ipam
                )
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
                continue

            if not iface.subnet_mask:
                continue
            try:
                net = ipaddress.IPv4Network(
                    f"{iface.ipv4_address}/{iface.subnet_mask}",
                    strict=False,
                )
                gw_ip = ipaddress.IPv4Address(iface.default_gateway)
            except Exception:
                continue
            is_invalid_gw = gw_ip not in net or (
                net.prefixlen < 31 and gw_ip in {net.network_address, net.broadcast_address}
            )
            if not is_invalid_gw:
                continue

            gw_suggestion = _suggest_gateway_for_host(
                iface.ipv4_address, iface.subnet_mask, ipam
            )
            finding = DiagnosticFinding(
                category=DiagnosticCategory.ADDRESSING_IPAM,
                severity=DiagnosticSeverity.ERROR,
                code="HOST_GATEWAY_OUTSIDE_SUBNET",
                target_device=d_name,
                target_interface=if_name,
                summary=(
                    f"Host {d_name} ({if_name}) default gateway {iface.default_gateway} "
                    f"is outside subnet {net}."
                ),
                evidence=[
                    f"Host: {d_name} ({dev.category.value}), Interface: {if_name}",
                    f"Host IP/Mask: {iface.ipv4_address}/{iface.subnet_mask} (Subnet: {net})",
                    f"Configured Default Gateway: {iface.default_gateway}",
                ],
                probable_causes=[
                    "Typo in host default gateway or subnet mask.",
                    "Host moved to a different VLAN/subnet without updating gateway.",
                ],
                recommended_fix=(
                    f"Update default gateway on {d_name} to an active router IP in {net} "
                    f"(e.g. {gw_suggestion})."
                ),
            )
            repair = RepairProposal(
                finding_id=finding.finding_id,
                target_device=d_name,
                summary=f"Correct default gateway to {gw_suggestion} for {d_name}.",
                actions=[
                    RepairAction(
                        target_device=d_name,
                        target_interface=if_name,
                        command_sequence=[
                            f"ipconfig {iface.ipv4_address} {host_mask} {gw_suggestion}"
                        ],
                        description=(
                            f"Set default gateway {gw_suggestion} matching subnet {net}."
                        ),
                        is_disruptive=True,
                    )
                ],
                requires_approval=True,
                approval_reason="Changing an existing default gateway alters active host routing.",
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


def check_trunk_mode_mismatch(
    topology: TopologyEngine,
) -> list[tuple[DiagnosticFinding, RepairProposal]]:
    """Flag switch-to-switch links where one endpoint is a trunk and the peer is not."""
    results: list[tuple[DiagnosticFinding, RepairProposal]] = []
    switch_categories = {DeviceCategory.L2_SWITCH, DeviceCategory.L3_SWITCH}

    for _link_id, conn in topology.model.connections.items():
        dev_a = topology.model.devices.get(conn.device_a)
        dev_b = topology.model.devices.get(conn.device_b)
        if not dev_a or not dev_b:
            continue
        if dev_a.category not in switch_categories or dev_b.category not in switch_categories:
            continue

        if_a = dev_a.interfaces.get(conn.interface_a)
        if_b = dev_b.interfaces.get(conn.interface_b)
        if not if_a or not if_b or if_a.is_trunk == if_b.is_trunk:
            continue

        trunk_dev, trunk_if = (dev_a, if_a) if if_a.is_trunk else (dev_b, if_b)
        non_trunk_dev, non_trunk_if = (dev_b, if_b) if if_a.is_trunk else (dev_a, if_a)

        cmd_seq = [f"interface {non_trunk_if.name}"]
        try:
            profile = topology.catalog.get_profile(non_trunk_dev.model)
            if profile.supports(ConfigCapability.TRUNK_ENCAP_DOT1Q):
                cmd_seq.append("switchport trunk encapsulation dot1q")
        except Exception:
            pass
        cmd_seq.extend(["switchport mode trunk", "exit"])

        finding = DiagnosticFinding(
            category=DiagnosticCategory.VLAN_TRUNKING,
            severity=DiagnosticSeverity.ERROR,
            code="TRUNK_MODE_MISMATCH",
            target_device=non_trunk_dev.name,
            target_interface=non_trunk_if.name,
            summary=(
                f"Trunk mode mismatch on {trunk_dev.name}:{trunk_if.name} (trunk) "
                f"<-> {non_trunk_dev.name}:{non_trunk_if.name} (non-trunk)."
            ),
            evidence=[
                f"Trunk side: {trunk_dev.name} {trunk_if.name} (is_trunk=True)",
                f"Peer side: {non_trunk_dev.name} {non_trunk_if.name} (is_trunk=False)",
            ],
            probable_causes=[
                "One switch uplink configured as trunk while peer remains in access/dynamic mode.",
            ],
            recommended_fix=(
                f"Configure {non_trunk_dev.name}:{non_trunk_if.name} as an 802.1Q trunk."
            ),
        )
        repair = RepairProposal(
            finding_id=finding.finding_id,
            target_device=non_trunk_dev.name,
            summary=f"Enable 802.1Q trunking on {non_trunk_dev.name}:{non_trunk_if.name}.",
            actions=[
                RepairAction(
                    target_device=non_trunk_dev.name,
                    target_interface=non_trunk_if.name,
                    command_sequence=cmd_seq,
                    description=(
                        f"Configure {non_trunk_if.name} as trunk to match {trunk_dev.name}."
                    ),
                    is_disruptive=True,
                    verification_commands=["show interfaces trunk"],
                )
            ],
            requires_approval=True,
            approval_reason="Switching an interface to trunk mode disrupts current port traffic.",
        )
        results.append((finding, repair))
    return results
