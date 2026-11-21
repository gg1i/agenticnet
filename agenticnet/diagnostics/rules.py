"""Diagnostic rule evaluators detecting addressing, interface, VLAN, and routing issues."""

from __future__ import annotations

import ipaddress
import re

from agenticnet.core.enums import ConfigCapability, DeviceCategory
from agenticnet.diagnostics.models import (
    DiagnosticCategory,
    DiagnosticFinding,
    DiagnosticSeverity,
    RepairAction,
    RepairProposal,
)
from agenticnet.ipam.engine import IPAMEngine
from agenticnet.simulation.parsers import (
    canonicalize_interface_name,
    parse_running_config_sections,
    parse_show_access_lists,
    parse_show_interfaces_trunk,
    parse_show_ip_int_brief,
    parse_show_ip_ospf_neighbor,
)
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


def _first_usable_ipv4(net: ipaddress.IPv4Network) -> ipaddress.IPv4Address | None:
    """Return the first usable host address in an IPv4 network in O(1) time and memory."""
    if net.prefixlen >= 31:
        return net.network_address
    return net.network_address + 1 if net.num_addresses > 2 else None


def _last_usable_ipv4(net: ipaddress.IPv4Network) -> ipaddress.IPv4Address | None:
    """Return the last usable host address in an IPv4 network in O(1) time and memory."""
    if net.prefixlen >= 31:
        return net.broadcast_address
    return net.broadcast_address - 1 if net.num_addresses > 2 else None


def _pick_distinct_ipv4(
    net: ipaddress.IPv4Network,
    existing_ip: ipaddress.IPv4Address | None,
    *,
    prefer_last: bool,
) -> ipaddress.IPv4Address | None:
    """Select an O(1) usable host IP in `net` that avoids colliding with `existing_ip`."""
    first_ip = _first_usable_ipv4(net)
    last_ip = _last_usable_ipv4(net)
    candidates = (last_ip, first_ip) if prefer_last else (first_ip, last_ip)
    for candidate in candidates:
        if candidate is not None and candidate != existing_ip:
            return candidate
    return candidates[0] or candidates[1]


def _suggest_gateway_for_host(
    ip_addr: str,
    subnet_mask: str | None,
    ipam: IPAMEngine | None,
) -> str:
    """Resolve the best default gateway suggestion from IPAM pools or host subnet."""
    try:
        host_ip: ipaddress.IPv4Address | None = ipaddress.IPv4Address(ip_addr)
    except ValueError:
        host_ip = None

    if ipam is not None and host_ip is not None:
        for pool in ipam.state.pools.values():
            try:
                net = ipaddress.IPv4Network(pool.cidr, strict=False)
                if host_ip in net:
                    if pool.default_gateway:
                        return pool.default_gateway
                    candidate = _pick_distinct_ipv4(net, host_ip, prefer_last=False)
                    if candidate is not None:
                        return str(candidate)
            except Exception:
                continue
    if subnet_mask:
        try:
            net = ipaddress.IPv4Network(f"{ip_addr}/{subnet_mask}", strict=False)
            candidate = _pick_distinct_ipv4(net, host_ip, prefer_last=False)
            if candidate is not None:
                return str(candidate)
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
                            description=(f"Configure default gateway {gw_suggestion} on {d_name}."),
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

            gw_suggestion = _suggest_gateway_for_host(iface.ipv4_address, iface.subnet_mask, ipam)
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
                        description=(f"Set default gateway {gw_suggestion} matching subnet {net}."),
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
                    ip_a_obj = ipaddress.IPv4Address(ip_a)
                    suggested_peer_ip = (
                        _pick_distinct_ipv4(net_a, ip_a_obj, prefer_last=True) or ip_a_obj
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
                                    f"ip address {suggested_peer_ip} {mask_a}",
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
            vlan_a = if_a.native_vlan if if_a.native_vlan != 1 else (if_a.vlan_id or 1)
            vlan_b = if_b.native_vlan if if_b.native_vlan != 1 else (if_b.vlan_id or 1)
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


def _wildcard_matches_ip(ip_str: str, net_str: str, wildcard_str: str) -> bool:
    """Return True if `ip_str` matches Cisco IOS `network <net_str> <wildcard_str>`."""
    try:
        ip_int = int(ipaddress.IPv4Address(ip_str))
        net_int = int(ipaddress.IPv4Address(net_str))
        wc_int = int(ipaddress.IPv4Address(wildcard_str))
    except ValueError:
        return False
    mask_int = (~wc_int) & 0xFFFFFFFF
    return (ip_int & mask_int) == (net_int & mask_int)


def _extract_ospf_config(running_cfg: str) -> dict[str, object] | None:
    """Extract OSPF process_id, `(net, wc, area, raw)` statements, and passive interfaces."""
    sections = parse_running_config_sections(running_cfg, section="router ospf")
    if not sections:
        return None
    sec = sections[0]
    m_pid = re.match(r"^router\s+ospf\s+(\d+)", sec.header, re.IGNORECASE)
    pid = int(m_pid.group(1)) if m_pid else 1
    networks: list[tuple[str, str, int, str]] = []
    passive_ifs: set[str] = set()
    passive_default = False
    no_passive_ifs: set[str] = set()

    _net_re = re.compile(
        r"^network\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+area\s+(\d+)$",
        re.IGNORECASE,
    )
    for line in sec.lines:
        stripped = " ".join(line.strip().split())
        nm = _net_re.match(stripped)
        if nm:
            networks.append((nm.group(1), nm.group(2), int(nm.group(3)), stripped))
            continue
        low = stripped.lower()
        if low == "passive-interface default":
            passive_default = True
        elif low.startswith("no passive-interface "):
            no_passive_ifs.add(canonicalize_interface_name(stripped[21:]))
        elif low.startswith("passive-interface "):
            passive_ifs.add(canonicalize_interface_name(stripped[18:]))

    return {
        "process_id": pid,
        "networks": networks,
        "passive_default": passive_default,
        "passive_ifs": passive_ifs,
        "no_passive_ifs": no_passive_ifs,
    }


def evaluate_live_cli_diagnostics(
    topology: TopologyEngine,
    live_snapshots: dict[str, dict[str, str]],
    *,
    categories: set[DiagnosticCategory] | None = None,
) -> list[tuple[DiagnosticFinding, RepairProposal]]:
    """Diagnose live root causes from captured IOS `show` outputs, quoting CLI evidence."""
    results: list[tuple[DiagnosticFinding, RepairProposal]] = []

    def _want(cat: DiagnosticCategory) -> bool:
        return categories is None or cat in categories

    int_brief_by_dev: dict[str, dict[str, object]] = {}
    ospf_cfg_by_dev: dict[str, dict[str, object]] = {}
    ospf_nbrs_by_dev: dict[str, list[object]] = {}
    trunks_by_dev: dict[str, dict[str, object]] = {}

    connected_ports: set[tuple[str, str]] = set()
    for conn in topology.model.connections.values():
        connected_ports.add((conn.device_a, canonicalize_interface_name(conn.interface_a)))
        connected_ports.add((conn.device_b, canonicalize_interface_name(conn.interface_b)))

    for d_name, snaps in live_snapshots.items():
        dev = topology.model.devices.get(d_name)
        brief_raw = snaps.get("show ip interface brief", "")
        run_raw = snaps.get("show running-config", "")
        trunk_raw = snaps.get("show interfaces trunk", "")
        ospf_raw = snaps.get("show ip ospf neighbor", "")
        acl_raw = snaps.get("show access-lists", "")

        brief_rows = parse_show_ip_int_brief(brief_raw) if brief_raw else []
        brief_map = {canonicalize_interface_name(r.interface): r for r in brief_rows}
        int_brief_by_dev[d_name] = brief_map

        if ospf_raw:
            ospf_nbrs_by_dev[d_name] = list(parse_show_ip_ospf_neighbor(ospf_raw))
        if trunk_raw:
            trunks_by_dev[d_name] = {
                canonicalize_interface_name(t.port): t
                for t in parse_show_interfaces_trunk(trunk_raw)
            }
        if run_raw:
            ospf_info = _extract_ospf_config(run_raw)
            if ospf_info is not None:
                ospf_cfg_by_dev[d_name] = ospf_info

        # 1. Live interface admin-down / protocol-down checks
        if _want(DiagnosticCategory.INTERFACE_PHYSICAL):
            for row in brief_rows:
                canon_if = canonicalize_interface_name(row.interface)
                has_ip = row.ip_address.lower() != "unassigned"
                is_linked = (d_name, canon_if) in connected_ports
                if not (has_ip or is_linked):
                    continue
                quoted = (
                    f"{d_name}# show ip interface brief -> "
                    f"{row.interface} {row.ip_address} {row.status}/{row.protocol}"
                )
                if row.status == "administratively down":
                    finding = DiagnosticFinding(
                        category=DiagnosticCategory.INTERFACE_PHYSICAL,
                        severity=DiagnosticSeverity.ERROR,
                        code="LIVE_INTERFACE_ADMIN_DOWN",
                        target_device=d_name,
                        target_interface=row.interface,
                        summary=(
                            f"Live interface {d_name} {row.interface} ({row.ip_address}) "
                            "is administratively down."
                        ),
                        evidence=[quoted],
                        probable_causes=["Interface remains shutdown in live running-config."],
                        recommended_fix=f"Configure 'no shutdown' on {d_name} {row.interface}.",
                    )
                    repair = RepairProposal(
                        finding_id=finding.finding_id,
                        target_device=d_name,
                        summary=f"Enable {row.interface} on {d_name} ('no shutdown').",
                        actions=[
                            RepairAction(
                                target_device=d_name,
                                target_interface=row.interface,
                                command_sequence=[
                                    f"interface {row.interface}",
                                    "no shutdown",
                                    "exit",
                                ],
                                description=f"Bring up {row.interface} on {d_name}.",
                                is_disruptive=False,
                                verification_commands=["show ip interface brief"],
                            )
                        ],
                    )
                    results.append((finding, repair))
                elif row.status == "up" and row.protocol == "down":
                    finding = DiagnosticFinding(
                        category=DiagnosticCategory.INTERFACE_PHYSICAL,
                        severity=DiagnosticSeverity.ERROR,
                        code="LIVE_INTERFACE_PROTOCOL_DOWN",
                        target_device=d_name,
                        target_interface=row.interface,
                        summary=(
                            f"Live interface {d_name} {row.interface} is up/down "
                            "(Layer 1 up, Layer 2 line protocol down)."
                        ),
                        evidence=[quoted],
                        probable_causes=[
                            "Peer interface is shutdown or disconnected.",
                            "Missing Serial DCE 'clock rate' or mismatched L2 encapsulation.",
                        ],
                        recommended_fix=(
                            f"Verify peer interface state, cabling, and encap on {row.interface}."
                        ),
                    )
                    repair = RepairProposal(
                        finding_id=finding.finding_id,
                        target_device=d_name,
                        summary=f"Bounce/enable {row.interface} on {d_name} and verify peer.",
                        actions=[
                            RepairAction(
                                target_device=d_name,
                                target_interface=row.interface,
                                command_sequence=[
                                    f"interface {row.interface}",
                                    "no shutdown",
                                    "exit",
                                ],
                                description=f"Ensure {row.interface} is administratively up.",
                                is_disruptive=False,
                                verification_commands=["show ip interface brief"],
                            )
                        ],
                    )
                    results.append((finding, repair))

        # 2. Live L3 switch missing `ip routing`
        if (
            _want(DiagnosticCategory.ROUTING)
            and dev is not None
            and dev.category == DeviceCategory.L3_SWITCH
            and run_raw
        ):
            global_secs = parse_running_config_sections(run_raw, section="global")
            global_lines = [ln.strip().lower() for sec in global_secs for ln in sec.lines]
            has_ip_routing = "ip routing" in global_lines and "no ip routing" not in global_lines
            routed_ifaces = [r for r in brief_rows if r.ip_address.lower() != "unassigned"]
            has_routing_intent = (
                len(routed_ifaces) >= 2
                or any(ln.startswith("ip route ") for ln in global_lines)
                or d_name in ospf_cfg_by_dev
                or bool(parse_running_config_sections(run_raw, section="router "))
            )
            if has_routing_intent and not has_ip_routing:
                ev_line = (
                    f"{d_name}# show running-config -> 'no ip routing' present"
                    if "no ip routing" in global_lines
                    else f"{d_name}# show running-config -> global 'ip routing' missing"
                )
                svi_summary = ", ".join(f"{r.interface}={r.ip_address}" for r in routed_ifaces[:4])
                finding = DiagnosticFinding(
                    category=DiagnosticCategory.ROUTING,
                    severity=DiagnosticSeverity.CRITICAL,
                    code="LIVE_L3_SWITCH_MISSING_IP_ROUTING",
                    target_device=d_name,
                    summary=(
                        f"Layer 3 switch {d_name} has L3 interfaces/routes ({svi_summary}) "
                        "but global 'ip routing' is disabled."
                    ),
                    evidence=[ev_line, f"Configured L3 interfaces: {svi_summary}"],
                    probable_causes=[
                        "Catalyst 3560/3650 defaults to L2 switching until 'ip routing' is enabled."
                    ],
                    recommended_fix=f"Enable 'ip routing' in global configuration on {d_name}.",
                )
                repair = RepairProposal(
                    finding_id=finding.finding_id,
                    target_device=d_name,
                    summary=f"Enable 'ip routing' on Layer 3 switch {d_name}.",
                    actions=[
                        RepairAction(
                            target_device=d_name,
                            command_sequence=["ip routing"],
                            description=f"Enable IPv4 inter-VLAN/L3 routing on {d_name}.",
                            is_disruptive=False,
                            verification_commands=["show ip route"],
                        )
                    ],
                )
                results.append((finding, repair))

        # 3. Live ACL deny drops / shadowed permits
        if _want(DiagnosticCategory.ACL_SECURITY) and acl_raw:
            acl_entries = parse_show_access_lists(acl_raw)
            by_acl: dict[str, list[object]] = {}
            for ace in acl_entries:
                by_acl.setdefault(ace.acl_name, []).append(ace)
            for acl_name, aces in by_acl.items():
                saw_deny_all = False
                for ace in aces:
                    if ace.action == "deny" and ace.matches > 0:
                        finding = DiagnosticFinding(
                            category=DiagnosticCategory.ACL_SECURITY,
                            severity=DiagnosticSeverity.WARNING,
                            code="LIVE_ACL_DENY_DROPS",
                            target_device=d_name,
                            summary=(
                                f"ACL '{acl_name}' on {d_name} has {ace.matches} packet drop(s) "
                                f"on 'deny {ace.rule_text}'."
                            ),
                            evidence=[
                                f"{d_name}# show access-lists -> {acl_name}: "
                                f"{ace.sequence or ''} deny {ace.rule_text} "
                                f"({ace.matches} matches)".strip()
                            ],
                            probable_causes=[
                                "Explicit ACL deny rule is actively dropping traffic."
                            ],
                            recommended_fix=(
                                f"Review ACL '{acl_name}' rule order and permit required flows."
                            ),
                        )
                        repair = RepairProposal(
                            finding_id=finding.finding_id,
                            target_device=d_name,
                            summary=f"Inspect/adjust ACL '{acl_name}' on {d_name}.",
                            actions=[],
                            requires_approval=True,
                            approval_reason="Modifying security ACLs requires operator review.",
                        )
                        results.append((finding, repair))
                    if ace.action == "deny" and ace.rule_text.lower() in {"any", "ip any any"}:
                        saw_deny_all = True
                    elif saw_deny_all and ace.action == "permit":
                        finding = DiagnosticFinding(
                            category=DiagnosticCategory.ACL_SECURITY,
                            severity=DiagnosticSeverity.ERROR,
                            code="LIVE_ACL_SHADOWED_PERMIT",
                            target_device=d_name,
                            summary=(
                                f"ACL '{acl_name}' on {d_name} has unreachable "
                                f"'permit {ace.rule_text}' after an earlier 'deny any'."
                            ),
                            evidence=[
                                f"{d_name}# show access-lists -> '{acl_name}' permit "
                                f"{ace.rule_text} shadowed by prior deny-all"
                            ],
                            probable_causes=["ACE sequence numbers placed permit after deny any."],
                            recommended_fix=(
                                f"Resequence ACL '{acl_name}' so permit precedes deny any."
                            ),
                        )
                        repair = RepairProposal(
                            finding_id=finding.finding_id,
                            target_device=d_name,
                            summary=f"Reorder shadowed permit in ACL '{acl_name}' on {d_name}.",
                            actions=[],
                            requires_approval=True,
                            approval_reason="Reordering security ACLs requires operator approval.",
                        )
                        results.append((finding, repair))

    # 4. Cross-device live OSPF root-cause checks & live trunk checks
    l3_categories = {DeviceCategory.ROUTER, DeviceCategory.L3_SWITCH}
    sw_categories = {DeviceCategory.L2_SWITCH, DeviceCategory.L3_SWITCH}

    for conn in topology.model.connections.values():
        dev_a = topology.model.devices.get(conn.device_a)
        dev_b = topology.model.devices.get(conn.device_b)
        if not dev_a or not dev_b:
            continue
        canon_a = canonicalize_interface_name(conn.interface_a)
        canon_b = canonicalize_interface_name(conn.interface_b)

        # Live trunk checks across connected switches
        if (
            _want(DiagnosticCategory.VLAN_TRUNKING)
            and dev_a.category in sw_categories
            and dev_b.category in sw_categories
            and conn.device_a in trunks_by_dev
            and conn.device_b in trunks_by_dev
        ):
            tr_a = trunks_by_dev[conn.device_a].get(canon_a)
            tr_b = trunks_by_dev[conn.device_b].get(canon_b)
            if tr_a is not None and tr_b is not None and tr_a.native_vlan != tr_b.native_vlan:
                finding = DiagnosticFinding(
                    category=DiagnosticCategory.VLAN_TRUNKING,
                    severity=DiagnosticSeverity.ERROR,
                    code="LIVE_TRUNK_NATIVE_VLAN_MISMATCH",
                    target_device=conn.device_b,
                    target_interface=conn.interface_b,
                    summary=(
                        f"Live trunk native VLAN mismatch: {conn.device_a}:{tr_a.port} "
                        f"(VLAN {tr_a.native_vlan}) <-> {conn.device_b}:{tr_b.port} "
                        f"(VLAN {tr_b.native_vlan})."
                    ),
                    evidence=[
                        f"{conn.device_a}# show interfaces trunk -> "
                        f"{tr_a.port} native vlan {tr_a.native_vlan}",
                        f"{conn.device_b}# show interfaces trunk -> "
                        f"{tr_b.port} native vlan {tr_b.native_vlan}",
                    ],
                    probable_causes=[
                        "Mismatched 'switchport trunk native vlan' across peer switches."
                    ],
                    recommended_fix=(
                        f"Set 'switchport trunk native vlan {tr_a.native_vlan}' on "
                        f"{conn.device_b} {conn.interface_b}."
                    ),
                )
                repair = RepairProposal(
                    finding_id=finding.finding_id,
                    target_device=conn.device_b,
                    summary=(
                        f"Align native VLAN to {tr_a.native_vlan} on "
                        f"{conn.device_b}:{conn.interface_b}."
                    ),
                    actions=[
                        RepairAction(
                            target_device=conn.device_b,
                            target_interface=conn.interface_b,
                            command_sequence=[
                                f"interface {conn.interface_b}",
                                f"switchport trunk native vlan {tr_a.native_vlan}",
                                "exit",
                            ],
                            description=f"Align trunk native VLAN to {tr_a.native_vlan}.",
                            is_disruptive=False,
                            verification_commands=["show interfaces trunk"],
                        )
                    ],
                )
                results.append((finding, repair))
            elif (tr_a is None) != (tr_b is None):
                trunk_side = (conn.device_a, tr_a) if tr_a is not None else (conn.device_b, tr_b)
                missing_dev = dev_b if tr_a is not None else dev_a
                missing_if = conn.interface_b if tr_a is not None else conn.interface_a
                cmd_seq = [f"interface {missing_if}"]
                try:
                    prof = topology.catalog.get_profile(missing_dev.model)
                    if prof.supports(ConfigCapability.TRUNK_ENCAP_DOT1Q):
                        cmd_seq.append("switchport trunk encapsulation dot1q")
                except Exception:
                    pass
                cmd_seq.extend(["switchport mode trunk", "exit"])
                finding = DiagnosticFinding(
                    category=DiagnosticCategory.VLAN_TRUNKING,
                    severity=DiagnosticSeverity.ERROR,
                    code="LIVE_TRUNK_MISSING_ON_PEER",
                    target_device=missing_dev.name,
                    target_interface=missing_if,
                    summary=(
                        f"Live switch link {trunk_side[0]}:{trunk_side[1].port} is trunking, "
                        f"but peer {missing_dev.name}:{missing_if} is absent from "
                        "`show interfaces trunk`."
                    ),
                    evidence=[
                        f"{trunk_side[0]}# show interfaces trunk -> {trunk_side[1].port} trunking",
                        f"{missing_dev.name}# show interfaces trunk -> {missing_if} absent",
                    ],
                    probable_causes=["Peer switch port left in access or dynamic auto mode."],
                    recommended_fix=(
                        f"Configure {missing_dev.name} {missing_if} as an 802.1Q trunk."
                    ),
                )
                repair = RepairProposal(
                    finding_id=finding.finding_id,
                    target_device=missing_dev.name,
                    summary=f"Configure 802.1Q trunk on {missing_dev.name}:{missing_if}.",
                    actions=[
                        RepairAction(
                            target_device=missing_dev.name,
                            target_interface=missing_if,
                            command_sequence=cmd_seq,
                            description=f"Enable trunking on {missing_dev.name} {missing_if}.",
                            is_disruptive=True,
                            verification_commands=["show interfaces trunk"],
                        )
                    ],
                    requires_approval=True,
                    approval_reason="Changing switchport mode on an active link is disruptive.",
                )
                results.append((finding, repair))

        # Live OSPF root-cause checks across connected L3 peers
        if (
            _want(DiagnosticCategory.OSPF_ADJACENCY)
            and dev_a.category in l3_categories
            and dev_b.category in l3_categories
            and (conn.device_a in ospf_cfg_by_dev or conn.device_b in ospf_cfg_by_dev)
        ):
            row_a = int_brief_by_dev.get(conn.device_a, {}).get(canon_a)
            row_b = int_brief_by_dev.get(conn.device_b, {}).get(canon_b)
            ip_a = (
                row_a.ip_address
                if (row_a and row_a.ip_address != "unassigned")
                else (
                    dev_a.interfaces.get(conn.interface_a).ipv4_address
                    if conn.interface_a in dev_a.interfaces
                    else None
                )
            )
            ip_b = (
                row_b.ip_address
                if (row_b and row_b.ip_address != "unassigned")
                else (
                    dev_b.interfaces.get(conn.interface_b).ipv4_address
                    if conn.interface_b in dev_b.interfaces
                    else None
                )
            )

            ospf_a = ospf_cfg_by_dev.get(conn.device_a)
            ospf_b = ospf_cfg_by_dev.get(conn.device_b)

            def _matched_area(
                ospf_info: dict[str, object] | None, ip_val: str | None
            ) -> tuple[int, str] | None:
                if not ospf_info or not ip_val:
                    return None
                for net_s, wc_s, area_id, raw_stmt in ospf_info["networks"]:  # type: ignore[index]
                    if _wildcard_matches_ip(ip_val, net_s, wc_s):
                        return (area_id, raw_stmt)
                return None

            def _is_passive(ospf_info: dict[str, object] | None, canon_if: str) -> bool:
                if not ospf_info:
                    return False
                if ospf_info["passive_default"]:
                    return canon_if not in ospf_info["no_passive_ifs"]  # type: ignore[operator]
                return canon_if in ospf_info["passive_ifs"]  # type: ignore[operator]

            match_a = _matched_area(ospf_a, ip_a)
            match_b = _matched_area(ospf_b, ip_b)

            for side_name, side_if, side_canon, side_ospf, side_match in (
                (conn.device_a, conn.interface_a, canon_a, ospf_a, match_a),
                (conn.device_b, conn.interface_b, canon_b, ospf_b, match_b),
            ):
                if side_ospf and side_match and _is_passive(side_ospf, side_canon):
                    pid = side_ospf["process_id"]
                    finding = DiagnosticFinding(
                        category=DiagnosticCategory.OSPF_ADJACENCY,
                        severity=DiagnosticSeverity.ERROR,
                        code="LIVE_OSPF_PASSIVE_INTERFACE_ON_TRANSIT",
                        target_device=side_name,
                        target_interface=side_if,
                        summary=(
                            f"OSPF transit interface {side_name} {side_if} is configured "
                            "as passive-interface, blocking Hello packets."
                        ),
                        evidence=[
                            f"{side_name}# show running-config -> router ospf {pid}: "
                            f"passive-interface suppressing Hellos on {side_if} ({side_match[1]})"
                        ],
                        probable_causes=[
                            "Transit router link mistakenly marked passive-interface."
                        ],
                        recommended_fix=(
                            f"Configure 'no passive-interface {side_if}' under "
                            f"router ospf {pid} on {side_name}."
                        ),
                    )
                    repair = RepairProposal(
                        finding_id=finding.finding_id,
                        target_device=side_name,
                        summary=(
                            f"Remove passive-interface {side_if} under OSPF {pid} on {side_name}."
                        ),
                        actions=[
                            RepairAction(
                                target_device=side_name,
                                target_interface=side_if,
                                command_sequence=[
                                    f"router ospf {pid}",
                                    f"no passive-interface {side_if}",
                                    "exit",
                                ],
                                description=f"Allow OSPF Hellos on transit link {side_if}.",
                                is_disruptive=False,
                                verification_commands=["show ip ospf neighbor"],
                            )
                        ],
                    )
                    results.append((finding, repair))

            if match_a is not None and match_b is not None and match_a[0] != match_b[0]:
                pid_b = ospf_b["process_id"] if ospf_b else 1
                finding = DiagnosticFinding(
                    category=DiagnosticCategory.OSPF_ADJACENCY,
                    severity=DiagnosticSeverity.ERROR,
                    code="LIVE_OSPF_AREA_MISMATCH",
                    target_device=conn.device_b,
                    target_interface=conn.interface_b,
                    summary=(
                        f"OSPF area mismatch on link {conn.device_a}:{conn.interface_a} "
                        f"(area {match_a[0]}) <-> "
                        f"{conn.device_b}:{conn.interface_b} (area {match_b[0]})."
                    ),
                    evidence=[
                        f"{conn.device_a}# show running-config -> {match_a[1]}",
                        f"{conn.device_b}# show running-config -> {match_b[1]}",
                    ],
                    probable_causes=[
                        "Connected OSPF routers advertise shared link in different areas."
                    ],
                    recommended_fix=(
                        f"Align OSPF network statement on {conn.device_b} to area {match_a[0]}."
                    ),
                )
                new_stmt = re.sub(
                    r"area\s+\d+$", f"area {match_a[0]}", match_b[1], flags=re.IGNORECASE
                )
                repair = RepairProposal(
                    finding_id=finding.finding_id,
                    target_device=conn.device_b,
                    summary=f"Align OSPF area on {conn.device_b} to area {match_a[0]}.",
                    actions=[
                        RepairAction(
                            target_device=conn.device_b,
                            target_interface=conn.interface_b,
                            command_sequence=[
                                f"router ospf {pid_b}",
                                f"no {match_b[1]}",
                                new_stmt,
                                "exit",
                            ],
                            description=(
                                f"Move {conn.device_b} link network into area {match_a[0]}."
                            ),
                            is_disruptive=True,
                            verification_commands=["show ip ospf neighbor"],
                        )
                    ],
                    requires_approval=True,
                    approval_reason="Changing an OSPF area resets existing neighbor adjacencies.",
                )
                results.append((finding, repair))
            elif (
                ospf_a is not None and ospf_b is not None and (match_a is None) != (match_b is None)
            ):
                active_match = match_a if match_a is not None else match_b
                miss_name = conn.device_b if match_a is not None else conn.device_a
                miss_if = conn.interface_b if match_a is not None else conn.interface_a
                miss_ip = ip_b if match_a is not None else ip_a
                miss_ospf = ospf_b if match_a is not None else ospf_a
                if active_match is not None and miss_ip and miss_ospf:
                    pid_m = miss_ospf["process_id"]
                    finding = DiagnosticFinding(
                        category=DiagnosticCategory.OSPF_ADJACENCY,
                        severity=DiagnosticSeverity.ERROR,
                        code="LIVE_OSPF_MISSING_NETWORK_STATEMENT",
                        target_device=miss_name,
                        target_interface=miss_if,
                        summary=(
                            f"Router {miss_name} runs OSPF {pid_m} but lacks a 'network' statement "
                            f"matching {miss_if} ({miss_ip})."
                        ),
                        evidence=[
                            f"{miss_name}# show running-config -> router ospf {pid_m} "
                            f"has no network covering {miss_ip}",
                            f"Peer OSPF link advertises area {active_match[0]} "
                            f"({active_match[1]})",
                        ],
                        probable_causes=[
                            "Missing or mistyped OSPF network/wildcard statement for transit link."
                        ],
                        recommended_fix=(
                            f"Add 'network {miss_ip} 0.0.0.0 area {active_match[0]}' "
                            f"under router ospf {pid_m}."
                        ),
                    )
                    repair = RepairProposal(
                        finding_id=finding.finding_id,
                        target_device=miss_name,
                        summary=(
                            f"Advertise {miss_if} ({miss_ip}) in OSPF {pid_m} "
                            f"area {active_match[0]} on {miss_name}."
                        ),
                        actions=[
                            RepairAction(
                                target_device=miss_name,
                                target_interface=miss_if,
                                command_sequence=[
                                    f"router ospf {pid_m}",
                                    f"network {miss_ip} 0.0.0.0 area {active_match[0]}",
                                    "exit",
                                ],
                                description=f"Enable OSPF on {miss_name} {miss_if}.",
                                is_disruptive=False,
                                verification_commands=["show ip ospf neighbor"],
                            )
                        ],
                    )
                    results.append((finding, repair))

    return results
