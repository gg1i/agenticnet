"""Parsers for Cisco IOS and Packet Tracer ping, routing, ARP, interface, and VLAN outputs."""

from __future__ import annotations

import re

from netforge.simulation.models import (
    PacketEventRecord,
    ParsedArpEntry,
    ParsedInterfaceBrief,
    ParsedOspfNeighbor,
    ParsedPingSummary,
    ParsedRouteEntry,
    ParsedVlanEntry,
)

_IOS_PING_RE = re.compile(
    r"Success rate is\s+(\d+)\s+percent\s+\((\d+)/(\d+)\)"
    r"(?:,\s*round-trip min/avg/max\s*=\s*(\d+)/(\d+)/(\d+)\s*ms)?",
    re.IGNORECASE,
)
_IOS_PING_TARGET_RE = re.compile(
    r"Sending\s+\d+,\s+\d+-byte\s+ICMP\s+Echos\s+to\s+([0-9.]+)",
    re.IGNORECASE,
)
_PC_PING_STATS_RE = re.compile(
    r"Packets:\s*Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)",
    re.IGNORECASE,
)
_PC_PING_RTT_RE = re.compile(
    r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
    re.IGNORECASE,
)
_PC_PING_HOST_RE = re.compile(r"(?:Pinging|Ping statistics for)\s+([0-9.]+)", re.IGNORECASE)

_ROUTE_LINE_RE = re.compile(
    r"^([CSOLRD*B][A-Z0-9* ]{0,4})\s+([0-9./]+)\s+"
    r"(?:\[(\d+/\d+)\]\s+via\s+([0-9.]+)(?:,\s*[^,]+,\s*(\S+))?|"
    r"is\s+directly\s+connected,\s*(\S+))",
    re.IGNORECASE,
)
_ARP_IOS_RE = re.compile(
    r"^Internet\s+([0-9.]+)\s+(\S+)\s+([0-9a-fA-F.:]+)\s+ARPA\s+(\S+)",
    re.IGNORECASE,
)
_INT_BRIEF_RE = re.compile(
    r"^(\S+)\s+(unassigned|[0-9.]+)\s+(YES|NO)\s+(\S+)\s+"
    r"(up|down|administratively down)\s+(up|down)$",
    re.IGNORECASE,
)
_VLAN_ROW_RE = re.compile(r"^(\d{1,4})\s+(\S+)\s+(active|act/unsup|suspended)\s*(.*)$", re.I)
_OSPF_NEIGHBOR_RE = re.compile(r"^([0-9.]+)\s+(\d+)\s+(\S+(?:/\S+)?)\s+\S+\s+([0-9.]+)\s+(\S+)$")


def parse_ios_ping_output(raw_text: str, *, target_ip: str | None = None) -> ParsedPingSummary:
    """Parse Cisco IOS `ping` output into structured statistics."""
    tgt_match = _IOS_PING_TARGET_RE.search(raw_text)
    target = target_ip or (tgt_match.group(1) if tgt_match else None)
    match = _IOS_PING_RE.search(raw_text)
    if not match:
        return ParsedPingSummary(parser_kind="cisco_ios", target_ip=target, reached=False)

    pct = int(match.group(1))
    rx = int(match.group(2))
    tx = int(match.group(3))
    min_ms = float(match.group(4)) if match.group(4) else None
    avg_ms = float(match.group(5)) if match.group(5) else None
    max_ms = float(match.group(6)) if match.group(6) else None
    return ParsedPingSummary(
        parser_kind="cisco_ios",
        target_ip=target,
        transmitted=tx,
        received=rx,
        loss_percent=round(100.0 - float(pct), 2),
        min_rtt_ms=min_ms,
        avg_rtt_ms=avg_ms,
        max_rtt_ms=max_ms,
        reached=rx > 0,
    )


def parse_pc_ping_output(raw_text: str, *, target_ip: str | None = None) -> ParsedPingSummary:
    """Parse Packet Tracer PC/Laptop Command Prompt `ping` output."""
    host_m = _PC_PING_HOST_RE.search(raw_text)
    target = target_ip or (host_m.group(1) if host_m else None)
    stat_m = _PC_PING_STATS_RE.search(raw_text)
    if not stat_m:
        return ParsedPingSummary(parser_kind="pt_pc_cmd", target_ip=target, reached=False)

    tx = int(stat_m.group(1))
    rx = int(stat_m.group(2))
    loss = round(((tx - rx) / tx) * 100.0, 2) if tx > 0 else 100.0
    rtt_m = _PC_PING_RTT_RE.search(raw_text)
    return ParsedPingSummary(
        parser_kind="pt_pc_cmd",
        target_ip=target,
        transmitted=tx,
        received=rx,
        loss_percent=loss,
        min_rtt_ms=float(rtt_m.group(1)) if rtt_m else None,
        max_rtt_ms=float(rtt_m.group(2)) if rtt_m else None,
        avg_rtt_ms=float(rtt_m.group(3)) if rtt_m else None,
        reached=rx > 0,
    )


def parse_ping_output(raw_text: str, *, target_ip: str | None = None) -> ParsedPingSummary:
    """Auto-detect IOS vs Packet Tracer PC ping output format and parse it."""
    if "Success rate is" in raw_text or "Sending " in raw_text:
        return parse_ios_ping_output(raw_text, target_ip=target_ip)
    return parse_pc_ping_output(raw_text, target_ip=target_ip)


def parse_show_ip_route(raw_text: str) -> dict[str, object]:
    """Parse Cisco IOS `show ip route` table lines and gateway of last resort."""
    gateway_of_last_resort: str | None = None
    routes: list[ParsedRouteEntry] = []

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if line.lower().startswith("gateway of last resort is"):
            gateway_of_last_resort = line
            continue
        m = _ROUTE_LINE_RE.match(line)
        if m:
            code, net, metric, next_hop, via_iface, direct_iface = m.groups()
            routes.append(
                ParsedRouteEntry(
                    code=code.strip(),
                    network=net.strip(),
                    metric=metric,
                    next_hop=next_hop,
                    outgoing_interface=via_iface or direct_iface,
                    raw_line=line,
                )
            )
    return {
        "gateway_of_last_resort": gateway_of_last_resort,
        "routes": routes,
    }


def parse_show_arp(raw_text: str) -> list[ParsedArpEntry]:
    """Parse Cisco IOS `show arp` table entries."""
    entries: list[ParsedArpEntry] = []
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        m = _ARP_IOS_RE.match(line)
        if m:
            ip, age, mac, iface = m.groups()
            entries.append(
                ParsedArpEntry(ip_address=ip, age_min=age, mac_address=mac, interface=iface)
            )
    return entries


def parse_show_ip_int_brief(raw_text: str) -> list[ParsedInterfaceBrief]:
    """Parse Cisco IOS `show ip interface brief` status rows."""
    rows: list[ParsedInterfaceBrief] = []
    for raw_line in raw_text.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line or line.lower().startswith("interface "):
            continue
        # Handle 'administratively down' two-token status field properly
        m = _INT_BRIEF_RE.match(line)
        if m:
            iface, ip_addr, ok_raw, method, status, proto = m.groups()
            rows.append(
                ParsedInterfaceBrief(
                    interface=iface,
                    ip_address=ip_addr,
                    ok=(ok_raw.upper() == "YES"),
                    method=method,
                    status=status.lower(),
                    protocol=proto.lower(),
                )
            )
    return rows


def parse_show_vlan_brief(raw_text: str) -> list[ParsedVlanEntry]:
    """Parse Cisco IOS switch `show vlan brief` table rows."""
    vlans: list[ParsedVlanEntry] = []
    current: ParsedVlanEntry | None = None
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("VLAN", "----")):
            continue
        m = _VLAN_ROW_RE.match(line)
        if m:
            vid_str, name, status, ports_str = m.groups()
            ports = [p.strip() for p in ports_str.split(",") if p.strip()]
            current = ParsedVlanEntry(vlan_id=int(vid_str), name=name, status=status, ports=ports)
            vlans.append(current)
        elif current is not None and not line[0].isdigit():
            extra_ports = [p.strip() for p in line.split(",") if p.strip()]
            current.ports.extend(extra_ports)
    return vlans


def parse_show_ip_ospf_neighbor(raw_text: str) -> list[ParsedOspfNeighbor]:
    """Parse Cisco IOS `show ip ospf neighbor` adjacency rows."""
    neighbors: list[ParsedOspfNeighbor] = []
    for raw_line in raw_text.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line or line.lower().startswith("neighbor id"):
            continue
        m = _OSPF_NEIGHBOR_RE.match(line)
        if m:
            nid, prio, state, addr, iface = m.groups()
            neighbors.append(
                ParsedOspfNeighbor(
                    neighbor_id=nid,
                    priority=int(prio),
                    state=state,
                    address=addr,
                    interface=iface,
                )
            )
    return neighbors


def parse_simulation_event_lines(raw_text: str) -> list[PacketEventRecord]:
    """Parse structured or delimited Packet Tracer Simulation Event List lines."""
    events: list[PacketEventRecord] = []
    seq = 1
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith(("vis", "time", "---")):
            continue
        parts = [p.strip() for p in re.split(r"\t+|\s*\|\s*|\s{2,}", line) if p.strip()]
        if len(parts) < 3:
            continue
        time_val: float | None = None
        offset = 0
        try:
            time_val = float(parts[0])
            offset = 1
        except ValueError:
            offset = 0
        last_dev = parts[offset] if len(parts) > offset else None
        at_dev = parts[offset + 1] if len(parts) > offset + 1 else (last_dev or "unknown")
        proto = parts[offset + 2] if len(parts) > offset + 2 else "ICMP"
        info = " | ".join(parts[offset + 3 :]) if len(parts) > offset + 3 else ""
        events.append(
            PacketEventRecord(
                event_seq=seq,
                time_sec=time_val,
                last_device=last_dev,
                at_device=at_dev,
                protocol=proto,
                details=info,
            )
        )
        seq += 1
    return events
