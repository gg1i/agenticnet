"""Parsers for Cisco IOS and Packet Tracer ping, routing, ARP, interface, and VLAN outputs."""

from __future__ import annotations

import re

from agenticnet.simulation.models import (
    PacketEventRecord,
    ParsedAclEntry,
    ParsedArpEntry,
    ParsedBgpNeighbor,
    ParsedCdpNeighbor,
    ParsedConfigSection,
    ParsedDhcpBinding,
    ParsedEphoneButton,
    ParsedEphoneEntry,
    ParsedEtherChannelGroup,
    ParsedEtherChannelMember,
    ParsedHostIpconfig,
    ParsedHsrpGroup,
    ParsedInterfaceBrief,
    ParsedNatTranslation,
    ParsedOspfNeighbor,
    ParsedPingSummary,
    ParsedRouteEntry,
    ParsedStpPortRole,
    ParsedStpVlanInstance,
    ParsedTelephonyStatus,
    ParsedTracerouteHop,
    ParsedTracerouteSummary,
    ParsedTrunkInterface,
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

_SUBNET_HEADER_RE = re.compile(
    r"^[0-9.]+\s*/(\d+)\s+is\s+(?!variably\s+)subnetted",
    re.IGNORECASE,
)
_ROUTE_LINE_RE = re.compile(
    r"^([CSOLRD*Bi](?:[A-Z0-9* ]{0,4})?)\s+([0-9.]+(?:/\d+)?)\s+"
    r"(?:\[(\d+/\d+)\]\s+via\s+([0-9.]+)(?:,\s*(?:[^,\s]+,\s*)?(\S+))?|"
    r"is\s+directly\s+connected,\s*(\S+))",
    re.IGNORECASE,
)
_ROUTE_WRAPPED_HEAD_RE = re.compile(
    r"^([CSOLRD*Bi](?:[A-Z0-9* ]{0,4})?)\s+([0-9.]+(?:/\d+)?)$",
    re.IGNORECASE,
)
_ROUTE_VIA_CONTINUATION_RE = re.compile(
    r"^\[(\d+/\d+)\]\s+via\s+([0-9.]+)(?:,\s*(?:[^,\s]+,\s*)?(\S+))?$",
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
_VLAN_ROW_RE = re.compile(
    r"^(\d{1,4})\s+(\S+)\s+(active|act/unsup|act/lshut|suspended|inactive)\s*(.*)$",
    re.IGNORECASE,
)
_VLAN_PORT_TOKEN_RE = re.compile(r"^(?:Fa|Gi|Te|Eth|Se|Po|Vl)\S*\d", re.IGNORECASE)
_OSPF_NEIGHBOR_RE = re.compile(r"^([0-9.]+)\s+(\d+)\s+(\S+(?:/\S+)?)\s+\S+\s+([0-9.]+)\s+(\S+)$")
_DHCP_BINDING_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s+(.+?)\s+(Automatic|Manual|Static|Dynamic)$",
    re.IGNORECASE,
)
_PROMPT_LINE_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:\([a-zA-Z0-9_-]+\))?[>#]\s*(?:show\b.*)?$")
_CLI_READ_ERROR_PATTERNS = (
    re.compile(r"%\s*Invalid input detected", re.IGNORECASE),
    re.compile(r"%\s*Incomplete command", re.IGNORECASE),
    re.compile(r"%\s*Ambiguous command", re.IGNORECASE),
    re.compile(r"%\s*Unknown command", re.IGNORECASE),
    re.compile(r"%\s*Unrecognized command", re.IGNORECASE),
    re.compile(r"Translating\s+\"[^\"]+\"\.\.\.domain server", re.IGNORECASE),
)

_IFACE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("tengigabitethernet", "tengigabitethernet"),
    ("tengig", "tengigabitethernet"),
    ("te", "tengigabitethernet"),
    ("gigabitethernet", "gigabitethernet"),
    ("gigabit", "gigabitethernet"),
    ("gig", "gigabitethernet"),
    ("gi", "gigabitethernet"),
    ("fastethernet", "fastethernet"),
    ("fasteth", "fastethernet"),
    ("fa", "fastethernet"),
    ("ethernet", "ethernet"),
    ("eth", "ethernet"),
    ("serial", "serial"),
    ("ser", "serial"),
    ("se", "serial"),
    ("loopback", "loopback"),
    ("lo", "loopback"),
    ("port-channel", "port-channel"),
    ("po", "port-channel"),
    ("dot11radio", "dot11radio"),
    ("dot11", "dot11radio"),
    ("wireless", "wireless"),
    ("wlan", "wireless"),
    ("management", "management"),
    ("mgmt", "management"),
    ("vlan", "vlan"),
    ("vl", "vlan"),
)


def canonicalize_interface_name(name: str) -> str:
    """Normalize short/long Cisco IOS interface names (e.g. `Gi0/0` -> `gigabitethernet0/0`)."""
    cleaned = re.sub(r"\s+", "", name.strip()).lower()
    m = re.match(r"^([a-z-]+?)(\d.*)$", cleaned)
    if not m:
        return cleaned
    prefix, suffix = m.groups()
    for short, full in _IFACE_PREFIXES:
        if prefix == short or (len(prefix) >= 2 and full.startswith(prefix)):
            return f"{full}{suffix}"
    return cleaned


def clean_ios_output(raw_text: str) -> str:
    """Strip CR, `--More--` / `<--- More --->` pagers, and IOS prompt echoes for parsing."""
    text = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\s*(?:--More--|<---\s*More\s*--->)\s*", "\n", text, flags=re.IGNORECASE)
    lines: list[str] = []
    for line in text.splitlines():
        if _PROMPT_LINE_RE.match(line.strip()):
            continue
        lines.append(line)
    return "\n".join(lines)


_TERM_LEN_ERR_RE = re.compile(
    r"terminal length 0\s*\r?\n\s*\^\s*\r?\n%\s*Invalid input detected[^\r\n]*",
    re.IGNORECASE,
)


def detect_cli_read_error(raw_text: str) -> str | None:
    """Return an error reason when raw CLI read output indicates failure or unreadability."""
    sanitized_for_err = _TERM_LEN_ERR_RE.sub("", raw_text)
    cleaned = clean_ios_output(sanitized_for_err).strip()
    if not cleaned:
        return "Empty CLI output received from device."
    for pattern in _CLI_READ_ERROR_PATTERNS:
        m = pattern.search(sanitized_for_err)
        if m:
            return f"IOS CLI error detected: {m.group(0)}"
    return None


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
    """Parse Cisco IOS `show ip route` table lines (including wrapped and ECMP routes)."""
    gateway_of_last_resort: str | None = None
    routes: list[ParsedRouteEntry] = []
    inherited_mask: str | None = None
    pending_wrapped: tuple[str, str] | None = None

    for raw_line in clean_ios_output(raw_text).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("gateway of last resort is"):
            gateway_of_last_resort = line
            pending_wrapped = None
            continue
        if "is variably subnetted" in line.lower():
            inherited_mask = None
            pending_wrapped = None
            continue
        sub_m = _SUBNET_HEADER_RE.match(line)
        if sub_m:
            inherited_mask = sub_m.group(1)
            pending_wrapped = None
            continue

        m = _ROUTE_LINE_RE.match(line)
        if m:
            code, net, metric, next_hop, via_iface, direct_iface = m.groups()
            norm_net = net.strip()
            if "/" not in norm_net and inherited_mask is not None:
                norm_net = f"{norm_net}/{inherited_mask}"
            routes.append(
                ParsedRouteEntry(
                    code=code.strip(),
                    network=norm_net,
                    metric=metric,
                    next_hop=next_hop,
                    outgoing_interface=via_iface or direct_iface,
                    raw_line=line,
                )
            )
            pending_wrapped = None
            continue

        wrap_m = _ROUTE_WRAPPED_HEAD_RE.match(line)
        if wrap_m:
            code, net = wrap_m.groups()
            norm_net = net.strip()
            if "/" not in norm_net and inherited_mask is not None:
                norm_net = f"{norm_net}/{inherited_mask}"
            pending_wrapped = (code.strip(), norm_net)
            continue

        cont_m = _ROUTE_VIA_CONTINUATION_RE.match(line)
        if cont_m:
            metric, next_hop, via_iface = cont_m.groups()
            if pending_wrapped is not None:
                w_code, w_net = pending_wrapped
                routes.append(
                    ParsedRouteEntry(
                        code=w_code,
                        network=w_net,
                        metric=metric,
                        next_hop=next_hop,
                        outgoing_interface=via_iface,
                        raw_line=f"{w_code} {w_net} {line}",
                    )
                )
                pending_wrapped = None
            elif routes:
                prev = routes[-1]
                routes.append(
                    ParsedRouteEntry(
                        code=prev.code,
                        network=prev.network,
                        metric=metric,
                        next_hop=next_hop,
                        outgoing_interface=via_iface,
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
    for raw_line in clean_ios_output(raw_text).splitlines():
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
    for raw_line in clean_ios_output(raw_text).splitlines():
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
    for raw_line in clean_ios_output(raw_text).splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("VLAN", "----")):
            continue
        m = _VLAN_ROW_RE.match(line)
        if m:
            vid_str, name, status, ports_str = m.groups()
            ports = [p.strip() for p in ports_str.split(",") if p.strip()]
            current = ParsedVlanEntry(
                vlan_id=int(vid_str),
                name=name,
                status=status.lower(),
                ports=ports,
            )
            vlans.append(current)
        elif current is not None and not line[0].isdigit():
            tokens = [p.strip() for p in line.split(",") if p.strip()]
            extra_ports = [t for t in tokens if _VLAN_PORT_TOKEN_RE.match(t)]
            if extra_ports:
                current.ports.extend(extra_ports)
            else:
                current = None
    return vlans


def parse_show_ip_ospf_neighbor(raw_text: str) -> list[ParsedOspfNeighbor]:
    """Parse Cisco IOS `show ip ospf neighbor` adjacency rows."""
    neighbors: list[ParsedOspfNeighbor] = []
    for raw_line in clean_ios_output(raw_text).splitlines():
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


def parse_running_config_sections(
    raw_text: str,
    *,
    section: str | None = None,
) -> list[ParsedConfigSection]:
    """Split Cisco IOS `show running-config` into logical top-level sections."""
    cleaned = clean_ios_output(raw_text)
    sections: list[ParsedConfigSection] = []
    global_lines: list[str] = []
    current_header: str | None = None
    current_lines: list[str] = []

    def _flush_block() -> None:
        nonlocal current_header, current_lines
        if current_header is not None:
            sections.append(
                ParsedConfigSection(
                    header=current_header,
                    lines=list(current_lines),
                    text="\n".join([current_header, *current_lines]),
                )
            )
            current_header = None
            current_lines = []

    _ignore_prefixes = (
        "Building configuration",
        "Current configuration",
        "version ",
        "end",
    )
    for raw_line in cleaned.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped == "!":
            _flush_block()
            continue
        if stripped.startswith(_ignore_prefixes):
            continue
        if line[:1].isspace():
            if current_header is not None:
                current_lines.append(stripped)
            else:
                global_lines.append(stripped)
            continue

        # Top-level unindented line starts either a section header or global directive
        _flush_block()
        if stripped.lower().startswith(
            (
                "interface ",
                "router ",
                "ip dhcp pool ",
                "telephony-service",
                "ephone-dn ",
                "ephone ",
                "vlan ",
                "line ",
                "ip access-list ",
            )
        ):
            current_header = stripped
            current_lines = []
        else:
            global_lines.append(stripped)

    _flush_block()
    if global_lines:
        sections.insert(
            0,
            ParsedConfigSection(
                header="global",
                lines=global_lines,
                text="\n".join(global_lines),
            ),
        )

    if section is not None:
        target = section.strip().lower()
        target_iface_canon = (
            canonicalize_interface_name(target[10:])
            if target.startswith("interface ")
            else canonicalize_interface_name(target)
        )
        matched: list[ParsedConfigSection] = []
        for sec in sections:
            hdr_low = sec.header.lower()
            hdr_iface_canon = (
                canonicalize_interface_name(hdr_low[10:])
                if hdr_low.startswith("interface ")
                else None
            )
            if (
                hdr_low == target
                or hdr_low.startswith(target)
                or (hdr_iface_canon is not None and hdr_iface_canon == target_iface_canon)
            ):
                matched.append(sec)
        return matched
    return sections


def parse_show_ip_dhcp_binding(raw_text: str) -> list[ParsedDhcpBinding]:
    """Parse Cisco IOS `show ip dhcp binding` lease table."""
    bindings: list[ParsedDhcpBinding] = []
    for raw_line in clean_ios_output(raw_text).splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue
        low = line.lower()
        if low.startswith(("ip address", "hardware address", "---", "bindings from all pools")):
            continue
        m = _DHCP_BINDING_RE.match(line)
        if m:
            ip_addr, client_id, exp, btype = m.groups()
            bindings.append(
                ParsedDhcpBinding(
                    ip_address=ip_addr.strip(),
                    client_id=client_id.strip(),
                    lease_expiration=exp.strip(),
                    binding_type=btype.strip(),
                    raw_line=line,
                )
            )
            continue
        # Tolerate minimalist PT rows where binding_type might be omitted
        parts = line.split()
        if len(parts) >= 2 and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", parts[0]):
            bindings.append(
                ParsedDhcpBinding(
                    ip_address=parts[0],
                    client_id=parts[1],
                    lease_expiration=parts[2] if len(parts) >= 3 else "",
                    binding_type=parts[-1] if len(parts) >= 4 else "",
                    raw_line=line,
                )
            )
    return bindings


def parse_show_telephony_service(raw_text: str) -> ParsedTelephonyStatus:
    """Parse Cisco CME `show telephony-service` output (tolerating PT IOS variations)."""
    cleaned = clean_ios_output(raw_text).strip()
    low = cleaned.lower()
    if not cleaned or "is not configured" in low or "not enabled" in low:
        return ParsedTelephonyStatus(configured=False, raw_summary=cleaned)

    version_m = re.search(r"Version\s+([A-Za-z0-9()._-]+)", cleaned, re.IGNORECASE)
    max_e_m = re.search(r"Max-ephones?\s*[:=]?\s*(\d+)", cleaned, re.IGNORECASE)
    max_dn_m = re.search(r"Max-dn\s*[:=]?\s*(\d+)", cleaned, re.IGNORECASE)
    src_m = re.search(
        r"ip\s+source-address\s+([0-9.]+)(?:\s+port\s+(\d+))?",
        cleaned,
        re.IGNORECASE,
    )
    auto_assign = re.findall(r"auto\s+assign\s+[^\r\n]+", cleaned, re.IGNORECASE)
    configured = (
        any(item is not None for item in (version_m, max_e_m, max_dn_m, src_m))
        or "telephony-service" in low
        or bool(auto_assign)
    )
    return ParsedTelephonyStatus(
        configured=configured,
        version=version_m.group(1) if version_m else None,
        max_ephones=int(max_e_m.group(1)) if max_e_m else None,
        max_dn=int(max_dn_m.group(1)) if max_dn_m else None,
        source_address=src_m.group(1) if src_m else None,
        source_port=int(src_m.group(2)) if (src_m and src_m.group(2)) else None,
        auto_assign_ranges=[a.strip() for a in auto_assign],
        raw_summary=cleaned,
    )


def parse_show_ephone(raw_text: str) -> list[ParsedEphoneEntry]:
    """Parse Cisco CME `show ephone` registration blocks and extension buttons."""
    cleaned = clean_ios_output(raw_text)
    entries: list[ParsedEphoneEntry] = []
    current: ParsedEphoneEntry | None = None

    _ephone_hdr_re = re.compile(r"^ephone-(\d+)\b(?:\[\d+\])?\s*(.*)$", re.IGNORECASE)
    _mac_re = re.compile(r"\bMac:([0-9a-fA-F.:-]+)", re.IGNORECASE)
    _status_re = re.compile(r"\b(REGISTERED|UNREGISTERED|DECEASED)\b", re.IGNORECASE)
    _ip_re = re.compile(r"\bIP:([0-9.]+)(?:\s+(?:\*\s+)?\d+\s+(\S+))?", re.IGNORECASE)
    _button_re = re.compile(
        r"^button\s+(\d+):\s*(?:dn\s+(\d+))?(?:\s+number\s+(\S+))?(?:\s+CH\d+\s+(\S+))?",
        re.IGNORECASE,
    )

    for raw_line in cleaned.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue
        hdr_m = _ephone_hdr_re.match(line)
        if hdr_m:
            eid = int(hdr_m.group(1))
            rest = hdr_m.group(2)
            mac_m = _mac_re.search(rest)
            st_m = _status_re.search(rest)
            current = ParsedEphoneEntry(
                ephone_id=eid,
                mac_address=mac_m.group(1) if mac_m else None,
                status=st_m.group(1).upper() if st_m else "UNKNOWN",
                raw_lines=[line],
            )
            entries.append(current)
            continue

        if current is None:
            continue

        current.raw_lines.append(line)
        if current.mac_address is None:
            mac_m = _mac_re.search(line)
            if mac_m:
                current.mac_address = mac_m.group(1)
        if current.status == "UNKNOWN":
            st_m = _status_re.search(line)
            if st_m:
                current.status = st_m.group(1).upper()
        ip_m = _ip_re.search(line)
        if ip_m:
            current.ip_address = ip_m.group(1)
            if ip_m.group(2):
                current.device_model = ip_m.group(2)
        btn_m = _button_re.match(line)
        if btn_m:
            bnum, dn_str, num_str, st_str = btn_m.groups()
            current.buttons.append(
                ParsedEphoneButton(
                    button=int(bnum),
                    dn=int(dn_str) if dn_str else None,
                    number=num_str,
                    state=st_str or "",
                )
            )
    return entries


def _expand_vlan_list(spec_text: str) -> list[int]:
    """Expand a Cisco IOS VLAN list string (e.g. '1,10,20-22' or 'none') into sorted VLAN IDs."""
    cleaned = spec_text.strip().lower()
    if not cleaned or cleaned == "none":
        return []
    if cleaned == "all":
        return list(range(1, 4095))
    vlans: set[int] = set()
    for token in cleaned.split(","):
        part = token.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            if bounds[0].isdigit() and bounds[1].isdigit():
                start_v, end_v = int(bounds[0]), int(bounds[1])
                if 1 <= start_v <= end_v <= 4094:
                    vlans.update(range(start_v, end_v + 1))
        elif part.isdigit():
            vid = int(part)
            if 1 <= vid <= 4094:
                vlans.add(vid)
    return sorted(vlans)


def parse_traceroute_output(
    raw_text: str, *, target_ip: str | None = None
) -> ParsedTracerouteSummary:
    """Parse Cisco IOS `traceroute` or Packet Tracer PC `tracert` hop-by-hop output."""
    cleaned = clean_ios_output(raw_text)
    low = cleaned.lower()
    is_pc = (
        "over a maximum of" in low
        or "trace complete" in low
        or "request timed out" in low
        or bool(re.search(r"^\s*\d+\s+(?:<?\d+\s*ms|\*)", cleaned, re.IGNORECASE | re.MULTILINE))
    )
    kind = "pt_pc_cmd" if is_pc else "cisco_ios"

    hdr_m = re.search(
        r"Tracing\s+(?:the\s+)?route\s+to\s+(?:\S+\s+\[([0-9a-fA-F.:]+)\]|([0-9a-fA-F.:]+))",
        cleaned,
        re.IGNORECASE,
    )
    resolved_target = target_ip or ((hdr_m.group(1) or hdr_m.group(2)) if hdr_m else None)

    hops: list[ParsedTracerouteHop] = []
    _ip_token_re = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)\b")

    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        hop_m = re.match(r"^(\d{1,2})\s+(.+)$", line)
        if not hop_m:
            continue
        hop_num = int(hop_m.group(1))
        rest = hop_m.group(2).strip()

        if kind == "pt_pc_cmd":
            rtts = [
                0.5 if val.startswith("<") else float(val)
                for val in re.findall(r"(<\d+|\d+)\s*ms\b", rest, re.IGNORECASE)
            ]
            # Strip RTT probes to isolate trailing hop IP
            tail = re.sub(r"(?:<\d+|\d+)\s*ms\b|\*", " ", rest, flags=re.IGNORECASE)
            ip_m = _ip_token_re.search(tail)
            hop_ip = ip_m.group(1) if ip_m else None
            timed_out = hop_ip is None and ("*" in rest or "timed out" in rest.lower())
        else:
            rtts = [
                float(val) for val in re.findall(r"(\d+(?:\.\d+)?)\s*msec\b", rest, re.IGNORECASE)
            ]
            ip_m = _ip_token_re.search(rest)
            hop_ip = ip_m.group(1) if ip_m else None
            timed_out = hop_ip is None and "*" in rest

        hops.append(
            ParsedTracerouteHop(
                hop_number=hop_num,
                ip_address=hop_ip,
                rtt_ms=rtts,
                timed_out=timed_out,
                raw_line=line,
            )
        )

    if resolved_target:
        completed = any(h.ip_address == resolved_target for h in hops)
    else:
        completed = bool(hops and not hops[-1].timed_out and hops[-1].ip_address is not None)

    return ParsedTracerouteSummary(
        parser_kind=kind,
        target_ip=resolved_target,
        hops=hops,
        completed=completed,
    )


def parse_ipconfig_all(raw_text: str) -> list[ParsedHostIpconfig]:
    """Parse Packet Tracer PC/Laptop/Server `ipconfig` or `ipconfig /all` output."""
    text = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    adapters: list[ParsedHostIpconfig] = []
    current: ParsedHostIpconfig | None = None

    _hdr_re = re.compile(r"^([A-Za-z0-9/_-]+)\s+Connection\s*:", re.IGNORECASE)
    _kv_re = re.compile(r"^([A-Za-z0-9 /-]+?)\.*:\s*(.*)$")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith(
            ("packet tracer pc", "cisco packet tracer", "c:\\>")
        ):
            continue
        hdr_m = _hdr_re.match(line)
        if hdr_m:
            current = ParsedHostIpconfig(adapter=hdr_m.group(1).strip())
            adapters.append(current)
            continue

        kv_m = _kv_re.match(line)
        if not kv_m:
            continue
        key = kv_m.group(1).strip().lower()
        val = kv_m.group(2).strip()
        if not val:
            continue

        if current is None:
            current = ParsedHostIpconfig()
            adapters.append(current)

        if key in {"ipv4 address", "ip address"}:
            current.ipv4_address = val
        elif key == "subnet mask":
            current.subnet_mask = val
        elif key == "default gateway":
            current.default_gateway = val
        elif key == "physical address":
            current.mac_address = val
        elif key == "ipv6 address" or (
            key == "link-local ipv6 address" and current.ipv6_address is None
        ):
            current.ipv6_address = val
        elif key in {"dns servers", "dns server"}:
            for item in re.split(r"[,\s]+", val):
                if item and item not in current.dns_servers:
                    current.dns_servers.append(item)
        elif key in {"dhcp servers", "dhcp server"}:
            for item in re.split(r"[,\s]+", val):
                if item and item not in current.dhcp_servers:
                    current.dhcp_servers.append(item)

    return adapters


def parse_show_interfaces_trunk(raw_text: str) -> list[ParsedTrunkInterface]:
    """Parse Cisco IOS `show interfaces trunk` port status, native VLAN, and VLAN lists."""
    cleaned = clean_ios_output(raw_text)
    by_canon: dict[str, ParsedTrunkInterface] = {}
    order: list[str] = []
    section = "status"

    _status_re = re.compile(
        r"^(\S+)\s+(on|auto|desirable|off|nonegotiate)\s+(\S+)\s+"
        r"(trunking|not-trunking|other)\s+(\d+)$",
        re.IGNORECASE,
    )
    _port_vlans_re = re.compile(r"^(\S+)\s+([0-9,\-a-zA-Z]+)$")

    for raw_line in cleaned.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue
        low = line.lower()
        if low.startswith("port mode"):
            section = "status"
            continue
        if "vlans allowed on trunk" in low:
            section = "allowed"
            continue
        if "vlans allowed and active" in low:
            section = "active"
            continue
        if "vlans in spanning tree forwarding" in low:
            section = "forwarding"
            continue

        if section == "status":
            m = _status_re.match(line)
            if m:
                port, mode, encap, st, native_str = m.groups()
                canon = canonicalize_interface_name(port)
                entry = ParsedTrunkInterface(
                    port=port,
                    mode=mode.lower(),
                    encapsulation=encap.lower(),
                    status=st.lower(),
                    native_vlan=int(native_str),
                )
                by_canon[canon] = entry
                if canon not in order:
                    order.append(canon)
        elif section in {"allowed", "forwarding"}:
            m = _port_vlans_re.match(line)
            if m:
                port, vlan_spec = m.groups()
                canon = canonicalize_interface_name(port)
                entry = by_canon.get(canon)
                if entry is None:
                    entry = ParsedTrunkInterface(port=port)
                    by_canon[canon] = entry
                    order.append(canon)
                expanded = _expand_vlan_list(vlan_spec)
                if section == "allowed":
                    entry.allowed_vlans_raw = vlan_spec
                    entry.allowed_vlans = expanded
                else:
                    entry.forwarding_vlans_raw = vlan_spec
                    entry.forwarding_vlans = expanded

    return [by_canon[k] for k in order]


def parse_show_spanning_tree(raw_text: str) -> list[ParsedStpVlanInstance]:
    """Parse Cisco IOS `show spanning-tree` per-VLAN root/bridge IDs and port roles."""
    cleaned = clean_ios_output(raw_text)
    instances: list[ParsedStpVlanInstance] = []
    current: ParsedStpVlanInstance | None = None
    in_section: str | None = None

    _vlan_hdr_re = re.compile(r"^VLAN0*(\d{1,4})\s*$", re.IGNORECASE)
    _proto_re = re.compile(r"Spanning tree enabled protocol\s+(\S+)", re.IGNORECASE)
    _prio_re = re.compile(r"\bPriority\s+(\d+)", re.IGNORECASE)
    _addr_re = re.compile(r"\bAddress\s+([0-9a-fA-F.:-]+)", re.IGNORECASE)
    _port_re = re.compile(
        r"^((?:Fa|Gi|Te|Eth|Po)\S*\d)\s+(Root|Desg|Altn|Back|Mstr)\s+"
        r"(FWD|BLK|LRN|LIS|BKN\*?)\s+(\d+)\s+(\d+\.\d+)",
        re.IGNORECASE,
    )

    for raw_line in cleaned.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue
        vh = _vlan_hdr_re.match(line)
        if vh:
            current = ParsedStpVlanInstance(vlan_id=int(vh.group(1)))
            instances.append(current)
            in_section = None
            continue

        if current is None:
            continue

        pm = _proto_re.search(line)
        if pm:
            current.protocol = pm.group(1).lower()
            continue

        low = line.lower()
        if low.startswith("root id"):
            in_section = "root"
            prio_m = _prio_re.search(line)
            if prio_m:
                current.root_priority = int(prio_m.group(1))
            continue
        if low.startswith("bridge id"):
            in_section = "bridge"
            prio_m = _prio_re.search(line)
            if prio_m:
                current.bridge_priority = int(prio_m.group(1))
            continue
        if low.startswith(("interface role", "----")):
            in_section = "ports"
            continue

        if "this bridge is the root" in low:
            current.is_root_bridge = True
            continue

        if in_section == "root":
            prio_m = _prio_re.search(line)
            if prio_m and current.root_priority is None:
                current.root_priority = int(prio_m.group(1))
            addr_m = _addr_re.search(line)
            if addr_m:
                current.root_mac = addr_m.group(1)
        elif in_section == "bridge":
            prio_m = _prio_re.search(line)
            if prio_m and current.bridge_priority is None:
                current.bridge_priority = int(prio_m.group(1))
            addr_m = _addr_re.search(line)
            if addr_m:
                current.bridge_mac = addr_m.group(1)
                if current.root_mac and current.root_mac.lower() == current.bridge_mac.lower():
                    current.is_root_bridge = True

        port_m = _port_re.match(line)
        if port_m:
            iface, role, st, cost_str, pid = port_m.groups()
            current.ports.append(
                ParsedStpPortRole(
                    interface=iface,
                    role=role,
                    status=st.upper(),
                    cost=int(cost_str),
                    port_id=pid,
                )
            )

    return instances


def parse_show_etherchannel_summary(raw_text: str) -> list[ParsedEtherChannelGroup]:
    """Parse Cisco IOS `show etherchannel summary` bundle table and member port flags."""
    cleaned = clean_ios_output(raw_text)
    groups: list[ParsedEtherChannelGroup] = []
    current: ParsedEtherChannelGroup | None = None
    in_table = False

    _row_re = re.compile(
        r"^(\d+)\s+(Po\d+)\(([A-Za-z]+)\)\s+(\S+)\s*(.*)$",
        re.IGNORECASE,
    )
    _member_re = re.compile(r"([A-Za-z]+\d+(?:/\d+)*)\(([A-Za-z]+)\)")

    for raw_line in cleaned.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue
        low = line.lower()
        if low.startswith("group port-channel") or low.startswith("------+"):
            in_table = True
            continue
        if not in_table and not re.match(r"^\d+\s+Po\d+\(", line, re.IGNORECASE):
            continue

        row_m = _row_re.match(line)
        if row_m:
            in_table = True
            gid_str, po_name, po_flags, proto, members_raw = row_m.groups()
            flags_up = po_flags.upper()
            members = [
                ParsedEtherChannelMember(interface=m_if, flag=m_fl)
                for m_if, m_fl in _member_re.findall(members_raw)
            ]
            current = ParsedEtherChannelGroup(
                group_id=int(gid_str),
                port_channel=po_name,
                layer="L3" if "R" in flags_up else "L2",
                in_use="U" in flags_up,
                protocol="" if proto == "-" else proto,
                members=members,
            )
            groups.append(current)
            continue

        if current is not None:
            extra_members = [
                ParsedEtherChannelMember(interface=m_if, flag=m_fl)
                for m_if, m_fl in _member_re.findall(line)
            ]
            if extra_members:
                current.members.extend(extra_members)

    return groups


def parse_show_cdp_neighbors(raw_text: str) -> list[ParsedCdpNeighbor]:
    """Parse Cisco IOS `show cdp neighbors` (supporting single-line and wrapped Device IDs)."""
    cleaned = clean_ios_output(raw_text)
    neighbors: list[ParsedCdpNeighbor] = []
    in_table = False
    pending_dev_id: str | None = None

    _if_pat = r"(?:Gig|Fas|Ten|Eth|Ser|Po|Fa|Gi|Te|Se)\s*\d+(?:/\d+)*(?:\.\d+)?"
    _tail_re = re.compile(
        rf"^({_if_pat})\s+(\d+)\s+((?:[R|T|B|S|H|I|r|P]\s+)+)(\S+)\s+({_if_pat}|\S+)$",
        re.IGNORECASE,
    )
    _full_re = re.compile(
        rf"^(\S+)\s+({_if_pat})\s+(\d+)\s+((?:[R|T|B|S|H|I|r|P]\s+)+)(\S+)\s+({_if_pat}|\S+)$",
        re.IGNORECASE,
    )

    for raw_line in cleaned.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if low.startswith("device id"):
            in_table = True
            pending_dev_id = None
            continue
        if low.startswith("total cdp entries"):
            break
        if not in_table:
            continue

        norm = " ".join(stripped.split())
        if pending_dev_id is not None:
            tail_m = _tail_re.match(norm)
            if tail_m:
                loc_if, hold_s, caps_s, platform, port_id = tail_m.groups()
                neighbors.append(
                    ParsedCdpNeighbor(
                        device_id=pending_dev_id,
                        local_interface=re.sub(r"\s+", "", loc_if),
                        holdtime=int(hold_s),
                        capabilities=[c for c in caps_s.split() if c],
                        platform=platform,
                        port_id=re.sub(r"\s+", "", port_id),
                    )
                )
                pending_dev_id = None
                continue
            pending_dev_id = None

        full_m = _full_re.match(norm)
        if full_m:
            dev_id, loc_if, hold_s, caps_s, platform, port_id = full_m.groups()
            neighbors.append(
                ParsedCdpNeighbor(
                    device_id=dev_id,
                    local_interface=re.sub(r"\s+", "", loc_if),
                    holdtime=int(hold_s),
                    capabilities=[c for c in caps_s.split() if c],
                    platform=platform,
                    port_id=re.sub(r"\s+", "", port_id),
                )
            )
        elif " " not in norm:
            pending_dev_id = norm

    return neighbors


def parse_show_ip_bgp_summary(raw_text: str) -> list[ParsedBgpNeighbor]:
    """Parse Cisco IOS `show ip bgp summary` neighbor session rows."""
    cleaned = clean_ios_output(raw_text)
    peers: list[ParsedBgpNeighbor] = []
    _peer_re = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+(\d+)\s+(\d+)\s+"
        r"\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)$"
    )
    for raw_line in cleaned.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line or line.lower().startswith("neighbor "):
            continue
        m = _peer_re.match(line)
        if m:
            nip, ver_s, asn_s, up_down, st_pfx = m.groups()
            is_est = st_pfx.isdigit()
            peers.append(
                ParsedBgpNeighbor(
                    neighbor_ip=nip,
                    version=int(ver_s),
                    remote_as=int(asn_s),
                    up_down=up_down,
                    state_or_prefixes=st_pfx,
                    established=is_est,
                    prefixes_received=int(st_pfx) if is_est else None,
                )
            )
    return peers


def parse_show_standby_brief(raw_text: str) -> list[ParsedHsrpGroup]:
    """Parse Cisco IOS `show standby brief` HSRP group status rows."""
    cleaned = clean_ios_output(raw_text)
    groups: list[ParsedHsrpGroup] = []
    _hsrp_re = re.compile(
        r"^(\S+)\s+(\d+)\s+(\d+)\s+(?:(P)\s+)?(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$",
        re.IGNORECASE,
    )
    for raw_line in cleaned.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line or line.lower().startswith(("interface ", "p indicates")):
            continue
        m = _hsrp_re.match(line)
        if m:
            iface, grp_s, pri_s, preempt_flag, state, active_r, standby_r, vip = m.groups()
            groups.append(
                ParsedHsrpGroup(
                    interface=iface,
                    group_id=int(grp_s),
                    priority=int(pri_s),
                    preempt=bool(preempt_flag),
                    state=state,
                    active_router=active_r,
                    standby_router=standby_r,
                    virtual_ip=vip,
                )
            )
    return groups


def parse_show_access_lists(raw_text: str) -> list[ParsedAclEntry]:
    """Parse Cisco IOS `show access-lists` standard and extended ACE entries and hit counters."""
    cleaned = clean_ios_output(raw_text)
    entries: list[ParsedAclEntry] = []
    current_name: str | None = None
    current_type: str = "extended"

    _hdr_re = re.compile(
        r"^(Standard|Extended)\s+IP\s+access\s+list\s+(\S+)$",
        re.IGNORECASE,
    )
    _ace_re = re.compile(
        r"^(?:(\d+)\s+)?(permit|deny)\s+(.+?)(?:\s+\((\d+)\s+match(?:es)?\))?$",
        re.IGNORECASE,
    )

    for raw_line in cleaned.splitlines():
        stripped = " ".join(raw_line.strip().split())
        if not stripped:
            continue
        hdr_m = _hdr_re.match(stripped)
        if hdr_m:
            current_type = hdr_m.group(1).lower()
            current_name = hdr_m.group(2)
            continue
        if current_name is None:
            continue
        ace_m = _ace_re.match(stripped)
        if ace_m:
            seq_s, action, body, matches_s = ace_m.groups()
            entries.append(
                ParsedAclEntry(
                    acl_name=current_name,
                    acl_type=current_type,
                    sequence=int(seq_s) if seq_s else None,
                    action=action.lower(),
                    rule_text=body.strip(),
                    matches=int(matches_s) if matches_s else 0,
                )
            )
    return entries


def parse_show_ip_nat_translations(raw_text: str) -> list[ParsedNatTranslation]:
    """Parse Cisco IOS `show ip nat translations` active NAT/PAT table."""
    cleaned = clean_ios_output(raw_text)
    rows: list[ParsedNatTranslation] = []
    _nat_re = re.compile(
        r"^(tcp|udp|icmp|esp|---)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$",
        re.IGNORECASE,
    )
    for raw_line in cleaned.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line or line.lower().startswith(("pro ", "total number")):
            continue
        m = _nat_re.match(line)
        if m:
            proto, in_glob, in_loc, out_loc, out_glob = m.groups()
            rows.append(
                ParsedNatTranslation(
                    protocol=proto.lower(),
                    inside_global=in_glob,
                    inside_local=in_loc,
                    outside_local=out_loc,
                    outside_global=out_glob,
                )
            )
    return rows
