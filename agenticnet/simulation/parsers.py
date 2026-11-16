"""Parsers for Cisco IOS and Packet Tracer ping, routing, ARP, interface, and VLAN outputs."""

from __future__ import annotations

import re

from agenticnet.simulation.models import (
    PacketEventRecord,
    ParsedArpEntry,
    ParsedConfigSection,
    ParsedDhcpBinding,
    ParsedEphoneButton,
    ParsedEphoneEntry,
    ParsedInterfaceBrief,
    ParsedOspfNeighbor,
    ParsedPingSummary,
    ParsedRouteEntry,
    ParsedTelephonyStatus,
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
    r"^([CSOLRD*B](?:[A-Z0-9* ]{0,4})?)\s+([0-9.]+(?:/\d+)?)\s+"
    r"(?:\[(\d+/\d+)\]\s+via\s+([0-9.]+)(?:,\s*(?:[^,\s]+,\s*)?(\S+))?|"
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
    """Strip CR, `--More--` pager artifacts, and IOS prompt echoes for resilient parsing."""
    text = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\s*--More--\s*", "\n", text, flags=re.IGNORECASE)
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
    """Parse Cisco IOS `show ip route` table lines and gateway of last resort."""
    gateway_of_last_resort: str | None = None
    routes: list[ParsedRouteEntry] = []
    inherited_mask: str | None = None

    for raw_line in clean_ios_output(raw_text).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("gateway of last resort is"):
            gateway_of_last_resort = line
            continue
        if "is variably subnetted" in line.lower():
            inherited_mask = None
            continue
        sub_m = _SUBNET_HEADER_RE.match(line)
        if sub_m:
            inherited_mask = sub_m.group(1)
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
        target_canon = canonicalize_interface_name(target)
        matched: list[ParsedConfigSection] = []
        for sec in sections:
            hdr_low = sec.header.lower()
            hdr_canon = hdr_low
            if hdr_low.startswith("interface "):
                hdr_canon = f"interface {canonicalize_interface_name(hdr_low[10:])}"
            if (
                hdr_low == target
                or hdr_low.startswith(target)
                or hdr_canon == target_canon
                or (
                    target.startswith("interface ")
                    and hdr_canon == f"interface {canonicalize_interface_name(target[10:])}"
                )
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
    configured = any(
        item is not None for item in (version_m, max_e_m, max_dn_m, src_m)
    ) or "telephony-service" in low or bool(auto_assign)
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
