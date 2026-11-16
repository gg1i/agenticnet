"""Structured models for Packet Tracer Simulation Mode, PDUs, and connectivity tests."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field

from agenticnet.core.enums import StateLevel


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SimulatorMode(StrEnum):
    """Packet Tracer operating clock mode."""

    REALTIME = "realtime"
    SIMULATION = "simulation"


class SimulationSource(StrEnum):
    """Origin of connectivity or simulation evidence (prevents false verification claims)."""

    PACKET_TRACER_CLI = "packet_tracer_cli"
    PACKET_TRACER_GUI_PDU = "packet_tracer_gui_pdu"
    OFFLINE_TOPOLOGY_CHECK = "offline_topology_ipam_check"


class PDUProtocol(StrEnum):
    """Supported PDU test protocols."""

    ICMP = "ICMP"
    ARP = "ARP"
    TCP = "TCP"
    UDP = "UDP"
    HTTP = "HTTP"
    DNS = "DNS"
    DHCP = "DHCP"


class TestPacketSpec(BaseModel):
    """Tracked Simple/Complex PDU specification for Simulation Mode."""

    packet_id: str = Field(default_factory=lambda: f"pdu_{uuid4().hex[:8]}")
    source_device: str
    destination_ip: str
    protocol: PDUProtocol = PDUProtocol.ICMP
    source_ip: str | None = None
    destination_port: int | None = None
    status: str = "planned"
    created_in_pt: bool = False
    created_at: datetime = Field(default_factory=_utc_now)


class PacketEventRecord(BaseModel):
    """Single hop/event parsed from Packet Tracer Simulation Event List or trace."""

    event_seq: int = Field(ge=1)
    time_sec: float | None = None
    at_device: str
    last_device: str | None = None
    protocol: str = "ICMP"
    status: str = "observed"
    details: str = ""


class ParsedPingSummary(BaseModel):
    """Structured ping statistics extracted from Cisco IOS or PT PC Command Prompt."""

    parser_kind: str
    target_ip: str | None = None
    transmitted: int = 0
    received: int = 0
    loss_percent: float = 100.0
    min_rtt_ms: float | None = None
    avg_rtt_ms: float | None = None
    max_rtt_ms: float | None = None
    reached: bool = False


class ParsedRouteEntry(BaseModel):
    """Single route entry parsed from `show ip route`."""

    code: str
    network: str
    next_hop: str | None = None
    outgoing_interface: str | None = None
    metric: str | None = None
    raw_line: str = ""


class ParsedArpEntry(BaseModel):
    """Single ARP resolution entry parsed from `show arp` or `arp -a`."""

    ip_address: str
    mac_address: str
    interface: str | None = None
    age_min: str | None = None


class ParsedInterfaceBrief(BaseModel):
    """Single interface status row parsed from `show ip interface brief`."""

    interface: str
    ip_address: str
    ok: bool = True
    method: str = ""
    status: str
    protocol: str

    @property
    def is_up_up(self) -> bool:
        """Return True when both Layer 1 status and Layer 2 line protocol are up."""
        return self.status.lower() == "up" and self.protocol.lower() == "up"


class ParsedVlanEntry(BaseModel):
    """Single VLAN row parsed from `show vlan brief`."""

    vlan_id: int
    name: str
    status: str
    ports: list[str] = Field(default_factory=list)


class ParsedOspfNeighbor(BaseModel):
    """Single OSPF neighbor row parsed from `show ip ospf neighbor`."""

    neighbor_id: str
    priority: int = 1
    state: str
    address: str
    interface: str


class ParsedDhcpBinding(BaseModel):
    """Single DHCP lease binding row parsed from `show ip dhcp binding`."""

    ip_address: str
    client_id: str
    lease_expiration: str = ""
    binding_type: str = ""
    raw_line: str = ""


class ParsedTelephonyStatus(BaseModel):
    """Structured summary parsed from Cisco CME `show telephony-service`."""

    configured: bool = False
    version: str | None = None
    max_ephones: int | None = None
    max_dn: int | None = None
    source_address: str | None = None
    source_port: int | None = None
    auto_assign_ranges: list[str] = Field(default_factory=list)
    raw_summary: str = ""


class ParsedEphoneButton(BaseModel):
    """Button/extension mapping parsed inside a `show ephone` block."""

    button: int
    dn: int | None = None
    number: str | None = None
    state: str = ""


class ParsedEphoneEntry(BaseModel):
    """Single SCCP ephone registration block parsed from `show ephone`."""

    ephone_id: int
    mac_address: str | None = None
    status: str = "unknown"
    ip_address: str | None = None
    device_model: str | None = None
    buttons: list[ParsedEphoneButton] = Field(default_factory=list)
    raw_lines: list[str] = Field(default_factory=list)


class ParsedConfigSection(BaseModel):
    """Single top-level section extracted from `show running-config`."""

    header: str
    lines: list[str] = Field(default_factory=list)
    text: str = ""


class ConnectivityCheckReport(BaseModel):
    """Comprehensive connectivity check report separating PT evidence from offline estimates."""

    source_device: str
    destination_ip: str
    protocol: PDUProtocol = PDUProtocol.ICMP
    simulation_source: SimulationSource
    verified_in_pt: bool = False
    state_level: StateLevel = StateLevel.PLANNED
    reachable: bool = False
    ping_summary: ParsedPingSummary | None = None
    packet_events: list[PacketEventRecord] = Field(default_factory=list)
    path_hops: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    checked_at: datetime = Field(default_factory=_utc_now)
