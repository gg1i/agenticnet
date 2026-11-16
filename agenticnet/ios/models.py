"""Structured Pydantic models for Cisco IOS configuration, validation, and snapshots."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from agenticnet.core.enums import StateLevel


class InterfaceConfigSpec(BaseModel):
    """Structured specification for configuring an interface, subinterface, SVI, or loopback."""

    device_name: str
    interface: str
    ipv4_address: str | None = None
    subnet_mask: str | None = None
    ipv6_address: str | None = None
    dhcp_client: bool = False
    description: str | None = None
    admin_up: bool = True
    dot1q_vlan: int | None = Field(default=None, ge=1, le=4094)
    native_vlan: bool = False
    l3_routed_port: bool = False
    clock_rate: int | None = Field(default=None, ge=1200)
    nat_role: Literal["inside", "outside"] | None = None


class VlanSpec(BaseModel):
    """Single VLAN definition."""

    vlan_id: int = Field(ge=1, le=4094)
    name: str | None = None


class AccessPortSpec(BaseModel):
    """Switch access port configuration including optional STP and port-security."""

    device_name: str
    interface: str
    vlan_id: int = Field(ge=1, le=4094)
    description: str | None = None
    portfast: bool = True
    bpduguard: bool = False
    port_security: bool = False
    port_security_max: int = Field(default=2, ge=1, le=132)
    port_security_sticky: bool = True
    port_security_violation: Literal["shutdown", "restrict", "protect"] = "restrict"


class TrunkPortSpec(BaseModel):
    """Switch 802.1Q trunk port configuration."""

    device_name: str
    interface: str
    allowed_vlans: list[int] | None = None
    native_vlan: int | None = Field(default=None, ge=1, le=4094)
    nonegotiate: bool = False
    description: str | None = None


class StaticRouteEntry(BaseModel):
    """Single IPv4 or IPv6 static route."""

    destination_network: str
    subnet_mask_or_prefix: str | None = None
    next_hop: str
    administrative_distance: int | None = Field(default=None, ge=1, le=255)
    ip_version: Literal[4, 6] = 4


class RipConfigSpec(BaseModel):
    """RIPv2 routing configuration."""

    device_name: str
    networks: list[str] = Field(min_length=1)
    passive_interfaces: list[str] = Field(default_factory=list)
    default_information_originate: bool = False
    no_auto_summary: bool = True


class OspfNetworkEntry(BaseModel):
    """Single OSPF network statement (supports CIDR or network + wildcard)."""

    network: str
    wildcard_mask: str | None = None
    area: int = Field(default=0, ge=0)


class OspfConfigSpec(BaseModel):
    """OSPFv2 configuration model."""

    device_name: str
    process_id: int = Field(default=1, ge=1, le=65535)
    router_id: str | None = None
    networks: list[OspfNetworkEntry] = Field(min_length=1)
    passive_interfaces: list[str] = Field(default_factory=list)
    default_information_originate: bool = False


class EigrpConfigSpec(BaseModel):
    """EIGRP configuration model."""

    device_name: str
    asn: int = Field(ge=1, le=65535)
    networks: list[str] = Field(min_length=1)
    passive_interfaces: list[str] = Field(default_factory=list)
    no_auto_summary: bool = True


class DhcpPoolSpec(BaseModel):
    """Cisco IOS DHCP server pool specification."""

    device_name: str
    pool_name: str
    network: str
    subnet_mask: str | None = None
    default_router: str
    dns_server: str | None = None
    domain_name: str | None = None
    excluded_ranges: list[tuple[str, str]] = Field(default_factory=list)


class NatPatSpec(BaseModel):
    """Cisco IOS NAT/PAT configuration specification."""

    device_name: str
    mode: Literal["pat_overload", "dynamic_pool", "static"] = "pat_overload"
    inside_interfaces: list[str] = Field(default_factory=list)
    outside_interfaces: list[str] = Field(default_factory=list)
    acl_number: int = Field(default=1, ge=1, le=99)
    source_cidrs: list[str] = Field(default_factory=list)
    overload_interface: str | None = None
    pool_name: str | None = None
    pool_start: str | None = None
    pool_end: str | None = None
    pool_netmask: str | None = None
    static_inside_local: str | None = None
    static_inside_global: str | None = None


class AclRule(BaseModel):
    """Single ACL permit/deny entry."""

    action: Literal["permit", "deny"]
    protocol: str = "ip"
    source: str = "any"
    source_wildcard: str | None = None
    destination: str | None = None
    destination_wildcard: str | None = None
    operator: Literal["eq", "gt", "lt", "neq"] | None = None
    port: str | None = None
    log: bool = False


class AclSpec(BaseModel):
    """Standard or Extended ACL definition and optional interface binding."""

    device_name: str
    acl_identifier: str
    acl_type: Literal["standard", "extended"] = "extended"
    rules: list[AclRule] = Field(min_length=1)
    apply_interface: str | None = None
    direction: Literal["in", "out"] = "in"


class StpSpec(BaseModel):
    """Spanning-Tree configuration."""

    device_name: str
    mode: Literal["rapid-pvst", "pvst"] = "rapid-pvst"
    root_primary_vlans: list[int] = Field(default_factory=list)
    root_secondary_vlans: list[int] = Field(default_factory=list)


class EtherChannelSpec(BaseModel):
    """Port-Channel EtherChannel configuration."""

    device_name: str
    group_id: int = Field(ge=1, le=48)
    member_interfaces: list[str] = Field(min_length=1)
    mode: Literal["active", "passive", "on", "desirable", "auto"] = "active"
    port_mode: Literal["trunk", "access"] = "trunk"
    access_vlan: int | None = Field(default=None, ge=1, le=4094)
    allowed_vlans: list[int] | None = None


class SshConfigSpec(BaseModel):
    """SSHv2 management access configuration."""

    device_name: str
    hostname: str | None = None
    domain_name: str
    username: str
    secret: str
    rsa_modulus: Literal[1024, 2048] = 2048
    vty_end: int = Field(default=15, ge=4, le=15)
    enable_secret: str | None = None


class CLIDiagnostic(BaseModel):
    """Detected CLI syntax/execution error or warning."""

    line_number: int
    command: str
    severity: Literal["error", "warning"]
    code: str
    message: str


class RenderedCommandSequence(BaseModel):
    """Validated Cisco IOS command sequence paired with verification commands."""

    device_name: str
    device_model: str
    feature: str
    requires_enable: bool = True
    requires_config_mode: bool = True
    commands: list[str]
    commands_redacted: list[str]
    verification_commands: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    state_level: StateLevel = StateLevel.PLANNED


class ConfigSnapshot(BaseModel):
    """Stored configuration block for a device at a specific truth/state level."""

    snapshot_id: str = Field(default_factory=lambda: f"snap_{uuid4().hex[:10]}")
    device_name: str
    state_level: StateLevel = StateLevel.PLANNED
    source: str = "ios_generator"
    config_text: str
    commands: list[str] = Field(default_factory=list)
    note: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ConfigDiffResult(BaseModel):
    """Comparison result between two configuration snapshots."""

    device_name: str
    left_snapshot_id: str
    right_snapshot_id: str
    identical: bool
    added_lines: int
    removed_lines: int
    unified_diff: str
