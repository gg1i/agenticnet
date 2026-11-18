"""Structured Pydantic models for Cisco IOS configuration, validation, and snapshots."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from agenticnet.core.enums import StateLevel
from agenticnet.security.validation import validate_cli_safe_text


class _CliSafeModel(BaseModel):
    """Base model rejecting CR/LF/NUL control characters in string and string-list fields."""

    @model_validator(mode="after")
    def _reject_control_chars(self) -> _CliSafeModel:
        for field_name in type(self).model_fields:
            val = getattr(self, field_name)
            if isinstance(val, str):
                validate_cli_safe_text(val, field_name=field_name)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        validate_cli_safe_text(item, field_name=field_name)
                    elif isinstance(item, tuple):
                        for sub in item:
                            if isinstance(sub, str):
                                validate_cli_safe_text(sub, field_name=field_name)
            elif isinstance(val, dict):
                for k, sub in val.items():
                    if isinstance(k, str):
                        validate_cli_safe_text(k, field_name=field_name)
                    if isinstance(sub, str):
                        validate_cli_safe_text(sub, field_name=field_name)
        return self


class InterfaceConfigSpec(_CliSafeModel):
    """Structured specification for configuring an interface, subinterface, SVI, or loopback."""

    device_name: str
    interface: str
    ipv4_address: str | None = None
    subnet_mask: str | None = None
    ipv6_address: str | None = None
    enable_ipv6_routing: bool = True
    dhcp_client: bool = False
    helper_addresses: list[str] = Field(default_factory=list)
    description: str | None = None
    admin_up: bool = True
    dot1q_vlan: int | None = Field(default=None, ge=1, le=4094)
    native_vlan: bool = False
    l3_routed_port: bool = False
    clock_rate: int | None = Field(default=None, ge=1200)
    nat_role: Literal["inside", "outside"] | None = None


class VlanSpec(_CliSafeModel):
    """Single VLAN definition."""

    vlan_id: int = Field(ge=1, le=4094)
    name: str | None = None


class AccessPortSpec(_CliSafeModel):
    """Switch access port configuration including optional voice VLAN, STP, and port-security."""

    device_name: str
    interface: str
    vlan_id: int = Field(ge=1, le=4094)
    voice_vlan: int | None = Field(default=None, ge=1, le=4094)
    description: str | None = None
    portfast: bool = True
    bpduguard: bool = False
    port_security: bool = False
    port_security_max: int = Field(default=2, ge=1, le=132)
    port_security_sticky: bool = True
    port_security_violation: Literal["shutdown", "restrict", "protect"] = "restrict"


class TrunkPortSpec(_CliSafeModel):
    """Switch 802.1Q trunk port configuration."""

    device_name: str
    interface: str
    allowed_vlans: list[int] | None = None
    native_vlan: int | None = Field(default=None, ge=1, le=4094)
    nonegotiate: bool = False
    description: str | None = None


class StaticRouteEntry(_CliSafeModel):
    """Single IPv4 or IPv6 static route."""

    destination_network: str
    subnet_mask_or_prefix: str | None = None
    next_hop: str
    administrative_distance: int | None = Field(default=None, ge=1, le=255)
    ip_version: Literal[4, 6] = 4


class RipConfigSpec(_CliSafeModel):
    """RIPv2 routing configuration."""

    device_name: str
    networks: list[str] = Field(min_length=1)
    passive_interfaces: list[str] = Field(default_factory=list)
    default_information_originate: bool = False
    no_auto_summary: bool = True


class OspfNetworkEntry(_CliSafeModel):
    """Single OSPF network statement (supports CIDR or network + wildcard)."""

    network: str
    wildcard_mask: str | None = None
    area: int = Field(default=0, ge=0)


class OspfConfigSpec(_CliSafeModel):
    """OSPFv2 configuration model."""

    device_name: str
    process_id: int = Field(default=1, ge=1, le=65535)
    router_id: str | None = None
    networks: list[OspfNetworkEntry] = Field(min_length=1)
    passive_interfaces: list[str] = Field(default_factory=list)
    default_information_originate: bool = False


class EigrpConfigSpec(_CliSafeModel):
    """EIGRP configuration model."""

    device_name: str
    asn: int = Field(ge=1, le=65535)
    networks: list[str] = Field(min_length=1)
    passive_interfaces: list[str] = Field(default_factory=list)
    no_auto_summary: bool = True


class DhcpPoolSpec(_CliSafeModel):
    """Cisco IOS DHCP server pool specification."""

    device_name: str
    pool_name: str
    network: str
    subnet_mask: str | None = None
    default_router: str
    dns_server: str | None = None
    domain_name: str | None = None
    option_150: str | list[str] | None = None
    excluded_ranges: list[tuple[str, str]] = Field(default_factory=list)


class NatPatSpec(_CliSafeModel):
    """Cisco IOS NAT/PAT configuration specification."""

    device_name: str
    mode: Literal["pat_overload", "dynamic_pool", "static"] = "pat_overload"
    inside_interfaces: list[str] = Field(default_factory=list)
    outside_interfaces: list[str] = Field(default_factory=list)
    acl_number: int = Field(default=1, ge=1, le=199)
    acl_name: str | None = None
    source_cidrs: list[str] = Field(default_factory=list)
    overload_interface: str | None = None
    overload: bool = True
    pool_name: str | None = None
    pool_start: str | None = None
    pool_end: str | None = None
    pool_netmask: str | None = None
    static_inside_local: str | None = None
    static_inside_global: str | None = None
    static_protocol: Literal["tcp", "udp"] | None = None
    static_local_port: int | None = Field(default=None, ge=1, le=65535)
    static_global_port: int | None = Field(default=None, ge=1, le=65535)


class AclRule(_CliSafeModel):
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


class AclSpec(_CliSafeModel):
    """Standard or Extended ACL definition and optional interface or VTY binding."""

    device_name: str
    acl_identifier: str
    acl_type: Literal["standard", "extended"] = "extended"
    rules: list[AclRule] = Field(min_length=1)
    apply_interface: str | None = None
    direction: Literal["in", "out"] = "in"
    apply_vty: bool = False
    vty_end: int = Field(default=15, ge=4, le=15)
    vty_direction: Literal["in", "out"] = "in"


class StpSpec(_CliSafeModel):
    """Spanning-Tree configuration."""

    device_name: str
    mode: Literal["rapid-pvst", "pvst"] = "rapid-pvst"
    root_primary_vlans: list[int] = Field(default_factory=list)
    root_secondary_vlans: list[int] = Field(default_factory=list)


class EtherChannelSpec(_CliSafeModel):
    """Port-Channel EtherChannel configuration (L2 trunk/access or L3 routed)."""

    device_name: str
    group_id: int = Field(ge=1, le=48)
    member_interfaces: list[str] = Field(min_length=1)
    mode: Literal["active", "passive", "on", "desirable", "auto"] = "active"
    port_mode: Literal["trunk", "access", "routed"] = "trunk"
    access_vlan: int | None = Field(default=None, ge=1, le=4094)
    native_vlan: int | None = Field(default=None, ge=1, le=4094)
    allowed_vlans: list[int] | None = None
    ipv4_address: str | None = None
    subnet_mask: str | None = None


class SshConfigSpec(_CliSafeModel):
    """SSHv2 management access configuration."""

    device_name: str
    hostname: str | None = None
    domain_name: str
    username: str
    secret: str
    rsa_modulus: Literal[1024, 2048] = 2048
    vty_end: int = Field(default=15, ge=4, le=15)
    enable_secret: str | None = None


class HsrpConfigSpec(_CliSafeModel):
    """HSRP first-hop redundancy configuration specification."""

    device_name: str
    interface: str
    group_id: int = Field(default=1, ge=0, le=4095)
    virtual_ip: str
    priority: int | None = Field(default=110, ge=1, le=255)
    preempt: bool = True
    version: Literal[1, 2] = 2
    track_interface: str | None = None
    decrement: int = Field(default=10, ge=1, le=255)
    ipv4_address: str | None = None
    subnet_mask: str | None = None


class BgpNeighborEntry(_CliSafeModel):
    """Single BGP neighbor session specification."""

    peer_ip: str
    remote_as: int = Field(ge=1, le=65535)
    update_source: str | None = None
    next_hop_self: bool = False
    description: str | None = None


class BgpNetworkEntry(_CliSafeModel):
    """Single BGP IPv4 network advertisement."""

    network: str
    subnet_mask: str | None = None


class BgpConfigSpec(_CliSafeModel):
    """BGP-4 autonomous system configuration specification."""

    device_name: str
    local_as: int = Field(ge=1, le=65535)
    router_id: str | None = None
    neighbors: list[BgpNeighborEntry] = Field(min_length=1)
    networks: list[BgpNetworkEntry | str] = Field(default_factory=list)


class DhcpSnoopingSpec(_CliSafeModel):
    """Switch Layer 2 DHCP Snooping configuration specification."""

    device_name: str
    vlans: list[int] = Field(min_length=1)
    trusted_interfaces: list[str] = Field(default_factory=list)
    rate_limit_interfaces: dict[str, int] = Field(default_factory=dict)
    disable_option_82: bool = True


class DaiConfigSpec(_CliSafeModel):
    """Switch Dynamic ARP Inspection (DAI) configuration specification."""

    device_name: str
    vlans: list[int] = Field(min_length=1)
    trusted_interfaces: list[str] = Field(default_factory=list)
    validate_src_mac: bool = False
    validate_dst_mac: bool = False
    validate_ip: bool = False


class ManagementServicesSpec(_CliSafeModel):
    """NTP, Syslog, SNMP, and AAA device management plane specification."""

    device_name: str
    ntp_servers: list[str] = Field(default_factory=list)
    ntp_master_stratum: int | None = Field(default=None, ge=1, le=15)
    syslog_servers: list[str] = Field(default_factory=list)
    logging_trap: str | None = "informational"
    service_timestamps: bool = True
    snmp_ro_community: str | None = None
    snmp_rw_community: str | None = None
    snmp_location: str | None = None
    snmp_contact: str | None = None
    aaa_new_model: bool = False
    radius_server_ip: str | None = None
    radius_key: str | None = None
    tacacs_server_ip: str | None = None
    tacacs_key: str | None = None
    local_fallback: bool = True


class EphoneDnEntry(_CliSafeModel):
    """CallManager Express directory number entry."""

    dn_id: int = Field(ge=1, le=288)
    number: str
    label: str | None = None


class EphoneEntry(_CliSafeModel):
    """CallManager Express SCCP IP Phone entry."""

    ephone_id: int = Field(ge=1, le=144)
    mac_address: str | None = None
    phone_type: str = "7960"
    button_mapping: str = "1:1"


class CmeVoipSpec(_CliSafeModel):
    """Cisco CallManager Express (CME) VoIP telephony configuration specification."""

    device_name: str
    source_address: str
    source_port: int = Field(default=2000, ge=1024, le=65535)
    max_ephones: int = Field(default=5, ge=1, le=144)
    max_dn: int = Field(default=10, ge=1, le=288)
    auto_assign_end: int | None = Field(default=5, ge=1, le=144)
    auto_reg_ephone: bool = True
    create_cnf_files: bool = True
    dns: list[EphoneDnEntry] = Field(default_factory=list)
    ephones: list[EphoneEntry] = Field(default_factory=list)


class AsaInterfaceZoneSpec(_CliSafeModel):
    """ASA security zone interface assignment (supports 5505 VLAN SVIs and 5506-X routed ports)."""

    interface: str
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    nameif: str
    security_level: int = Field(ge=0, le=100)
    ip_address: str
    subnet_mask: str | None = None


class AsaRouteEntry(_CliSafeModel):
    """ASA static route entry."""

    interface_nameif: str = "outside"
    destination: str = "0.0.0.0"
    netmask: str = "0.0.0.0"
    next_hop: str


class AsaObjectNatSpec(_CliSafeModel):
    """ASA network-object dynamic PAT specification."""

    object_name: str
    subnet: str
    netmask: str | None = None
    inside_nameif: str = "inside"
    outside_nameif: str = "outside"


class AsaAclRule(_CliSafeModel):
    """ASA extended access-list entry and optional interface access-group binding."""

    acl_name: str
    action: Literal["permit", "deny"] = "permit"
    protocol: str = "ip"
    source: str = "any"
    destination: str = "any"
    eq_port: str | None = None
    apply_nameif: str | None = None
    direction: Literal["in", "out"] = "in"


class AsaBasicConfigSpec(_CliSafeModel):
    """Cisco ASA 5505 / 5506-X baseline security appliance configuration specification."""

    device_name: str
    hostname: str | None = None
    interfaces: list[AsaInterfaceZoneSpec] = Field(min_length=1)
    routes: list[AsaRouteEntry] = Field(default_factory=list)
    object_nats: list[AsaObjectNatSpec] = Field(default_factory=list)
    acl_rules: list[AsaAclRule] = Field(default_factory=list)


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
