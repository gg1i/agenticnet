"""Core domain enumerations shared across AgenticNet subsystems."""

from __future__ import annotations

from enum import StrEnum


class StateLevel(StrEnum):
    """Explicit separation between intended, attempted, and observed state."""

    PLANNED = "planned"
    EXECUTED = "executed"
    VERIFIED = "verified"


class PermissionTier(StrEnum):
    """Tool execution permission hierarchy."""

    READ_ONLY = "read_only"
    PLANNING = "planning"
    CONFIGURATION = "configuration"
    GUI_CONTROL = "gui_control"
    DESTRUCTIVE = "destructive"


class OperationStatus(StrEnum):
    """Outcome status for an operation or tool invocation."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    APPROVAL_REQUIRED = "approval_required"
    BLOCKED = "blocked"


class DeviceCategory(StrEnum):
    """Supported network device classifications."""

    ROUTER = "router"
    L2_SWITCH = "l2_switch"
    L3_SWITCH = "l3_switch"
    PC = "pc"
    LAPTOP = "laptop"
    SERVER = "server"
    PRINTER = "printer"
    WIRELESS_ROUTER = "wireless_router"
    ACCESS_POINT = "access_point"
    FIREWALL = "firewall"
    WLC = "wlc"
    CLOUD = "cloud"


class PortMedia(StrEnum):
    """Physical and logical interface media types."""

    FAST_ETHERNET = "fast_ethernet"
    GIGABIT_ETHERNET = "gigabit_ethernet"
    TEN_GIGABIT_ETHERNET = "ten_gigabit_ethernet"
    SERIAL = "serial"
    FIBER = "fiber"
    WIRELESS = "wireless"
    SVI = "svi"
    LOOPBACK = "loopback"
    CONSOLE = "console"


class CableType(StrEnum):
    """Packet Tracer physical interconnection cable types."""

    AUTO = "auto"
    STRAIGHT_THROUGH = "straight_through"
    CROSSOVER = "crossover"
    FIBER = "fiber"
    SERIAL_DCE = "serial_dce"
    SERIAL_DTE = "serial_dte"
    CONSOLE = "console"
    COAXIAL = "coaxial"
    PHONE = "phone"


_CABLE_TYPE_ALIASES: dict[str, CableType] = {
    "auto": CableType.AUTO,
    "automatic": CableType.AUTO,
    "auto_choose": CableType.AUTO,
    "straight": CableType.STRAIGHT_THROUGH,
    "straight_through": CableType.STRAIGHT_THROUGH,
    "copper_straight": CableType.STRAIGHT_THROUGH,
    "copper_straight_through": CableType.STRAIGHT_THROUGH,
    "straight_through_copper": CableType.STRAIGHT_THROUGH,
    "cross": CableType.CROSSOVER,
    "crossover": CableType.CROSSOVER,
    "copper_cross": CableType.CROSSOVER,
    "copper_crossover": CableType.CROSSOVER,
    "crossover_copper": CableType.CROSSOVER,
    "fiber": CableType.FIBER,
    "fibre": CableType.FIBER,
    "optical": CableType.FIBER,
    "serial": CableType.SERIAL_DCE,
    "serial_dce": CableType.SERIAL_DCE,
    "dce": CableType.SERIAL_DCE,
    "serial_dte": CableType.SERIAL_DTE,
    "dte": CableType.SERIAL_DTE,
    "console": CableType.CONSOLE,
    "rollover": CableType.CONSOLE,
    "coaxial": CableType.COAXIAL,
    "coax": CableType.COAXIAL,
    "phone": CableType.PHONE,
}


def parse_cable_type(value: CableType | str | None) -> CableType | None:
    """Normalize common cable aliases (e.g. 'copper_straight', 'copper_cross') into CableType."""
    if value is None or isinstance(value, CableType):
        return value
    norm = value.strip().lower().replace("-", "_").replace(" ", "_")
    if norm in _CABLE_TYPE_ALIASES:
        return _CABLE_TYPE_ALIASES[norm]
    return CableType(norm)


class ConfigCapability(StrEnum):
    """Fine-grained device configuration and protocol capabilities."""

    IOS_CLI = "ios_cli"
    DESKTOP_IP_GUI = "desktop_ip_gui"
    WEB_CONFIG_GUI = "web_config_gui"
    HOSTNAME = "hostname"
    STATIC_IP = "static_ip"
    IPV6 = "ipv6"
    DHCP_CLIENT = "dhcp_client"
    DHCP_SERVER = "dhcp_server"
    DNS_SERVER = "dns_server"
    VLANS = "vlans"
    TRUNKING = "trunking"
    TRUNK_ENCAP_DOT1Q = "trunk_encap_dot1q"
    INTER_VLAN_SVI = "inter_vlan_svi"
    ROUTER_ON_A_STICK = "router_on_a_stick"
    STATIC_ROUTING = "static_routing"
    RIP = "rip"
    OSPF = "ospf"
    EIGRP = "eigrp"
    NAT_PAT = "nat_pat"
    ACL_STANDARD = "acl_standard"
    ACL_EXTENDED = "acl_extended"
    PORT_SECURITY = "port_security"
    STP = "stp"
    ETHERCHANNEL = "etherchannel"
    SSH = "ssh"
    DEFAULT_GATEWAY_L2 = "default_gateway_l2"
    WIRELESS_SSID = "wireless_ssid"
    BGP = "bgp"
    HSRP = "hsrp"
    DHCP_SNOOPING = "dhcp_snooping"
    DAI = "dai"
    IPSEC_VPN = "ipsec_vpn"
    ZONE_BASED_FIREWALL = "zone_based_firewall"
    AAA = "aaa"
    SYSLOG = "syslog"
    NTP = "ntp"
    SNMP = "snmp"
    ASA_FIREWALL = "asa_firewall"
    WLC_CAPWAP = "wlc_capwap"
