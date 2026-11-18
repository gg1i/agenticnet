"""Verified Packet Tracer device capability registry and interface normalization."""

from __future__ import annotations

import re

from agenticnet.core.enums import ConfigCapability, DeviceCategory, PortMedia
from agenticnet.core.exceptions import DeviceModelError, InterfaceError
from agenticnet.devices.models import DeviceCapabilityReport, DeviceProfile, InterfaceTemplate

_IFACE_PREFIX_RE = re.compile(
    r"^(fastethernet|fa|f|gigabitethernet|gi|gig|g|tengigabitethernet|te|t|"
    r"serial|se|s|vlan|vl|loopback|lo|port-channel|po|ethernet|eth|port|wireless|wlan|"
    r"dot11radio|dot11|management|mgmt)"
    r"\s*([0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?)$",
    re.IGNORECASE,
)

_CANONICAL_PREFIX_MAP: dict[str, str] = {
    "fastethernet": "FastEthernet",
    "fa": "FastEthernet",
    "f": "FastEthernet",
    "gigabitethernet": "GigabitEthernet",
    "gi": "GigabitEthernet",
    "gig": "GigabitEthernet",
    "g": "GigabitEthernet",
    "tengigabitethernet": "TenGigabitEthernet",
    "te": "TenGigabitEthernet",
    "t": "TenGigabitEthernet",
    "serial": "Serial",
    "se": "Serial",
    "s": "Serial",
    "vlan": "Vlan",
    "vl": "Vlan",
    "loopback": "Loopback",
    "lo": "Loopback",
    "port-channel": "Port-channel",
    "po": "Port-channel",
    "ethernet": "Ethernet",
    "eth": "Ethernet",
    "port": "Port",
    "wireless": "Wireless",
    "wlan": "Wireless",
    "dot11radio": "Dot11Radio",
    "dot11": "Dot11Radio",
    "management": "Management",
    "mgmt": "Management",
}


def _eth_ports(
    prefix: str,
    short_prefix: str,
    media: PortMedia,
    speed_mbps: int,
    slot: str,
    start: int,
    end: int,
    *,
    supports_switchport: bool,
    supports_routed_ip: bool,
) -> list[InterfaceTemplate]:
    return [
        InterfaceTemplate(
            name=f"{prefix}{slot}{idx}",
            short_name=f"{short_prefix}{slot}{idx}",
            media=media,
            speed_mbps=speed_mbps,
            supports_switchport=supports_switchport,
            supports_routed_ip=supports_routed_ip,
        )
        for idx in range(start, end + 1)
    ]


_ROUTER_COMMON_CAPS: set[ConfigCapability] = {
    ConfigCapability.IOS_CLI,
    ConfigCapability.HOSTNAME,
    ConfigCapability.STATIC_IP,
    ConfigCapability.IPV6,
    ConfigCapability.DHCP_CLIENT,
    ConfigCapability.DHCP_SERVER,
    ConfigCapability.ROUTER_ON_A_STICK,
    ConfigCapability.STATIC_ROUTING,
    ConfigCapability.RIP,
    ConfigCapability.OSPF,
    ConfigCapability.EIGRP,
    ConfigCapability.BGP,
    ConfigCapability.HSRP,
    ConfigCapability.NAT_PAT,
    ConfigCapability.ACL_STANDARD,
    ConfigCapability.ACL_EXTENDED,
    ConfigCapability.IPSEC_VPN,
    ConfigCapability.ZONE_BASED_FIREWALL,
    ConfigCapability.AAA,
    ConfigCapability.SYSLOG,
    ConfigCapability.NTP,
    ConfigCapability.SNMP,
    ConfigCapability.SSH,
}

_L2_SWITCH_CAPS: set[ConfigCapability] = {
    ConfigCapability.IOS_CLI,
    ConfigCapability.HOSTNAME,
    ConfigCapability.VLANS,
    ConfigCapability.TRUNKING,
    ConfigCapability.PORT_SECURITY,
    ConfigCapability.STP,
    ConfigCapability.ETHERCHANNEL,
    ConfigCapability.DHCP_SNOOPING,
    ConfigCapability.DAI,
    ConfigCapability.SSH,
    ConfigCapability.DEFAULT_GATEWAY_L2,
}

_L3_SWITCH_CAPS: set[ConfigCapability] = {
    ConfigCapability.IOS_CLI,
    ConfigCapability.HOSTNAME,
    ConfigCapability.STATIC_IP,
    ConfigCapability.IPV6,
    ConfigCapability.VLANS,
    ConfigCapability.TRUNKING,
    ConfigCapability.TRUNK_ENCAP_DOT1Q,
    ConfigCapability.INTER_VLAN_SVI,
    ConfigCapability.STATIC_ROUTING,
    ConfigCapability.RIP,
    ConfigCapability.OSPF,
    ConfigCapability.EIGRP,
    ConfigCapability.HSRP,
    ConfigCapability.DHCP_SERVER,
    ConfigCapability.DHCP_SNOOPING,
    ConfigCapability.DAI,
    ConfigCapability.ACL_STANDARD,
    ConfigCapability.ACL_EXTENDED,
    ConfigCapability.PORT_SECURITY,
    ConfigCapability.STP,
    ConfigCapability.ETHERCHANNEL,
    ConfigCapability.AAA,
    ConfigCapability.SYSLOG,
    ConfigCapability.NTP,
    ConfigCapability.SNMP,
    ConfigCapability.SSH,
}


def _build_default_profiles() -> list[DeviceProfile]:
    return [
        # --- ROUTERS ---
        DeviceProfile(
            model="2911",
            display_name="Cisco 2911 ISR",
            category=DeviceCategory.ROUTER,
            packet_tracer_group="Network Devices > Routers > 2911",
            aliases=["cisco 2911", "router-2911", "isr2911"],
            interfaces=[
                *_eth_ports(
                    "GigabitEthernet",
                    "Gi",
                    PortMedia.GIGABIT_ETHERNET,
                    1000,
                    "0/",
                    0,
                    2,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                *_eth_ports(
                    "Serial",
                    "Se",
                    PortMedia.SERIAL,
                    2,
                    "0/0/",
                    0,
                    1,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
            ],
            capabilities=set(_ROUTER_COMMON_CAPS),
            restrictions=[
                "No Layer 2 switchport commands; use subinterfaces for 802.1Q trunking.",
                "Serial0/0/0 and Serial0/0/1 assume HWIC-2T WIC module installed in slot 0.",
            ],
            quirks=[
                "IPsec VPN and Zone-Based Firewall require 'license boot module c2900 "
                "technology-package securityk9' + reload in PT 8.2.2.",
                "Supports HWIC-1GE-SFP + GLC-LH-SMD for Gigabit fiber uplinks.",
            ],
            modules_supported=["HWIC-2T", "HWIC-1GE-SFP", "GLC-LH-SMD", "HWIC-4ESW"],
            supports_subinterfaces=True,
            supports_loopback=True,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        DeviceProfile(
            model="1941",
            display_name="Cisco 1941 ISR",
            category=DeviceCategory.ROUTER,
            packet_tracer_group="Network Devices > Routers > 1941",
            aliases=["cisco 1941", "router-1941", "isr1941"],
            interfaces=[
                *_eth_ports(
                    "GigabitEthernet",
                    "Gi",
                    PortMedia.GIGABIT_ETHERNET,
                    1000,
                    "0/",
                    0,
                    1,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                *_eth_ports(
                    "Serial",
                    "Se",
                    PortMedia.SERIAL,
                    2,
                    "0/0/",
                    0,
                    1,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
            ],
            capabilities=set(_ROUTER_COMMON_CAPS),
            restrictions=[
                "Only 2 built-in GigabitEthernet ports (Gi0/0, Gi0/1).",
                "Serial ports require HWIC-2T module in Packet Tracer physical view.",
            ],
            quirks=[
                "IPsec/ZBFW require 'license boot module c1900 technology-package "
                "securityk9' + reload.",
                "Supports HWIC-1GE-SFP + GLC-LH-SMD for Gigabit fiber connectivity.",
            ],
            modules_supported=["HWIC-2T", "HWIC-1GE-SFP", "GLC-LH-SMD", "HWIC-4ESW"],
            supports_subinterfaces=True,
            supports_loopback=True,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        DeviceProfile(
            model="2811",
            display_name="Cisco 2811 ISR",
            category=DeviceCategory.ROUTER,
            packet_tracer_group="Network Devices > Routers > 2811",
            aliases=["cisco 2811", "router-2811"],
            interfaces=[
                *_eth_ports(
                    "FastEthernet",
                    "Fa",
                    PortMedia.FAST_ETHERNET,
                    100,
                    "0/",
                    0,
                    1,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                *_eth_ports(
                    "Serial",
                    "Se",
                    PortMedia.SERIAL,
                    2,
                    "0/0/",
                    0,
                    1,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
            ],
            capabilities=set(_ROUTER_COMMON_CAPS),
            restrictions=[
                "Built-in LAN ports are FastEthernet (100 Mbps), not GigabitEthernet.",
            ],
            quirks=[
                "Primary Packet Tracer router supporting Cisco CallManager Express "
                "('telephony-service', 'ephone-dn', 'ephone') natively.",
            ],
            modules_supported=["HWIC-2T", "NM-ESW-161"],
            supports_subinterfaces=True,
            supports_loopback=True,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        DeviceProfile(
            model="4321",
            display_name="Cisco 4321 ISR",
            category=DeviceCategory.ROUTER,
            packet_tracer_group="Network Devices > Routers > 4321",
            aliases=["cisco 4321", "isr4321", "isr 4321"],
            interfaces=[
                *_eth_ports(
                    "GigabitEthernet",
                    "Gi",
                    PortMedia.GIGABIT_ETHERNET,
                    1000,
                    "0/0/",
                    0,
                    1,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                *_eth_ports(
                    "Serial",
                    "Se",
                    PortMedia.SERIAL,
                    2,
                    "0/1/",
                    0,
                    1,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
            ],
            capabilities=set(_ROUTER_COMMON_CAPS),
            restrictions=[
                "Uses 3-tuple interface naming: GigabitEthernet0/0/0..1 plus optional "
                "NIM-2T Serial0/1/0..1.",
                "Packet Tracer IOS-XE 15.5 lacks route-map, ip prefix-list, and PBR commands.",
            ],
            quirks=[
                "Serial0/1/0..1 require NIM-2T module in NIM slot "
                "(auto-inserted by bridge on router add).",
                "IPsec/ZBFW require 'license boot level securityk9' + write + reload in PT 8.2.2.",
                "Supports GLC-LH-SMD / GLC-GE-100FX SFP modules for fiber links.",
            ],
            modules_supported=["NIM-2T", "NIM-ES2-4", "GLC-LH-SMD", "GLC-GE-100FX"],
            supports_subinterfaces=True,
            supports_loopback=True,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        DeviceProfile(
            model="Router-PT",
            display_name="Generic Packet Tracer Router",
            category=DeviceCategory.ROUTER,
            packet_tracer_group="Network Devices > Routers > PT-Router",
            aliases=["pt-router", "router-pt", "generic-router"],
            interfaces=[
                InterfaceTemplate(
                    name="FastEthernet0/0",
                    short_name="Fa0/0",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                ),
                InterfaceTemplate(
                    name="FastEthernet1/0",
                    short_name="Fa1/0",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                ),
                InterfaceTemplate(
                    name="Serial2/0",
                    short_name="Se2/0",
                    media=PortMedia.SERIAL,
                    speed_mbps=2,
                ),
                InterfaceTemplate(
                    name="Serial3/0",
                    short_name="Se3/0",
                    media=PortMedia.SERIAL,
                    speed_mbps=2,
                ),
            ],
            capabilities=set(_ROUTER_COMMON_CAPS),
            restrictions=["Modular slot numbering places Serial ports at Serial2/0 and Serial3/0."],
            supports_subinterfaces=True,
            supports_loopback=True,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        # --- LAYER 2 SWITCHES ---
        DeviceProfile(
            model="2960-24TT",
            display_name="Cisco Catalyst 2960-24TT",
            category=DeviceCategory.L2_SWITCH,
            packet_tracer_group="Network Devices > Switches > 2960",
            aliases=["2960", "cisco 2960", "catalyst 2960", "switch-2960"],
            interfaces=[
                *_eth_ports(
                    "FastEthernet",
                    "Fa",
                    PortMedia.FAST_ETHERNET,
                    100,
                    "0/",
                    1,
                    24,
                    supports_switchport=True,
                    supports_routed_ip=False,
                ),
                *_eth_ports(
                    "GigabitEthernet",
                    "Gi",
                    PortMedia.GIGABIT_ETHERNET,
                    1000,
                    "0/",
                    1,
                    2,
                    supports_switchport=True,
                    supports_routed_ip=False,
                ),
            ],
            capabilities=set(_L2_SWITCH_CAPS),
            restrictions=[
                "Layer 2 only: no 'ip routing', OSPF, EIGRP, RIP, NAT, or routed ports.",
                "Does NOT accept 'switchport trunk encapsulation dot1q' (802.1Q is implicit).",
                "Only one active management SVI IP should use 'ip default-gateway'.",
            ],
            max_vlans=255,
            supports_svi=True,
            supports_port_channel=True,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        DeviceProfile(
            model="Switch-PT",
            display_name="Generic Packet Tracer Switch",
            category=DeviceCategory.L2_SWITCH,
            packet_tracer_group="Network Devices > Switches > PT-Switch",
            aliases=["pt-switch", "generic-switch"],
            interfaces=_eth_ports(
                "FastEthernet",
                "Fa",
                PortMedia.FAST_ETHERNET,
                100,
                "0/",
                1,
                4,
                supports_switchport=True,
                supports_routed_ip=False,
            ),
            capabilities={
                ConfigCapability.IOS_CLI,
                ConfigCapability.HOSTNAME,
                ConfigCapability.VLANS,
                ConfigCapability.TRUNKING,
                ConfigCapability.STP,
                ConfigCapability.DEFAULT_GATEWAY_L2,
            },
            restrictions=[
                "Minimal Layer 2 switch; default ports Fa0/1–Fa0/4 unless PT-SWITCH-NM added.",
            ],
            max_vlans=64,
            supports_svi=True,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        # --- LAYER 3 SWITCHES ---
        DeviceProfile(
            model="3560-24PS",
            display_name="Cisco Catalyst 3560-24PS Multilayer Switch",
            category=DeviceCategory.L3_SWITCH,
            packet_tracer_group="Network Devices > Switches > 3560-24PS",
            aliases=["3560", "cisco 3560", "catalyst 3560", "l3-switch"],
            interfaces=[
                *_eth_ports(
                    "FastEthernet",
                    "Fa",
                    PortMedia.FAST_ETHERNET,
                    100,
                    "0/",
                    1,
                    24,
                    supports_switchport=True,
                    supports_routed_ip=True,
                ),
                *_eth_ports(
                    "GigabitEthernet",
                    "Gi",
                    PortMedia.GIGABIT_ETHERNET,
                    1000,
                    "0/",
                    1,
                    2,
                    supports_switchport=True,
                    supports_routed_ip=True,
                ),
            ],
            capabilities=set(_L3_SWITCH_CAPS),
            restrictions=[
                "Requires 'switchport trunk encapsulation dot1q' BEFORE 'switchport mode trunk'.",
                "Requires global 'ip routing' to enable inter-VLAN SVI and dynamic routing.",
                "Physical ports require 'no switchport' before assigning an IP address.",
                "Does not support NAT/PAT in Packet Tracer.",
            ],
            quirks=[
                "PoE-capable on FastEthernet0/1..24 "
                "(powers Cisco 7960 IP Phones without external brick).",
                "GigabitEthernet0/1..2 dual-purpose copper/SFP uplink ports.",
            ],
            max_vlans=1005,
            supports_svi=True,
            supports_loopback=True,
            supports_port_channel=True,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        DeviceProfile(
            model="3650-24PS",
            display_name="Cisco Catalyst 3650-24PS Multilayer Switch",
            category=DeviceCategory.L3_SWITCH,
            packet_tracer_group="Network Devices > Switches > 3650-24PS",
            aliases=["3650", "cisco 3650", "catalyst 3650"],
            interfaces=[
                *_eth_ports(
                    "GigabitEthernet",
                    "Gi",
                    PortMedia.GIGABIT_ETHERNET,
                    1000,
                    "1/0/",
                    1,
                    24,
                    supports_switchport=True,
                    supports_routed_ip=True,
                ),
                *_eth_ports(
                    "GigabitEthernet",
                    "Gi",
                    PortMedia.GIGABIT_ETHERNET,
                    1000,
                    "1/1/",
                    1,
                    4,
                    supports_switchport=True,
                    supports_routed_ip=True,
                ),
            ],
            capabilities=set(_L3_SWITCH_CAPS),
            restrictions=[
                "Requires power supply module installed in Packet Tracer before CLI boots.",
                "Uses 3-tuple interface naming: GigabitEthernet1/0/1..24 and "
                "GigabitEthernet1/1/1..4.",
            ],
            quirks=[
                "Spawns unpowered in PT 8.2.2 (DeviceType=17) until AC-POWER-SUPPLY "
                "is inserted into power slot.",
                "GigabitEthernet1/1/1..4 SFP slots accept GLC-LH-SMD (fiber) or "
                "GLC-T/GLC-TE (copper) transceivers.",
            ],
            modules_supported=["AC-POWER-SUPPLY", "GLC-LH-SMD", "GLC-T", "GLC-TE"],
            max_vlans=1005,
            supports_svi=True,
            supports_loopback=True,
            supports_port_channel=True,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        # --- END DEVICES ---
        DeviceProfile(
            model="PC-PT",
            display_name="Packet Tracer PC",
            category=DeviceCategory.PC,
            packet_tracer_group="End Devices > End Devices > PC",
            aliases=["pc", "desktop", "workstation", "host"],
            interfaces=[
                InterfaceTemplate(
                    name="FastEthernet0",
                    short_name="Fa0",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                )
            ],
            capabilities={
                ConfigCapability.DESKTOP_IP_GUI,
                ConfigCapability.STATIC_IP,
                ConfigCapability.IPV6,
                ConfigCapability.DHCP_CLIENT,
            },
            restrictions=[
                "No Cisco IOS CLI; configure IP/Gateway/DNS via Desktop > IP Configuration.",
            ],
        ),
        DeviceProfile(
            model="Laptop-PT",
            display_name="Packet Tracer Laptop",
            category=DeviceCategory.LAPTOP,
            packet_tracer_group="End Devices > End Devices > Laptop",
            aliases=["laptop", "notebook"],
            interfaces=[
                InterfaceTemplate(
                    name="FastEthernet0",
                    short_name="Fa0",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                ),
                InterfaceTemplate(
                    name="Wireless0",
                    short_name="Wlan0",
                    media=PortMedia.WIRELESS,
                    speed_mbps=54,
                ),
            ],
            capabilities={
                ConfigCapability.DESKTOP_IP_GUI,
                ConfigCapability.STATIC_IP,
                ConfigCapability.IPV6,
                ConfigCapability.DHCP_CLIENT,
                ConfigCapability.WIRELESS_SSID,
            },
            restrictions=[
                "No Cisco IOS CLI; Wireless0 requires swapping Ethernet module in Physical tab.",
            ],
        ),
        DeviceProfile(
            model="Server-PT",
            display_name="Packet Tracer Server",
            category=DeviceCategory.SERVER,
            packet_tracer_group="End Devices > End Devices > Server",
            aliases=["server", "dhcp-server", "dns-server"],
            interfaces=[
                InterfaceTemplate(
                    name="FastEthernet0",
                    short_name="Fa0",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                )
            ],
            capabilities={
                ConfigCapability.DESKTOP_IP_GUI,
                ConfigCapability.STATIC_IP,
                ConfigCapability.IPV6,
                ConfigCapability.DHCP_CLIENT,
                ConfigCapability.DHCP_SERVER,
                ConfigCapability.DNS_SERVER,
            },
            restrictions=[
                "No Cisco IOS CLI; configure IP and Services (DHCP/DNS/HTTP) via Server GUI.",
            ],
        ),
        DeviceProfile(
            model="7960",
            display_name="Cisco IP Phone 7960",
            category=DeviceCategory.PC,
            packet_tracer_group="End Devices > End Devices > IP Phone",
            aliases=["cisco 7960", "ip phone", "ipphone", "7960"],
            interfaces=[
                InterfaceTemplate(
                    name="Switch",
                    short_name="Switch",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                InterfaceTemplate(
                    name="PC",
                    short_name="PC",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                    supports_switchport=False,
                    supports_routed_ip=False,
                ),
            ],
            capabilities={
                ConfigCapability.DHCP_CLIENT,
                ConfigCapability.STATIC_IP,
            },
            restrictions=[
                "Requires external power adapter in Physical tab when connected to non-PoE switch.",
                "Registers via SCCP/TFTP Option 150 to CallManager Express.",
            ],
        ),
        DeviceProfile(
            model="Home-VOIP-PT",
            display_name="Home VoIP ATA Adapter",
            category=DeviceCategory.PC,
            packet_tracer_group="End Devices > End Devices > Home VoIP",
            aliases=["home-voip-pt", "home-voip", "ata", "voip-adapter"],
            interfaces=[
                InterfaceTemplate(
                    name="FastEthernet0",
                    short_name="Fa0",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                InterfaceTemplate(
                    name="Phone",
                    short_name="Phone",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=10,
                    supports_switchport=False,
                    supports_routed_ip=False,
                    notes="RJ-11 analog telephone port (connect via Phone cable).",
                ),
            ],
            capabilities={
                ConfigCapability.DHCP_CLIENT,
                ConfigCapability.STATIC_IP,
            },
            restrictions=[
                "Connects Analog-Phone-PT via RJ-11 Phone port (DeviceType=24 in PT 8.2.2).",
                "Requires Server IP and Phone Number configured in Config tab.",
            ],
        ),
        DeviceProfile(
            model="Analog-Phone-PT",
            display_name="Packet Tracer Analog Phone",
            category=DeviceCategory.PC,
            packet_tracer_group="End Devices > End Devices > Analog Phone",
            aliases=["analog-phone-pt", "analog-phone", "analog phone"],
            interfaces=[
                InterfaceTemplate(
                    name="Phone",
                    short_name="Phone",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=10,
                    supports_switchport=False,
                    supports_routed_ip=False,
                    notes="RJ-11 analog handset port (connect to Home-VOIP-PT Phone port).",
                )
            ],
            capabilities=set(),
            restrictions=[
                "Passive analog RJ-11 telephone (DeviceType=25 in PT 8.2.2); no IP stack or CLI.",
            ],
        ),
        DeviceProfile(
            model="Smartphone-PT",
            display_name="Packet Tracer Smartphone",
            category=DeviceCategory.PC,
            packet_tracer_group="End Devices > End Devices > Smartphone",
            aliases=["smartphone", "smartphone-pt", "smart-phone"],
            interfaces=[
                InterfaceTemplate(
                    name="Wireless0",
                    short_name="Wlan0",
                    media=PortMedia.WIRELESS,
                    speed_mbps=54,
                    supports_switchport=False,
                    supports_routed_ip=True,
                )
            ],
            capabilities={
                ConfigCapability.DESKTOP_IP_GUI,
                ConfigCapability.STATIC_IP,
                ConfigCapability.IPV6,
                ConfigCapability.DHCP_CLIENT,
                ConfigCapability.WIRELESS_SSID,
            },
            restrictions=[
                "Wireless-only end device; no wired Ethernet slot or Cisco IOS CLI.",
            ],
        ),
        DeviceProfile(
            model="TabletPC-PT",
            display_name="Packet Tracer Tablet PC",
            category=DeviceCategory.PC,
            packet_tracer_group="End Devices > End Devices > Tablet",
            aliases=["tablet", "tabletpc", "tabletpc-pt", "tablet-pt"],
            interfaces=[
                InterfaceTemplate(
                    name="Wireless0",
                    short_name="Wlan0",
                    media=PortMedia.WIRELESS,
                    speed_mbps=54,
                    supports_switchport=False,
                    supports_routed_ip=True,
                )
            ],
            capabilities={
                ConfigCapability.DESKTOP_IP_GUI,
                ConfigCapability.STATIC_IP,
                ConfigCapability.IPV6,
                ConfigCapability.DHCP_CLIENT,
                ConfigCapability.WIRELESS_SSID,
            },
            restrictions=[
                "Wireless-only tablet end device (DeviceType=19 in PT 8.2.2); no IOS CLI.",
            ],
        ),
        DeviceProfile(
            model="Printer-PT",
            display_name="Packet Tracer Network Printer",
            category=DeviceCategory.PRINTER,
            packet_tracer_group="End Devices > End Devices > Printer",
            aliases=["printer"],
            interfaces=[
                InterfaceTemplate(
                    name="FastEthernet0",
                    short_name="Fa0",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                )
            ],
            capabilities={
                ConfigCapability.DESKTOP_IP_GUI,
                ConfigCapability.STATIC_IP,
                ConfigCapability.DHCP_CLIENT,
            },
            restrictions=["Does NOT support Cisco IOS CLI; static IP or DHCP client only."],
        ),
        # --- WIRELESS & IOT GATEWAYS ---
        DeviceProfile(
            model="WRT300N",
            display_name="Linksys WRT300N Wireless Router",
            vendor="Linksys",
            category=DeviceCategory.WIRELESS_ROUTER,
            packet_tracer_group="Network Devices > Wireless Devices > WRT300N",
            aliases=["wrt300n", "wireless-router", "home-router"],
            interfaces=[
                InterfaceTemplate(
                    name="Internet",
                    short_name="WAN",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                ),
                *_eth_ports(
                    "Ethernet",
                    "Eth",
                    PortMedia.FAST_ETHERNET,
                    100,
                    "",
                    1,
                    4,
                    supports_switchport=True,
                    supports_routed_ip=False,
                ),
                InterfaceTemplate(
                    name="Wireless",
                    short_name="WLAN",
                    media=PortMedia.WIRELESS,
                    speed_mbps=300,
                ),
            ],
            capabilities={
                ConfigCapability.WEB_CONFIG_GUI,
                ConfigCapability.STATIC_IP,
                ConfigCapability.DHCP_CLIENT,
                ConfigCapability.DHCP_SERVER,
                ConfigCapability.NAT_PAT,
                ConfigCapability.WIRELESS_SSID,
            },
            restrictions=[
                "Does NOT support Cisco IOS CLI; configured via GUI Web Setup.",
                "Has 1 Internet (WAN) port and 4 switched LAN Ethernet ports.",
            ],
        ),
        DeviceProfile(
            model="HomeGateway-PT",
            display_name="Cisco IoT Home Gateway",
            category=DeviceCategory.WIRELESS_ROUTER,
            packet_tracer_group="Network Devices > Wireless Devices > Home Gateway",
            aliases=["homegateway", "home-gateway", "homegateway-pt", "dlc100", "iot-gateway"],
            interfaces=[
                InterfaceTemplate(
                    name="Internet",
                    short_name="WAN",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                ),
                *_eth_ports(
                    "Ethernet",
                    "Eth",
                    PortMedia.FAST_ETHERNET,
                    100,
                    "",
                    1,
                    4,
                    supports_switchport=True,
                    supports_routed_ip=False,
                ),
                InterfaceTemplate(
                    name="Wireless",
                    short_name="WLAN",
                    media=PortMedia.WIRELESS,
                    speed_mbps=300,
                ),
            ],
            capabilities={
                ConfigCapability.WEB_CONFIG_GUI,
                ConfigCapability.STATIC_IP,
                ConfigCapability.DHCP_CLIENT,
                ConfigCapability.DHCP_SERVER,
                ConfigCapability.NAT_PAT,
                ConfigCapability.WIRELESS_SSID,
            },
            restrictions=[
                "IoT Registration Server + Home Router (DeviceType=29 in PT 8.2.2); no IOS CLI.",
                "Internet port is MDI (WAN); Ethernet1..4 are MDI-X LAN switch ports.",
            ],
            quirks=[
                "Broadcasts default IoT SSID 'HomeGateway' and hosts built-in "
                "Smart Thing registration service.",
            ],
        ),
        DeviceProfile(
            model="AccessPoint-PT",
            display_name="Generic Wireless Access Point",
            category=DeviceCategory.ACCESS_POINT,
            packet_tracer_group="Network Devices > Wireless Devices > AP-PT",
            aliases=["ap-pt", "access-point", "ap"],
            interfaces=[
                InterfaceTemplate(
                    name="Port0",
                    short_name="Port0",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                    supports_routed_ip=False,
                ),
                InterfaceTemplate(
                    name="Port1",
                    short_name="Port1",
                    media=PortMedia.WIRELESS,
                    speed_mbps=54,
                    supports_routed_ip=False,
                ),
            ],
            capabilities={
                ConfigCapability.DESKTOP_IP_GUI,
                ConfigCapability.WIRELESS_SSID,
            },
            restrictions=[
                "Bridge-only L2 Access Point; does NOT support Cisco IOS CLI or IP routing.",
            ],
        ),
        # --- ENTERPRISE ROUTERS, FIREWALLS, WLC, & CLOUD (PT 8.2.2) ---
        DeviceProfile(
            model="ISR4331",
            display_name="Cisco ISR 4331 Router",
            category=DeviceCategory.ROUTER,
            packet_tracer_group="Network Devices > Routers > 4331",
            aliases=["4331", "cisco 4331", "isr 4331"],
            interfaces=[
                *_eth_ports(
                    "GigabitEthernet",
                    "Gi",
                    PortMedia.GIGABIT_ETHERNET,
                    1000,
                    "0/0/",
                    0,
                    2,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                *_eth_ports(
                    "Serial",
                    "Se",
                    PortMedia.SERIAL,
                    2,
                    "0/1/",
                    0,
                    1,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
            ],
            capabilities=set(_ROUTER_COMMON_CAPS),
            restrictions=[
                "Uses 3-tuple Gi0/0/0..2 plus optional NIM-2T Serial0/1/0..1.",
                "Packet Tracer IOS-XE 15.5 lacks route-map, ip prefix-list, and PBR commands.",
            ],
            quirks=[
                "IPsec VPN and Zone-Based Firewall require 'license boot level securityk9' "
                "+ write + reload in PT 8.2.2.",
                "Supports GLC-LH-SMD / GLC-GE-100FX fiber SFPs and NIM-2T serial modules.",
            ],
            modules_supported=["NIM-2T", "NIM-ES2-4", "GLC-LH-SMD", "GLC-GE-100FX", "GLC-T"],
            supports_subinterfaces=True,
            supports_loopback=True,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        DeviceProfile(
            model="5505",
            display_name="Cisco ASA 5505 Adaptive Security Appliance",
            category=DeviceCategory.FIREWALL,
            packet_tracer_group="Network Devices > Security > ASA 5505",
            aliases=["asa 5505", "asa5505", "asa"],
            interfaces=_eth_ports(
                "Ethernet",
                "Eth",
                PortMedia.FAST_ETHERNET,
                100,
                "0/",
                0,
                7,
                supports_switchport=True,
                supports_routed_ip=False,
            ),
            capabilities={
                ConfigCapability.HOSTNAME,
                ConfigCapability.ASA_FIREWALL,
                ConfigCapability.VLANS,
                ConfigCapability.STATIC_ROUTING,
                ConfigCapability.NAT_PAT,
                ConfigCapability.ACL_STANDARD,
                ConfigCapability.ACL_EXTENDED,
                ConfigCapability.IPSEC_VPN,
                ConfigCapability.AAA,
                ConfigCapability.SSH,
            },
            restrictions=[
                "Switchport-based firewall assigned to VLAN SVIs with nameif/security-level.",
                "PT 8.2.2 ASA does not support dynamic routing protocols, HA failover, or IKEv2.",
                "Uses ASA OS CLI syntax ('nameif', 'security-level', 'route outside 0 0', "
                "'object network' NAT) rather than IOS.",
            ],
            quirks=[
                "Ethernet0/0..7 are L2 switchports (MDI-X); assign 'switchport access vlan <id>' "
                "and put IP/nameif on 'interface Vlan<id>'.",
                "Base license in PT restricts active VLAN security zones unless inside/outside/dmz "
                "restricted properly; blank enable password by default; disable paging via "
                "'terminal pager 0'.",
            ],
            max_vlans=20,
            supports_subinterfaces=False,
            supports_svi=True,
            supports_loopback=False,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        DeviceProfile(
            model="5506-X",
            display_name="Cisco ASA 5506-X Adaptive Security Appliance",
            category=DeviceCategory.FIREWALL,
            packet_tracer_group="Network Devices > Security > ASA 5506-X",
            aliases=["asa 5506-x", "asa5506-x", "5506", "asa 5506", "asa 5506x"],
            interfaces=[
                *_eth_ports(
                    "GigabitEthernet",
                    "Gi",
                    PortMedia.GIGABIT_ETHERNET,
                    1000,
                    "1/",
                    1,
                    8,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                InterfaceTemplate(
                    name="Management1/1",
                    short_name="Mgmt1/1",
                    media=PortMedia.GIGABIT_ETHERNET,
                    speed_mbps=1000,
                    supports_switchport=False,
                    supports_routed_ip=True,
                    notes="Dedicated out-of-band management port on ASA 5506-X.",
                ),
            ],
            capabilities={
                ConfigCapability.HOSTNAME,
                ConfigCapability.ASA_FIREWALL,
                ConfigCapability.STATIC_ROUTING,
                ConfigCapability.ROUTER_ON_A_STICK,
                ConfigCapability.NAT_PAT,
                ConfigCapability.ACL_STANDARD,
                ConfigCapability.ACL_EXTENDED,
                ConfigCapability.IPSEC_VPN,
                ConfigCapability.DHCP_SERVER,
                ConfigCapability.AAA,
                ConfigCapability.SSH,
            },
            restrictions=[
                "Routed firewall (ASA 9.6): configure 'nameif', 'security-level', and "
                "'ip address' directly on GigabitEthernet1/1..8 (no 'switchport' or VLAN SVIs).",
                "PT 8.2.2 ASA 5506-X uses ASA CLI syntax ('terminal pager 0', "
                "'route outside 0.0.0.0 0.0.0.0 <gw>', 'object network' NAT).",
            ],
            quirks=[
                "Unlike ASA 5505, GigabitEthernet1/1..8 are routed L3 ports "
                "(MDI pinout; connect to switches with straight-through cable).",
                "Blank enable password by default on 'enable'; uses '<--- More --->' pager "
                "until 'terminal pager 0'.",
            ],
            supports_subinterfaces=True,
            supports_svi=False,
            supports_loopback=False,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        DeviceProfile(
            model="WLC-2504",
            display_name="Cisco 2504 Wireless LAN Controller",
            category=DeviceCategory.WLC,
            packet_tracer_group="Network Devices > Wireless Devices > WLC-2504",
            aliases=["2504", "wlc2504", "wlc-2504"],
            interfaces=[
                InterfaceTemplate(
                    name=f"GigabitEthernet{i}",
                    short_name=f"Gi{i}",
                    media=PortMedia.GIGABIT_ETHERNET,
                    speed_mbps=1000,
                    supports_switchport=True,
                    supports_routed_ip=False,
                )
                for i in range(1, 5)
            ]
            + [
                InterfaceTemplate(
                    name="management",
                    short_name="mgmt",
                    media=PortMedia.SVI,
                    speed_mbps=1000,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                InterfaceTemplate(
                    name="virtual",
                    short_name="virt",
                    media=PortMedia.SVI,
                    speed_mbps=1000,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
            ],
            capabilities={
                ConfigCapability.WEB_CONFIG_GUI,
                ConfigCapability.STATIC_IP,
                ConfigCapability.DHCP_SERVER,
                ConfigCapability.WIRELESS_SSID,
                ConfigCapability.WLC_CAPWAP,
            },
            restrictions=[
                "Managed via Web Browser HTTP/HTTPS GUI against management IP (no IOS CLI).",
            ],
            supports_svi=True,
        ),
        DeviceProfile(
            model="WLC-3504",
            display_name="Cisco 3504 Wireless LAN Controller",
            category=DeviceCategory.WLC,
            packet_tracer_group="Network Devices > Wireless Devices > WLC-3504",
            aliases=["3504", "wlc3504", "wlc-3504"],
            interfaces=[
                InterfaceTemplate(
                    name=f"GigabitEthernet{i}",
                    short_name=f"Gi{i}",
                    media=PortMedia.GIGABIT_ETHERNET,
                    speed_mbps=1000,
                    supports_switchport=True,
                    supports_routed_ip=False,
                )
                for i in range(1, 6)
            ]
            + [
                InterfaceTemplate(
                    name="management",
                    short_name="mgmt",
                    media=PortMedia.SVI,
                    speed_mbps=1000,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                InterfaceTemplate(
                    name="virtual",
                    short_name="virt",
                    media=PortMedia.SVI,
                    speed_mbps=1000,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
            ],
            capabilities={
                ConfigCapability.WEB_CONFIG_GUI,
                ConfigCapability.STATIC_IP,
                ConfigCapability.DHCP_SERVER,
                ConfigCapability.WIRELESS_SSID,
                ConfigCapability.WLC_CAPWAP,
            },
            restrictions=[
                "Managed via Web Browser HTTP/HTTPS GUI against management IP (no IOS CLI).",
            ],
            supports_svi=True,
        ),
        DeviceProfile(
            model="WLC-PT",
            display_name="Packet Tracer Generic WLC",
            category=DeviceCategory.WLC,
            packet_tracer_group="Network Devices > Wireless Devices > WLC-PT",
            aliases=["wlc-pt", "generic-wlc"],
            interfaces=[
                InterfaceTemplate(
                    name=f"GigabitEthernet{i}",
                    short_name=f"Gi{i}",
                    media=PortMedia.GIGABIT_ETHERNET,
                    speed_mbps=1000,
                    supports_switchport=True,
                    supports_routed_ip=False,
                )
                for i in range(1, 5)
            ]
            + [
                InterfaceTemplate(
                    name="management",
                    short_name="mgmt",
                    media=PortMedia.SVI,
                    speed_mbps=1000,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
            ],
            capabilities={
                ConfigCapability.WEB_CONFIG_GUI,
                ConfigCapability.STATIC_IP,
                ConfigCapability.DHCP_SERVER,
                ConfigCapability.WIRELESS_SSID,
                ConfigCapability.WLC_CAPWAP,
            },
            restrictions=[
                "Configure WLANs/AP Groups/RADIUS via PT Config tab GUI or IPC.",
            ],
            supports_svi=True,
        ),
        DeviceProfile(
            model="LAP-PT",
            display_name="Cisco Lightweight Access Point",
            category=DeviceCategory.ACCESS_POINT,
            packet_tracer_group="Network Devices > Wireless Devices > LAP-PT",
            aliases=["lap", "lap-pt", "lightweight access point", "light weight access point"],
            interfaces=[
                InterfaceTemplate(
                    name="GigabitEthernet0",
                    short_name="Gi0",
                    media=PortMedia.GIGABIT_ETHERNET,
                    speed_mbps=1000,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                InterfaceTemplate(
                    name="Dot11Radio0",
                    short_name="Dot11Radio0",
                    media=PortMedia.WIRELESS,
                    speed_mbps=54,
                    supports_switchport=False,
                    supports_routed_ip=False,
                ),
            ],
            capabilities={
                ConfigCapability.DHCP_CLIENT,
                ConfigCapability.WIRELESS_SSID,
                ConfigCapability.WLC_CAPWAP,
            },
            restrictions=[
                "CAPWAP lightweight AP; joins WLC via DHCP/DNS and serves controller-pushed SSIDs.",
            ],
        ),
        DeviceProfile(
            model="3702i",
            display_name="Cisco Aironet 3702i Lightweight AP",
            category=DeviceCategory.ACCESS_POINT,
            packet_tracer_group="Network Devices > Wireless Devices > 3702i",
            aliases=["air-cap3702i", "cap3702i", "ap-3702i"],
            interfaces=[
                InterfaceTemplate(
                    name="GigabitEthernet0",
                    short_name="Gi0",
                    media=PortMedia.GIGABIT_ETHERNET,
                    speed_mbps=1000,
                    supports_switchport=False,
                    supports_routed_ip=True,
                ),
                InterfaceTemplate(
                    name="Dot11Radio0",
                    short_name="Dot11Radio0",
                    media=PortMedia.WIRELESS,
                    speed_mbps=54,
                    supports_switchport=False,
                    supports_routed_ip=False,
                ),
            ],
            capabilities={
                ConfigCapability.DHCP_CLIENT,
                ConfigCapability.WIRELESS_SSID,
                ConfigCapability.WLC_CAPWAP,
            },
            restrictions=[
                "CAPWAP lightweight AP; requires PoE or power adapter and WLC discovery.",
            ],
        ),
        DeviceProfile(
            model="Cloud-PT",
            display_name="Packet Tracer WAN Cloud",
            category=DeviceCategory.CLOUD,
            packet_tracer_group="Network Devices > WAN Emulation > Cloud-PT",
            aliases=["cloud", "cloud-pt", "wan-cloud"],
            interfaces=[
                InterfaceTemplate(
                    name="Ethernet6",
                    short_name="Eth6",
                    media=PortMedia.FAST_ETHERNET,
                    speed_mbps=100,
                    supports_switchport=False,
                    supports_routed_ip=False,
                ),
                *[
                    InterfaceTemplate(
                        name=f"Serial{i}",
                        short_name=f"Se{i}",
                        media=PortMedia.SERIAL,
                        speed_mbps=2,
                        supports_switchport=False,
                        supports_routed_ip=False,
                    )
                    for i in range(0, 4)
                ],
            ],
            capabilities=set(),
            restrictions=[
                "L2 WAN/Frame Relay/DSL/Cable cloud; configure DLCI mappings via Config GUI.",
            ],
        ),
    ]


class DeviceCatalog:
    """Registry of verified Packet Tracer device profiles, models, and interface rules."""

    def __init__(self, profiles: list[DeviceProfile] | None = None) -> None:
        self._profiles: dict[str, DeviceProfile] = {}
        self._alias_map: dict[str, str] = {}
        for profile in profiles or _build_default_profiles():
            self.register(profile)

    def register(self, profile: DeviceProfile) -> None:
        """Register or update a device capability profile."""
        self._profiles[profile.model] = profile
        self._alias_map[profile.model.lower()] = profile.model
        self._alias_map[profile.display_name.lower()] = profile.model
        for alias in profile.aliases:
            self._alias_map[alias.lower()] = profile.model

    def resolve_model_name(self, model_or_alias: str) -> str:
        """Resolve a model name or alias to its canonical Packet Tracer model string."""
        cleaned = model_or_alias.strip()
        canonical = self._alias_map.get(cleaned.lower())
        if canonical is None:
            available = ", ".join(sorted(self._profiles.keys()))
            raise DeviceModelError(
                f"Unknown or unverified Packet Tracer device model {model_or_alias!r}.",
                details={
                    "requested_model": model_or_alias,
                    "supported_models": sorted(self._profiles),
                },
                remediation=f"Choose a verified model: {available}.",
            )
        return canonical

    def get_profile(self, model_or_alias: str) -> DeviceProfile:
        """Retrieve the DeviceProfile for a model name or alias."""
        canonical = self.resolve_model_name(model_or_alias)
        return self._profiles[canonical]

    def list_profiles(self, category: DeviceCategory | None = None) -> list[DeviceProfile]:
        """List all registered device profiles, optionally filtered by category."""
        profiles = list(self._profiles.values())
        if category is not None:
            profiles = [p for p in profiles if p.category == category]
        return sorted(profiles, key=lambda p: (p.category.value, p.model))

    def capability_report(self, model_or_alias: str) -> DeviceCapabilityReport:
        """Produce a structured capability report for a device model."""
        profile = self.get_profile(model_or_alias)
        return DeviceCapabilityReport(
            model=profile.model,
            display_name=profile.display_name,
            vendor=profile.vendor,
            category=profile.category,
            packet_tracer_group=profile.packet_tracer_group,
            target_mode=profile.target_mode,
            physical_interfaces=[iface.name for iface in profile.interfaces],
            capabilities=sorted(c.value for c in profile.capabilities),
            restrictions=list(profile.restrictions),
            quirks=list(profile.quirks),
            supports_ios_cli=profile.supports(ConfigCapability.IOS_CLI),
            supports_routing=any(
                profile.supports(cap)
                for cap in (
                    ConfigCapability.STATIC_ROUTING,
                    ConfigCapability.OSPF,
                    ConfigCapability.EIGRP,
                    ConfigCapability.RIP,
                    ConfigCapability.BGP,
                )
            ),
            supports_vlans=profile.supports(ConfigCapability.VLANS),
        )

    def normalize_interface_name(
        self,
        model_or_alias: str,
        interface_name: str,
        *,
        allow_logical: bool = True,
    ) -> str:
        """Normalize shorthand interface names (e.g. 'Gi0/0' -> 'GigabitEthernet0/0').

        Validates physical interface presence or permitted logical interfaces
        (subinterfaces, SVIs, Loopbacks, Port-channels).
        """
        profile = self.get_profile(model_or_alias)
        raw = interface_name.strip()
        if not raw:
            raise InterfaceError("Interface name cannot be empty.")

        # Direct case-insensitive match against physical interface name or short_name
        for iface in profile.interfaces:
            if raw.lower() in {iface.name.lower(), iface.short_name.lower()}:
                return iface.name

        # Canonical prefix expansion
        match = _IFACE_PREFIX_RE.match(raw)
        canonical = raw
        if match:
            prefix_token, suffix = match.group(1).lower(), match.group(2)
            expanded_prefix = _CANONICAL_PREFIX_MAP.get(prefix_token)
            if expanded_prefix:
                canonical = f"{expanded_prefix}{suffix}"

        # Exact match after prefix expansion
        for iface in profile.interfaces:
            if canonical.lower() == iface.name.lower():
                return iface.name

        if allow_logical:
            if "." in canonical:
                parent_name, sub_id = canonical.split(".", 1)
                if sub_id.isdigit() and 1 <= int(sub_id) <= 4094:
                    if not profile.supports_subinterfaces:
                        msg = (
                            f"Model '{profile.model}' does not support subinterfaces ({canonical})."
                        )
                        raise InterfaceError(
                            msg,
                            details={"model": profile.model, "interface": canonical},
                        )
                    parent_canonical = self.normalize_interface_name(
                        profile.model, parent_name, allow_logical=False
                    )
                    return f"{parent_canonical}.{sub_id}"

            if canonical.startswith("Vlan"):
                vlan_part = canonical[4:]
                if vlan_part.isdigit() and 1 <= int(vlan_part) <= 4094 and profile.supports_svi:
                    return f"Vlan{int(vlan_part)}"

            if canonical.startswith("Loopback"):
                lo_part = canonical[8:]
                if (
                    lo_part.isdigit()
                    and 0 <= int(lo_part) <= 2147483647
                    and profile.supports_loopback
                ):
                    return f"Loopback{int(lo_part)}"

            if canonical.startswith("Port-channel"):
                po_part = canonical[12:]
                if po_part.isdigit() and 1 <= int(po_part) <= 48 and profile.supports_port_channel:
                    return f"Port-channel{int(po_part)}"

        available = [iface.name for iface in profile.interfaces]
        raise InterfaceError(
            f"Interface {interface_name!r} is not valid on model '{profile.model}'.",
            details={
                "model": profile.model,
                "requested_interface": interface_name,
                "available_physical_interfaces": available,
            },
            remediation=f"Use a valid interface on {profile.model}, e.g. {available[:4]}.",
        )
