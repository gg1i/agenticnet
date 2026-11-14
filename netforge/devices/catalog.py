"""Verified Packet Tracer device capability registry and interface normalization."""

from __future__ import annotations

import re

from netforge.core.enums import ConfigCapability, DeviceCategory, PortMedia
from netforge.core.exceptions import DeviceModelError, InterfaceError
from netforge.devices.models import DeviceCapabilityReport, DeviceProfile, InterfaceTemplate

_IFACE_PREFIX_RE = re.compile(
    r"^(fastethernet|fa|f|gigabitethernet|gi|gig|g|tengigabitethernet|te|t|"
    r"serial|se|s|vlan|vl|loopback|lo|port-channel|po|ethernet|eth|port|wireless|wlan)"
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
    ConfigCapability.NAT_PAT,
    ConfigCapability.ACL_STANDARD,
    ConfigCapability.ACL_EXTENDED,
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
    ConfigCapability.DHCP_SERVER,
    ConfigCapability.ACL_STANDARD,
    ConfigCapability.ACL_EXTENDED,
    ConfigCapability.PORT_SECURITY,
    ConfigCapability.STP,
    ConfigCapability.ETHERCHANNEL,
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
            supports_subinterfaces=True,
            supports_loopback=True,
            cli_prompt_pattern=r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*$",
        ),
        DeviceProfile(
            model="4321",
            display_name="Cisco 4321 ISR",
            category=DeviceCategory.ROUTER,
            packet_tracer_group="Network Devices > Routers > 4321",
            aliases=["cisco 4321", "isr4321"],
            interfaces=_eth_ports(
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
            capabilities=set(_ROUTER_COMMON_CAPS),
            restrictions=[
                "Uses 3-tuple interface naming: GigabitEthernet0/0/0 and GigabitEthernet0/0/1.",
            ],
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
                "Uses 3-tuple interface naming: GigabitEthernet1/0/1..24.",
            ],
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
            aliases=["home-voip-pt", "ata", "voip-adapter", "analog-phone-pt"],
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
                ),
            ],
            capabilities={
                ConfigCapability.DHCP_CLIENT,
                ConfigCapability.STATIC_IP,
            },
            restrictions=[
                "Connects analog phone via RJ-11 Phone port.",
                "Requires Server IP and Phone Number configured in Config tab.",
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
        # --- WIRELESS ---
        DeviceProfile(
            model="WRT300N",
            display_name="Linksys WRT300N Wireless Router",
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
            category=profile.category,
            packet_tracer_group=profile.packet_tracer_group,
            physical_interfaces=[iface.name for iface in profile.interfaces],
            capabilities=sorted(c.value for c in profile.capabilities),
            restrictions=list(profile.restrictions),
            supports_ios_cli=profile.supports(ConfigCapability.IOS_CLI),
            supports_routing=any(
                profile.supports(cap)
                for cap in (
                    ConfigCapability.STATIC_ROUTING,
                    ConfigCapability.OSPF,
                    ConfigCapability.EIGRP,
                    ConfigCapability.RIP,
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
