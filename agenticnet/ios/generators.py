"""Structured Cisco IOS configuration generator backed by device capability profiles."""

from __future__ import annotations

import ipaddress

from agenticnet.core.enums import ConfigCapability, DeviceCategory
from agenticnet.core.exceptions import IOSConfigError
from agenticnet.devices import DEFAULT_CATALOG, DeviceCatalog, DeviceProfile
from agenticnet.ios.models import (
    AccessPortSpec,
    AclSpec,
    DhcpPoolSpec,
    EigrpConfigSpec,
    EtherChannelSpec,
    InterfaceConfigSpec,
    NatPatSpec,
    OspfConfigSpec,
    RenderedCommandSequence,
    RipConfigSpec,
    SshConfigSpec,
    StaticRouteEntry,
    StpSpec,
    TrunkPortSpec,
    VlanSpec,
)
from agenticnet.ios.validators import (
    parse_ipv4_and_mask,
    require_capability,
    to_network_and_wildcard,
)
from agenticnet.security.redaction import redact_cli_text


class IOSGenerator:
    """Generates validated, Packet-Tracer-accurate Cisco IOS command sequences."""

    def __init__(self, catalog: DeviceCatalog | None = None) -> None:
        self.catalog = catalog or DEFAULT_CATALOG

    def _finalize(
        self,
        device_name: str,
        profile: DeviceProfile,
        feature: str,
        commands: list[str],
        *,
        verification_commands: list[str] | None = None,
        warnings: list[str] | None = None,
    ) -> RenderedCommandSequence:
        redacted = [redact_cli_text(cmd) for cmd in commands]
        return RenderedCommandSequence(
            device_name=device_name,
            device_model=profile.model,
            feature=feature,
            commands=commands,
            commands_redacted=redacted,
            verification_commands=verification_commands or [],
            warnings=warnings or [],
        )

    def hostname(
        self, device_name: str, model: str, *, disable_dns_lookup: bool = True
    ) -> RenderedCommandSequence:
        """Generate hostname and optional 'no ip domain-lookup' hardening."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.HOSTNAME, "hostname")
        cmds = [f"hostname {device_name}"]
        if disable_dns_lookup:
            cmds.append("no ip domain-lookup")
        return self._finalize(device_name, profile, "hostname", cmds)

    def default_gateway_l2(
        self, device_name: str, model: str, gateway_ip: str
    ) -> RenderedCommandSequence:
        """Configure 'ip default-gateway' for a Layer 2 switch management plane."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.DEFAULT_GATEWAY_L2, "ip default-gateway")
        try:
            ipaddress.IPv4Address(gateway_ip.strip())
        except ValueError as exc:
            raise IOSConfigError(f"Invalid gateway IP {gateway_ip!r}: {exc}") from exc
        cmds = [f"ip default-gateway {gateway_ip.strip()}"]
        return self._finalize(
            device_name,
            profile,
            "default_gateway",
            cmds,
            verification_commands=["show ip default-gateway"],
        )

    def interface(self, model: str, spec: InterfaceConfigSpec) -> RenderedCommandSequence:
        """Generate interface, SVI, loopback, or 802.1Q subinterface commands."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.IOS_CLI, "interface configuration")
        canonical_iface = self.catalog.normalize_interface_name(profile.model, spec.interface)

        cmds: list[str] = [f"interface {canonical_iface}"]
        warnings: list[str] = []

        if spec.description:
            cmds.append(f" description {spec.description.strip()}")

        is_subif = "." in canonical_iface
        if is_subif:
            vlan_id = spec.dot1q_vlan or int(canonical_iface.split(".")[1])
            encap = f" encapsulation dot1Q {vlan_id}"
            if spec.native_vlan:
                encap += " native"
            cmds.append(encap)
            # Parent interface should also be enabled
            parent = canonical_iface.split(".")[0]
            warnings.append(
                f"Ensure parent interface '{parent}' is also brought up ('no shutdown')."
            )
        elif spec.dot1q_vlan is not None:
            raise IOSConfigError(
                "dot1q_vlan can only be used on router subinterfaces (e.g. GigabitEthernet0/0.10)."
            )

        if spec.l3_routed_port:
            if profile.category != DeviceCategory.L3_SWITCH:
                raise IOSConfigError(
                    f"'no switchport' is only valid on Layer 3 switches, not '{profile.model}'."
                )
            cmds.append(" no switchport")

        if spec.dhcp_client:
            require_capability(profile, ConfigCapability.DHCP_CLIENT, "interface DHCP client")
            cmds.append(" ip address dhcp")
        elif spec.ipv4_address:
            if profile.category == DeviceCategory.L2_SWITCH and not canonical_iface.startswith(
                "Vlan"
            ):
                raise IOSConfigError(
                    f"L2 switch '{profile.model}' cannot assign IPv4 addresses to physical port "
                    f"'{canonical_iface}'. Use a management SVI such as 'Vlan1' or 'Vlan99'."
                )
            ip_str, mask_str = parse_ipv4_and_mask(spec.ipv4_address, spec.subnet_mask)
            cmds.append(f" ip address {ip_str} {mask_str}")

        if spec.ipv6_address:
            require_capability(profile, ConfigCapability.IPV6, "IPv6 addressing")
            try:
                ipv6_iface = ipaddress.IPv6Interface(spec.ipv6_address.strip())
            except ValueError as exc:
                raise IOSConfigError(f"Invalid IPv6 CIDR {spec.ipv6_address!r}: {exc}") from exc
            cmds.append(f" ipv6 address {ipv6_iface.with_prefixlen}")

        if spec.clock_rate is not None:
            if not canonical_iface.startswith("Serial"):
                raise IOSConfigError("clock rate applies only to Serial DCE interfaces.")
            cmds.append(f" clock rate {spec.clock_rate}")

        if spec.nat_role is not None:
            require_capability(profile, ConfigCapability.NAT_PAT, "NAT interface role")
            cmds.append(f" ip nat {spec.nat_role}")

        cmds.append(" no shutdown" if spec.admin_up else " shutdown")
        cmds.append(" exit")

        return self._finalize(
            spec.device_name,
            profile,
            "interface",
            cmds,
            verification_commands=["show ip interface brief", f"show interfaces {canonical_iface}"],
            warnings=warnings,
        )

    def vlans(self, device_name: str, model: str, vlans: list[VlanSpec]) -> RenderedCommandSequence:
        """Generate VLAN creation commands."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.VLANS, "VLAN configuration")
        if not vlans:
            raise IOSConfigError("At least one VLAN entry is required.")

        cmds: list[str] = []
        warnings: list[str] = []
        for vlan in vlans:
            if vlan.vlan_id == 1:
                warnings.append(
                    "VLAN 1 already exists by default; only name updates apply if supported."
                )
            if 1002 <= vlan.vlan_id <= 1005:
                warnings.append(
                    f"VLAN {vlan.vlan_id} is a legacy reserved default VLAN in Cisco IOS."
                )
            cmds.append(f"vlan {vlan.vlan_id}")
            if vlan.name:
                clean_vlan_name = vlan.name.strip().replace(" ", "_")
                cmds.append(f" name {clean_vlan_name}")
            cmds.append(" exit")

        return self._finalize(
            device_name,
            profile,
            "vlans",
            cmds,
            verification_commands=["show vlan brief"],
            warnings=warnings,
        )

    def access_port(self, model: str, spec: AccessPortSpec) -> RenderedCommandSequence:
        """Generate switch access port, PortFast, BPDU Guard, and port-security commands."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.VLANS, "access port")
        iface = self.catalog.normalize_interface_name(
            profile.model, spec.interface, allow_logical=False
        )
        if iface.startswith(("Vlan", "Loopback")):
            raise IOSConfigError(f"{iface} cannot be configured as a switch access port.")

        cmds = [
            f"interface {iface}",
            *([f" description {spec.description.strip()}"] if spec.description else []),
            " switchport mode access",
            f" switchport access vlan {spec.vlan_id}",
        ]
        if spec.portfast:
            cmds.append(" spanning-tree portfast")
        if spec.bpduguard:
            cmds.append(" spanning-tree bpduguard enable")
        if spec.port_security:
            require_capability(profile, ConfigCapability.PORT_SECURITY, "port-security")
            cmds.append(" switchport port-security")
            cmds.append(f" switchport port-security maximum {spec.port_security_max}")
            if spec.port_security_sticky:
                cmds.append(" switchport port-security mac-address sticky")
            cmds.append(f" switchport port-security violation {spec.port_security_violation}")
        cmds.extend([" no shutdown", " exit"])
        return self._finalize(
            spec.device_name,
            profile,
            "access_port",
            cmds,
            verification_commands=[f"show interfaces {iface} switchport", "show vlan brief"],
        )

    def trunk_port(self, model: str, spec: TrunkPortSpec) -> RenderedCommandSequence:
        """Generate 802.1Q trunk commands tailored to 2960 vs. 3560/3650 IOS behavior."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.TRUNKING, "802.1Q trunking")
        iface = self.catalog.normalize_interface_name(profile.model, spec.interface)

        cmds = [f"interface {iface}"]
        if spec.description:
            cmds.append(f" description {spec.description.strip()}")
        if profile.supports(ConfigCapability.TRUNK_ENCAP_DOT1Q):
            cmds.append(" switchport trunk encapsulation dot1q")
        cmds.append(" switchport mode trunk")
        if spec.native_vlan is not None:
            cmds.append(f" switchport trunk native vlan {spec.native_vlan}")
        if spec.allowed_vlans:
            vlan_list = ",".join(str(v) for v in sorted(set(spec.allowed_vlans)))
            cmds.append(f" switchport trunk allowed vlan {vlan_list}")
        if spec.nonegotiate:
            cmds.append(" switchport nonegotiate")
        cmds.extend([" no shutdown", " exit"])

        return self._finalize(
            spec.device_name,
            profile,
            "trunk_port",
            cmds,
            verification_commands=["show interfaces trunk"],
        )

    def static_routes(
        self,
        device_name: str,
        model: str,
        routes: list[StaticRouteEntry],
        *,
        enable_ip_routing: bool = True,
    ) -> RenderedCommandSequence:
        """Generate IPv4/IPv6 static routes (including L3 switch 'ip routing')."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.STATIC_ROUTING, "static routing")
        if not routes:
            raise IOSConfigError("At least one static route is required.")

        cmds: list[str] = []
        if profile.category == DeviceCategory.L3_SWITCH and enable_ip_routing:
            cmds.append("ip routing")

        for route in routes:
            if route.ip_version == 6:
                require_capability(profile, ConfigCapability.IPV6, "IPv6 static routing")
                net6 = ipaddress.IPv6Network(route.destination_network.strip(), strict=False)
                line = f"ipv6 route {net6.with_prefixlen} {route.next_hop.strip()}"
            else:
                net_ip, mask = parse_ipv4_and_mask(
                    route.destination_network, route.subnet_mask_or_prefix
                )
                line = f"ip route {net_ip} {mask} {route.next_hop.strip()}"
            if route.administrative_distance is not None:
                line += f" {route.administrative_distance}"
            cmds.append(line)

        return self._finalize(
            device_name,
            profile,
            "static_routing",
            cmds,
            verification_commands=["show ip route"],
        )

    def rip(self, spec: RipConfigSpec, model: str) -> RenderedCommandSequence:
        """Generate RIPv2 commands."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.RIP, "RIPv2")
        cmds: list[str] = []
        if profile.category == DeviceCategory.L3_SWITCH:
            cmds.append("ip routing")
        cmds.extend(["router rip", " version 2"])
        if spec.no_auto_summary:
            cmds.append(" no auto-summary")
        for net_str in spec.networks:
            ip_only = net_str.split("/")[0].strip()
            ipaddress.IPv4Address(ip_only)
            cmds.append(f" network {ip_only}")
        for passive in spec.passive_interfaces:
            canon = self.catalog.normalize_interface_name(profile.model, passive)
            cmds.append(f" passive-interface {canon}")
        if spec.default_information_originate:
            cmds.append(" default-information originate")
        cmds.append(" exit")
        return self._finalize(
            spec.device_name,
            profile,
            "rip",
            cmds,
            verification_commands=["show ip protocols", "show ip route rip"],
        )

    def ospf(self, spec: OspfConfigSpec, model: str) -> RenderedCommandSequence:
        """Generate OSPFv2 configuration with validated network/wildcard/area statements."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.OSPF, "OSPFv2")
        cmds: list[str] = []
        if profile.category == DeviceCategory.L3_SWITCH:
            cmds.append("ip routing")
        cmds.append(f"router ospf {spec.process_id}")
        if spec.router_id:
            try:
                rid = ipaddress.IPv4Address(spec.router_id.strip())
            except ValueError as exc:
                raise IOSConfigError(f"Invalid OSPF router-id {spec.router_id!r}: {exc}") from exc
            cmds.append(f" router-id {rid}")
        for entry in spec.networks:
            net_ip, wildcard = to_network_and_wildcard(entry.network, entry.wildcard_mask)
            cmds.append(f" network {net_ip} {wildcard} area {entry.area}")
        for passive in spec.passive_interfaces:
            canon = self.catalog.normalize_interface_name(profile.model, passive)
            cmds.append(f" passive-interface {canon}")
        if spec.default_information_originate:
            cmds.append(" default-information originate")
        cmds.append(" exit")

        return self._finalize(
            spec.device_name,
            profile,
            "ospf",
            cmds,
            verification_commands=[
                "show ip ospf neighbor",
                "show ip ospf interface brief",
                "show ip route ospf",
            ],
        )

    def eigrp(self, spec: EigrpConfigSpec, model: str) -> RenderedCommandSequence:
        """Generate EIGRP configuration."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.EIGRP, "EIGRP")
        cmds: list[str] = []
        if profile.category == DeviceCategory.L3_SWITCH:
            cmds.append("ip routing")
        cmds.append(f"router eigrp {spec.asn}")
        if spec.no_auto_summary:
            cmds.append(" no auto-summary")
        for net_entry in spec.networks:
            if "/" in net_entry:
                net_ip, wildcard = to_network_and_wildcard(net_entry)
                cmds.append(f" network {net_ip} {wildcard}")
            else:
                ipaddress.IPv4Address(net_entry.strip())
                cmds.append(f" network {net_entry.strip()}")
        for passive in spec.passive_interfaces:
            canon = self.catalog.normalize_interface_name(profile.model, passive)
            cmds.append(f" passive-interface {canon}")
        cmds.append(" exit")
        return self._finalize(
            spec.device_name,
            profile,
            "eigrp",
            cmds,
            verification_commands=["show ip eigrp neighbors", "show ip route eigrp"],
        )

    def dhcp(self, spec: DhcpPoolSpec, model: str) -> RenderedCommandSequence:
        """Generate Cisco IOS DHCP server pool and excluded-address statements."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.DHCP_SERVER, "IOS DHCP server")
        net_ip, mask = parse_ipv4_and_mask(spec.network, spec.subnet_mask)
        ipaddress.IPv4Address(spec.default_router.strip())

        cmds: list[str] = []
        for start_ip, end_ip in spec.excluded_ranges:
            ipaddress.IPv4Address(start_ip.strip())
            ipaddress.IPv4Address(end_ip.strip())
            if start_ip.strip() == end_ip.strip():
                cmds.append(f"ip dhcp excluded-address {start_ip.strip()}")
            else:
                cmds.append(f"ip dhcp excluded-address {start_ip.strip()} {end_ip.strip()}")

        cmds.append(f"ip dhcp pool {spec.pool_name.strip()}")
        cmds.append(f" network {net_ip} {mask}")
        cmds.append(f" default-router {spec.default_router.strip()}")
        if spec.dns_server:
            ipaddress.IPv4Address(spec.dns_server.strip())
            cmds.append(f" dns-server {spec.dns_server.strip()}")
        if spec.domain_name:
            cmds.append(f" domain-name {spec.domain_name.strip()}")
        cmds.append(" exit")

        return self._finalize(
            spec.device_name,
            profile,
            "dhcp",
            cmds,
            verification_commands=["show ip dhcp binding", "show ip dhcp pool"],
        )

    def nat_pat(self, spec: NatPatSpec, model: str) -> RenderedCommandSequence:
        """Generate NAT/PAT configuration."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.NAT_PAT, "NAT/PAT")

        cmds: list[str] = []
        for iface in spec.inside_interfaces:
            canon = self.catalog.normalize_interface_name(profile.model, iface)
            cmds.extend([f"interface {canon}", " ip nat inside", " exit"])
        for iface in spec.outside_interfaces:
            canon = self.catalog.normalize_interface_name(profile.model, iface)
            cmds.extend([f"interface {canon}", " ip nat outside", " exit"])

        if spec.mode == "pat_overload":
            if not spec.source_cidrs or not spec.overload_interface:
                raise IOSConfigError("pat_overload requires source_cidrs and overload_interface.")
            for cidr in spec.source_cidrs:
                net_ip, wildcard = to_network_and_wildcard(cidr)
                cmds.append(f"access-list {spec.acl_number} permit {net_ip} {wildcard}")
            out_iface = self.catalog.normalize_interface_name(
                profile.model, spec.overload_interface
            )
            cmds.append(
                f"ip nat inside source list {spec.acl_number} interface {out_iface} overload"
            )
        elif spec.mode == "dynamic_pool":
            if not (
                spec.pool_name
                and spec.pool_start
                and spec.pool_end
                and spec.pool_netmask
                and spec.source_cidrs
            ):
                raise IOSConfigError(
                    "dynamic_pool requires pool_name, pool_start, pool_end, "
                    "pool_netmask, and source_cidrs."
                )
            for cidr in spec.source_cidrs:
                net_ip, wildcard = to_network_and_wildcard(cidr)
                cmds.append(f"access-list {spec.acl_number} permit {net_ip} {wildcard}")
            cmds.append(
                f"ip nat pool {spec.pool_name} {spec.pool_start} "
                f"{spec.pool_end} netmask {spec.pool_netmask}"
            )
            cmds.append(
                f"ip nat inside source list {spec.acl_number} pool {spec.pool_name} overload"
            )
        elif spec.mode == "static":
            if not (spec.static_inside_local and spec.static_inside_global):
                raise IOSConfigError(
                    "static NAT requires static_inside_local and static_inside_global."
                )
            ipaddress.IPv4Address(spec.static_inside_local.strip())
            ipaddress.IPv4Address(spec.static_inside_global.strip())
            cmds.append(
                f"ip nat inside source static {spec.static_inside_local.strip()} "
                f"{spec.static_inside_global.strip()}"
            )

        return self._finalize(
            spec.device_name,
            profile,
            "nat_pat",
            cmds,
            verification_commands=["show ip nat translations", "show ip nat statistics"],
        )

    def acl(self, spec: AclSpec, model: str) -> RenderedCommandSequence:
        """Generate Standard or Extended IPv4 ACLs and optional interface binding."""
        profile = self.catalog.get_profile(model)
        cap = (
            ConfigCapability.ACL_STANDARD
            if spec.acl_type == "standard"
            else ConfigCapability.ACL_EXTENDED
        )
        require_capability(profile, cap, f"{spec.acl_type} ACL")

        cmds: list[str] = [f"ip access-list {spec.acl_type} {spec.acl_identifier.strip()}"]
        for rule in spec.rules:
            src_part = (
                f"{rule.source} {rule.source_wildcard}".strip()
                if rule.source_wildcard
                else rule.source
            )
            if spec.acl_type == "standard":
                line = f" {rule.action} {src_part}"
            else:
                dst_raw = rule.destination or "any"
                dst_part = (
                    f"{dst_raw} {rule.destination_wildcard}".strip()
                    if rule.destination_wildcard
                    else dst_raw
                )
                line = f" {rule.action} {rule.protocol} {src_part} {dst_part}"
                if rule.operator and rule.port:
                    line += f" {rule.operator} {rule.port}"
            if rule.log:
                line += " log"
            cmds.append(line)
        cmds.append(" exit")

        if spec.apply_interface:
            iface = self.catalog.normalize_interface_name(profile.model, spec.apply_interface)
            cmds.extend(
                [
                    f"interface {iface}",
                    f" ip access-group {spec.acl_identifier.strip()} {spec.direction}",
                    " exit",
                ]
            )

        return self._finalize(
            spec.device_name,
            profile,
            "acl",
            cmds,
            verification_commands=["show access-lists"],
        )

    def stp(self, spec: StpSpec, model: str) -> RenderedCommandSequence:
        """Generate Spanning Tree mode and root bridge priority commands."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.STP, "Spanning Tree")
        cmds: list[str] = [f"spanning-tree mode {spec.mode}"]
        for vlan in spec.root_primary_vlans:
            cmds.append(f"spanning-tree vlan {vlan} root primary")
        for vlan in spec.root_secondary_vlans:
            cmds.append(f"spanning-tree vlan {vlan} root secondary")
        return self._finalize(
            spec.device_name,
            profile,
            "stp",
            cmds,
            verification_commands=["show spanning-tree summary"],
        )

    def etherchannel(self, spec: EtherChannelSpec, model: str) -> RenderedCommandSequence:
        """Generate LACP/PAgP/Static EtherChannel and Port-channel interface commands."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.ETHERCHANNEL, "EtherChannel")

        cmds: list[str] = []
        for member in spec.member_interfaces:
            canon = self.catalog.normalize_interface_name(
                profile.model, member, allow_logical=False
            )
            cmds.extend(
                [
                    f"interface {canon}",
                    f" channel-group {spec.group_id} mode {spec.mode}",
                    " no shutdown",
                    " exit",
                ]
            )
        po_iface = f"Port-channel{spec.group_id}"
        cmds.append(f"interface {po_iface}")
        if spec.port_mode == "trunk":
            if profile.supports(ConfigCapability.TRUNK_ENCAP_DOT1Q):
                cmds.append(" switchport trunk encapsulation dot1q")
            cmds.append(" switchport mode trunk")
            if spec.allowed_vlans:
                vlan_csv = ",".join(str(v) for v in sorted(set(spec.allowed_vlans)))
                cmds.append(f" switchport trunk allowed vlan {vlan_csv}")
        else:
            cmds.append(" switchport mode access")
            if spec.access_vlan:
                cmds.append(f" switchport access vlan {spec.access_vlan}")
        cmds.append(" exit")
        return self._finalize(
            spec.device_name,
            profile,
            "etherchannel",
            cmds,
            verification_commands=["show etherchannel summary"],
        )

    def ssh(self, spec: SshConfigSpec, model: str) -> RenderedCommandSequence:
        """Generate SSHv2 configuration (with redacted copy for audit logs)."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.SSH, "SSHv2")

        target_hostname = spec.hostname or spec.device_name
        cmds: list[str] = [
            f"hostname {target_hostname}",
            f"ip domain-name {spec.domain_name.strip()}",
            f"username {spec.username.strip()} privilege 15 secret {spec.secret}",
        ]
        if spec.enable_secret:
            cmds.append(f"enable secret {spec.enable_secret}")
        cmds.extend(
            [
                f"crypto key generate rsa modulus {spec.rsa_modulus}",
                "ip ssh version 2",
                f"line vty 0 {spec.vty_end}",
                " transport input ssh",
                " login local",
                " exit",
            ]
        )
        return self._finalize(
            spec.device_name,
            profile,
            "ssh",
            cmds,
            verification_commands=["show ip ssh"],
            warnings=["RSA key generation in Packet Tracer IOS may prompt if keys already exist."],
        )
