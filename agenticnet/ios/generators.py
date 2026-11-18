"""Structured Cisco IOS configuration generator backed by device capability profiles."""

from __future__ import annotations

import ipaddress
from typing import TypeVar

from pydantic import BaseModel

from agenticnet.core.enums import ConfigCapability, DeviceCategory
from agenticnet.core.exceptions import IOSConfigError
from agenticnet.devices import DEFAULT_CATALOG, DeviceCatalog, DeviceProfile
from agenticnet.ios.models import (
    AccessPortSpec,
    AclSpec,
    AsaBasicConfigSpec,
    BgpConfigSpec,
    BgpNetworkEntry,
    CmeVoipSpec,
    DaiConfigSpec,
    DhcpPoolSpec,
    DhcpSnoopingSpec,
    EigrpConfigSpec,
    EtherChannelSpec,
    HsrpConfigSpec,
    InterfaceConfigSpec,
    ManagementServicesSpec,
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
from agenticnet.security.validation import validate_cli_safe_text, validate_device_name

_SpecT = TypeVar("_SpecT", bound=BaseModel)


def _coerce_spec_and_model(
    first: _SpecT | dict[str, object] | str,
    second: str | _SpecT | dict[str, object],
    spec_cls: type[_SpecT],
) -> tuple[_SpecT, str]:
    """Support both (spec, model) and (model, spec) call conventions seamlessly."""
    if isinstance(first, str) and not isinstance(second, str):
        raw_spec, model_str = second, first
    elif isinstance(second, str) and not isinstance(first, str):
        raw_spec, model_str = first, second
    else:
        raise IOSConfigError(
            f"Expected one {spec_cls.__name__} specification and one device model string."
        )
    spec_obj = raw_spec if isinstance(raw_spec, spec_cls) else spec_cls.model_validate(raw_spec)
    return spec_obj, model_str


def _format_ios_acl_endpoint(endpoint: str, wildcard: str | None = None) -> str:
    """Format an IOS ACL source/destination into valid 'any', 'host <ip>', or '<net> <wildcard>'."""
    clean_ep = validate_cli_safe_text(endpoint, field_name="acl_endpoint").strip()
    if wildcard is not None and wildcard.strip():
        clean_wc = validate_cli_safe_text(wildcard, field_name="acl_wildcard").strip()
        return f"{clean_ep} {clean_wc}"
    if clean_ep.lower() == "any" or clean_ep.lower().startswith("host ") or " " in clean_ep:
        return clean_ep
    if "/" in clean_ep:
        net_ip, wc = to_network_and_wildcard(clean_ep)
        return f"host {net_ip}" if wc == "0.0.0.0" else f"{net_ip} {wc}"
    try:
        ip_obj = ipaddress.IPv4Address(clean_ep)
        return f"host {ip_obj}"
    except ValueError:
        return clean_ep


def _format_asa_acl_endpoint(endpoint: str) -> str:
    """Format an ASA ACL source/destination using ASA subnet-mask syntax (not wildcard)."""
    clean_ep = validate_cli_safe_text(endpoint, field_name="asa_acl_endpoint").strip()
    if clean_ep.lower() == "any" or clean_ep.lower().startswith("host ") or " " in clean_ep:
        return clean_ep
    if "/" in clean_ep:
        net_ip, mask_str = parse_ipv4_and_mask(clean_ep, None)
        if mask_str == "255.255.255.255":
            return f"host {net_ip}"
        net_addr = ipaddress.IPv4Network(f"{net_ip}/{mask_str}", strict=False).network_address
        return f"{net_addr} {mask_str}"
    try:
        ip_obj = ipaddress.IPv4Address(clean_ep)
        return f"host {ip_obj}"
    except ValueError:
        return clean_ep


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
        clean_name = validate_device_name(
            validate_cli_safe_text(device_name, field_name="device_name")
        )
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.HOSTNAME, "hostname")
        cmds = [f"hostname {clean_name}"]
        if disable_dns_lookup:
            cmds.append("no ip domain-lookup")
        return self._finalize(clean_name, profile, "hostname", cmds)

    def default_gateway_l2(
        self, device_name: str, model: str, gateway_ip: str
    ) -> RenderedCommandSequence:
        """Configure 'ip default-gateway' for a Layer 2 switch management plane."""
        clean_name = validate_device_name(
            validate_cli_safe_text(device_name, field_name="device_name")
        )
        clean_gw = validate_cli_safe_text(gateway_ip, field_name="gateway_ip").strip()
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.DEFAULT_GATEWAY_L2, "ip default-gateway")
        try:
            ipaddress.IPv4Address(clean_gw)
        except ValueError as exc:
            raise IOSConfigError(f"Invalid gateway IP {gateway_ip!r}: {exc}") from exc
        cmds = [f"ip default-gateway {clean_gw}"]
        return self._finalize(
            clean_name,
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

        cmds: list[str] = []
        warnings: list[str] = []

        needs_l3_routing = (
            profile.category == DeviceCategory.L3_SWITCH
            and (canonical_iface.startswith("Vlan") or spec.l3_routed_port)
            and bool(spec.ipv4_address or spec.ipv6_address or spec.dhcp_client)
        )
        if needs_l3_routing:
            cmds.append("ip routing")

        if (
            spec.ipv6_address
            and spec.enable_ipv6_routing
            and profile.category in {DeviceCategory.ROUTER, DeviceCategory.L3_SWITCH}
        ):
            cmds.append("ipv6 unicast-routing")

        cmds.append(f"interface {canonical_iface}")

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

        for helper_raw in spec.helper_addresses:
            try:
                helper_ip = ipaddress.IPv4Address(helper_raw.strip())
            except ValueError as exc:
                raise IOSConfigError(
                    f"Invalid DHCP helper IPv4 address {helper_raw!r}: {exc}"
                ) from exc
            cmds.append(f" ip helper-address {helper_ip}")

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
        clean_name = validate_device_name(
            validate_cli_safe_text(device_name, field_name="device_name")
        )
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
            clean_name,
            profile,
            "vlans",
            cmds,
            verification_commands=["show vlan brief"],
            warnings=warnings,
        )

    def access_port(self, model: str, spec: AccessPortSpec) -> RenderedCommandSequence:
        """Generate switch access port, voice VLAN, PortFast, BPDU Guard, and port-security."""
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
        if spec.voice_vlan is not None:
            cmds.append(f" switchport voice vlan {spec.voice_vlan}")
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
        """Generate IPv4/IPv6 static routes (including L3 switch 'ip routing' and IPv6 routing)."""
        clean_name = validate_device_name(
            validate_cli_safe_text(device_name, field_name="device_name")
        )
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.STATIC_ROUTING, "static routing")
        if not routes:
            raise IOSConfigError("At least one static route is required.")

        cmds: list[str] = []
        if profile.category == DeviceCategory.L3_SWITCH and enable_ip_routing:
            cmds.append("ip routing")
        if (
            any(r.ip_version == 6 for r in routes)
            and enable_ip_routing
            and profile.category in {DeviceCategory.ROUTER, DeviceCategory.L3_SWITCH}
        ):
            require_capability(profile, ConfigCapability.IPV6, "IPv6 static routing")
            cmds.append("ipv6 unicast-routing")

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

        verif = ["show ip route"]
        if any(r.ip_version == 6 for r in routes):
            verif.append("show ipv6 route")
        return self._finalize(
            clean_name,
            profile,
            "static_routing",
            cmds,
            verification_commands=verif,
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
        """Generate Cisco IOS DHCP server pool, excluded-address, and Option 150 statements."""
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
        if spec.option_150:
            raw_tftp = (
                [spec.option_150] if isinstance(spec.option_150, str) else list(spec.option_150)
            )
            validated_tftp: list[str] = []
            for tftp_ip in raw_tftp:
                try:
                    validated_tftp.append(str(ipaddress.IPv4Address(tftp_ip.strip())))
                except ValueError as exc:
                    raise IOSConfigError(
                        f"Invalid DHCP option 150 TFTP IPv4 address {tftp_ip!r}: {exc}"
                    ) from exc
            if validated_tftp:
                cmds.append(f" option 150 ip {' '.join(validated_tftp)}")
        cmds.append(" exit")

        return self._finalize(
            spec.device_name,
            profile,
            "dhcp",
            cmds,
            verification_commands=["show ip dhcp binding", "show ip dhcp pool"],
        )

    def nat_pat(self, spec: NatPatSpec, model: str) -> RenderedCommandSequence:
        """Generate NAT/PAT configuration (overload, dynamic pool, static 1:1, or port-forward)."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.NAT_PAT, "NAT/PAT")

        cmds: list[str] = []
        for iface in spec.inside_interfaces:
            canon = self.catalog.normalize_interface_name(profile.model, iface)
            cmds.extend([f"interface {canon}", " ip nat inside", " exit"])
        for iface in spec.outside_interfaces:
            canon = self.catalog.normalize_interface_name(profile.model, iface)
            cmds.extend([f"interface {canon}", " ip nat outside", " exit"])

        acl_ref = (
            spec.acl_name.strip()
            if spec.acl_name and spec.acl_name.strip()
            else str(spec.acl_number)
        )

        def _append_nat_acl(cidrs: list[str]) -> None:
            if spec.acl_name and spec.acl_name.strip():
                cmds.append(f"ip access-list standard {spec.acl_name.strip()}")
                for cidr in cidrs:
                    net_ip, wildcard = to_network_and_wildcard(cidr)
                    cmds.append(f" permit {net_ip} {wildcard}")
                cmds.append(" exit")
            elif spec.acl_number >= 100:
                for cidr in cidrs:
                    net_ip, wildcard = to_network_and_wildcard(cidr)
                    cmds.append(f"access-list {spec.acl_number} permit ip {net_ip} {wildcard} any")
            else:
                for cidr in cidrs:
                    net_ip, wildcard = to_network_and_wildcard(cidr)
                    cmds.append(f"access-list {spec.acl_number} permit {net_ip} {wildcard}")

        if spec.mode == "pat_overload":
            if not spec.source_cidrs or not spec.overload_interface:
                raise IOSConfigError("pat_overload requires source_cidrs and overload_interface.")
            _append_nat_acl(spec.source_cidrs)
            out_iface = self.catalog.normalize_interface_name(
                profile.model, spec.overload_interface
            )
            cmds.append(f"ip nat inside source list {acl_ref} interface {out_iface} overload")
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
            _append_nat_acl(spec.source_cidrs)
            cmds.append(
                f"ip nat pool {spec.pool_name} {spec.pool_start} "
                f"{spec.pool_end} netmask {spec.pool_netmask}"
            )
            suffix = " overload" if spec.overload else ""
            cmds.append(f"ip nat inside source list {acl_ref} pool {spec.pool_name}{suffix}")
        elif spec.mode == "static":
            if not (spec.static_inside_local and spec.static_inside_global):
                raise IOSConfigError(
                    "static NAT requires static_inside_local and static_inside_global."
                )
            local_ip = str(ipaddress.IPv4Address(spec.static_inside_local.strip()))
            global_ip = str(ipaddress.IPv4Address(spec.static_inside_global.strip()))
            if spec.static_protocol or spec.static_local_port or spec.static_global_port:
                if not (
                    spec.static_protocol
                    and spec.static_local_port is not None
                    and spec.static_global_port is not None
                ):
                    raise IOSConfigError(
                        "Static PAT port-forwarding requires static_protocol, "
                        "static_local_port, and static_global_port."
                    )
                cmds.append(
                    f"ip nat inside source static {spec.static_protocol} "
                    f"{local_ip} {spec.static_local_port} "
                    f"{global_ip} {spec.static_global_port}"
                )
            else:
                cmds.append(f"ip nat inside source static {local_ip} {global_ip}")

        return self._finalize(
            spec.device_name,
            profile,
            "nat_pat",
            cmds,
            verification_commands=["show ip nat translations", "show ip nat statistics"],
        )

    def acl(self, spec: AclSpec, model: str) -> RenderedCommandSequence:
        """Generate Standard or Extended IPv4 ACLs and optional interface or VTY binding."""
        profile = self.catalog.get_profile(model)
        cap = (
            ConfigCapability.ACL_STANDARD
            if spec.acl_type == "standard"
            else ConfigCapability.ACL_EXTENDED
        )
        require_capability(profile, cap, f"{spec.acl_type} ACL")

        acl_id = spec.acl_identifier.strip()
        cmds: list[str] = [f"ip access-list {spec.acl_type} {acl_id}"]
        for rule in spec.rules:
            src_part = _format_ios_acl_endpoint(rule.source, rule.source_wildcard)
            if spec.acl_type == "standard":
                line = f" {rule.action} {src_part}"
            else:
                dst_raw = rule.destination or "any"
                dst_part = _format_ios_acl_endpoint(dst_raw, rule.destination_wildcard)
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
                    f" ip access-group {acl_id} {spec.direction}",
                    " exit",
                ]
            )
        if spec.apply_vty:
            cmds.extend(
                [
                    f"line vty 0 {spec.vty_end}",
                    f" access-class {acl_id} {spec.vty_direction}",
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

    def vty_access_class(
        self,
        device_name: str,
        model: str,
        acl_identifier: str,
        *,
        vty_end: int = 15,
        direction: str = "in",
    ) -> RenderedCommandSequence:
        """Bind a standard or extended ACL to VTY management lines via 'access-class'."""
        clean_name = validate_device_name(
            validate_cli_safe_text(device_name, field_name="device_name")
        )
        clean_acl = validate_cli_safe_text(acl_identifier, field_name="acl_identifier").strip()
        if not clean_acl or any(ch.isspace() for ch in clean_acl):
            raise IOSConfigError(f"Invalid ACL identifier {acl_identifier!r}.")
        if direction not in {"in", "out"}:
            raise IOSConfigError(f"Invalid VTY direction {direction!r}; expected 'in' or 'out'.")
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.ACL_STANDARD, "VTY access-class")
        cmds = [
            f"line vty 0 {vty_end}",
            f" access-class {clean_acl} {direction}",
            " exit",
        ]
        return self._finalize(
            clean_name,
            profile,
            "vty_access_class",
            cmds,
            verification_commands=["show running-config", "show access-lists"],
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
        """Generate LACP/PAgP/Static EtherChannel (L2 trunk/access or L3 routed Port-channel)."""
        profile = self.catalog.get_profile(model)
        require_capability(profile, ConfigCapability.ETHERCHANNEL, "EtherChannel")

        if spec.port_mode == "routed" and profile.category != DeviceCategory.L3_SWITCH:
            raise IOSConfigError(
                f"Layer 3 routed EtherChannel requires an L3 switch, not '{profile.model}'."
            )

        cmds: list[str] = []
        if spec.port_mode == "routed":
            cmds.append("ip routing")

        for member in spec.member_interfaces:
            canon = self.catalog.normalize_interface_name(
                profile.model, member, allow_logical=False
            )
            cmds.append(f"interface {canon}")
            if spec.port_mode == "routed":
                cmds.append(" no switchport")
            cmds.extend(
                [
                    f" channel-group {spec.group_id} mode {spec.mode}",
                    " no shutdown",
                    " exit",
                ]
            )
        po_iface = f"Port-channel{spec.group_id}"
        cmds.append(f"interface {po_iface}")
        if spec.port_mode == "routed":
            cmds.append(" no switchport")
            if spec.ipv4_address:
                ip_str, mask_str = parse_ipv4_and_mask(spec.ipv4_address, spec.subnet_mask)
                cmds.append(f" ip address {ip_str} {mask_str}")
            cmds.append(" no shutdown")
        elif spec.port_mode == "trunk":
            if profile.supports(ConfigCapability.TRUNK_ENCAP_DOT1Q):
                cmds.append(" switchport trunk encapsulation dot1q")
            cmds.append(" switchport mode trunk")
            if spec.native_vlan is not None:
                cmds.append(f" switchport trunk native vlan {spec.native_vlan}")
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

        target_hostname = validate_device_name(spec.hostname or spec.device_name)
        clean_user = spec.username.strip()
        clean_domain = spec.domain_name.strip()
        if not clean_user or any(ch.isspace() for ch in clean_user):
            raise IOSConfigError(f"Invalid SSH username {spec.username!r}.")
        if not clean_domain or any(ch.isspace() for ch in clean_domain):
            raise IOSConfigError(f"Invalid SSH domain name {spec.domain_name!r}.")

        cmds: list[str] = [
            f"hostname {target_hostname}",
            f"ip domain-name {clean_domain}",
            f"username {clean_user} privilege 15 secret {spec.secret}",
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

    def generate_hsrp(
        self,
        spec: HsrpConfigSpec | dict[str, object] | str,
        model: str | HsrpConfigSpec | dict[str, object],
    ) -> RenderedCommandSequence:
        """Generate HSRP v1/v2 first-hop redundancy configuration."""
        hsrp_spec, model_str = _coerce_spec_and_model(spec, model, HsrpConfigSpec)
        profile = self.catalog.get_profile(model_str)
        require_capability(profile, ConfigCapability.HSRP, "HSRP")
        iface = self.catalog.normalize_interface_name(profile.model, hsrp_spec.interface)
        try:
            vip = str(ipaddress.IPv4Address(hsrp_spec.virtual_ip.strip()))
        except ValueError as exc:
            raise IOSConfigError(
                f"Invalid HSRP virtual IP {hsrp_spec.virtual_ip!r}: {exc}"
            ) from exc

        cmds: list[str] = []
        if profile.category == DeviceCategory.L3_SWITCH:
            cmds.append("ip routing")
        cmds.append(f"interface {iface}")
        if profile.category == DeviceCategory.L3_SWITCH and not iface.startswith(
            ("Vlan", "Loopback", "Port-channel")
        ):
            cmds.append(" no switchport")
        if hsrp_spec.ipv4_address:
            ip_str, mask_str = parse_ipv4_and_mask(hsrp_spec.ipv4_address, hsrp_spec.subnet_mask)
            cmds.append(f" ip address {ip_str} {mask_str}")
        if hsrp_spec.version == 2:
            cmds.append(" standby version 2")
        cmds.append(f" standby {hsrp_spec.group_id} ip {vip}")
        if hsrp_spec.priority is not None:
            cmds.append(f" standby {hsrp_spec.group_id} priority {hsrp_spec.priority}")
        if hsrp_spec.preempt:
            cmds.append(f" standby {hsrp_spec.group_id} preempt")
        if hsrp_spec.track_interface:
            track_if = self.catalog.normalize_interface_name(
                profile.model, hsrp_spec.track_interface, allow_logical=False
            )
            cmds.append(f" standby {hsrp_spec.group_id} track {track_if} {hsrp_spec.decrement}")
        cmds.extend([" no shutdown", " exit"])
        return self._finalize(
            hsrp_spec.device_name,
            profile,
            "hsrp",
            cmds,
            verification_commands=["show standby brief", "show standby"],
        )

    def generate_bgp(
        self,
        spec: BgpConfigSpec | dict[str, object] | str,
        model: str | BgpConfigSpec | dict[str, object],
    ) -> RenderedCommandSequence:
        """Generate BGP-4 eBGP/iBGP autonomous system configuration."""
        bgp_spec, model_str = _coerce_spec_and_model(spec, model, BgpConfigSpec)
        profile = self.catalog.get_profile(model_str)
        require_capability(profile, ConfigCapability.BGP, "BGP")

        cmds: list[str] = []
        if profile.category == DeviceCategory.L3_SWITCH:
            cmds.append("ip routing")
        cmds.append(f"router bgp {bgp_spec.local_as}")
        if bgp_spec.router_id:
            try:
                rid = ipaddress.IPv4Address(bgp_spec.router_id.strip())
            except ValueError as exc:
                raise IOSConfigError(
                    f"Invalid BGP router-id {bgp_spec.router_id!r}: {exc}"
                ) from exc
            cmds.append(f" bgp router-id {rid}")
        cmds.append(" bgp log-neighbor-changes")

        for nbr in bgp_spec.neighbors:
            try:
                peer_ip = str(ipaddress.IPv4Address(nbr.peer_ip.strip()))
            except ValueError as exc:
                raise IOSConfigError(f"Invalid BGP neighbor IP {nbr.peer_ip!r}: {exc}") from exc
            cmds.append(f" neighbor {peer_ip} remote-as {nbr.remote_as}")
            if nbr.description:
                cmds.append(f" neighbor {peer_ip} description {nbr.description.strip()}")
            if nbr.update_source:
                src_if = self.catalog.normalize_interface_name(profile.model, nbr.update_source)
                cmds.append(f" neighbor {peer_ip} update-source {src_if}")
            if nbr.next_hop_self:
                cmds.append(f" neighbor {peer_ip} next-hop-self")

        for net in bgp_spec.networks:
            if isinstance(net, BgpNetworkEntry):
                ip_str, mask_str = parse_ipv4_and_mask(net.network, net.subnet_mask)
            else:
                ip_str, mask_str = parse_ipv4_and_mask(net, None)
            net_addr = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False).network_address
            cmds.append(f" network {net_addr} mask {mask_str}")

        cmds.append(" exit")
        return self._finalize(
            bgp_spec.device_name,
            profile,
            "bgp",
            cmds,
            verification_commands=["show ip bgp summary", "show ip bgp", "show ip route bgp"],
        )

    def generate_dhcp_snooping(
        self,
        spec: DhcpSnoopingSpec | dict[str, object] | str,
        model: str | DhcpSnoopingSpec | dict[str, object],
    ) -> RenderedCommandSequence:
        """Generate Layer 2 DHCP Snooping global, VLAN, trust, and rate-limit configuration."""
        snoop_spec, model_str = _coerce_spec_and_model(spec, model, DhcpSnoopingSpec)
        profile = self.catalog.get_profile(model_str)
        require_capability(profile, ConfigCapability.DHCP_SNOOPING, "DHCP Snooping")

        for vid in snoop_spec.vlans:
            if not (1 <= vid <= 4094):
                raise IOSConfigError(f"Invalid VLAN ID {vid} for DHCP Snooping (must be 1..4094).")
        vlan_csv = ",".join(str(v) for v in sorted(set(snoop_spec.vlans)))

        cmds: list[str] = ["ip dhcp snooping", f"ip dhcp snooping vlan {vlan_csv}"]
        if snoop_spec.disable_option_82:
            cmds.append("no ip dhcp snooping information option")

        for t_if in snoop_spec.trusted_interfaces:
            canon = self.catalog.normalize_interface_name(profile.model, t_if)
            cmds.extend([f"interface {canon}", " ip dhcp snooping trust", " exit"])

        for rl_if, pps in snoop_spec.rate_limit_interfaces.items():
            if not (1 <= pps <= 2048):
                raise IOSConfigError(
                    f"Invalid DHCP snooping rate limit {pps} on {rl_if!r} (expected 1..2048 pps)."
                )
            canon = self.catalog.normalize_interface_name(profile.model, rl_if)
            cmds.extend([f"interface {canon}", f" ip dhcp snooping limit rate {pps}", " exit"])

        return self._finalize(
            snoop_spec.device_name,
            profile,
            "dhcp_snooping",
            cmds,
            verification_commands=["show ip dhcp snooping", "show ip dhcp snooping binding"],
        )

    def generate_dai(
        self,
        spec: DaiConfigSpec | dict[str, object] | str,
        model: str | DaiConfigSpec | dict[str, object],
    ) -> RenderedCommandSequence:
        """Generate Layer 2 Dynamic ARP Inspection (DAI) configuration."""
        dai_spec, model_str = _coerce_spec_and_model(spec, model, DaiConfigSpec)
        profile = self.catalog.get_profile(model_str)
        require_capability(profile, ConfigCapability.DAI, "Dynamic ARP Inspection")

        for vid in dai_spec.vlans:
            if not (1 <= vid <= 4094):
                raise IOSConfigError(f"Invalid VLAN ID {vid} for DAI (must be 1..4094).")
        vlan_csv = ",".join(str(v) for v in sorted(set(dai_spec.vlans)))

        cmds: list[str] = [f"ip arp inspection vlan {vlan_csv}"]
        validations: list[str] = []
        if dai_spec.validate_src_mac:
            validations.append("src-mac")
        if dai_spec.validate_dst_mac:
            validations.append("dst-mac")
        if dai_spec.validate_ip:
            validations.append("ip")
        if validations:
            cmds.append(f"ip arp inspection validate {' '.join(validations)}")

        for t_if in dai_spec.trusted_interfaces:
            canon = self.catalog.normalize_interface_name(profile.model, t_if)
            cmds.extend([f"interface {canon}", " ip arp inspection trust", " exit"])

        return self._finalize(
            dai_spec.device_name,
            profile,
            "dai",
            cmds,
            verification_commands=["show ip arp inspection", "show ip arp inspection interfaces"],
        )

    def generate_management_services(
        self,
        spec: ManagementServicesSpec | dict[str, object] | str,
        model: str | ManagementServicesSpec | dict[str, object],
    ) -> RenderedCommandSequence:
        """Generate NTP, Syslog, SNMP, and AAA RADIUS/TACACS+ management configuration."""
        mgmt_spec, model_str = _coerce_spec_and_model(spec, model, ManagementServicesSpec)
        profile = self.catalog.get_profile(model_str)
        require_capability(profile, ConfigCapability.IOS_CLI, "management services")

        has_ntp = bool(mgmt_spec.ntp_servers or mgmt_spec.ntp_master_stratum is not None)
        has_syslog = bool(mgmt_spec.syslog_servers)
        has_snmp = bool(
            mgmt_spec.snmp_ro_community
            or mgmt_spec.snmp_rw_community
            or mgmt_spec.snmp_location
            or mgmt_spec.snmp_contact
        )
        has_aaa = bool(
            mgmt_spec.aaa_new_model or mgmt_spec.radius_server_ip or mgmt_spec.tacacs_server_ip
        )

        if has_ntp:
            require_capability(profile, ConfigCapability.NTP, "NTP")
        if has_syslog:
            require_capability(profile, ConfigCapability.SYSLOG, "Syslog")
        if has_snmp:
            require_capability(profile, ConfigCapability.SNMP, "SNMP")
        if has_aaa:
            require_capability(profile, ConfigCapability.AAA, "AAA")

        cmds: list[str] = []
        verif: list[str] = []

        if mgmt_spec.service_timestamps and (has_ntp or has_syslog):
            cmds.append("service timestamps log datetime msec")

        for ntp_raw in mgmt_spec.ntp_servers:
            try:
                ntp_ip = ipaddress.IPv4Address(ntp_raw.strip())
            except ValueError as exc:
                raise IOSConfigError(f"Invalid NTP server IP {ntp_raw!r}: {exc}") from exc
            cmds.append(f"ntp server {ntp_ip}")
        if mgmt_spec.ntp_master_stratum is not None:
            cmds.append(f"ntp master {mgmt_spec.ntp_master_stratum}")
        if has_ntp:
            verif.append("show ntp associations")

        for log_raw in mgmt_spec.syslog_servers:
            try:
                log_ip = ipaddress.IPv4Address(log_raw.strip())
            except ValueError as exc:
                raise IOSConfigError(f"Invalid Syslog server IP {log_raw!r}: {exc}") from exc
            cmds.append(f"logging host {log_ip}")
        if has_syslog and mgmt_spec.logging_trap:
            cmds.append(f"logging trap {mgmt_spec.logging_trap.strip()}")
        if has_syslog:
            verif.append("show logging")

        if mgmt_spec.snmp_ro_community:
            ro_comm = mgmt_spec.snmp_ro_community.strip()
            if not ro_comm or any(ch.isspace() for ch in ro_comm):
                raise IOSConfigError("SNMP RO community must be a single non-empty token.")
            cmds.append(f"snmp-server community {ro_comm} RO")
        if mgmt_spec.snmp_rw_community:
            rw_comm = mgmt_spec.snmp_rw_community.strip()
            if not rw_comm or any(ch.isspace() for ch in rw_comm):
                raise IOSConfigError("SNMP RW community must be a single non-empty token.")
            cmds.append(f"snmp-server community {rw_comm} RW")
        if mgmt_spec.snmp_location:
            cmds.append(f"snmp-server location {mgmt_spec.snmp_location.strip()}")
        if mgmt_spec.snmp_contact:
            cmds.append(f"snmp-server contact {mgmt_spec.snmp_contact.strip()}")
        if has_snmp:
            verif.append("show snmp")

        if has_aaa:
            cmds.append("aaa new-model")
            groups: list[str] = []
            if mgmt_spec.radius_server_ip:
                try:
                    rad_ip = ipaddress.IPv4Address(mgmt_spec.radius_server_ip.strip())
                except ValueError as exc:
                    raise IOSConfigError(
                        f"Invalid RADIUS server IP {mgmt_spec.radius_server_ip!r}: {exc}"
                    ) from exc
                if mgmt_spec.radius_key:
                    rkey = mgmt_spec.radius_key.strip()
                    if any(ch.isspace() for ch in rkey):
                        raise IOSConfigError("RADIUS key must not contain spaces.")
                    cmds.append(f"radius-server host {rad_ip} key {rkey}")
                else:
                    cmds.append(f"radius-server host {rad_ip}")
                groups.append("group radius")
            if mgmt_spec.tacacs_server_ip:
                try:
                    tac_ip = ipaddress.IPv4Address(mgmt_spec.tacacs_server_ip.strip())
                except ValueError as exc:
                    raise IOSConfigError(
                        f"Invalid TACACS+ server IP {mgmt_spec.tacacs_server_ip!r}: {exc}"
                    ) from exc
                if mgmt_spec.tacacs_key:
                    tkey = mgmt_spec.tacacs_key.strip()
                    if any(ch.isspace() for ch in tkey):
                        raise IOSConfigError("TACACS+ key must not contain spaces.")
                    cmds.append(f"tacacs-server host {tac_ip} key {tkey}")
                else:
                    cmds.append(f"tacacs-server host {tac_ip}")
                groups.append("group tacacs+")
            if mgmt_spec.local_fallback:
                groups.append("local")
            method_list = " ".join(groups) if groups else "local"
            cmds.append(f"aaa authentication login default {method_list}")
            verif.append("show running-config")

        if not cmds:
            raise IOSConfigError(
                "ManagementServicesSpec requires at least one NTP, Syslog, SNMP, or AAA setting."
            )

        return self._finalize(
            mgmt_spec.device_name,
            profile,
            "management_services",
            cmds,
            verification_commands=verif,
        )

    def generate_cme_voip(
        self,
        spec: CmeVoipSpec | dict[str, object] | str,
        model: str | CmeVoipSpec | dict[str, object],
    ) -> RenderedCommandSequence:
        """Generate Cisco CallManager Express (CME) SCCP telephony configuration."""
        voip_spec, model_str = _coerce_spec_and_model(spec, model, CmeVoipSpec)
        profile = self.catalog.get_profile(model_str)
        require_capability(profile, ConfigCapability.IOS_CLI, "CallManager Express VoIP")
        if profile.category != DeviceCategory.ROUTER:
            raise IOSConfigError(
                f"CallManager Express telephony-service requires a router, not '{profile.model}'."
            )
        try:
            src_ip = str(ipaddress.IPv4Address(voip_spec.source_address.strip()))
        except ValueError as exc:
            raise IOSConfigError(
                f"Invalid CME source IPv4 address {voip_spec.source_address!r}: {exc}"
            ) from exc

        warnings: list[str] = []
        if profile.model != "2811":
            warnings.append(
                f"In Packet Tracer 8.2.2, Cisco 2811 is the primary router with native "
                f"'telephony-service' support ('{profile.model}' may lack CME IOS image support)."
            )

        cmds: list[str] = [
            "telephony-service",
            f" max-ephones {voip_spec.max_ephones}",
            f" max-dn {voip_spec.max_dn}",
            f" ip source-address {src_ip} port {voip_spec.source_port}",
        ]
        if voip_spec.auto_assign_end is not None:
            cmds.append(f" auto assign 1 to {voip_spec.auto_assign_end}")
        if not voip_spec.auto_reg_ephone:
            cmds.append(" no auto-reg-ephone")
        if voip_spec.create_cnf_files:
            cmds.append(" create cnf-files")
        cmds.append(" exit")

        for dn in voip_spec.dns:
            cmds.extend(
                [
                    f"ephone-dn {dn.dn_id}",
                    f" number {dn.number.strip()}",
                    *([f" label {dn.label.strip()}"] if dn.label else []),
                    " exit",
                ]
            )
        for ep in voip_spec.ephones:
            cmds.append(f"ephone {ep.ephone_id}")
            if ep.mac_address:
                cmds.append(f" mac-address {ep.mac_address.strip()}")
            cmds.extend(
                [
                    f" type {ep.phone_type.strip()}",
                    f" button {ep.button_mapping.strip()}",
                    " exit",
                ]
            )

        return self._finalize(
            voip_spec.device_name,
            profile,
            "cme_voip",
            cmds,
            verification_commands=["show ephone", "show ephone-dn"],
            warnings=warnings,
        )

    def generate_asa_basic(
        self,
        spec: AsaBasicConfigSpec | dict[str, object] | str,
        model: str | AsaBasicConfigSpec | dict[str, object],
    ) -> RenderedCommandSequence:
        """Generate Cisco ASA 5505 (VLAN SVI) or ASA 5506-X (routed port) firewall configuration."""
        asa_spec, model_str = _coerce_spec_and_model(spec, model, AsaBasicConfigSpec)
        profile = self.catalog.get_profile(model_str)
        if not profile.supports(ConfigCapability.ASA_FIREWALL):
            raise IOSConfigError(
                f"Device '{profile.display_name}' ({profile.model}) is not an ASA firewall.",
                details={"model": profile.model, "capability": ConfigCapability.ASA_FIREWALL.value},
                remediation="Select Cisco ASA 5505 or ASA 5506-X for ASA firewall configuration.",
            )

        cmds: list[str] = []
        if asa_spec.hostname:
            cmds.append(f"hostname {validate_device_name(asa_spec.hostname)}")

        for zone in asa_spec.interfaces:
            ip_str, mask_str = parse_ipv4_and_mask(zone.ip_address, zone.subnet_mask)
            nameif = zone.nameif.strip()
            if not nameif or any(ch.isspace() for ch in nameif):
                raise IOSConfigError(f"Invalid ASA nameif {zone.nameif!r}.")

            if profile.supports_svi:
                # ASA 5505 switchport + VLAN SVI architecture
                if zone.interface.strip().lower().startswith("vl"):
                    svi_name = self.catalog.normalize_interface_name(profile.model, zone.interface)
                else:
                    phys = self.catalog.normalize_interface_name(
                        profile.model, zone.interface, allow_logical=False
                    )
                    vid = zone.vlan_id or (1 if nameif.lower() == "inside" else 2)
                    cmds.extend(
                        [
                            f"interface {phys}",
                            f" switchport access vlan {vid}",
                            " no shutdown",
                            " exit",
                        ]
                    )
                    svi_name = f"Vlan{vid}"
                cmds.extend(
                    [
                        f"interface {svi_name}",
                        f" nameif {nameif}",
                        f" security-level {zone.security_level}",
                        f" ip address {ip_str} {mask_str}",
                        " no shutdown",
                        " exit",
                    ]
                )
            else:
                # ASA 5506-X routed GigabitEthernet1/1..8 (or subinterface) architecture
                phys = self.catalog.normalize_interface_name(profile.model, zone.interface)
                cmds.append(f"interface {phys}")
                if "." in phys:
                    sub_vid = zone.vlan_id or int(phys.split(".")[1])
                    cmds.append(f" vlan {sub_vid}")
                cmds.extend(
                    [
                        f" nameif {nameif}",
                        f" security-level {zone.security_level}",
                        f" ip address {ip_str} {mask_str}",
                        " no shutdown",
                        " exit",
                    ]
                )

        for rt in asa_spec.routes:
            dst_ip, dst_mask = parse_ipv4_and_mask(rt.destination, rt.netmask)
            dst_net = ipaddress.IPv4Network(f"{dst_ip}/{dst_mask}", strict=False).network_address
            try:
                nh_ip = ipaddress.IPv4Address(rt.next_hop.strip())
            except ValueError as exc:
                raise IOSConfigError(f"Invalid ASA route next-hop {rt.next_hop!r}: {exc}") from exc
            cmds.append(f"route {rt.interface_nameif.strip()} {dst_net} {dst_mask} {nh_ip}")

        for nat_obj in asa_spec.object_nats:
            sub_ip, sub_mask = parse_ipv4_and_mask(nat_obj.subnet, nat_obj.netmask)
            net_addr = ipaddress.IPv4Network(f"{sub_ip}/{sub_mask}", strict=False).network_address
            in_z = nat_obj.inside_nameif.strip()
            out_z = nat_obj.outside_nameif.strip()
            cmds.extend(
                [
                    f"object network {nat_obj.object_name.strip()}",
                    f" subnet {net_addr} {sub_mask}",
                    f" nat ({in_z},{out_z}) dynamic interface",
                    " exit",
                ]
            )

        bound_groups: set[tuple[str, str, str]] = set()
        for rule in asa_spec.acl_rules:
            acl_name = rule.acl_name.strip()
            src_asa = _format_asa_acl_endpoint(rule.source)
            dst_asa = _format_asa_acl_endpoint(rule.destination)
            line = (
                f"access-list {acl_name} extended {rule.action} "
                f"{rule.protocol.strip()} {src_asa} {dst_asa}"
            )
            if rule.eq_port:
                line += f" eq {rule.eq_port.strip()}"
            cmds.append(line)
            if rule.apply_nameif:
                grp_key = (acl_name, rule.direction, rule.apply_nameif.strip())
                if grp_key not in bound_groups:
                    bound_groups.add(grp_key)
                    cmds.append(f"access-group {grp_key[0]} {grp_key[1]} interface {grp_key[2]}")

        return self._finalize(
            asa_spec.device_name,
            profile,
            "asa_basic",
            cmds,
            verification_commands=[
                "show interface ip brief",
                "show route",
                "show nat",
                "show access-list",
            ],
        )
