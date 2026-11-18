"""MCP tools for Cisco IOS config generation, validation, backup, and diff."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, Field

from agenticnet.adapters.router import transport_to_execution_backend
from agenticnet.core.enums import PermissionTier, StateLevel
from agenticnet.core.exceptions import ValidationError
from agenticnet.core.models import ExecutionBackend, OperationResult
from agenticnet.ios.models import (
    AccessPortSpec,
    AclRule,
    AclSpec,
    AsaAclRule,
    AsaBasicConfigSpec,
    AsaInterfaceZoneSpec,
    AsaObjectNatSpec,
    AsaRouteEntry,
    BgpConfigSpec,
    BgpNeighborEntry,
    BgpNetworkEntry,
    CmeVoipSpec,
    DaiConfigSpec,
    DhcpPoolSpec,
    DhcpSnoopingSpec,
    EigrpConfigSpec,
    EphoneDnEntry,
    EphoneEntry,
    EtherChannelSpec,
    HsrpConfigSpec,
    InterfaceConfigSpec,
    ManagementServicesSpec,
    NatPatSpec,
    OspfConfigSpec,
    OspfNetworkEntry,
    RenderedCommandSequence,
    RipConfigSpec,
    SshConfigSpec,
    StaticRouteEntry,
    StpSpec,
    TrunkPortSpec,
    VlanSpec,
)
from agenticnet.ios.validators import parse_cli_output, validate_pre_apply, validate_raw_commands
from agenticnet.mcp.registry import AgenticNetRuntime


class AccessPortAssignment(BaseModel):
    """Access port assignment paired with configure_vlan."""

    interface: str
    vlan_id: int = Field(ge=1, le=4094)
    description: str | None = None
    portfast: bool = True
    bpduguard: bool = False
    port_security: bool = False


def _resolve_topo_device_name(runtime: AgenticNetRuntime, device_name: str) -> str:
    """Resolve a device name or IOS hostname alias against the active TopologyEngine."""
    _, topo, _, _ = runtime.manager.require_active()
    if device_name in topo.model.devices:
        return device_name
    mapped = runtime.router.resolve_pt_device_name(device_name)
    if mapped in topo.model.devices:
        return mapped
    for cand_name, node in topo.model.devices.items():
        if node.metadata.get("hostname") == device_name or node.role == device_name:
            return cand_name
    return device_name


def register_ios_tools(server: MCPServer, runtime: AgenticNetRuntime) -> None:
    """Register configure_*, configuration_*, and command_validate tools onto MCPServer."""

    def _record_and_format(
        tool_name: str,
        seq: RenderedCommandSequence,
        *,
        record_snapshot: bool = True,
        apply: bool = False,
    ) -> OperationResult:
        pre_apply_payload: dict[str, Any] | None = None
        if apply:
            ipam_active = None
            if runtime.manager.has_active_project:
                _, _, ipam_active, _ = runtime.manager.require_active()
            raw_pre = validate_pre_apply(
                seq.device_model,
                seq.commands,
                device_name=seq.device_name,
                ipam=ipam_active,
                catalog=runtime.catalog,
                raise_on_error=True,
            )
            pre_apply_payload = {
                **raw_pre,
                "diagnostics": [d.model_dump(mode="json") for d in raw_pre["diagnostics"]],
            }

        snap_id: str | None = None
        if record_snapshot and runtime.manager.has_active_project:
            snap_id = runtime.manager.record_generated_sequence(seq)

        data: dict[str, Any] = {
            "device_name": seq.device_name,
            "device_model": seq.device_model,
            "feature": seq.feature,
            "commands": seq.commands,
            "commands_redacted": seq.commands_redacted,
            "verification_commands": seq.verification_commands,
            "snapshot_id": snap_id,
        }
        warnings = list(seq.warnings)
        evidence = [
            f"Validated '{seq.feature}' against DeviceCatalog profile '{seq.device_model}'.",
            *([f"Recorded redacted PLANNED snapshot '{snap_id}'."] if snap_id else []),
        ]
        lvl = StateLevel.PLANNED
        backend: ExecutionBackend = "offline_model"
        summary = (
            f"Generated {seq.feature} IOS commands for '{seq.device_name}' ({seq.device_model})."
        )

        if apply:
            data["pre_apply_validation"] = pre_apply_payload
            if runtime.console.transport.is_available():
                exec_rep = runtime.console.execute_commands(
                    seq.device_name,
                    seq.commands,
                    model=seq.device_model,
                    target_mode="global_config",
                    stop_on_error=True,
                )
                data["applied"] = True
                data["execution_report"] = exec_rep
                backend = transport_to_execution_backend(runtime.console.transport.transport_name)
                lvl = StateLevel(exec_rep.get("state_level", StateLevel.EXECUTED.value))
                evidence.extend(exec_rep.get("evidence", []))
                warnings.extend(exec_rep.get("warnings", []))
                summary = (
                    f"Generated and applied {seq.feature} commands on '{seq.device_name}' "
                    f"({seq.device_model}) via {backend}."
                )
            else:
                data["applied"] = False
                warnings.append(
                    "Console transport is offline; pre-apply validation passed and "
                    "commands remain PLANNED."
                )

        return OperationResult.ok(
            tool_name,
            summary,
            data=data,
            state_level=lvl,
            execution_backend=backend,
            warnings=warnings,
            evidence=evidence,
        )

    def configure_interface(
        device_name: str,
        interface: str,
        ipv4_address: str | None = None,
        subnet_mask: str | None = None,
        ipv6_address: str | None = None,
        dhcp_client: bool = False,
        description: str | None = None,
        admin_up: bool = True,
        dot1q_vlan: int | None = None,
        native_vlan: bool = False,
        l3_routed_port: bool = False,
        clock_rate: int | None = None,
        nat_role: Literal["inside", "outside"] | None = None,
        sync_ipam: bool = True,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate Cisco IOS interface, SVI, loopback, or 802.1Q subinterface config."""
        params = {
            "device_name": device_name,
            "interface": interface,
            "ipv4_address": ipv4_address,
            "subnet_mask": subnet_mask,
            "ipv6_address": ipv6_address,
            "dhcp_client": dhcp_client,
            "admin_up": admin_up,
            "dot1q_vlan": dot1q_vlan,
            "l3_routed_port": l3_routed_port,
            "nat_role": nat_role,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, ipam, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            spec = InterfaceConfigSpec(
                device_name=dev.name,
                interface=interface,
                ipv4_address=ipv4_address,
                subnet_mask=subnet_mask,
                ipv6_address=ipv6_address,
                dhcp_client=dhcp_client,
                description=description,
                admin_up=admin_up,
                dot1q_vlan=dot1q_vlan,
                native_vlan=native_vlan,
                l3_routed_port=l3_routed_port,
                clock_rate=clock_rate,
                nat_role=nat_role,
            )
            seq = runtime.ios.interface(dev.model, spec)
            if apply:
                validate_pre_apply(
                    dev.model,
                    seq.commands,
                    device_name=dev.name,
                    ipam=ipam,
                    catalog=runtime.catalog,
                    raise_on_error=True,
                )
            canon = runtime.catalog.normalize_interface_name(dev.model, interface)
            if sync_ipam and ipv4_address:
                alloc = ipam.allocate_address(
                    dev.name,
                    canon,
                    ipv4_address,
                    subnet_mask=subnet_mask,
                    vlan_id=dot1q_vlan,
                    allocation_type="svi"
                    if canon.startswith("Vlan")
                    else ("loopback" if canon.startswith("Loopback") else "static"),
                )
                if canon in dev.interfaces:
                    dev.interfaces[canon].ip_address = alloc.ip_address
                    dev.interfaces[canon].subnet_mask = alloc.subnet_mask
            if canon in dev.interfaces:
                dev.interfaces[canon].admin_up = admin_up
                if description is not None:
                    dev.interfaces[canon].description = description
            return _record_and_format("configure_interface", seq, apply=apply)

        return runtime.execute("configure_interface", PermissionTier.CONFIGURATION, params, _run)

    def configure_vlan(
        device_name: str,
        vlans: list[VlanSpec] = Field(default_factory=list),
        access_ports: list[AccessPortAssignment] = Field(default_factory=list),
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate validated VLAN definitions and optional switch access-port assignments."""
        params = {
            "device_name": device_name,
            "vlan_count": len(vlans),
            "access_port_count": len(access_ports),
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            if not vlans and not access_ports:
                raise ValidationError("Provide at least one VLAN or access_port entry.")

            all_cmds: list[str] = []
            all_verifs: list[str] = []
            warnings: list[str] = []

            if vlans:
                v_seq = runtime.ios.vlans(dev.name, dev.model, vlans)
                all_cmds.extend(v_seq.commands)
                all_verifs.extend(v_seq.verification_commands)
                warnings.extend(v_seq.warnings)

            for ap in access_ports:
                ap_seq = runtime.ios.access_port(
                    dev.model,
                    AccessPortSpec(
                        device_name=dev.name,
                        interface=ap.interface,
                        vlan_id=ap.vlan_id,
                        description=ap.description,
                        portfast=ap.portfast,
                        bpduguard=ap.bpduguard,
                        port_security=ap.port_security,
                    ),
                )
                all_cmds.extend(ap_seq.commands)
                for v in ap_seq.verification_commands:
                    if v not in all_verifs:
                        all_verifs.append(v)
                canon = runtime.catalog.normalize_interface_name(dev.model, ap.interface)
                if canon in dev.interfaces:
                    dev.interfaces[canon].vlan_mode = "access"
                    dev.interfaces[canon].is_trunk = False
                    dev.interfaces[canon].access_vlan = ap.vlan_id

            combined = RenderedCommandSequence(
                device_name=dev.name,
                device_model=dev.model,
                feature="vlan_and_access_ports",
                commands=all_cmds,
                commands_redacted=all_cmds,
                verification_commands=all_verifs,
                warnings=warnings,
            )
            return _record_and_format("configure_vlan", combined, apply=apply)

        return runtime.execute("configure_vlan", PermissionTier.CONFIGURATION, params, _run)

    def configure_trunk(
        device_name: str,
        interface: str,
        allowed_vlans: list[int] | None = None,
        native_vlan: int | None = None,
        nonegotiate: bool = False,
        description: str | None = None,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate 802.1Q trunk config tailored to switch model (2960 vs. 3560/3650)."""
        params = {
            "device_name": device_name,
            "interface": interface,
            "allowed_vlans": allowed_vlans,
            "native_vlan": native_vlan,
            "nonegotiate": nonegotiate,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.trunk_port(
                dev.model,
                TrunkPortSpec(
                    device_name=dev.name,
                    interface=interface,
                    allowed_vlans=allowed_vlans,
                    native_vlan=native_vlan,
                    nonegotiate=nonegotiate,
                    description=description,
                ),
            )
            canon = runtime.catalog.normalize_interface_name(dev.model, interface)
            if canon in dev.interfaces:
                dev.interfaces[canon].vlan_mode = "trunk"
                dev.interfaces[canon].is_trunk = True
                if native_vlan is not None:
                    dev.interfaces[canon].native_vlan = native_vlan
                if allowed_vlans:
                    dev.interfaces[canon].trunk_allowed_vlans = ",".join(
                        str(v) for v in sorted(set(allowed_vlans))
                    )
            return _record_and_format("configure_trunk", seq, apply=apply)

        return runtime.execute("configure_trunk", PermissionTier.CONFIGURATION, params, _run)

    def configure_routing(
        device_name: str,
        mode: Literal["static", "rip", "default_gateway_l2"] = "static",
        static_routes: list[StaticRouteEntry] = Field(default_factory=list),
        rip_networks: list[str] = Field(default_factory=list),
        passive_interfaces: list[str] = Field(default_factory=list),
        default_information_originate: bool = False,
        default_gateway_ip: str | None = None,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate static routes, RIPv2 routing, or L2 switch ip default-gateway commands."""
        params = {
            "device_name": device_name,
            "mode": mode,
            "static_route_count": len(static_routes),
            "rip_network_count": len(rip_networks),
            "default_gateway_ip": default_gateway_ip,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            if mode == "default_gateway_l2":
                if not default_gateway_ip:
                    raise ValidationError(
                        "default_gateway_ip is required for mode='default_gateway_l2'."
                    )
                seq = runtime.ios.default_gateway_l2(dev.name, dev.model, default_gateway_ip)
            elif mode == "rip":
                seq = runtime.ios.rip(
                    RipConfigSpec(
                        device_name=dev.name,
                        networks=rip_networks,
                        passive_interfaces=passive_interfaces,
                        default_information_originate=default_information_originate,
                    ),
                    dev.model,
                )
            else:
                seq = runtime.ios.static_routes(dev.name, dev.model, static_routes)
            return _record_and_format("configure_routing", seq, apply=apply)

        return runtime.execute("configure_routing", PermissionTier.CONFIGURATION, params, _run)

    def configure_ospf(
        device_name: str,
        networks: list[OspfNetworkEntry],
        process_id: int = 1,
        router_id: str | None = None,
        passive_interfaces: list[str] = Field(default_factory=list),
        default_information_originate: bool = False,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate validated OSPFv2 router configuration."""
        params = {
            "device_name": device_name,
            "process_id": process_id,
            "router_id": router_id,
            "network_count": len(networks),
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.ospf(
                OspfConfigSpec(
                    device_name=dev.name,
                    process_id=process_id,
                    router_id=router_id,
                    networks=networks,
                    passive_interfaces=passive_interfaces,
                    default_information_originate=default_information_originate,
                ),
                dev.model,
            )
            return _record_and_format("configure_ospf", seq, apply=apply)

        return runtime.execute("configure_ospf", PermissionTier.CONFIGURATION, params, _run)

    def configure_eigrp(
        device_name: str,
        asn: int,
        networks: list[str],
        passive_interfaces: list[str] = Field(default_factory=list),
        no_auto_summary: bool = True,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate validated EIGRP routing configuration."""
        params = {
            "device_name": device_name,
            "asn": asn,
            "network_count": len(networks),
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.eigrp(
                EigrpConfigSpec(
                    device_name=dev.name,
                    asn=asn,
                    networks=networks,
                    passive_interfaces=passive_interfaces,
                    no_auto_summary=no_auto_summary,
                ),
                dev.model,
            )
            return _record_and_format("configure_eigrp", seq, apply=apply)

        return runtime.execute("configure_eigrp", PermissionTier.CONFIGURATION, params, _run)

    def configure_dhcp(
        device_name: str,
        pool_name: str,
        network: str,
        default_router: str,
        subnet_mask: str | None = None,
        dns_server: str | None = None,
        domain_name: str | None = None,
        excluded_ranges: list[list[str]] = Field(default_factory=list),
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate validated Cisco IOS DHCP server pool and excluded addresses."""
        params = {
            "device_name": device_name,
            "pool_name": pool_name,
            "network": network,
            "default_router": default_router,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            normalized_ranges: list[tuple[str, str]] = []
            for pair in excluded_ranges:
                if len(pair) == 1:
                    normalized_ranges.append((pair[0], pair[0]))
                elif len(pair) == 2:
                    normalized_ranges.append((pair[0], pair[1]))
                else:
                    raise ValidationError(
                        "Each excluded_range entry must have 1 or 2 IP addresses."
                    )

            seq = runtime.ios.dhcp(
                DhcpPoolSpec(
                    device_name=dev.name,
                    pool_name=pool_name,
                    network=network,
                    subnet_mask=subnet_mask,
                    default_router=default_router,
                    dns_server=dns_server,
                    domain_name=domain_name,
                    excluded_ranges=normalized_ranges,
                ),
                dev.model,
            )
            return _record_and_format("configure_dhcp", seq, apply=apply)

        return runtime.execute("configure_dhcp", PermissionTier.CONFIGURATION, params, _run)

    def configure_nat(
        device_name: str,
        mode: Literal["pat_overload", "dynamic_pool", "static"] = "pat_overload",
        inside_interfaces: list[str] = Field(default_factory=list),
        outside_interfaces: list[str] = Field(default_factory=list),
        acl_number: int = 1,
        source_cidrs: list[str] = Field(default_factory=list),
        overload_interface: str | None = None,
        pool_name: str | None = None,
        pool_start: str | None = None,
        pool_end: str | None = None,
        pool_netmask: str | None = None,
        static_inside_local: str | None = None,
        static_inside_global: str | None = None,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate validated Cisco IOS NAT/PAT configuration."""
        params = {
            "device_name": device_name,
            "mode": mode,
            "inside_interfaces": inside_interfaces,
            "outside_interfaces": outside_interfaces,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.nat_pat(
                NatPatSpec(
                    device_name=dev.name,
                    mode=mode,
                    inside_interfaces=inside_interfaces,
                    outside_interfaces=outside_interfaces,
                    acl_number=acl_number,
                    source_cidrs=source_cidrs,
                    overload_interface=overload_interface,
                    pool_name=pool_name,
                    pool_start=pool_start,
                    pool_end=pool_end,
                    pool_netmask=pool_netmask,
                    static_inside_local=static_inside_local,
                    static_inside_global=static_inside_global,
                ),
                dev.model,
            )
            return _record_and_format("configure_nat", seq, apply=apply)

        return runtime.execute("configure_nat", PermissionTier.CONFIGURATION, params, _run)

    def configure_acl(
        device_name: str,
        acl_identifier: str,
        rules: list[AclRule],
        acl_type: Literal["standard", "extended"] = "extended",
        apply_interface: str | None = None,
        direction: Literal["in", "out"] = "in",
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate validated Standard or Extended IPv4 ACLs and optional interface binding."""
        params = {
            "device_name": device_name,
            "acl_identifier": acl_identifier,
            "acl_type": acl_type,
            "rule_count": len(rules),
            "apply_interface": apply_interface,
            "direction": direction,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.acl(
                AclSpec(
                    device_name=dev.name,
                    acl_identifier=acl_identifier,
                    acl_type=acl_type,
                    rules=rules,
                    apply_interface=apply_interface,
                    direction=direction,
                ),
                dev.model,
            )
            return _record_and_format("configure_acl", seq, apply=apply)

        return runtime.execute("configure_acl", PermissionTier.CONFIGURATION, params, _run)

    def configure_ssh(
        device_name: str,
        domain_name: str,
        username: str,
        secret: str,
        hostname: str | None = None,
        rsa_modulus: Literal[1024, 2048] = 2048,
        vty_end: int = 15,
        enable_secret: str | None = None,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate SSHv2 configuration with automatic secret redaction in logs/snapshots."""
        params = {
            "device_name": device_name,
            "domain_name": domain_name,
            "username": username,
            "secret": secret,
            "enable_secret": enable_secret,
            "rsa_modulus": rsa_modulus,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.ssh(
                SshConfigSpec(
                    device_name=dev.name,
                    hostname=hostname,
                    domain_name=domain_name,
                    username=username,
                    secret=secret,
                    rsa_modulus=rsa_modulus,
                    vty_end=vty_end,
                    enable_secret=enable_secret,
                ),
                dev.model,
            )
            # Redact secrets before snapshot persistence; commands_redacted stored safely.
            return _record_and_format("configure_ssh", seq, apply=apply)

        return runtime.execute("configure_ssh", PermissionTier.CONFIGURATION, params, _run)

    def configure_stp(
        device_name: str,
        mode: Literal["rapid-pvst", "pvst"] = "rapid-pvst",
        root_primary_vlans: list[int] = Field(default_factory=list),
        root_secondary_vlans: list[int] = Field(default_factory=list),
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate Spanning Tree Protocol mode and root bridge priority commands."""
        params = {"device_name": device_name, "mode": mode, "apply": apply}

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.stp(
                StpSpec(
                    device_name=dev.name,
                    mode=mode,
                    root_primary_vlans=root_primary_vlans,
                    root_secondary_vlans=root_secondary_vlans,
                ),
                dev.model,
            )
            return _record_and_format("configure_stp", seq, apply=apply)

        return runtime.execute("configure_stp", PermissionTier.CONFIGURATION, params, _run)

    def configure_etherchannel(
        device_name: str,
        group_id: int,
        member_interfaces: list[str],
        mode: Literal["active", "passive", "on", "desirable", "auto"] = "active",
        port_mode: Literal["trunk", "access", "routed"] = "trunk",
        access_vlan: int | None = None,
        allowed_vlans: list[int] | None = None,
        native_vlan: int | None = None,
        ipv4_address: str | None = None,
        subnet_mask: str | None = None,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate LACP/PAgP/Static EtherChannel and Port-channel configuration."""
        params = {
            "device_name": device_name,
            "group_id": group_id,
            "member_interfaces": member_interfaces,
            "mode": mode,
            "port_mode": port_mode,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.etherchannel(
                EtherChannelSpec(
                    device_name=dev.name,
                    group_id=group_id,
                    member_interfaces=member_interfaces,
                    mode=mode,
                    port_mode=port_mode,
                    access_vlan=access_vlan,
                    native_vlan=native_vlan,
                    allowed_vlans=allowed_vlans,
                    ipv4_address=ipv4_address,
                    subnet_mask=subnet_mask,
                ),
                dev.model,
            )
            return _record_and_format("configure_etherchannel", seq, apply=apply)

        return runtime.execute("configure_etherchannel", PermissionTier.CONFIGURATION, params, _run)

    def configuration_backup(
        device_name: str,
        config_text: str | None = None,
        state_level: Literal["planned", "executed", "verified"] = "planned",
        source: str = "manual_snapshot",
        note: str = "",
        fetch_live: bool = False,
    ) -> dict[str, Any]:
        """Save a device config snapshot (reads live running-config if omitted or fetch_live)."""
        params = {
            "device_name": device_name,
            "state_level": state_level,
            "source": source,
            "note": note,
            "fetch_live": fetch_live or config_text is None,
        }

        def _run() -> OperationResult:
            _, topo, _, history = runtime.manager.require_active()
            resolved_name = _resolve_topo_device_name(runtime, device_name)
            live_read = fetch_live or config_text is None
            if resolved_name in topo.model.devices:
                target_name = topo.get_device(resolved_name).name
            elif live_read and runtime.router.has_live_script():
                target_name = runtime.router.resolve_pt_device_name(device_name)
            else:
                target_name = topo.get_device(device_name).name

            from agenticnet.security.redaction import redact_cli_text

            backend = "offline_model"
            resolved_level = StateLevel(state_level)
            resolved_source = source
            evidence: list[str] = []
            warnings: list[str] = []

            if live_read:
                backend, raw_cfg, ev, warnings = runtime.router.read_show_output(
                    target_name,
                    "show running-config",
                    console_engine=runtime.console,
                )
                safe_text = redact_cli_text(raw_cfg)
                resolved_level = StateLevel.VERIFIED
                if resolved_source == "manual_snapshot":
                    resolved_source = f"live_{backend}"
                evidence.extend(ev)
            else:
                assert config_text is not None
                safe_text = redact_cli_text(config_text)

            snap = history.add_snapshot(
                target_name,
                safe_text,
                state_level=resolved_level,
                source=resolved_source,
                note=note,
            )
            evidence.append(f"Stored redacted snapshot '{snap.snapshot_id}' in ConfigHistory.")
            return OperationResult.ok(
                "configuration_backup",
                (
                    f"Saved snapshot '{snap.snapshot_id}' for '{target_name}' "
                    f"({resolved_level.value})."
                ),
                data=snap.model_dump(mode="json"),
                state_level=resolved_level,
                execution_backend=backend,
                warnings=warnings,
                evidence=evidence,
            )

        return runtime.execute("configuration_backup", PermissionTier.CONFIGURATION, params, _run)

    def configuration_compare(
        left_snapshot_id: str,
        right_snapshot_id: str,
    ) -> dict[str, Any]:
        """Compare two stored configuration snapshots using unified diff."""
        params = {"left_snapshot_id": left_snapshot_id, "right_snapshot_id": right_snapshot_id}

        def _run() -> OperationResult:
            _, _, _, history = runtime.manager.require_active()
            diff = history.compare(left_snapshot_id, right_snapshot_id)
            return OperationResult.ok(
                "configuration_compare",
                (
                    "Snapshots are identical."
                    if diff.identical
                    else f"Found +{diff.added_lines} / -{diff.removed_lines} line difference(s)."
                ),
                data=diff.model_dump(mode="json"),
                state_level=StateLevel.VERIFIED,
                evidence=[
                    f"Computed unified diff between '{left_snapshot_id}' and '{right_snapshot_id}'."
                ],
            )

        return runtime.execute("configuration_compare", PermissionTier.READ_ONLY, params, _run)

    def command_validate(
        commands: list[str],
        device_name: str | None = None,
        device_model: str | None = None,
        raw_cli_output: str | None = None,
    ) -> dict[str, Any]:
        """Validate raw IOS commands against device capabilities or parse CLI error output."""
        params = {
            "device_name": device_name,
            "device_model": device_model,
            "command_count": len(commands),
            "has_output": raw_cli_output is not None,
        }

        def _run() -> OperationResult:
            resolved_model = device_model
            if resolved_model is None and device_name is not None:
                _, topo, _, _ = runtime.manager.require_active()
                resolved_model = topo.get_device(device_name).model
            if resolved_model is None:
                raise ValidationError(
                    "Provide either device_name (in an open project) or device_model."
                )

            profile = runtime.catalog.get_profile(resolved_model)
            pre_diags = validate_raw_commands(profile, commands)
            out_diags = parse_cli_output(raw_cli_output) if raw_cli_output else []
            all_diags = pre_diags + out_diags
            errors = [d for d in all_diags if d.severity == "error"]
            return OperationResult.ok(
                "command_validate",
                f"Validated {len(commands)} command(s) for '{profile.model}': "
                f"{len(errors)} error(s).",
                data={
                    "model": profile.model,
                    "valid": len(errors) == 0,
                    "diagnostics": [d.model_dump(mode="json") for d in all_diags],
                },
                state_level=StateLevel.VERIFIED,
                warnings=[d.message for d in all_diags if d.severity == "warning"],
                evidence=[f"Checked commands against DeviceCatalog profile '{profile.model}'."],
            )

        return runtime.execute("command_validate", PermissionTier.READ_ONLY, params, _run)

    def configure_hsrp(
        device_name: str,
        interface: str,
        virtual_ip: str,
        group_id: int = 1,
        priority: int | None = 110,
        preempt: bool = True,
        version: Literal[1, 2] = 2,
        track_interface: str | None = None,
        decrement: int = 10,
        ipv4_address: str | None = None,
        subnet_mask: str | None = None,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate validated HSRP v1/v2 first-hop redundancy configuration."""
        params = {
            "device_name": device_name,
            "interface": interface,
            "group_id": group_id,
            "virtual_ip": virtual_ip,
            "priority": priority,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.generate_hsrp(
                HsrpConfigSpec(
                    device_name=dev.name,
                    interface=interface,
                    group_id=group_id,
                    virtual_ip=virtual_ip,
                    priority=priority,
                    preempt=preempt,
                    version=version,
                    track_interface=track_interface,
                    decrement=decrement,
                    ipv4_address=ipv4_address,
                    subnet_mask=subnet_mask,
                ),
                dev.model,
            )
            return _record_and_format("configure_hsrp", seq, apply=apply)

        return runtime.execute("configure_hsrp", PermissionTier.CONFIGURATION, params, _run)

    def configure_bgp(
        device_name: str,
        local_as: int,
        neighbors: list[BgpNeighborEntry],
        router_id: str | None = None,
        networks: list[BgpNetworkEntry | str] = Field(default_factory=list),
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate validated BGP-4 eBGP/iBGP autonomous system configuration."""
        params = {
            "device_name": device_name,
            "local_as": local_as,
            "router_id": router_id,
            "neighbor_count": len(neighbors),
            "network_count": len(networks),
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.generate_bgp(
                BgpConfigSpec(
                    device_name=dev.name,
                    local_as=local_as,
                    router_id=router_id,
                    neighbors=neighbors,
                    networks=networks,
                ),
                dev.model,
            )
            return _record_and_format("configure_bgp", seq, apply=apply)

        return runtime.execute("configure_bgp", PermissionTier.CONFIGURATION, params, _run)

    def configure_dhcp_snooping(
        device_name: str,
        vlans: list[int],
        trusted_interfaces: list[str] = Field(default_factory=list),
        rate_limit_interfaces: dict[str, int] = Field(default_factory=dict),
        disable_option_82: bool = True,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate Layer 2 DHCP Snooping global, VLAN, trust, and rate-limit configuration."""
        params = {
            "device_name": device_name,
            "vlans": vlans,
            "trusted_interfaces": trusted_interfaces,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.generate_dhcp_snooping(
                DhcpSnoopingSpec(
                    device_name=dev.name,
                    vlans=vlans,
                    trusted_interfaces=trusted_interfaces,
                    rate_limit_interfaces=rate_limit_interfaces,
                    disable_option_82=disable_option_82,
                ),
                dev.model,
            )
            return _record_and_format("configure_dhcp_snooping", seq, apply=apply)

        return runtime.execute(
            "configure_dhcp_snooping", PermissionTier.CONFIGURATION, params, _run
        )

    def configure_dai(
        device_name: str,
        vlans: list[int],
        trusted_interfaces: list[str] = Field(default_factory=list),
        validate_src_mac: bool = False,
        validate_dst_mac: bool = False,
        validate_ip: bool = False,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate Layer 2 Dynamic ARP Inspection (DAI) configuration."""
        params = {
            "device_name": device_name,
            "vlans": vlans,
            "trusted_interfaces": trusted_interfaces,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.generate_dai(
                DaiConfigSpec(
                    device_name=dev.name,
                    vlans=vlans,
                    trusted_interfaces=trusted_interfaces,
                    validate_src_mac=validate_src_mac,
                    validate_dst_mac=validate_dst_mac,
                    validate_ip=validate_ip,
                ),
                dev.model,
            )
            return _record_and_format("configure_dai", seq, apply=apply)

        return runtime.execute("configure_dai", PermissionTier.CONFIGURATION, params, _run)

    def configure_services(
        device_name: str,
        ntp_servers: list[str] = Field(default_factory=list),
        ntp_master_stratum: int | None = None,
        syslog_servers: list[str] = Field(default_factory=list),
        logging_trap: str | None = "informational",
        service_timestamps: bool = True,
        snmp_ro_community: str | None = None,
        snmp_rw_community: str | None = None,
        snmp_location: str | None = None,
        snmp_contact: str | None = None,
        aaa_new_model: bool = False,
        radius_server_ip: str | None = None,
        radius_key: str | None = None,
        tacacs_server_ip: str | None = None,
        tacacs_key: str | None = None,
        local_fallback: bool = True,
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate NTP, Syslog, SNMP, and AAA RADIUS/TACACS+ management plane configuration."""
        params = {
            "device_name": device_name,
            "ntp_servers": ntp_servers,
            "syslog_servers": syslog_servers,
            "has_snmp": bool(snmp_ro_community or snmp_rw_community),
            "aaa_new_model": aaa_new_model,
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.generate_management_services(
                ManagementServicesSpec(
                    device_name=dev.name,
                    ntp_servers=ntp_servers,
                    ntp_master_stratum=ntp_master_stratum,
                    syslog_servers=syslog_servers,
                    logging_trap=logging_trap,
                    service_timestamps=service_timestamps,
                    snmp_ro_community=snmp_ro_community,
                    snmp_rw_community=snmp_rw_community,
                    snmp_location=snmp_location,
                    snmp_contact=snmp_contact,
                    aaa_new_model=aaa_new_model,
                    radius_server_ip=radius_server_ip,
                    radius_key=radius_key,
                    tacacs_server_ip=tacacs_server_ip,
                    tacacs_key=tacacs_key,
                    local_fallback=local_fallback,
                ),
                dev.model,
            )
            return _record_and_format("configure_services", seq, apply=apply)

        return runtime.execute("configure_services", PermissionTier.CONFIGURATION, params, _run)

    def configure_voip_cme(
        device_name: str,
        source_address: str,
        source_port: int = 2000,
        max_ephones: int = 5,
        max_dn: int = 10,
        auto_assign_end: int | None = 5,
        auto_reg_ephone: bool = True,
        create_cnf_files: bool = True,
        dns: list[EphoneDnEntry] = Field(default_factory=list),
        ephones: list[EphoneEntry] = Field(default_factory=list),
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate Cisco CallManager Express (CME) SCCP telephony configuration."""
        params = {
            "device_name": device_name,
            "source_address": source_address,
            "dn_count": len(dns),
            "ephone_count": len(ephones),
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.generate_cme_voip(
                CmeVoipSpec(
                    device_name=dev.name,
                    source_address=source_address,
                    source_port=source_port,
                    max_ephones=max_ephones,
                    max_dn=max_dn,
                    auto_assign_end=auto_assign_end,
                    auto_reg_ephone=auto_reg_ephone,
                    create_cnf_files=create_cnf_files,
                    dns=dns,
                    ephones=ephones,
                ),
                dev.model,
            )
            return _record_and_format("configure_voip_cme", seq, apply=apply)

        return runtime.execute("configure_voip_cme", PermissionTier.CONFIGURATION, params, _run)

    def configure_asa(
        device_name: str,
        interfaces: list[AsaInterfaceZoneSpec],
        hostname: str | None = None,
        routes: list[AsaRouteEntry] = Field(default_factory=list),
        object_nats: list[AsaObjectNatSpec] = Field(default_factory=list),
        acl_rules: list[AsaAclRule] = Field(default_factory=list),
        apply: bool = False,
    ) -> dict[str, Any]:
        """Generate Cisco ASA 5505 (VLAN SVI) or ASA 5506-X (routed port) firewall config."""
        params = {
            "device_name": device_name,
            "hostname": hostname,
            "zone_count": len(interfaces),
            "route_count": len(routes),
            "nat_count": len(object_nats),
            "acl_rule_count": len(acl_rules),
            "apply": apply,
        }

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            dev = topo.get_device(_resolve_topo_device_name(runtime, device_name))
            seq = runtime.ios.generate_asa_basic(
                AsaBasicConfigSpec(
                    device_name=dev.name,
                    hostname=hostname,
                    interfaces=interfaces,
                    routes=routes,
                    object_nats=object_nats,
                    acl_rules=acl_rules,
                ),
                dev.model,
            )
            return _record_and_format("configure_asa", seq, apply=apply)

        return runtime.execute("configure_asa", PermissionTier.CONFIGURATION, params, _run)

    def stored_config_manage(
        action: Literal["upsert", "read", "merge", "delete", "validate"],
        device_name: str,
        config_text: str | None = None,
        start_line: int = 1,
        end_line: int | None = None,
        new_lines: list[str] | str | None = None,
        note: str = "",
        state_level: Literal["planned", "executed", "verified"] | None = None,
        device_model: str | None = None,
        strict: bool = False,
    ) -> dict[str, Any]:
        """Manage stored per-device design configs (upsert/read/merge/delete) & pre-apply checks."""
        params = {
            "action": action,
            "device_name": device_name,
            "start_line": start_line,
            "end_line": end_line,
            "state_level": state_level,
            "strict": strict,
        }
        tier = (
            PermissionTier.READ_ONLY
            if action in {"read", "validate"}
            else PermissionTier.PLANNING
        )

        def _run() -> OperationResult:
            from agenticnet.security.redaction import redact_cli_text

            _, topo, ipam, history = runtime.manager.require_active()
            resolved_name = _resolve_topo_device_name(runtime, device_name)
            target_dev = topo.model.devices.get(resolved_name)
            target_name = target_dev.name if target_dev is not None else resolved_name
            resolved_model = device_model or (target_dev.model if target_dev else None)
            lvl_filter = StateLevel(state_level) if state_level else None

            if action == "upsert":
                if config_text is None:
                    raise ValidationError(
                        "stored_config_manage action='upsert' requires config_text."
                    )
                safe_text = redact_cli_text(config_text)
                val_payload: dict[str, Any] | None = None
                if resolved_model is not None:
                    raw_val = validate_pre_apply(
                        resolved_model,
                        safe_text.splitlines(),
                        device_name=target_name,
                        ipam=ipam,
                        catalog=runtime.catalog,
                        raise_on_error=strict,
                    )
                    val_payload = {
                        **raw_val,
                        "diagnostics": [
                            d.model_dump(mode="json") for d in raw_val["diagnostics"]
                        ],
                    }
                snap = history.upsert_config(target_name, safe_text, note=note)
                payload = snap.model_dump(mode="json")
                if val_payload is not None:
                    payload["pre_apply_validation"] = val_payload
                return OperationResult.ok(
                    "stored_config_manage",
                    f"Upserted stored PLANNED config '{snap.snapshot_id}' for '{target_name}'.",
                    data=payload,
                    state_level=StateLevel.PLANNED,
                    evidence=[f"Upserted design_store snapshot '{snap.snapshot_id}'."],
                )

            if action == "read":
                numbered = history.read_config_numbered(
                    target_name,
                    start_line=start_line,
                    end_line=end_line,
                    state_level=lvl_filter,
                )
                return OperationResult.ok(
                    "stored_config_manage",
                    (
                        f"Read lines {numbered['start_line']}..{numbered['end_line']} "
                        f"of {numbered['total_lines']} for '{target_name}'."
                    ),
                    data=numbered,
                    state_level=StateLevel.PLANNED,
                    evidence=[f"Read numbered stored config for '{target_name}'."],
                )

            if action == "merge":
                if new_lines is None:
                    raise ValidationError("stored_config_manage action='merge' requires new_lines.")
                if isinstance(new_lines, str):
                    safe_lines: list[str] | str = redact_cli_text(new_lines)
                else:
                    safe_lines = [redact_cli_text(str(ln)) for ln in new_lines]
                snap = history.merge_config_lines(
                    target_name,
                    start_line=start_line,
                    end_line=end_line,
                    new_lines=safe_lines,
                    note=note,
                )
                return OperationResult.ok(
                    "stored_config_manage",
                    f"Merged lines {start_line}..{end_line or start_line} on '{target_name}'.",
                    data=snap.model_dump(mode="json"),
                    state_level=StateLevel.PLANNED,
                    evidence=[f"Updated stored config '{snap.snapshot_id}' on '{target_name}'."],
                )

            if action == "delete":
                deleted = history.delete_config(target_name, state_level=lvl_filter)
                return OperationResult.ok(
                    "stored_config_manage",
                    f"Deleted {deleted} stored snapshot(s) for '{target_name}'.",
                    data={"device_name": target_name, "deleted_count": deleted},
                    state_level=StateLevel.PLANNED,
                    evidence=[f"Deleted {deleted} snapshot(s) for '{target_name}'."],
                )

            # action == "validate"
            if resolved_model is None:
                raise ValidationError(
                    "Provide device_model or ensure device_name exists in the active topology."
                )
            if config_text is not None:
                cmds_to_check = config_text.splitlines()
            else:
                latest = history.latest_for_device(target_name, state_level=lvl_filter)
                if latest is None:
                    raise ValidationError(
                        f"No stored configuration found for '{target_name}' to validate."
                    )
                cmds_to_check = latest.config_text.splitlines()

            raw_val = validate_pre_apply(
                resolved_model,
                cmds_to_check,
                device_name=target_name,
                ipam=ipam,
                catalog=runtime.catalog,
                raise_on_error=strict,
            )
            serialized_diags = [d.model_dump(mode="json") for d in raw_val["diagnostics"]]
            out_val = {**raw_val, "diagnostics": serialized_diags}
            return OperationResult.ok(
                "stored_config_manage",
                (
                    f"Pre-apply validation for '{target_name}' ({resolved_model}): "
                    f"valid={raw_val['valid']} ({raw_val['error_count']} error(s))."
                ),
                data=out_val,
                state_level=StateLevel.VERIFIED,
                warnings=[
                    d.message for d in raw_val["diagnostics"] if d.severity == "warning"
                ],
                evidence=[f"Ran validate_pre_apply on {len(cmds_to_check)} line(s)."],
            )

        return runtime.execute("stored_config_manage", tier, params, _run)

    specs = [
        (
            "configure_interface",
            "configuration",
            PermissionTier.CONFIGURATION,
            configure_interface,
            False,
        ),
        ("configure_vlan", "configuration", PermissionTier.CONFIGURATION, configure_vlan, False),
        ("configure_trunk", "configuration", PermissionTier.CONFIGURATION, configure_trunk, False),
        (
            "configure_routing",
            "configuration",
            PermissionTier.CONFIGURATION,
            configure_routing,
            False,
        ),
        ("configure_ospf", "configuration", PermissionTier.CONFIGURATION, configure_ospf, False),
        ("configure_eigrp", "configuration", PermissionTier.CONFIGURATION, configure_eigrp, False),
        ("configure_dhcp", "configuration", PermissionTier.CONFIGURATION, configure_dhcp, False),
        ("configure_nat", "configuration", PermissionTier.CONFIGURATION, configure_nat, False),
        ("configure_acl", "configuration", PermissionTier.CONFIGURATION, configure_acl, False),
        ("configure_ssh", "configuration", PermissionTier.CONFIGURATION, configure_ssh, False),
        ("configure_stp", "configuration", PermissionTier.CONFIGURATION, configure_stp, False),
        (
            "configure_etherchannel",
            "configuration",
            PermissionTier.CONFIGURATION,
            configure_etherchannel,
            False,
        ),
        ("configure_hsrp", "configuration", PermissionTier.CONFIGURATION, configure_hsrp, False),
        ("configure_bgp", "configuration", PermissionTier.CONFIGURATION, configure_bgp, False),
        (
            "configure_dhcp_snooping",
            "configuration",
            PermissionTier.CONFIGURATION,
            configure_dhcp_snooping,
            False,
        ),
        ("configure_dai", "configuration", PermissionTier.CONFIGURATION, configure_dai, False),
        (
            "configure_services",
            "configuration",
            PermissionTier.CONFIGURATION,
            configure_services,
            False,
        ),
        (
            "configure_voip_cme",
            "configuration",
            PermissionTier.CONFIGURATION,
            configure_voip_cme,
            False,
        ),
        ("configure_asa", "configuration", PermissionTier.CONFIGURATION, configure_asa, False),
        (
            "stored_config_manage",
            "configuration",
            PermissionTier.PLANNING,
            stored_config_manage,
            False,
        ),
        (
            "configuration_backup",
            "configuration",
            PermissionTier.CONFIGURATION,
            configuration_backup,
            False,
        ),
        (
            "configuration_compare",
            "configuration",
            PermissionTier.READ_ONLY,
            configuration_compare,
            True,
        ),
        ("command_validate", "cli", PermissionTier.READ_ONLY, command_validate, True),
    ]
    for name, cat, tier, fn, ro in specs:
        runtime.registry.register_tool(
            server,
            name=name,
            category=cat,
            permission_tier=tier,
            description=fn.__doc__ or "",
            fn=fn,
            read_only=ro,
            destructive=False,
        )
