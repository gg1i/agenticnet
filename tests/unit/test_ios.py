"""Unit tests for Cisco IOS generators, device capability enforcement, CLI parser, and diffs."""

from __future__ import annotations

import pytest

from agenticnet.core.enums import StateLevel
from agenticnet.core.exceptions import IOSConfigError
from agenticnet.devices import DEFAULT_CATALOG
from agenticnet.ios import (
    AccessPortSpec,
    AclRule,
    AclSpec,
    ConfigHistory,
    DhcpPoolSpec,
    EigrpConfigSpec,
    EtherChannelSpec,
    InterfaceConfigSpec,
    IOSGenerator,
    NatPatSpec,
    OspfConfigSpec,
    OspfNetworkEntry,
    RipConfigSpec,
    SshConfigSpec,
    StaticRouteEntry,
    StpSpec,
    TrunkPortSpec,
    VlanSpec,
    parse_cli_output,
    validate_raw_commands,
)


@pytest.mark.unit
def test_ios_generator_model_specific_trunk_and_routed_port() -> None:
    ios = IOSGenerator()

    trunk_2960 = ios.trunk_port(
        "2960-24TT",
        TrunkPortSpec(device_name="SW1", interface="Gi0/1", allowed_vlans=[10, 20], native_vlan=99),
    )
    assert " switchport trunk encapsulation dot1q" not in trunk_2960.commands
    assert " switchport mode trunk" in trunk_2960.commands
    assert " switchport trunk allowed vlan 10,20" in trunk_2960.commands

    trunk_3560 = ios.trunk_port(
        "3560-24PS",
        TrunkPortSpec(device_name="SW-CORE", interface="Gi0/1", allowed_vlans=[10, 20]),
    )
    assert " switchport trunk encapsulation dot1q" in trunk_3560.commands
    assert " switchport mode trunk" in trunk_3560.commands

    l3_routed = ios.interface(
        "3560-24PS",
        InterfaceConfigSpec(
            device_name="SW-CORE",
            interface="Gi0/2",
            ipv4_address="10.0.0.2/30",
            l3_routed_port=True,
        ),
    )
    assert " no switchport" in l3_routed.commands
    assert " ip address 10.0.0.2 255.255.255.252" in l3_routed.commands


@pytest.mark.unit
def test_ios_generator_protocols_and_capability_guards() -> None:
    ios = IOSGenerator()

    # Router subinterface + OSPF + DHCP + NAT + ACL + SSH
    subif = ios.interface(
        "2911",
        InterfaceConfigSpec(
            device_name="R1",
            interface="Gi0/0.10",
            ipv4_address="192.168.10.1/24",
            dot1q_vlan=10,
        ),
    )
    assert " encapsulation dot1Q 10" in subif.commands

    ospf = ios.ospf(
        OspfConfigSpec(
            device_name="R1",
            process_id=1,
            router_id="1.1.1.1",
            networks=[OspfNetworkEntry(network="192.168.10.0/24", area=0)],
            passive_interfaces=["Gi0/0.10"],
        ),
        "2911",
    )
    assert " network 192.168.10.0 0.0.0.255 area 0" in ospf.commands
    assert " passive-interface GigabitEthernet0/0.10" in ospf.commands

    dhcp = ios.dhcp(
        DhcpPoolSpec(
            device_name="R1",
            pool_name="VLAN10_POOL",
            network="192.168.10.0/24",
            default_router="192.168.10.1",
            dns_server="8.8.8.8",
            excluded_ranges=[("192.168.10.1", "192.168.10.10")],
        ),
        "2911",
    )
    assert "ip dhcp excluded-address 192.168.10.1 192.168.10.10" in dhcp.commands
    assert "ip dhcp pool VLAN10_POOL" in dhcp.commands

    nat = ios.nat_pat(
        NatPatSpec(
            device_name="R1",
            mode="pat_overload",
            inside_interfaces=["Gi0/0"],
            outside_interfaces=["Gi0/1"],
            source_cidrs=["192.168.10.0/24"],
            overload_interface="Gi0/1",
        ),
        "2911",
    )
    assert "ip nat inside source list 1 interface GigabitEthernet0/1 overload" in nat.commands

    acl = ios.acl(
        AclSpec(
            device_name="R1",
            acl_identifier="BLOCK_TELNET",
            acl_type="extended",
            rules=[
                AclRule(
                    action="deny",
                    protocol="tcp",
                    source="any",
                    destination="any",
                    operator="eq",
                    port="23",
                ),
                AclRule(action="permit", protocol="ip", source="any", destination="any"),
            ],
            apply_interface="Gi0/0",
            direction="in",
        ),
        "2911",
    )
    assert " deny tcp any any eq 23" in acl.commands
    assert " ip access-group BLOCK_TELNET in" in acl.commands

    ssh = ios.ssh(
        SshConfigSpec(
            device_name="R1",
            domain_name="agenticnet.local",
            username="netops",
            secret="VerySecretKey99",
            enable_secret="Enable99",
        ),
        "2911",
    )
    assert any("VerySecretKey99" in c for c in ssh.commands)
    assert all("VerySecretKey99" not in c for c in ssh.commands_redacted)
    assert all("Enable99" not in c for c in ssh.commands_redacted)

    # Verify remaining IOS helpers execute cleanly
    assert (
        "ip route 0.0.0.0 0.0.0.0 203.0.113.1"
        in ios.static_routes(
            "R1",
            "2911",
            [
                StaticRouteEntry(
                    destination_network="0.0.0.0",
                    subnet_mask_or_prefix="0.0.0.0",
                    next_hop="203.0.113.1",
                )
            ],
        ).commands
    )
    assert (
        " version 2"
        in ios.rip(RipConfigSpec(device_name="R1", networks=["10.0.0.0"]), "2911").commands
    )
    assert (
        "router eigrp 100"
        in ios.eigrp(
            EigrpConfigSpec(device_name="R1", asn=100, networks=["10.0.0.0/8"]), "2911"
        ).commands
    )
    assert "vlan 10" in ios.vlans("SW1", "2960-24TT", [VlanSpec(vlan_id=10, name="Users")]).commands
    assert (
        " switchport port-security"
        in ios.access_port(
            "2960-24TT",
            AccessPortSpec(device_name="SW1", interface="Fa0/1", vlan_id=10, port_security=True),
        ).commands
    )
    assert (
        "spanning-tree mode rapid-pvst"
        in ios.stp(StpSpec(device_name="SW1", root_primary_vlans=[10]), "2960-24TT").commands
    )
    assert (
        " channel-group 1 mode active"
        in ios.etherchannel(
            EtherChannelSpec(device_name="SW1", group_id=1, member_interfaces=["Gi0/1", "Gi0/2"]),
            "2960-24TT",
        ).commands
    )

    # Capability enforcement: OSPF must fail on 2960-24TT and IOS must fail on PC-PT
    with pytest.raises(IOSConfigError):
        ios.ospf(
            OspfConfigSpec(device_name="SW1", networks=[OspfNetworkEntry(network="10.0.0.0/24")]),
            "2960-24TT",
        )

    with pytest.raises(IOSConfigError):
        ios.hostname("PC1", "PC-PT")


@pytest.mark.unit
def test_cli_validator_parser_and_config_diff() -> None:
    profile_2960 = DEFAULT_CATALOG.get_profile("2960-24TT")
    diags = validate_raw_commands(
        profile_2960,
        ["ip routing", "switchport trunk encapsulation dot1q", "switchport mode trunk"],
    )
    codes = {d.code for d in diags}
    assert "UNSUPPORTED_IP_ROUTING" in codes
    assert "UNNEEDED_TRUNK_ENCAP" in codes

    from pathlib import Path

    fixture_path = Path(__file__).resolve().parents[1] / "fixtures" / "sample_cli_outputs.txt"
    parsed = parse_cli_output(fixture_path.read_text(encoding="utf-8"))
    assert len(parsed) == 3
    assert parsed[0].code == "CLI_INVALID_INPUT"
    assert parsed[1].code == "CLI_OVERLAPPING_SUBNET"
    assert parsed[2].code == "CLI_INCOMPLETE_COMMAND"

    history = ConfigHistory()
    s1 = history.add_snapshot(
        "R1", "hostname R1\ninterface Gi0/0\n shutdown", state_level=StateLevel.PLANNED
    )
    s2 = history.add_snapshot(
        "R1", "hostname R1\ninterface Gi0/0\n no shutdown", state_level=StateLevel.VERIFIED
    )
    diff = history.compare(s1.snapshot_id, s2.snapshot_id)
    assert not diff.identical
    assert diff.added_lines == 1
    assert diff.removed_lines == 1
    assert "+ no shutdown" in diff.unified_diff


@pytest.mark.unit
def test_validate_raw_commands_extended_checks() -> None:
    profile_3560 = DEFAULT_CATALOG.get_profile("3560-24PS")
    warn_diags = validate_raw_commands(
        profile_3560,
        ["interface Gi0/1", "switchport mode trunk"],
    )
    assert any(
        d.code == "MISSING_TRUNK_ENCAP_DOT1Q" and d.severity == "warning" for d in warn_diags
    )

    ok_diags = validate_raw_commands(
        profile_3560,
        ["interface Gi0/1", "switchport trunk encapsulation dot1q", "switchport mode trunk"],
    )
    assert not any(d.code == "MISSING_TRUNK_ENCAP_DOT1Q" for d in ok_diags)

    profile_2960 = DEFAULT_CATALOG.get_profile("2960-24TT")
    l2_diags = validate_raw_commands(
        profile_2960,
        ["router rip", "encapsulation dot1q 10"],
    )
    l2_codes = {d.code for d in l2_diags}
    assert "UNSUPPORTED_ROUTING_PROTOCOL" in l2_codes
    assert "UNSUPPORTED_SUBINTERFACE_ENCAP" in l2_codes

    profile_2911 = DEFAULT_CATALOG.get_profile("2911")
    ip_diags = validate_raw_commands(
        profile_2911,
        [
            "interface Gi0/0",
            "ip address dhcp",
            "interface Gi0/1",
            "ip address 10.0.0.1 255.0.255.0",
        ],
    )
    assert [d.code for d in ip_diags] == ["INVALID_IP_OR_MASK"]


@pytest.mark.unit
def test_ios_enterprise_generators_security_redaction_and_pre_apply_gate() -> None:
    from agenticnet.core.exceptions import ValidationError
    from agenticnet.ios.models import (
        AsaAclRule,
        AsaBasicConfigSpec,
        AsaInterfaceZoneSpec,
        AsaObjectNatSpec,
        AsaRouteEntry,
        BgpConfigSpec,
        BgpNeighborEntry,
        CmeVoipSpec,
        DaiConfigSpec,
        DhcpSnoopingSpec,
        EphoneDnEntry,
        EphoneEntry,
        HsrpConfigSpec,
        ManagementServicesSpec,
    )
    from agenticnet.ios.validators import validate_pre_apply
    from agenticnet.ipam import IPAMEngine

    ios = IOSGenerator()

    # 1. L3 switch SVI auto-emits 'ip routing' + helper-address + IPv6 unicast-routing
    svi = ios.interface(
        "3560-24PS",
        InterfaceConfigSpec(
            device_name="SW-CORE",
            interface="Vlan10",
            ipv4_address="10.10.10.1/24",
            ipv6_address="2001:db8:10::1/64",
            helper_addresses=["10.10.99.10"],
        ),
    )
    assert svi.commands[0] == "ip routing"
    assert "ipv6 unicast-routing" in svi.commands
    assert " ip helper-address 10.10.99.10" in svi.commands

    # 2. Voice VLAN on access port + Option 150 on DHCP + bare-IP ACL + VTY access-class + L3 Po
    voice_port = ios.access_port(
        "2960-24TT",
        AccessPortSpec(device_name="SW1", interface="Fa0/5", vlan_id=10, voice_vlan=100),
    )
    assert " switchport voice vlan 100" in voice_port.commands

    dhcp_voip = ios.dhcp(
        DhcpPoolSpec(
            device_name="R-VOICE",
            pool_name="VOICE",
            network="10.50.100.0/24",
            default_router="10.50.100.1",
            option_150="10.50.100.1",
        ),
        "2811",
    )
    assert " option 150 ip 10.50.100.1" in dhcp_voip.commands

    acl_host = ios.acl(
        AclSpec(
            device_name="R1",
            acl_identifier="MGMT_ONLY",
            acl_type="extended",
            rules=[
                AclRule(
                    action="permit",
                    protocol="tcp",
                    source="10.10.10.5",
                    destination="10.10.20.0/24",
                    operator="eq",
                    port="22",
                )
            ],
            apply_vty=True,
        ),
        "2911",
    )
    assert " permit tcp host 10.10.10.5 10.10.20.0 0.0.0.255 eq 22" in acl_host.commands
    assert " access-class MGMT_ONLY in" in acl_host.commands

    nat_portfwd = ios.nat_pat(
        NatPatSpec(
            device_name="R1",
            mode="static",
            static_inside_local="192.168.1.50",
            static_inside_global="203.0.113.10",
            static_protocol="tcp",
            static_local_port=8080,
            static_global_port=80,
        ),
        "2911",
    )
    assert (
        "ip nat inside source static tcp 192.168.1.50 8080 203.0.113.10 80" in nat_portfwd.commands
    )

    routed_po = ios.etherchannel(
        EtherChannelSpec(
            device_name="SW-CORE",
            group_id=1,
            member_interfaces=["Gi0/1", "Gi0/2"],
            port_mode="routed",
            ipv4_address="10.0.0.1/30",
        ),
        "3560-24PS",
    )
    assert routed_po.commands[0] == "ip routing"
    assert " no switchport" in routed_po.commands
    assert " ip address 10.0.0.1 255.255.255.252" in routed_po.commands

    # 3. 7 new enterprise generators: HSRP, BGP, DHCP Snooping, DAI, Management, CME, ASA
    hsrp = ios.generate_hsrp(
        HsrpConfigSpec(
            device_name="R1",
            interface="Gi0/0",
            group_id=10,
            virtual_ip="192.168.10.1",
            priority=120,
            track_interface="Gi0/1",
        ),
        "2911",
    )
    assert " standby version 2" in hsrp.commands
    assert " standby 10 ip 192.168.10.1" in hsrp.commands
    assert " standby 10 track GigabitEthernet0/1 10" in hsrp.commands

    bgp = ios.generate_bgp(
        BgpConfigSpec(
            device_name="R-EDGE",
            local_as=65001,
            router_id="1.1.1.1",
            neighbors=[
                BgpNeighborEntry(peer_ip="203.0.113.2", remote_as=65002, next_hop_self=True)
            ],
            networks=["192.168.10.0/24"],
        ),
        "ISR4331",
    )
    assert "router bgp 65001" in bgp.commands
    assert " neighbor 203.0.113.2 remote-as 65002" in bgp.commands
    assert " network 192.168.10.0 mask 255.255.255.0" in bgp.commands

    snoop = ios.generate_dhcp_snooping(
        DhcpSnoopingSpec(
            device_name="SW1",
            vlans=[10, 20],
            trusted_interfaces=["Gi0/1"],
            rate_limit_interfaces={"Fa0/1": 15},
        ),
        "2960-24TT",
    )
    assert "ip dhcp snooping vlan 10,20" in snoop.commands
    assert " ip dhcp snooping trust" in snoop.commands
    assert " ip dhcp snooping limit rate 15" in snoop.commands

    dai = ios.generate_dai(
        DaiConfigSpec(
            device_name="SW1",
            vlans=[10],
            trusted_interfaces=["Gi0/1"],
            validate_src_mac=True,
            validate_ip=True,
        ),
        "2960-24TT",
    )
    assert "ip arp inspection vlan 10" in dai.commands
    assert "ip arp inspection validate src-mac ip" in dai.commands

    mgmt = ios.generate_management_services(
        ManagementServicesSpec(
            device_name="R1",
            ntp_servers=["10.0.0.100"],
            syslog_servers=["10.0.0.101"],
            snmp_ro_community="SecretReadComm",
            aaa_new_model=True,
            radius_server_ip="10.0.0.102",
            radius_key="RadKey999",
        ),
        "2911",
    )
    assert any("SecretReadComm" in c for c in mgmt.commands)
    assert all("SecretReadComm" not in c for c in mgmt.commands_redacted)
    assert all("RadKey999" not in c for c in mgmt.commands_redacted)

    cme = ios.generate_cme_voip(
        CmeVoipSpec(
            device_name="R-VOICE",
            source_address="10.50.100.1",
            dns=[EphoneDnEntry(dn_id=1, number="1001", label="Desk1")],
            ephones=[EphoneEntry(ephone_id=1, mac_address="0001.42AA.BBCC", button_mapping="1:1")],
        ),
        "2811",
    )
    assert "telephony-service" in cme.commands
    assert "ephone-dn 1" in cme.commands
    assert cme.warnings == []

    asa_5505 = ios.generate_asa_basic(
        AsaBasicConfigSpec(
            device_name="FW1",
            hostname="ASA-EDGE",
            interfaces=[
                AsaInterfaceZoneSpec(
                    interface="Eth0/0",
                    vlan_id=2,
                    nameif="outside",
                    security_level=0,
                    ip_address="203.0.113.2/29",
                ),
                AsaInterfaceZoneSpec(
                    interface="Eth0/1",
                    vlan_id=1,
                    nameif="inside",
                    security_level=100,
                    ip_address="192.168.1.1/24",
                ),
            ],
            routes=[AsaRouteEntry(interface_nameif="outside", next_hop="203.0.113.1")],
            object_nats=[AsaObjectNatSpec(object_name="LAN-NET", subnet="192.168.1.0/24")],
            acl_rules=[
                AsaAclRule(
                    acl_name="OUTSIDE_IN",
                    action="permit",
                    protocol="tcp",
                    source="any",
                    destination="192.168.1.10",
                    eq_port="443",
                    apply_nameif="outside",
                )
            ],
        ),
        "5505",
    )
    assert " switchport access vlan 2" in asa_5505.commands
    assert "interface Vlan2" in asa_5505.commands
    assert " nat (inside,outside) dynamic interface" in asa_5505.commands
    assert (
        "access-list OUTSIDE_IN extended permit tcp any host 192.168.1.10 eq 443"
        in asa_5505.commands
    )

    asa_5506 = ios.generate_asa_basic(
        AsaBasicConfigSpec(
            device_name="FW2",
            interfaces=[
                AsaInterfaceZoneSpec(
                    interface="Gi1/1",
                    nameif="outside",
                    security_level=0,
                    ip_address="203.0.113.2/29",
                )
            ],
        ),
        "5506-X",
    )
    assert "interface GigabitEthernet1/1" in asa_5506.commands
    assert " switchport access vlan 2" not in asa_5506.commands

    # 4. Control-character injection rejected + pre-apply validation + ConfigHistory CRUD
    with pytest.raises(ValidationError):
        InterfaceConfigSpec(device_name="R1", interface="Gi0/0", description="ok\nusername pwn")
    with pytest.raises(ValidationError):
        ios.hostname("R1\nreload", "2911")

    ipam = IPAMEngine()
    ipam.allocate_address("R2", "GigabitEthernet0/0", "10.0.0.1/24")
    p_4331 = DEFAULT_CATALOG.get_profile("ISR4331")
    pre_res = validate_pre_apply(
        p_4331,
        [
            "interface Gi0/0/0",
            "ip address 10.0.0.1 255.255.255.0",
            "interface Gi0/0/1",
            "ip address 10.0.0.50 255.255.255.128",
            "route-map RM_TEST permit 10",
        ],
        device_name="R1",
        ipam=ipam,
        raise_on_error=False,
    )
    assert pre_res["blocked"] is True
    pre_codes = {d.code for d in pre_res["diagnostics"]}
    assert "IPAM_DUPLICATE_IP" in pre_codes
    assert "OVERLAPPING_INTERFACE_SUBNET" in pre_codes
    assert "UNSUPPORTED_PT_IOS_XE_COMMAND" in pre_codes

    hist = ConfigHistory()
    hist.upsert_config("R1", "hostname R1\ninterface Gi0/0\n shutdown")
    numbered = hist.read_config_numbered("R1")
    assert numbered["total_lines"] == 3
    hist.merge_config_lines("R1", start_line=3, end_line=3, new_lines=["no shutdown"])
    assert hist.read_config_numbered("R1")["lines"][2]["text"] == "no shutdown"
    other_snap = hist.add_snapshot("R2", "hostname R2")
    r1_snap = hist.latest_for_device("R1")
    assert r1_snap is not None
    with pytest.raises(ValidationError):
        hist.compare(r1_snap.snapshot_id, other_snap.snapshot_id)
    assert hist.delete_config("R1") == 1
