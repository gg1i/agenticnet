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
