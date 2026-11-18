"""Unit tests for the IPAM subsystem: CIDR math, VLSM, conflict detection, and tables."""

from __future__ import annotations

import ipaddress

import pytest

from agenticnet.core.exceptions import IPAMConflictError
from agenticnet.ipam import IPAMEngine, SubnetRequirement, calculate_subnet, plan_vlsm


@pytest.mark.unit
def test_ipv4_and_ipv6_subnet_calculations() -> None:
    s24 = calculate_subnet("192.168.10.0/24")
    assert s24.network_address == "192.168.10.0"
    assert s24.broadcast_address == "192.168.10.255"
    assert s24.netmask == "255.255.255.0"
    assert s24.wildcard_mask == "0.0.0.255"
    assert s24.usable_hosts == 254
    assert s24.first_usable == "192.168.10.1"
    assert s24.last_usable == "192.168.10.254"

    s31 = calculate_subnet("10.0.0.0/31")
    assert s31.usable_hosts == 2

    s6 = calculate_subnet("2001:db8:cafe:1::/64")
    assert s6.ip_version == 6
    assert s6.prefix_length == 64
    assert s6.first_usable == "2001:db8:cafe:1::1"


@pytest.mark.unit
def test_vlsm_allocation_non_overlapping_and_overflow() -> None:
    plan = plan_vlsm(
        "192.168.10.0/24",
        [
            SubnetRequirement(name="Students", required_hosts=100, vlan_id=10),
            SubnetRequirement(name="Staff", required_hosts=50, vlan_id=20),
            SubnetRequirement(name="Servers", required_hosts=20, vlan_id=30),
            SubnetRequirement(name="WAN-R1-R2", required_hosts=2),
        ],
    )
    assert [a.allocated_cidr for a in plan.allocations] == [
        "192.168.10.0/25",
        "192.168.10.128/26",
        "192.168.10.192/27",
        "192.168.10.224/30",
    ]
    assert plan.allocations[0].gateway == "192.168.10.1"
    assert plan.allocations[0].dhcp_range_start == "192.168.10.2"

    # Verify pairwise disjointness
    nets = [ipaddress.ip_network(a.allocated_cidr) for a in plan.allocations]
    for i in range(len(nets)):
        for j in range(i + 1, len(nets)):
            assert not nets[i].overlaps(nets[j])

    # Overflow must fail clearly
    with pytest.raises(IPAMConflictError):
        plan_vlsm(
            "192.168.10.0/24",
            [
                SubnetRequirement(name="BigA", required_hosts=200),
                SubnetRequirement(name="BigB", required_hosts=100),
            ],
        )


@pytest.mark.unit
def test_ipam_registry_conflict_detection_and_export() -> None:
    ipam = IPAMEngine()
    ipam.register_pool("VLAN10", "10.10.10.0/24", vlan_id=10, gateway="10.10.10.1")

    with pytest.raises(IPAMConflictError):
        ipam.register_pool("Overlap", "10.10.10.128/25")

    ipam.allocate_address("R1", "GigabitEthernet0/0.10", "10.10.10.1/24", allocation_type="static")
    ipam.allocate_address("PC1", "FastEthernet0", "10.10.10.10/24", gateway="10.10.10.1")

    # Duplicate IP rejected
    with pytest.raises(IPAMConflictError):
        ipam.allocate_address("PC2", "FastEthernet0", "10.10.10.10/24")

    # Broadcast address rejected
    with pytest.raises(IPAMConflictError):
        ipam.allocate_address("PC2", "FastEthernet0", "10.10.10.255/24")

    report = ipam.utilization_report()
    assert report.total_pools == 1
    assert report.total_allocations == 2
    assert report.pools[0].allocated_hosts == 2

    md = ipam.export_addressing_table("markdown")
    assert "| R1 | GigabitEthernet0/0.10 | 10.10.10.1 |" in md
    csv_out = ipam.export_addressing_table("csv")
    assert "PC1,FastEthernet0,10.10.10.10" in csv_out


@pytest.mark.unit
def test_ipam_dual_stack_ipv4_and_ipv6_coexistence_on_same_interface() -> None:
    ipam = IPAMEngine()
    ipam.register_pool("LAN-V4", "192.168.50.0/24", gateway="192.168.50.1")
    ipam.register_pool("LAN-V6", "2001:db8:50::/64", gateway="2001:db8:50::1")

    v4_alloc = ipam.allocate_address("R1", "GigabitEthernet0/0", "192.168.50.1/24")
    v6_alloc = ipam.allocate_address("R1", "GigabitEthernet0/0", "2001:db8:50::1/64")

    assert v4_alloc.ip_version == 4
    assert v6_alloc.ip_version == 6
    assert len(ipam.state.allocations) == 2

    # Updating IPv6 on the same interface updates only the IPv6 record, preserving IPv4
    v6_updated = ipam.allocate_address("R1", "GigabitEthernet0/0", "2001:db8:50::254/64")
    assert v6_updated.allocation_id == v6_alloc.allocation_id
    ips_on_if = {
        a.ip_version: a.ip_address
        for a in ipam.state.allocations.values()
        if a.device_name == "R1" and a.interface_name == "GigabitEthernet0/0"
    }
    assert ips_on_if == {4: "192.168.50.1", 6: "2001:db8:50::254"}
