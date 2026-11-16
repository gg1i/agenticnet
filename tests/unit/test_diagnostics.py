"""Unit tests for Network Diagnostics and Self-Repair Engine."""

from __future__ import annotations

import pytest

from netforge.console.engine import DeviceConsoleEngine
from netforge.console.transport import SimulatedConsoleTransport
from netforge.core.exceptions import ApprovalRequiredError
from netforge.diagnostics.engine import DiagnosticsEngine
from netforge.ipam.engine import IPAMEngine
from netforge.topology.engine import TopologyEngine


@pytest.mark.unit
def test_diagnostic_rules_detection_and_repair_proposals() -> None:
    topo = TopologyEngine()
    topo.add_device("R1", "2911")
    topo.add_device("SW1", "2960-24TT")
    topo.add_device("PC1", "PC-PT")

    # Issue 1: Interface with IP configured but shutdown (admin_up=False)
    if_r1 = topo.model.devices["R1"].interfaces["GigabitEthernet0/0"]
    if_r1.ipv4_address = "192.168.1.1"
    if_r1.subnet_mask = "255.255.255.0"
    if_r1.admin_up = False

    # Issue 2: End device missing default gateway
    if_pc = topo.model.devices["PC1"].interfaces["FastEthernet0"]
    if_pc.ipv4_address = "192.168.1.50"
    if_pc.subnet_mask = "255.255.255.0"
    if_pc.default_gateway = None

    ipam = IPAMEngine()
    ipam.register_pool("LAN1", "192.168.1.0/24", default_gateway="192.168.1.1")

    engine = DiagnosticsEngine()
    report = engine.run_diagnostics(topology=topo, ipam=ipam)

    assert report.clean is False
    codes = {f.code for f in report.findings}
    assert "INTERFACE_ADMIN_DOWN_WITH_IP" in codes
    assert "HOST_MISSING_DEFAULT_GATEWAY" in codes
    assert len(report.proposed_repairs) >= 2


@pytest.mark.unit
def test_link_subnet_mismatch_and_native_vlan_mismatch() -> None:
    topo = TopologyEngine()
    topo.add_device("R1", "2911")
    topo.add_device("R2", "2911")
    topo.add_device("SW1", "2960-24TT")
    topo.add_device("SW2", "2960-24TT")

    # Connect R1 and R2 with mismatched subnets
    topo.connect("R1", "GigabitEthernet0/0", "R2", "GigabitEthernet0/0")
    topo.model.devices["R1"].interfaces["GigabitEthernet0/0"].ipv4_address = "10.0.0.1"
    topo.model.devices["R1"].interfaces["GigabitEthernet0/0"].subnet_mask = "255.255.255.252"

    topo.model.devices["R2"].interfaces["GigabitEthernet0/0"].ipv4_address = "192.168.0.2"
    topo.model.devices["R2"].interfaces["GigabitEthernet0/0"].subnet_mask = "255.255.255.0"

    # Connect SW1 and SW2 with trunk native VLAN mismatch
    topo.connect("SW1", "GigabitEthernet0/1", "SW2", "GigabitEthernet0/1")
    if_sw1 = topo.model.devices["SW1"].interfaces["GigabitEthernet0/1"]
    if_sw1.is_trunk = True
    if_sw1.vlan_id = 10

    if_sw2 = topo.model.devices["SW2"].interfaces["GigabitEthernet0/1"]
    if_sw2.is_trunk = True
    if_sw2.vlan_id = 20

    engine = DiagnosticsEngine()
    report = engine.run_diagnostics(topology=topo)

    codes = {f.code for f in report.findings}
    assert "LINK_SUBNET_MISMATCH" in codes
    assert "NATIVE_VLAN_MISMATCH" in codes


@pytest.mark.unit
def test_repair_execution_safety_gate_and_state_sync() -> None:
    transport = SimulatedConsoleTransport()
    transport.seed_device("R1", hostname="R1", mode="privileged_exec")
    console = DeviceConsoleEngine(transport=transport)
    engine = DiagnosticsEngine(console_engine=console)

    topo = TopologyEngine()
    topo.add_device("R1", "2911")
    iface = topo.model.devices["R1"].interfaces["GigabitEthernet0/0"]
    iface.ipv4_address = "10.0.0.1"
    iface.subnet_mask = "255.255.255.0"
    iface.admin_up = False

    report = engine.run_diagnostics(topology=topo)
    proposal = report.proposed_repairs[0]

    # Non-disruptive repair ("no shutdown") executes cleanly
    res = engine.execute_repair(proposal.proposal_id, confirm=False, topology=topo)
    assert res["all_succeeded"] is True
    assert iface.admin_up is True

    # Disruptive repair requiring confirmation
    topo.add_device("R2", "2911")
    topo.connect("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1")
    topo.model.devices["R1"].interfaces["GigabitEthernet0/1"].ipv4_address = "172.16.0.1"
    topo.model.devices["R1"].interfaces["GigabitEthernet0/1"].subnet_mask = "255.255.255.252"
    topo.model.devices["R2"].interfaces["GigabitEthernet0/1"].ipv4_address = "10.10.10.2"
    topo.model.devices["R2"].interfaces["GigabitEthernet0/1"].subnet_mask = "255.255.255.0"

    rep2 = engine.run_diagnostics(topology=topo)
    mismatch_prop = next(p for p in rep2.proposed_repairs if "Re-address" in p.summary)
    assert mismatch_prop.requires_approval is True

    with pytest.raises(ApprovalRequiredError):
        engine.execute_repair(mismatch_prop.proposal_id, confirm=False, topology=topo)

    # With confirmation, executes cleanly
    res_ok = engine.execute_repair(mismatch_prop.proposal_id, confirm=True, topology=topo)
    assert res_ok["all_succeeded"] is True


@pytest.mark.unit
def test_ipam_gateway_lookup_out_of_subnet_gateway_and_trunk_mode_mismatch() -> None:
    topo = TopologyEngine()
    r1 = topo.add_device("R1", "2911")
    sw_core = topo.add_device("SW-CORE", "3560-24PS")
    sw_acc = topo.add_device("SW-ACC", "2960-24TT")
    pc = topo.add_device("PC-ENG", "PC-PT")

    # Router-on-a-stick link: trunk on switch, non-trunk on router must NOT flag trunk mismatch
    topo.connect("R1", "Gi0/0", "SW-ACC", "Gi0/1")
    sw_acc.interfaces["GigabitEthernet0/1"].is_trunk = True

    # Switch-to-switch link: SW-ACC is trunk, SW-CORE is NOT trunk -> MUST flag TRUNK_MODE_MISMATCH
    topo.connect("SW-ACC", "Gi0/2", "SW-CORE", "Gi0/1")
    sw_acc.interfaces["GigabitEthernet0/2"].is_trunk = True
    sw_core.interfaces["GigabitEthernet0/1"].is_trunk = False

    # Host missing GW in non-192.168.1.0/24 pool tests ipam.state.pools.values() lookup
    pc.interfaces["FastEthernet0"].ipv4_address = "10.50.20.10"
    pc.interfaces["FastEthernet0"].subnet_mask = "255.255.255.0"
    pc.interfaces["FastEthernet0"].default_gateway = None

    # Second host with out-of-subnet gateway
    pc2 = topo.add_device("PC-BADGW", "PC-PT")
    pc2.interfaces["FastEthernet0"].ipv4_address = "10.50.20.11"
    pc2.interfaces["FastEthernet0"].subnet_mask = "255.255.255.0"
    pc2.interfaces["FastEthernet0"].default_gateway = "10.50.99.1"

    ipam = IPAMEngine()
    ipam.register_pool("ENG-VLAN20", "10.50.20.0/24", default_gateway="10.50.20.254")

    report = DiagnosticsEngine().run_diagnostics(topology=topo, ipam=ipam)
    codes = {f.code for f in report.findings}
    assert "TRUNK_MODE_MISMATCH" in codes
    assert "HOST_MISSING_DEFAULT_GATEWAY" in codes
    assert "HOST_GATEWAY_OUTSIDE_SUBNET" in codes

    # Verify router interface wasn't flagged as trunk mismatch
    trunk_mismatches = [f for f in report.findings if f.code == "TRUNK_MODE_MISMATCH"]
    assert len(trunk_mismatches) == 1
    assert trunk_mismatches[0].target_device == "SW-CORE"
    trunk_repair = next(
        p for p in report.proposed_repairs if p.finding_id == trunk_mismatches[0].finding_id
    )
    assert "switchport trunk encapsulation dot1q" in trunk_repair.actions[0].command_sequence

    # Verify IPAM pool gateway (.254) was suggested rather than hardcoded 192.168.1.1
    missing_gw = next(f for f in report.findings if f.code == "HOST_MISSING_DEFAULT_GATEWAY")
    missing_repair = next(
        p for p in report.proposed_repairs if p.finding_id == missing_gw.finding_id
    )
    assert missing_repair.actions[0].command_sequence == [
        "ipconfig 10.50.20.10 255.255.255.0 10.50.20.254"
    ]

    bad_gw = next(f for f in report.findings if f.code == "HOST_GATEWAY_OUTSIDE_SUBNET")
    bad_repair = next(p for p in report.proposed_repairs if p.finding_id == bad_gw.finding_id)
    assert bad_repair.requires_approval is True
    assert bad_repair.actions[0].command_sequence == [
        "ipconfig 10.50.20.11 255.255.255.0 10.50.20.254"
    ]
    assert r1.name == "R1"
