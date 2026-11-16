"""Unit tests for Packet Tracer Simulation Engine, parsers, and connectivity tests."""

from __future__ import annotations

import pytest

from agenticnet.console.engine import DeviceConsoleEngine
from agenticnet.console.transport import SimulatedConsoleTransport
from agenticnet.simulation.engine import SimulationEngine
from agenticnet.simulation.models import SimulationSource, SimulatorMode
from agenticnet.simulation.parsers import (
    parse_ios_ping_output,
    parse_pc_ping_output,
    parse_ping_output,
    parse_show_arp,
    parse_show_ip_int_brief,
    parse_show_ip_ospf_neighbor,
    parse_show_ip_route,
    parse_show_vlan_brief,
    parse_simulation_event_lines,
)
from agenticnet.topology.engine import TopologyEngine


@pytest.mark.unit
def test_ping_and_event_parsers() -> None:
    ios_sample = (
        "Type escape sequence to abort.\n"
        "Sending 5, 100-byte ICMP Echos to 192.168.1.1, timeout is 2 seconds:\n"
        "!!!!!\n"
        "Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms\n"
    )
    res_ios = parse_ios_ping_output(ios_sample)
    assert res_ios.reached is True
    assert res_ios.received == 5
    assert res_ios.transmitted == 5
    assert res_ios.loss_percent == 0.0
    assert res_ios.target_ip == "192.168.1.1"

    pc_sample = (
        "Pinging 10.0.0.1 with 32 bytes of data:\n"
        "Reply from 10.0.0.1: bytes=32 time=2ms TTL=128\n"
        "Reply from 10.0.0.1: bytes=32 time=1ms TTL=128\n"
        "Ping statistics for 10.0.0.1:\n"
        "    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\n"
        "Approximate round trip times in milli-seconds:\n"
        "    Minimum = 1ms, Maximum = 2ms, Average = 1ms\n"
    )
    res_pc = parse_pc_ping_output(pc_sample)
    assert res_pc.reached is True
    assert res_pc.received == 4
    assert res_pc.loss_percent == 0.0

    auto_parsed = parse_ping_output(ios_sample)
    assert auto_parsed.parser_kind == "cisco_ios"

    events_raw = (
        "0.000\tPC1\tSwitch1\tICMP\tICMP Echo Request\n0.002\tSwitch1\tR1\tICMP\tForwarding Frame\n"
    )
    events = parse_simulation_event_lines(events_raw)
    assert len(events) == 2
    assert events[0].at_device == "Switch1"
    assert events[1].at_device == "R1"


@pytest.mark.unit
def test_table_parsers_route_arp_interface_vlan_ospf() -> None:
    route_raw = (
        "Gateway of last resort is 10.0.0.1 to network 0.0.0.0\n"
        "C    192.168.10.0/24 is directly connected, GigabitEthernet0/0\n"
        "O    172.16.1.0/24 [110/2] via 10.0.0.2, 00:05:12, GigabitEthernet0/1\n"
    )
    rt = parse_show_ip_route(route_raw)
    assert rt["gateway_of_last_resort"] is not None
    assert len(rt["routes"]) == 2  # type: ignore[arg-type]

    arp_raw = "Internet  192.168.10.50          10   0001.42ab.cd12  ARPA  GigabitEthernet0/0\n"
    arps = parse_show_arp(arp_raw)
    assert len(arps) == 1
    assert arps[0].ip_address == "192.168.10.50"

    brief_raw = (
        "Interface                  IP-Address      OK? Method Status                Protocol\n"
        "GigabitEthernet0/0         192.168.10.1    YES manual up                    up\n"
        "GigabitEthernet0/1         unassigned      YES unset  administratively down down\n"
    )
    briefs = parse_show_ip_int_brief(brief_raw)
    assert len(briefs) == 2
    assert briefs[0].is_up_up is True
    assert briefs[1].status == "administratively down"

    vlan_raw = (
        "VLAN Name                             Status    Ports\n"
        "---- -------------------------------- --------- -------------------------------\n"
        "1    default                          active    Fa0/1, Fa0/2\n"
        "10   Engineering                      active    Fa0/3\n"
    )
    vlans = parse_show_vlan_brief(vlan_raw)
    assert len(vlans) == 2
    assert vlans[1].vlan_id == 10

    ospf_raw = (
        "Neighbor ID     Pri   State           Dead Time   Address         Interface\n"
        "1.1.1.1           1   FULL/DR         00:00:34    10.0.0.2        GigabitEthernet0/1\n"
    )
    nbrs = parse_show_ip_ospf_neighbor(ospf_raw)
    assert len(nbrs) == 1
    assert nbrs[0].neighbor_id == "1.1.1.1"


@pytest.mark.unit
def test_simulation_engine_offline_and_cli_modes() -> None:
    transport = SimulatedConsoleTransport()
    transport.seed_device("R1", hostname="R1", mode="privileged_exec")
    console = DeviceConsoleEngine(transport=transport)
    sim = SimulationEngine(console_engine=console)

    mode_res = sim.set_mode("simulation")
    assert mode_res["mode"] == "simulation"
    assert sim.current_mode == SimulatorMode.SIMULATION

    sim.stop_simulation()
    assert sim.current_mode == SimulatorMode.REALTIME

    pdu = sim.create_packet("PC1", "192.168.1.1", protocol="ICMP")
    assert pdu["packet"]["source_device"] == "PC1"

    # Live console test
    res_live = sim.run_connectivity_check("R1", "10.0.0.2")
    assert res_live["verified_in_pt"] is True
    assert res_live["simulation_source"] == SimulationSource.PACKET_TRACER_CLI.value
    assert res_live["reachable"] is True

    # Offline topology check
    topo = TopologyEngine()
    topo.add_device("R_A", "2911")
    topo.add_device("R_B", "2911")
    topo.connect("R_A", "GigabitEthernet0/0", "R_B", "GigabitEthernet0/0")
    topo.model.devices["R_B"].interfaces["GigabitEthernet0/0"].ipv4_address = "172.16.0.2"

    sim_offline = SimulationEngine()
    res_offline = sim_offline.run_connectivity_check(
        "R_A", "172.16.0.2", topology=topo, allow_offline_estimation=True
    )
    assert res_offline["verified_in_pt"] is False
    assert res_offline["simulation_source"] == SimulationSource.OFFLINE_TOPOLOGY_CHECK.value
    assert res_offline["reachable"] is True
    assert res_offline["path_hops"] == ["R_A", "R_B"]
