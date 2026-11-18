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


@pytest.mark.unit
def test_simulation_ten_new_parsers_transcript_lookup_and_ping_target_guard() -> None:
    from agenticnet.core.exceptions import ValidationError
    from agenticnet.simulation.parsers import (
        parse_ipconfig_all,
        parse_show_access_lists,
        parse_show_cdp_neighbors,
        parse_show_etherchannel_summary,
        parse_show_interfaces_trunk,
        parse_show_ip_bgp_summary,
        parse_show_ip_nat_translations,
        parse_show_spanning_tree,
        parse_show_standby_brief,
        parse_traceroute_output,
    )

    # Wrapped + ECMP show ip route & OSPF neighbor prompt echo stripping
    ecmp_routes = parse_show_ip_route(
        "O    192.168.200.0/24\n"
        "           [110/2] via 10.0.0.2, 00:01:10, GigabitEthernet0/0\n"
        "           [110/2] via 10.0.0.6, 00:01:08, GigabitEthernet0/1\n"
    )
    assert len(ecmp_routes["routes"]) == 2  # type: ignore[arg-type]
    assert ecmp_routes["routes"][1].next_hop == "10.0.0.6"  # type: ignore[index]

    ospf_echo = parse_show_ip_ospf_neighbor(
        "R1#show ip ospf neighbor\r\n"
        "Neighbor ID     Pri   State           Dead Time   Address         Interface\r\n"
        "2.2.2.2           1   FULL/BDR        00:00:38    10.0.0.2        Gi0/0\r\n"
        "R1#\r\n"
    )
    assert len(ospf_echo) == 1 and ospf_echo[0].neighbor_id == "2.2.2.2"

    # 1. Traceroute (IOS + PC tracert)
    tr_ios = parse_traceroute_output(
        "Tracing the route to 10.10.2.1\n"
        "  1 10.10.12.2 4 msec 0 msec 4 msec\n"
        "  2 10.10.2.1 4 msec 4 msec 4 msec\n"
    )
    assert tr_ios.parser_kind == "cisco_ios"
    assert tr_ios.completed is True
    assert [h.ip_address for h in tr_ios.hops] == ["10.10.12.2", "10.10.2.1"]

    tr_pc = parse_traceroute_output(
        "Tracing route to 10.10.2.1 over a maximum of 30 hops:\n"
        "  1   1 ms   0 ms   1 ms   10.10.1.1\n"
        "  2   *      *      *      Request timed out.\n"
        "  3   2 ms   1 ms   2 ms   10.10.2.1\n"
        "Trace complete.\n"
    )
    assert tr_pc.parser_kind == "pt_pc_cmd"
    assert tr_pc.completed is True
    assert tr_pc.hops[1].timed_out is True

    # 2. PC ipconfig /all
    ipcfg = parse_ipconfig_all(
        "FastEthernet0 Connection:(default port)\n"
        "   Physical Address................: 0001.42AB.1122\n"
        "   IPv4 Address....................: 192.168.10.25\n"
        "   Subnet Mask.....................: 255.255.255.0\n"
        "   Default Gateway.................: 192.168.10.1\n"
        "   DNS Servers.....................: 8.8.8.8\n"
    )
    assert len(ipcfg) == 1
    assert ipcfg[0].ipv4_address == "192.168.10.25"
    assert ipcfg[0].default_gateway == "192.168.10.1"
    assert ipcfg[0].dns_servers == ["8.8.8.8"]

    # 3. show interfaces trunk
    trunks = parse_show_interfaces_trunk(
        "Port        Mode         Encapsulation  Status        Native vlan\n"
        "Gi0/1       on           802.1q         trunking      99\n\n"
        "Port        Vlans allowed on trunk\n"
        "Gi0/1       10,20-22,99\n\n"
        "Port        Vlans in spanning tree forwarding state and not pruned\n"
        "Gi0/1       10,20\n"
    )
    assert len(trunks) == 1
    assert trunks[0].native_vlan == 99
    assert trunks[0].allowed_vlans == [10, 20, 21, 22, 99]
    assert trunks[0].forwarding_vlans == [10, 20]

    # 4. show spanning-tree
    stp = parse_show_spanning_tree(
        "VLAN0010\n"
        "  Spanning tree enabled protocol rstp\n"
        "  Root ID    Priority    24586\n"
        "             Address     0001.42AA.1111\n"
        "             This bridge is the root\n"
        "  Bridge ID  Priority    24586\n"
        "             Address     0001.42AA.1111\n"
        "Interface        Role Sts Cost      Prio.Nbr Type\n"
        "---------------- ---- --- --------- -------- --------------------------------\n"
        "Gi0/1            Desg FWD 4         128.25   P2p\n"
    )
    assert len(stp) == 1 and stp[0].is_root_bridge is True and stp[0].ports[0].role == "Desg"

    # 5. show etherchannel summary
    po = parse_show_etherchannel_summary(
        "Group  Port-channel  Protocol    Ports\n"
        "------+-------------+-----------+----------------------------------------------\n"
        "1      Po1(SU)           LACP   Gi0/1(P) Gi0/2(P)\n"
        "2      Po2(RU)           LACP   Gi0/3(P) Gi0/4(D)\n"
    )
    assert len(po) == 2
    assert po[0].layer == "L2" and po[0].in_use is True
    assert po[1].layer == "L3" and po[1].members[1].flag == "D"

    # 6. show cdp neighbors (including wrapped long Device ID)
    cdp = parse_show_cdp_neighbors(
        "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n"
        "SW-ACCESS-FLOOR1-LONGNAME\n"
        "                 Gig 0/1            155         S I       2960      Gig 0/2\n"
        "R2               Gig 0/0            140         R S       C2900     Gig 0/0\n"
    )
    assert len(cdp) == 2
    assert cdp[0].device_id == "SW-ACCESS-FLOOR1-LONGNAME"
    assert cdp[0].local_interface == "Gig0/1"

    # 7. show ip bgp summary
    bgp = parse_show_ip_bgp_summary(
        "Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n"
        "203.0.113.2     4 65002      15      16        5    0    0 00:10:02        3\n"
        "203.0.113.6     4 65003       0       0        0    0    0 never    Active\n"
    )
    assert bgp[0].established is True and bgp[0].prefixes_received == 3
    assert bgp[1].established is False and bgp[1].state_or_prefixes == "Active"

    # 8. show standby brief
    hsrp = parse_show_standby_brief(
        "Interface   Grp  Pri P State    Active          Standby         Virtual IP\n"
        "Gi0/0       10   120 P Active   local           192.168.10.3    192.168.10.1\n"
    )
    assert len(hsrp) == 1 and hsrp[0].preempt is True and hsrp[0].state == "Active"

    # 9. show access-lists
    acls = parse_show_access_lists(
        "Extended IP access list EDGE_FILTER\n"
        "    10 deny tcp any any eq telnet (12 matches)\n"
        "    20 permit ip any any (45 matches)\n"
    )
    assert len(acls) == 2 and acls[0].matches == 12 and acls[0].action == "deny"

    # 10. show ip nat translations
    nats = parse_show_ip_nat_translations(
        "Pro  Inside global     Inside local       Outside local      Outside global\n"
        "tcp 203.0.113.2:1025   192.168.1.10:1025  198.51.100.5:443   198.51.100.5:443\n"
    )
    assert len(nats) == 1 and nats[0].protocol == "tcp"

    # SimulationEngine: ping injection guard & multi-transcript lookup when user_exec runs 'enable'
    transport = SimulatedConsoleTransport()
    transport.seed_device("R1", hostname="R1", mode="user_exec")
    sim = SimulationEngine(console_engine=DeviceConsoleEngine(transport=transport))
    int_res = sim.inspect_interface_status("R1")
    assert int_res["state_level"] == "verified"

    with pytest.raises(ValidationError):
        sim.run_connectivity_check("R1", "10.0.0.1\nreload")
    with pytest.raises(ValidationError):
        sim.run_connectivity_check("R1", "10.0.0.1 ; reload")
