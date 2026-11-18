"""Unit tests for the NetworkX-backed TopologyEngine."""

from __future__ import annotations

import pytest

from agenticnet.core.enums import CableType
from agenticnet.core.exceptions import InterfaceError, TopologyConflictError
from agenticnet.topology import TopologyEngine


@pytest.mark.unit
def test_topology_crud_and_mdi_cable_selection() -> None:
    topo = TopologyEngine()
    topo.add_device("R1", "2911")
    topo.add_device("R2", "2911")
    topo.add_device("SW1", "2960-24TT")
    topo.add_device("SW2", "2960-24TT")
    topo.add_device("PC1", "PC-PT")

    l_r_sw = topo.connect("R1", "Gi0/0", "SW1", "Gi0/1")
    assert l_r_sw.cable_type == CableType.STRAIGHT_THROUGH

    l_sw_pc = topo.connect("SW1", "Fa0/1", "PC1", "Fa0")
    assert l_sw_pc.cable_type == CableType.STRAIGHT_THROUGH

    l_r_r = topo.connect("R1", "Gi0/1", "R2", "Gi0/0")
    assert l_r_r.cable_type == CableType.CROSSOVER

    l_sw_sw = topo.connect("SW1", "Gi0/2", "SW2", "Gi0/1")
    assert l_sw_sw.cable_type == CableType.CROSSOVER

    l_ser = topo.connect("R1", "Se0/0/0", "R2", "Se0/0/0")
    assert l_ser.cable_type == CableType.SERIAL_DCE
    assert l_ser.clock_rate == 64000


@pytest.mark.unit
def test_topology_rejects_occupied_self_and_media_mismatch() -> None:
    topo = TopologyEngine()
    topo.add_device("R1", "2911")
    topo.add_device("R2", "2911")
    topo.add_device("LAP1", "Laptop-PT")

    topo.connect("R1", "Gi0/0", "R2", "Gi0/0")

    # Occupied port
    with pytest.raises(InterfaceError):
        topo.connect("R1", "Gi0/0", "R2", "Gi0/1")

    # Self-loop
    with pytest.raises(TopologyConflictError):
        topo.connect("R1", "Gi0/1", "R1", "Gi0/2")

    # Serial vs Ethernet media mismatch
    with pytest.raises(TopologyConflictError):
        topo.connect("R1", "Se0/0/0", "R2", "Gi0/1")

    # Wireless port cannot be wired
    with pytest.raises(TopologyConflictError):
        topo.connect("R1", "Gi0/1", "LAP1", "Wireless0")


@pytest.mark.unit
def test_topology_analysis_stp_cycles_layout_and_roundtrip() -> None:
    topo = TopologyEngine()
    topo.add_device("SW1", "2960-24TT")
    topo.add_device("SW2", "2960-24TT")
    topo.add_device("SW3", "2960-24TT")
    topo.add_device("PC1", "PC-PT")

    topo.connect("SW1", "Gi0/1", "SW2", "Gi0/1")
    topo.connect("SW2", "Gi0/2", "SW3", "Gi0/1")
    topo.connect("SW3", "Gi0/2", "SW1", "Gi0/2")
    topo.connect("SW1", "Fa0/1", "PC1", "Fa0")

    positions = topo.auto_layout("hierarchical")
    assert positions["PC1"].y > positions["SW1"].y

    analysis = topo.analyze(source="PC1", target="SW3")
    assert analysis.connected_components == 1
    assert len(analysis.switching_cycles) == 1
    assert analysis.shortest_path == ["PC1", "SW1", "SW3"]
    assert ("PC1", "SW1") in analysis.bridges

    issues = topo.validate()
    assert any(i.code == "SWITCHING_LOOP_DETECTED" for i in issues)

    yaml_text = topo.export_data(fmt="yaml")
    restored = TopologyEngine.from_exported_data(yaml_text)
    assert len(restored.model.devices) == 4
    assert len(restored.model.connections) == 4

    mermaid = topo.to_mermaid()
    assert "flowchart LR" in mermaid
    assert "SW1" in mermaid


@pytest.mark.unit
def test_topology_trunk_sync_site_zone_merge_and_diff() -> None:
    base = TopologyEngine()
    r1 = base.add_device("R1", "2911", site_zone="Core")
    sw1 = base.add_device("SW1", "2960-24TT", site_zone="Access")
    assert r1.site_zone == "Core"

    # vlan_mode="trunk" and is_trunk synchronize automatically on InterfaceState
    sw1_gi = sw1.interfaces["GigabitEthernet0/1"]
    sw1_gi_synced = sw1_gi.model_validate({**sw1_gi.model_dump(), "vlan_mode": "trunk"})
    assert sw1_gi_synced.is_trunk is True
    sw1.interfaces["GigabitEthernet0/1"] = sw1_gi_synced
    r1.interfaces["GigabitEthernet0/0"].ipv6_address = "2001:db8:1::1/64"

    base.connect("R1", "Gi0/0", "SW1", "Gi0/1")

    branch = TopologyEngine()
    branch.add_device("R1", "2911")
    branch.add_device("PC1", "PC-PT", site_zone="Access")
    branch.connect("R1", "Gi0/1", "PC1", "Fa0")

    diff_before = base.diff_topology(branch)
    assert diff_before["identical"] is False
    assert diff_before["has_changes"] is True
    assert diff_before["devices_added"] == ["PC1"]
    assert diff_before["devices_removed"] == ["SW1"]

    merged = base.merge_topology(branch)
    assert merged["devices_added"] == ["PC1"]
    assert "PC1" in base.model.devices
    assert len(base.model.connections) == 2

    # target_mode mismatch rejected unless allow_mode_mismatch=True
    gns_topo = TopologyEngine()
    gns_topo.model.target_mode = "gns3"
    with pytest.raises(TopologyConflictError):
        base.merge_topology(gns_topo)
