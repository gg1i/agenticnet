"""Unit tests for enterprise Packet Tracer 8.2.2 device catalog & bridge extensions."""

from __future__ import annotations

import pytest

from agenticnet.adapters.script_bridge import (
    PT_DEVICE_TYPES,
    HttpScriptBridgeBackend,
    HttpScriptBridgeServer,
    resolve_device_type,
)
from agenticnet.core.enums import ConfigCapability, DeviceCategory
from agenticnet.devices import DEFAULT_CATALOG
from agenticnet.topology.engine import TopologyEngine


@pytest.mark.unit
def test_enterprise_models_and_interfaces() -> None:
    assert DEFAULT_CATALOG.resolve_model_name("4331") == "ISR4331"
    assert DEFAULT_CATALOG.resolve_model_name("asa 5505") == "5505"
    assert DEFAULT_CATALOG.resolve_model_name("2504") == "WLC-2504"
    assert DEFAULT_CATALOG.resolve_model_name("3504") == "WLC-3504"
    assert DEFAULT_CATALOG.resolve_model_name("lap") == "LAP-PT"
    assert DEFAULT_CATALOG.resolve_model_name("cloud") == "Cloud-PT"

    assert DEFAULT_CATALOG.normalize_interface_name("ISR4331", "gi0/0/2") == "GigabitEthernet0/0/2"
    assert DEFAULT_CATALOG.normalize_interface_name("ISR4331", "se0/1/0") == "Serial0/1/0"
    assert DEFAULT_CATALOG.normalize_interface_name("5505", "eth0/7") == "Ethernet0/7"
    assert DEFAULT_CATALOG.normalize_interface_name("5505", "vl2") == "Vlan2"
    assert DEFAULT_CATALOG.normalize_interface_name("WLC-2504", "gi1") == "GigabitEthernet1"
    assert DEFAULT_CATALOG.normalize_interface_name("WLC-2504", "management") == "management"
    assert DEFAULT_CATALOG.normalize_interface_name("LAP-PT", "dot11radio0") == "Dot11Radio0"

    asa = DEFAULT_CATALOG.get_profile("5505")
    assert asa.category == DeviceCategory.FIREWALL
    assert asa.supports(ConfigCapability.ASA_FIREWALL)
    assert not asa.supports(ConfigCapability.IOS_CLI)

    isr4331 = DEFAULT_CATALOG.get_profile("ISR4331")
    assert isr4331.supports(ConfigCapability.BGP)
    assert isr4331.supports(ConfigCapability.IPSEC_VPN)
    assert isr4331.supports(ConfigCapability.ZONE_BASED_FIREWALL)


@pytest.mark.unit
def test_pt_device_type_codes_and_topology_cabling() -> None:
    assert PT_DEVICE_TYPES["asa"] == 27
    assert PT_DEVICE_TYPES["firewall"] == 27
    assert PT_DEVICE_TYPES["wlc"] == 41
    assert PT_DEVICE_TYPES["lightweight_ap"] == 44
    assert resolve_device_type("wlc") == 41
    assert resolve_device_type("asa") == 27

    topo = TopologyEngine()
    topo.add_device("EDGE1", "ISR4331")
    topo.add_device("FW1", "5505")
    topo.add_device("WLC1", "WLC-2504")
    topo.add_device("SW1", "3560-24PS")

    link1 = topo.connect("EDGE1", "Gi0/0/0", "FW1", "Ethernet0/0")
    link2 = topo.connect("WLC1", "Gi1", "SW1", "Gi0/1")
    assert link1.cable_type.value == "straight_through"
    assert link2.cable_type.value == "straight_through"


@pytest.mark.unit
def test_wait_for_connection_nonblocking_when_unstarted() -> None:
    srv = HttpScriptBridgeServer()
    backend = HttpScriptBridgeBackend(srv, auto_launch_pt=False)
    assert backend.wait_for_connection(timeout_seconds=0.1) is False


@pytest.mark.unit
def test_asa_5506x_and_wireless_iot_cabling_parity() -> None:
    asa_5506 = DEFAULT_CATALOG.get_profile("5506-X")
    assert asa_5506.category == DeviceCategory.FIREWALL
    assert asa_5506.supports(ConfigCapability.ASA_FIREWALL)
    assert not asa_5506.supports(ConfigCapability.IOS_CLI)
    assert asa_5506.supports_subinterfaces is True
    assert asa_5506.supports_svi is False

    topo = TopologyEngine()
    topo.add_device("SW1", "2960-24TT")
    topo.add_device("FW5506", "5506-X")
    topo.add_device("AP1", "LAP-PT")
    topo.add_device("PHONE1", "7960")
    topo.add_device("PC1", "PC-PT")
    topo.add_device("ATA1", "Home-VOIP-PT")
    topo.add_device("HANDSET1", "Analog-Phone-PT")

    # Routed 5506-X (MDI) <-> Switch (MDI-X) uses straight-through
    assert topo.connect("SW1", "Gi0/1", "FW5506", "Gi1/1").cable_type.value == "straight_through"
    # Lightweight AP (MDI) <-> Switch (MDI-X) uses straight-through
    assert topo.connect("SW1", "Gi0/2", "AP1", "Gi0").cable_type.value == "straight_through"
    # 7960 Switch port -> Switch, 7960 PC port (MDI-X) -> PC-PT (MDI) both use straight-through
    assert topo.connect("SW1", "Fa0/1", "PHONE1", "Switch").cable_type.value == "straight_through"
    assert topo.connect("PHONE1", "PC", "PC1", "Fa0").cable_type.value == "straight_through"
    # Home-VOIP-PT Phone <-> Analog-Phone-PT Phone uses RJ-11 phone cable
    assert topo.connect("ATA1", "Phone", "HANDSET1", "Phone").cable_type.value == "phone"
