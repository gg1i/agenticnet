"""Unit tests for the verified Packet Tracer DeviceCatalog and interface normalization."""

from __future__ import annotations

import pytest

from agenticnet.core.enums import ConfigCapability, DeviceCategory
from agenticnet.core.exceptions import DeviceModelError, InterfaceError
from agenticnet.devices import DEFAULT_CATALOG


@pytest.mark.unit
def test_catalog_models_and_aliases() -> None:
    assert DEFAULT_CATALOG.resolve_model_name("2960") == "2960-24TT"
    assert DEFAULT_CATALOG.resolve_model_name("Cisco 2911") == "2911"
    assert DEFAULT_CATALOG.resolve_model_name("3560") == "3560-24PS"
    assert DEFAULT_CATALOG.resolve_model_name("pc") == "PC-PT"

    routers = DEFAULT_CATALOG.list_profiles(category=DeviceCategory.ROUTER)
    assert {r.model for r in routers} >= {"2911", "1941", "2811", "4321", "Router-PT"}

    with pytest.raises(DeviceModelError):
        DEFAULT_CATALOG.get_profile("NonExistentRouter9999")


@pytest.mark.unit
def test_interface_normalization_and_logical_ports() -> None:
    assert DEFAULT_CATALOG.normalize_interface_name("2911", "gi0/0") == "GigabitEthernet0/0"
    assert DEFAULT_CATALOG.normalize_interface_name("2911", "s0/0/0") == "Serial0/0/0"
    assert DEFAULT_CATALOG.normalize_interface_name("2911", "Gi0/0.10") == "GigabitEthernet0/0.10"
    assert DEFAULT_CATALOG.normalize_interface_name("2911", "lo0") == "Loopback0"
    assert DEFAULT_CATALOG.normalize_interface_name("2960-24TT", "fa0/12") == "FastEthernet0/12"
    assert DEFAULT_CATALOG.normalize_interface_name("2960-24TT", "vl99") == "Vlan99"
    assert DEFAULT_CATALOG.normalize_interface_name("3560-24PS", "po1") == "Port-channel1"

    with pytest.raises(InterfaceError):
        DEFAULT_CATALOG.normalize_interface_name("2960-24TT", "GigabitEthernet0/0.10")

    with pytest.raises(InterfaceError):
        DEFAULT_CATALOG.normalize_interface_name("PC-PT", "GigabitEthernet0/0")


@pytest.mark.unit
def test_device_capability_differences() -> None:
    sw_l2 = DEFAULT_CATALOG.get_profile("2960-24TT")
    sw_l3 = DEFAULT_CATALOG.get_profile("3560-24PS")
    pc = DEFAULT_CATALOG.get_profile("PC-PT")

    assert sw_l2.supports(ConfigCapability.VLANS)
    assert not sw_l2.supports(ConfigCapability.OSPF)
    assert not sw_l2.supports(ConfigCapability.TRUNK_ENCAP_DOT1Q)

    assert sw_l3.supports(ConfigCapability.OSPF)
    assert sw_l3.supports(ConfigCapability.TRUNK_ENCAP_DOT1Q)
    assert sw_l3.supports(ConfigCapability.INTER_VLAN_SVI)

    assert not pc.supports(ConfigCapability.IOS_CLI)
    assert pc.supports(ConfigCapability.DHCP_CLIENT)


@pytest.mark.unit
def test_pt_822_catalog_profiles_quirks_and_vendor_metadata() -> None:
    models = {p.model for p in DEFAULT_CATALOG.list_profiles()}
    assert len(models) == 30
    assert {
        "5506-X",
        "HomeGateway-PT",
        "Smartphone-PT",
        "TabletPC-PT",
        "Analog-Phone-PT",
    } <= models

    # WRT300N vendor metadata & capability report fields
    wrt = DEFAULT_CATALOG.get_profile("WRT300N")
    assert wrt.vendor == "Linksys"
    wrt_rep = DEFAULT_CATALOG.capability_report("WRT300N")
    assert wrt_rep.vendor == "Linksys"
    assert wrt_rep.target_mode == "packet_tracer"

    # Analog-Phone-PT is distinct from Home-VOIP-PT (ATA)
    assert DEFAULT_CATALOG.resolve_model_name("analog-phone-pt") == "Analog-Phone-PT"
    assert DEFAULT_CATALOG.resolve_model_name("home-voip-pt") == "Home-VOIP-PT"
    analog = DEFAULT_CATALOG.get_profile("Analog-Phone-PT")
    assert not analog.supports(ConfigCapability.STATIC_IP)

    # 4321 supports NIM-2T Serial0/1/0..1 + quirks/modules_supported
    r4321 = DEFAULT_CATALOG.get_profile("4321")
    assert DEFAULT_CATALOG.normalize_interface_name("4321", "se0/1/0") == "Serial0/1/0"
    assert "NIM-2T" in r4321.modules_supported
    assert any("securityk9" in q for q in r4321.quirks)

    # 3650-24PS AC-POWER-SUPPLY quirk documented
    sw3650 = DEFAULT_CATALOG.get_profile("3650-24PS")
    assert "AC-POWER-SUPPLY" in sw3650.modules_supported
    assert any("AC-POWER-SUPPLY" in q for q in sw3650.quirks)

    # 5506-X routed firewall ports + Mgmt1/1 normalization
    assert DEFAULT_CATALOG.normalize_interface_name("5506-X", "gi1/1") == "GigabitEthernet1/1"
    assert DEFAULT_CATALOG.normalize_interface_name("5506-X", "mgmt1/1") == "Management1/1"
    assert DEFAULT_CATALOG.normalize_interface_name("5506-X", "Gi1/1.20") == "GigabitEthernet1/1.20"
