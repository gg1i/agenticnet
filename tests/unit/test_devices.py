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
