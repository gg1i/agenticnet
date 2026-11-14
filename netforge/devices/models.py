"""Device capability models and interface templates."""

from __future__ import annotations

from pydantic import BaseModel, Field

from netforge.core.enums import ConfigCapability, DeviceCategory, PortMedia


class InterfaceTemplate(BaseModel):
    """Specification for a physical or default interface on a device model."""

    name: str
    short_name: str
    media: PortMedia
    speed_mbps: int
    supports_switchport: bool = False
    supports_routed_ip: bool = True
    notes: str = ""


class DeviceProfile(BaseModel):
    """Verified Packet Tracer device model capability profile."""

    model: str
    display_name: str
    vendor: str = "Cisco"
    category: DeviceCategory
    packet_tracer_group: str
    aliases: list[str] = Field(default_factory=list)
    interfaces: list[InterfaceTemplate] = Field(default_factory=list)
    capabilities: set[ConfigCapability] = Field(default_factory=set)
    restrictions: list[str] = Field(default_factory=list)
    max_vlans: int = 0
    supports_subinterfaces: bool = False
    supports_svi: bool = False
    supports_loopback: bool = False
    supports_port_channel: bool = False
    verified_in_pt: str = "8.2.2"
    cli_prompt_pattern: str | None = None

    def supports(self, capability: ConfigCapability) -> bool:
        """Check whether this device profile supports a configuration capability."""
        return capability in self.capabilities


class DeviceCapabilityReport(BaseModel):
    """Structured summary of what a device model supports and restricts."""

    model: str
    display_name: str
    category: DeviceCategory
    packet_tracer_group: str
    physical_interfaces: list[str]
    capabilities: list[str]
    restrictions: list[str]
    supports_ios_cli: bool
    supports_routing: bool
    supports_vlans: bool
