"""Graph topology data models independent of Packet Tracer's GUI."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from netforge.core.enums import CableType, DeviceCategory, PortMedia, StateLevel


class Position2D(BaseModel):
    """2D logical canvas coordinates (Packet Tracer Logical Workspace scale)."""

    x: float = 100.0
    y: float = 100.0


class InterfaceState(BaseModel):
    """Tracked state of a device interface within the topology."""

    name: str
    short_name: str
    media: PortMedia
    speed_mbps: int
    admin_up: bool = True
    connected_to_connection_id: str | None = None
    peer_device: str | None = None
    peer_interface: str | None = None
    ip_address: str | None = None
    subnet_mask: str | None = None
    default_gateway: str | None = None
    description: str = ""
    vlan_mode: str | None = None
    access_vlan: int | None = None
    trunk_allowed_vlans: str | None = None
    native_vlan: int | None = None
    is_trunk: bool = False
    state_level: StateLevel = StateLevel.PLANNED

    @property
    def ipv4_address(self) -> str | None:
        """Alias for ip_address."""
        return self.ip_address

    @ipv4_address.setter
    def ipv4_address(self, value: str | None) -> None:
        self.ip_address = value

    @property
    def vlan_id(self) -> int | None:
        """Alias for access_vlan or native_vlan."""
        return self.native_vlan if self.is_trunk else self.access_vlan

    @vlan_id.setter
    def vlan_id(self, value: int | None) -> None:
        if self.is_trunk:
            self.native_vlan = value
        else:
            self.access_vlan = value


class DeviceNode(BaseModel):
    """Normalized network device node in the topology graph."""

    name: str
    model: str
    category: DeviceCategory
    role: str = ""
    position: Position2D = Field(default_factory=Position2D)
    interfaces: dict[str, InterfaceState] = Field(default_factory=dict)
    state_level: StateLevel = StateLevel.PLANNED
    metadata: dict[str, Any] = Field(default_factory=dict)


class LinkEdge(BaseModel):
    """Normalized interconnection link between two device interfaces."""

    connection_id: str
    source_device: str
    source_interface: str
    target_device: str
    target_interface: str
    cable_type: CableType
    dce_side: str | None = None
    clock_rate: int | None = None
    state_level: StateLevel = StateLevel.PLANNED
    notes: str = ""

    @property
    def device_a(self) -> str:
        """Alias for source_device."""
        return self.source_device

    @property
    def interface_a(self) -> str:
        """Alias for source_interface."""
        return self.source_interface

    @property
    def device_b(self) -> str:
        """Alias for target_device."""
        return self.target_device

    @property
    def interface_b(self) -> str:
        """Alias for target_interface."""
        return self.target_interface


class TopologyValidationIssue(BaseModel):
    """Single validation finding produced by TopologyEngine.validate()."""

    severity: str  # "error" | "warning" | "info"
    code: str
    message: str
    affected_devices: list[str] = Field(default_factory=list)
    affected_connections: list[str] = Field(default_factory=list)
    remediation: str | None = None


class TopologyAnalysis(BaseModel):
    """Graph-theoretic analysis metrics computed with NetworkX."""

    device_count: int
    connection_count: int
    connected_components: int
    isolated_devices: list[str]
    bridges: list[tuple[str, str]]
    articulation_points: list[str]
    switching_cycles: list[list[str]]
    degree_by_device: dict[str, int]
    shortest_path: list[str] | None = None


class TopologyModel(BaseModel):
    """Serializable topology snapshot."""

    devices: dict[str, DeviceNode] = Field(default_factory=dict)
    connections: dict[str, LinkEdge] = Field(default_factory=dict)
