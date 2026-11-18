"""Pydantic data models for AgenticNet IP Address Management (IPAM)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SubnetCalculation(BaseModel):
    """Detailed subnet metrics for an IPv4 or IPv6 CIDR block."""

    cidr: str
    ip_version: int
    network_address: str
    broadcast_address: str | None = None
    netmask: str
    wildcard_mask: str | None = None
    prefix_length: int
    total_addresses: int
    usable_hosts: int
    first_usable: str | None = None
    last_usable: str | None = None
    is_private: bool


class SubnetRequirement(BaseModel):
    """Host capacity requirement used as input to VLSM planning."""

    name: str
    required_hosts: int = Field(ge=1)
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    description: str = ""
    reserve_gateway: str = "first"  # "first" | "last" | "none"


class SubnetPool(BaseModel):
    """Registered subnet pool in a project's IPAM database."""

    pool_id: str
    name: str
    cidr: str
    ip_version: int
    vlan_id: int | None = None
    gateway: str | None = None
    netmask: str
    wildcard_mask: str | None = None
    first_usable: str | None = None
    last_usable: str | None = None
    usable_hosts: int
    dns_servers: list[str] = Field(default_factory=list)
    dhcp_pool_name: str | None = None
    excluded_ranges: list[tuple[str, str]] = Field(default_factory=list)
    description: str = ""

    @property
    def default_gateway(self) -> str | None:
        """Alias for gateway."""
        return self.gateway


class IPAllocation(BaseModel):
    """Assigned IP address bound to a device interface."""

    allocation_id: str
    device_name: str
    interface_name: str
    ip_address: str
    ip_version: int = 4
    prefix_length: int
    subnet_mask: str
    cidr: str
    pool_id: str | None = None
    gateway: str | None = None
    vlan_id: int | None = None
    allocation_type: str = "static"  # "static" | "svi" | "loopback" | "dhcp_reserved"


class VLSMAllocationEntry(BaseModel):
    """Single subnet allocated inside a VLSM plan."""

    name: str
    vlan_id: int | None = None
    required_hosts: int
    allocated_cidr: str
    network_address: str
    netmask: str
    wildcard_mask: str | None = None
    broadcast_address: str | None = None
    gateway: str | None = None
    usable_hosts: int
    first_usable: str | None = None
    last_usable: str | None = None
    dhcp_range_start: str | None = None
    dhcp_range_end: str | None = None
    wasted_hosts: int


class VLSMPlanResult(BaseModel):
    """Complete result of a VLSM calculation."""

    base_cidr: str
    total_base_addresses: int
    total_allocated_addresses: int
    utilization_percent: float
    allocations: list[VLSMAllocationEntry]


class IPAMValidationIssue(BaseModel):
    """Validation finding detected across IPAM pools and allocations."""

    severity: str  # "error" | "warning"
    code: str
    message: str
    affected_devices: list[str] = Field(default_factory=list)
    remediation: str | None = None


class SubnetUtilizationEntry(BaseModel):
    """Per-pool utilization metrics."""

    pool_id: str
    name: str
    cidr: str
    vlan_id: int | None
    usable_hosts: int
    allocated_hosts: int
    available_hosts: int
    utilization_percent: float


class IPAMUtilizationReport(BaseModel):
    """Summary utilization report across all project IPAM pools."""

    total_pools: int
    total_allocations: int
    pools: list[SubnetUtilizationEntry]
    unpooled_allocations: list[IPAllocation]
    issues: list[IPAMValidationIssue]


class IPAMState(BaseModel):
    """Serializable IPAM state stored inside a AgenticNet project."""

    pools: dict[str, SubnetPool] = Field(default_factory=dict)
    allocations: dict[str, IPAllocation] = Field(default_factory=dict)
