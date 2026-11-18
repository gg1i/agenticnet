"""Declarative JSON schema and Pydantic validation models for `verify_lab` requirements."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agenticnet.security.validation import validate_cli_safe_text, validate_ping_target


class _BaseRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str | None = Field(
        default=None,
        description="Optional caller-assigned requirement identifier.",
    )
    task_id: str | None = Field(
        default=None,
        description=(
            "Optional lab task identifier attached to this requirement for coverage tracking."
        ),
    )
    description: str | None = Field(
        default=None,
        description="Optional human-readable explanation of what this requirement checks.",
    )

    @model_validator(mode="after")
    def _validate_cli_safe_fields(self) -> _BaseRequirement:
        skip_fields = {"contains", "must_not_contain", "description"}
        for fname in type(self).model_fields:
            if fname in skip_fields:
                continue
            val = getattr(self, fname)
            if isinstance(val, str):
                validate_cli_safe_text(val, field_name=fname)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        validate_cli_safe_text(item, field_name=fname)
        return self


class InterfaceUpRequirement(_BaseRequirement):
    """Require an interface on `device` to be `up/up` in `show ip interface brief`."""

    type: Literal["interface_up"]
    device: str = Field(min_length=1)
    interface: str = Field(min_length=1)
    expected_status: str = Field(default="up")
    expected_protocol: str = Field(default="up")


class IpAssignedRequirement(_BaseRequirement):
    """Require `interface` on `device` to carry `ip` (and optionally be `up/up`)."""

    type: Literal["ip_assigned"]
    device: str = Field(min_length=1)
    interface: str = Field(min_length=1)
    ip: str = Field(min_length=1, description="Expected IPv4 address (bare or with /prefix).")
    require_up: bool = Field(default=True)


class RouteExistsRequirement(_BaseRequirement):
    """Require `network` (CIDR or IP) to appear in `show ip route` on `device`."""

    type: Literal["route_exists"]
    device: str = Field(min_length=1)
    network: str = Field(min_length=1, description="Expected route prefix e.g. '192.168.20.0/24'.")
    next_hop: str | None = Field(default=None)
    outgoing_interface: str | None = Field(default=None)
    protocol_code: str | None = Field(default=None, description="Optional route code e.g. S, C, O.")


class VlanExistsRequirement(_BaseRequirement):
    """Require `vlan_id` to exist in `show vlan brief` on switch `device`."""

    type: Literal["vlan_exists"]
    device: str = Field(min_length=1)
    vlan_id: int = Field(ge=1, le=4094)
    name: str | None = Field(default=None)
    status: str = Field(default="active")
    ports: list[str] = Field(default_factory=list)


class DhcpBindingRequirement(_BaseRequirement):
    """Require at least one (or a specific) lease in `show ip dhcp binding` on `device`."""

    type: Literal["dhcp_binding"]
    device: str = Field(min_length=1)
    ip: str | None = Field(default=None)
    client_id: str | None = Field(default=None)
    min_bindings: int = Field(default=1, ge=1)


class ReachableRequirement(_BaseRequirement):
    """Require ICMP reachability from source device `from` to target IP `to`."""

    type: Literal["reachable"]
    source: str = Field(alias="from", min_length=1, description="Source device name.")
    target: str = Field(alias="to", min_length=1, description="Destination IPv4 address.")
    min_received: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def _validate_target(self) -> ReachableRequirement:
        self.target = validate_ping_target(self.target)
        return self


class ConfigContainsRequirement(_BaseRequirement):
    """Require text line(s)/substring(s) in `show running-config` (or within a section)."""

    type: Literal["config_contains"]
    device: str = Field(min_length=1)
    contains: list[str] = Field(default_factory=list)
    must_not_contain: list[str] = Field(default_factory=list)
    section: str | None = Field(
        default=None,
        description="Optional running-config section header prefix, e.g. 'interface Gi0/0.20'.",
    )

    @model_validator(mode="before")
    @classmethod
    def _coerce_contains(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("contains"), str):
            data = {**data, "contains": [data["contains"]]}
        return data

    @model_validator(mode="after")
    def _require_pattern(self) -> ConfigContainsRequirement:
        if not self.contains and not self.must_not_contain:
            raise ValueError("config_contains requires non-empty `contains` or `must_not_contain`.")
        return self


class TelephonyServiceRequirement(_BaseRequirement):
    """Require CME `telephony-service` active state on `device` via `show telephony-service`."""

    type: Literal["telephony_service"]
    device: str = Field(min_length=1)
    source_address: str | None = Field(default=None)
    source_port: int | None = Field(default=None, ge=1, le=65535)
    min_ephones: int | None = Field(default=None, ge=1)
    min_dn: int | None = Field(default=None, ge=1)


class EphoneRegisteredRequirement(_BaseRequirement):
    """Require SCCP phone definition/registration on `device` via `show ephone`."""

    type: Literal["ephone_registered"]
    device: str = Field(min_length=1)
    ephone_id: int | None = Field(default=None, ge=1)
    number: str | None = Field(default=None)
    mac_address: str | None = Field(default=None)
    require_registered: bool = Field(
        default=True,
        description="When True, require status == 'REGISTERED'; when False, existence suffices.",
    )


class TracerouteHopsRequirement(_BaseRequirement):
    """Require hop-by-hop path verification via IOS `traceroute` or PC `tracert`."""

    type: Literal["traceroute_hops"]
    source: str = Field(alias="from", min_length=1, description="Source device name.")
    target: str = Field(alias="to", min_length=1, description="Destination IP or hostname.")
    expected_hops: list[str] = Field(default_factory=list)
    max_hops: int | None = Field(default=None, ge=1, le=30)
    require_completed: bool = Field(default=True)

    @model_validator(mode="after")
    def _validate_target(self) -> TracerouteHopsRequirement:
        self.target = validate_ping_target(self.target)
        return self


class TrunkExistsRequirement(_BaseRequirement):
    """Require an active 802.1Q trunk in `show interfaces trunk` on switch `device`."""

    type: Literal["trunk_exists"]
    device: str = Field(min_length=1)
    interface: str = Field(min_length=1)
    native_vlan: int | None = Field(default=None, ge=1, le=4094)
    allowed_vlans: list[int] = Field(default_factory=list)


class StpRootRequirement(_BaseRequirement):
    """Require Spanning-Tree root bridge status for `vlan_id` in `show spanning-tree`."""

    type: Literal["stp_root"]
    device: str = Field(min_length=1)
    vlan_id: int = Field(default=1, ge=1, le=4094)
    expect_root: bool = Field(default=True)


class HostIpconfigRequirement(_BaseRequirement):
    """Require IP/gateway/DNS configuration in PT PC `ipconfig /all` output."""

    type: Literal["host_ipconfig"]
    device: str = Field(min_length=1)
    ip: str | None = Field(default=None)
    default_gateway: str | None = Field(default=None)
    dns_server: str | None = Field(default=None)


LabRequirement = Annotated[
    InterfaceUpRequirement
    | IpAssignedRequirement
    | RouteExistsRequirement
    | VlanExistsRequirement
    | DhcpBindingRequirement
    | ReachableRequirement
    | ConfigContainsRequirement
    | TelephonyServiceRequirement
    | EphoneRegisteredRequirement
    | TracerouteHopsRequirement
    | TrunkExistsRequirement
    | StpRootRequirement
    | HostIpconfigRequirement,
    Field(discriminator="type"),
]


class VerifyLabRequest(BaseModel):
    """Canonical top-level declarative lab verification specification."""

    model_config = ConfigDict(extra="forbid")

    lab_name: str | None = Field(default=None, description="Optional descriptive lab title.")
    task_ids: list[str] | None = Field(
        default=None,
        description="Optional ordered list of expected task IDs for requirement coverage checks.",
    )
    requirements: list[LabRequirement] = Field(min_length=1)


SCHEMA_EXAMPLES: list[dict[str, Any]] = [
    {
        "title": "Two-router static routing verification",
        "payload": {
            "lab_name": "Static Routing",
            "requirements": [
                {
                    "id": "r1_link_up",
                    "type": "interface_up",
                    "device": "R1",
                    "interface": "GigabitEthernet0/0",
                },
                {
                    "id": "r1_lan_ip",
                    "type": "ip_assigned",
                    "device": "R1",
                    "interface": "GigabitEthernet0/1",
                    "ip": "10.10.1.1",
                },
                {
                    "id": "r1_static_to_lan2",
                    "type": "route_exists",
                    "device": "R1",
                    "network": "10.10.2.0/24",
                    "next_hop": "10.10.12.2",
                    "protocol_code": "S",
                },
                {
                    "id": "r1_to_r2_lan",
                    "type": "reachable",
                    "from": "R1",
                    "to": "10.10.2.1",
                },
            ],
        },
    },
    {
        "title": "Switch VLAN + DHCP verification",
        "payload": {
            "lab_name": "VLAN and DHCP",
            "requirements": [
                {
                    "type": "vlan_exists",
                    "device": "SW1",
                    "vlan_id": 20,
                    "name": "WORKSTATIONS",
                    "ports": ["FastEthernet0/2"],
                },
                {
                    "type": "dhcp_binding",
                    "device": "GW",
                    "min_bindings": 1,
                },
                {
                    "type": "config_contains",
                    "device": "GW",
                    "section": "ip dhcp pool WORKSTATIONS",
                    "contains": ["network 172.16.20.0 255.255.255.0", "default-router 172.16.20.1"],
                },
            ],
        },
    },
    {
        "title": "Minimal CME Voice verification",
        "payload": {
            "lab_name": "Voice Lab",
            "requirements": [
                {
                    "type": "telephony_service",
                    "device": "R_VOICE",
                    "source_address": "10.50.100.1",
                    "source_port": 2000,
                },
                {
                    "type": "ephone_registered",
                    "device": "R_VOICE",
                    "ephone_id": 1,
                    "number": "1001",
                    "require_registered": True,
                },
            ],
        },
    },
]


def get_verify_requirements_schema() -> dict[str, Any]:
    """Return the JSON Schema and worked examples for `verify_lab` requirements."""
    return {
        "schema_version": "1.1.0",
        "json_schema": VerifyLabRequest.model_json_schema(),
        "supported_types": [
            "interface_up",
            "ip_assigned",
            "route_exists",
            "vlan_exists",
            "dhcp_binding",
            "reachable",
            "config_contains",
            "telephony_service",
            "ephone_registered",
            "traceroute_hops",
            "trunk_exists",
            "stp_root",
            "host_ipconfig",
        ],
        "examples": SCHEMA_EXAMPLES,
    }


def normalize_requirements_payload(
    requirements: dict[str, Any] | list[dict[str, Any]] | VerifyLabRequest,
) -> VerifyLabRequest:
    """Validate either `{requirements: [...]}` or a bare list `[...]` of requirements."""
    if isinstance(requirements, VerifyLabRequest):
        return requirements
    if isinstance(requirements, list):
        return VerifyLabRequest.model_validate({"requirements": requirements})
    if isinstance(requirements, dict):
        if "type" in requirements and "requirements" not in requirements:
            return VerifyLabRequest.model_validate({"requirements": [requirements]})
        return VerifyLabRequest.model_validate(requirements)
    raise TypeError("requirements must be a dict, list of requirement dicts, or VerifyLabRequest.")
