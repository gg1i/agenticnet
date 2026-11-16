"""Structured Cisco IOS configuration generation, validation, and snapshot history."""

from __future__ import annotations

from agenticnet.ios.generators import IOSGenerator
from agenticnet.ios.history import ConfigHistory
from agenticnet.ios.models import (
    AccessPortSpec,
    AclRule,
    AclSpec,
    CLIDiagnostic,
    ConfigDiffResult,
    ConfigSnapshot,
    DhcpPoolSpec,
    EigrpConfigSpec,
    EtherChannelSpec,
    InterfaceConfigSpec,
    NatPatSpec,
    OspfConfigSpec,
    OspfNetworkEntry,
    RenderedCommandSequence,
    RipConfigSpec,
    SshConfigSpec,
    StaticRouteEntry,
    StpSpec,
    TrunkPortSpec,
    VlanSpec,
)
from agenticnet.ios.validators import parse_cli_output, validate_raw_commands

__all__ = [
    "AccessPortSpec",
    "AclRule",
    "AclSpec",
    "CLIDiagnostic",
    "ConfigDiffResult",
    "ConfigHistory",
    "ConfigSnapshot",
    "DhcpPoolSpec",
    "EigrpConfigSpec",
    "EtherChannelSpec",
    "IOSGenerator",
    "InterfaceConfigSpec",
    "NatPatSpec",
    "OspfConfigSpec",
    "OspfNetworkEntry",
    "RenderedCommandSequence",
    "RipConfigSpec",
    "SshConfigSpec",
    "StaticRouteEntry",
    "StpSpec",
    "TrunkPortSpec",
    "VlanSpec",
    "parse_cli_output",
    "validate_raw_commands",
]
