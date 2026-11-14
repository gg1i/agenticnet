"""Structured Cisco IOS configuration generation, validation, and snapshot history."""

from __future__ import annotations

from netforge.ios.generators import IOSGenerator
from netforge.ios.history import ConfigHistory
from netforge.ios.models import (
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
from netforge.ios.validators import parse_cli_output, validate_raw_commands

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
