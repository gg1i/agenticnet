"""Intelligent Diagnostics and Self-Repair Engine (Phase 4)."""

from agenticnet.diagnostics.engine import DiagnosticsEngine
from agenticnet.diagnostics.models import (
    DiagnosticCategory,
    DiagnosticFinding,
    DiagnosticReport,
    DiagnosticSeverity,
    RepairAction,
    RepairProposal,
)
from agenticnet.diagnostics.rules import (
    check_disabled_interfaces_with_ip,
    check_link_subnet_mismatch,
    check_missing_default_gateways,
    check_trunk_mode_mismatch,
    check_vlan_trunk_native_mismatch,
)

__all__ = [
    "DiagnosticCategory",
    "DiagnosticFinding",
    "DiagnosticReport",
    "DiagnosticSeverity",
    "DiagnosticsEngine",
    "RepairAction",
    "RepairProposal",
    "check_disabled_interfaces_with_ip",
    "check_link_subnet_mismatch",
    "check_missing_default_gateways",
    "check_trunk_mode_mismatch",
    "check_vlan_trunk_native_mismatch",
]
