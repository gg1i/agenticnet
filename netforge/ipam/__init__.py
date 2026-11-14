"""IP Address Management (IPAM) engine for IPv4/IPv6 planning and conflict detection."""

from __future__ import annotations

from netforge.ipam.engine import IPAMEngine, calculate_subnet, plan_vlsm
from netforge.ipam.models import (
    IPAllocation,
    IPAMState,
    IPAMUtilizationReport,
    IPAMValidationIssue,
    SubnetCalculation,
    SubnetPool,
    SubnetRequirement,
    SubnetUtilizationEntry,
    VLSMAllocationEntry,
    VLSMPlanResult,
)

__all__ = [
    "IPAMEngine",
    "IPAMState",
    "IPAMUtilizationReport",
    "IPAMValidationIssue",
    "IPAllocation",
    "SubnetCalculation",
    "SubnetPool",
    "SubnetRequirement",
    "SubnetUtilizationEntry",
    "VLSMAllocationEntry",
    "VLSMPlanResult",
    "calculate_subnet",
    "plan_vlsm",
]
