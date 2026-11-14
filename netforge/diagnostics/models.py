"""Data models for network diagnostics, ranked root causes, and self-repair proposals."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field

from netforge.core.enums import StateLevel


def _utc_now() -> datetime:
    return datetime.now(UTC)


class DiagnosticSeverity(StrEnum):
    """Severity rating for a detected network problem."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class DiagnosticCategory(StrEnum):
    """Categorization of network diagnostic issues."""

    ADDRESSING_IPAM = "addressing_ipam"
    INTERFACE_PHYSICAL = "interface_physical"
    VLAN_TRUNKING = "vlan_trunking"
    ROUTING = "routing"
    OSPF_ADJACENCY = "ospf_adjacency"
    ACL_SECURITY = "acl_security"
    CONNECTIVITY = "connectivity"


class DiagnosticFinding(BaseModel):
    """A single diagnosed network anomaly or misconfiguration with supporting evidence."""

    finding_id: str = Field(default_factory=lambda: f"find_{uuid4().hex[:8]}")
    category: DiagnosticCategory
    severity: DiagnosticSeverity
    code: str
    target_device: str | None = None
    target_interface: str | None = None
    summary: str
    evidence: list[str] = Field(default_factory=list)
    probable_causes: list[str] = Field(default_factory=list)
    recommended_fix: str = ""
    repaired: bool = False
    detected_at: datetime = Field(default_factory=_utc_now)


class RepairAction(BaseModel):
    """Single corrective step inside an executable repair proposal."""

    action_id: str = Field(default_factory=lambda: f"act_{uuid4().hex[:6]}")
    target_device: str
    target_interface: str | None = None
    command_sequence: list[str]
    description: str
    is_disruptive: bool = False
    verification_commands: list[str] = Field(default_factory=list)


class RepairProposal(BaseModel):
    """Structured, safe repair plan mapping to a specific diagnostic finding."""

    proposal_id: str = Field(default_factory=lambda: f"rep_{uuid4().hex[:8]}")
    finding_id: str
    target_device: str
    summary: str
    actions: list[RepairAction] = Field(default_factory=list)
    requires_approval: bool = False
    approval_reason: str | None = None
    executed: bool = False
    verified: bool = False
    state_level: StateLevel = StateLevel.PLANNED
    created_at: datetime = Field(default_factory=_utc_now)


class DiagnosticReport(BaseModel):
    """Complete diagnostic assessment for a network project or subsystem."""

    project_id: str | None = None
    state_level: StateLevel = StateLevel.PLANNED
    findings: list[DiagnosticFinding] = Field(default_factory=list)
    proposed_repairs: list[RepairProposal] = Field(default_factory=list)
    clean: bool = True
    assessed_at: datetime = Field(default_factory=_utc_now)
