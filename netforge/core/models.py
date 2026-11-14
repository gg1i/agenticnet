"""Core Pydantic models for operation results, metadata, logging, and diagnostics."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from netforge.core.enums import OperationStatus, PermissionTier, StateLevel

ExecutionBackend = Literal["offline_model", "script_backend", "gui_backend", "hybrid"]


def utc_now() -> datetime:
    """Return current UTC timestamp."""
    return datetime.now(UTC)


def new_operation_id() -> str:
    """Generate a unique traceable operation identifier."""
    return f"op_{uuid4().hex[:12]}"


class OperationError(BaseModel):
    """Structured error payload attached to failed operations."""

    error_code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None = None


class OperationResult(BaseModel):
    """Uniform response envelope returned by all NetForge MCP tools.

    Explicitly tracks `state_level` (`planned`, `executed`, `verified`) and requires
    concrete `evidence` before reporting verified network behavior.
    """

    operation_id: str = Field(default_factory=new_operation_id)
    tool_name: str
    timestamp: datetime = Field(default_factory=utc_now)
    success: bool
    status: OperationStatus
    state_level: StateLevel = StateLevel.PLANNED
    execution_backend: ExecutionBackend = "offline_model"
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[OperationError] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)

    @classmethod
    def ok(
        cls,
        tool_name: str,
        summary: str,
        *,
        data: dict[str, Any] | None = None,
        state_level: StateLevel = StateLevel.PLANNED,
        execution_backend: ExecutionBackend = "offline_model",
        warnings: list[str] | None = None,
        evidence: list[str] | None = None,
        operation_id: str | None = None,
    ) -> OperationResult:
        """Create a successful OperationResult."""
        return cls(
            operation_id=operation_id or new_operation_id(),
            tool_name=tool_name,
            success=True,
            status=OperationStatus.SUCCEEDED,
            state_level=state_level,
            execution_backend=execution_backend,
            summary=summary,
            data=data or {},
            warnings=warnings or [],
            evidence=evidence or [],
        )

    @classmethod
    def fail(
        cls,
        tool_name: str,
        summary: str,
        *,
        error_code: str = "OPERATION_FAILED",
        details: dict[str, Any] | None = None,
        remediation: str | None = None,
        status: OperationStatus = OperationStatus.FAILED,
        state_level: StateLevel = StateLevel.PLANNED,
        execution_backend: ExecutionBackend = "offline_model",
        operation_id: str | None = None,
    ) -> OperationResult:
        """Create a failed or blocked OperationResult."""
        return cls(
            operation_id=operation_id or new_operation_id(),
            tool_name=tool_name,
            success=False,
            status=status,
            state_level=state_level,
            execution_backend=execution_backend,
            summary=summary,
            errors=[
                OperationError(
                    error_code=error_code,
                    message=summary,
                    details=details or {},
                    remediation=remediation,
                )
            ],
        )


class ProjectMetadata(BaseModel):
    """Metadata describing a NetForge network automation project."""

    project_id: str
    name: str
    description: str = ""
    schema_version: str = "1.0.0"
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    packet_tracer_file: str | None = None
    author: str = ""
    tags: list[str] = Field(default_factory=list)


class ExecutionLogEntry(BaseModel):
    """Audit log entry stored in SQLite for tool calls and system actions."""

    operation_id: str
    project_id: str | None = None
    tool_name: str
    permission_tier: PermissionTier
    status: OperationStatus
    state_level: StateLevel
    summary: str
    params_redacted: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0
    created_at: datetime = Field(default_factory=utc_now)


class DiagnosticRecord(BaseModel):
    """Persistent diagnostic finding recorded for a project."""

    diagnostic_id: str = Field(default_factory=lambda: f"diag_{uuid4().hex[:10]}")
    category: str
    severity: str
    target_device: str | None = None
    probable_cause: str
    evidence: list[str] = Field(default_factory=list)
    proposed_fix: str | None = None
    resolved: bool = False
    created_at: datetime = Field(default_factory=utc_now)
