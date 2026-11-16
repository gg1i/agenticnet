"""Core domain abstractions, error types, settings, and logging."""

from __future__ import annotations

from agenticnet.core.enums import (
    CableType,
    ConfigCapability,
    DeviceCategory,
    OperationStatus,
    PermissionTier,
    PortMedia,
    StateLevel,
)
from agenticnet.core.exceptions import (
    AdapterUnavailableError,
    AgenticNetError,
    ApprovalRequiredError,
    DeviceModelError,
    DeviceNotFoundError,
    InterfaceError,
    IOSConfigError,
    IPAMConflictError,
    NetForgeError,
    PermissionDeniedError,
    ProjectAlreadyExistsError,
    ProjectNotFoundError,
    ProjectNotOpenError,
    StorageError,
    TopologyConflictError,
    ValidationError,
)
from agenticnet.core.logging import configure_logging
from agenticnet.core.models import (
    DiagnosticRecord,
    ExecutionLogEntry,
    OperationError,
    OperationResult,
    ProjectMetadata,
    new_operation_id,
)
from agenticnet.core.settings import AgenticNetSettings, NetForgeSettings

__all__ = [
    "AdapterUnavailableError",
    "AgenticNetError",
    "AgenticNetSettings",
    "ApprovalRequiredError",
    "CableType",
    "ConfigCapability",
    "DeviceCategory",
    "DeviceModelError",
    "DeviceNotFoundError",
    "DiagnosticRecord",
    "ExecutionLogEntry",
    "IOSConfigError",
    "IPAMConflictError",
    "InterfaceError",
    "NetForgeError",
    "NetForgeSettings",
    "OperationError",
    "OperationResult",
    "OperationStatus",
    "PermissionDeniedError",
    "PermissionTier",
    "PortMedia",
    "ProjectAlreadyExistsError",
    "ProjectMetadata",
    "ProjectNotFoundError",
    "ProjectNotOpenError",
    "StateLevel",
    "StorageError",
    "TopologyConflictError",
    "ValidationError",
    "configure_logging",
    "new_operation_id",
]
