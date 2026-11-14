"""Core domain abstractions, error types, settings, and logging."""

from __future__ import annotations

from netforge.core.enums import (
    CableType,
    ConfigCapability,
    DeviceCategory,
    OperationStatus,
    PermissionTier,
    PortMedia,
    StateLevel,
)
from netforge.core.exceptions import (
    AdapterUnavailableError,
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
from netforge.core.logging import configure_logging
from netforge.core.models import (
    DiagnosticRecord,
    ExecutionLogEntry,
    OperationError,
    OperationResult,
    ProjectMetadata,
    new_operation_id,
)
from netforge.core.settings import NetForgeSettings

__all__ = [
    "AdapterUnavailableError",
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
