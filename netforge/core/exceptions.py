"""Structured exception hierarchy with descriptive error codes and remediation hints."""

from __future__ import annotations

from typing import Any


class NetForgeError(Exception):
    """Base exception for all NetForge domain and runtime failures."""

    error_code: str = "NETFORGE_ERROR"

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        details: dict[str, Any] | None = None,
        remediation: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if error_code is not None:
            self.error_code = error_code
        self.details: dict[str, Any] = details or {}
        self.remediation = remediation

    def to_dict(self) -> dict[str, Any]:
        """Serialize exception details into a structured dictionary."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
            "remediation": self.remediation,
        }


class ValidationError(NetForgeError):
    """Raised when input arguments or schemas fail validation."""

    error_code = "VALIDATION_ERROR"


class PermissionDeniedError(NetForgeError):
    """Raised when a tool exceeds the active security permission policy."""

    error_code = "PERMISSION_DENIED"


class ApprovalRequiredError(NetForgeError):
    """Raised when a destructive or risky operation requires explicit confirmation."""

    error_code = "APPROVAL_REQUIRED"


class ProjectNotOpenError(NetForgeError):
    """Raised when an operation requires an open project."""

    error_code = "PROJECT_NOT_OPEN"


class ProjectAlreadyExistsError(NetForgeError):
    """Raised when creating or importing a project whose ID collides unless overwrite is set."""

    error_code = "PROJECT_EXISTS"


class ProjectNotFoundError(NetForgeError):
    """Raised when a requested project ID or file does not exist."""

    error_code = "PROJECT_NOT_FOUND"


class DeviceNotFoundError(NetForgeError):
    """Raised when a referenced device does not exist in the active topology."""

    error_code = "DEVICE_NOT_FOUND"


class DeviceModelError(NetForgeError):
    """Raised when an unknown or unsupported device model is requested."""

    error_code = "UNSUPPORTED_DEVICE_MODEL"


class InterfaceError(NetForgeError):
    """Raised when an interface is missing, invalid, or already occupied."""

    error_code = "INTERFACE_ERROR"


class TopologyConflictError(NetForgeError):
    """Raised when a topology mutation violates physical or graph constraints."""

    error_code = "TOPOLOGY_CONFLICT"


class IPAMConflictError(NetForgeError):
    """Raised on overlapping subnets, address exhaustion, or duplicate IP allocations."""

    error_code = "IPAM_CONFLICT"


class IOSConfigError(NetForgeError):
    """Raised when IOS configuration parameters violate device capabilities or syntax."""

    error_code = "IOS_CONFIG_ERROR"


class StorageError(NetForgeError):
    """Raised on SQLite persistence, schema migration, or export/import failures."""

    error_code = "STORAGE_ERROR"


class AdapterUnavailableError(NetForgeError):
    """Raised when a Packet Tracer GUI/console adapter is unavailable or disconnected."""

    error_code = "ADAPTER_UNAVAILABLE"
