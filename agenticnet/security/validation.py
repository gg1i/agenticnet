"""Input sanitization and safe filesystem boundary checks."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from agenticnet.core.exceptions import ValidationError

_DEVICE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,62}$")
_PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
_PING_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")


def validate_device_name(name: str) -> str:
    """Validate and normalize a network device hostname/identifier."""
    cleaned = name.strip()
    if not _DEVICE_NAME_RE.match(cleaned):
        raise ValidationError(
            f"Invalid device name {name!r}. Must start with a letter and use only "
            "alphanumerics, '-', '_', or '.' (max 63 chars).",
            details={"device_name": name},
            remediation="Provide a valid hostname such as 'R1', 'SW-CORE-01', or 'PC1'.",
        )
    return cleaned


def validate_project_id(project_id: str) -> str:
    """Validate a project slug identifier."""
    cleaned = project_id.strip().lower()
    if not _PROJECT_ID_RE.match(cleaned):
        raise ValidationError(
            f"Invalid project ID {project_id!r}. "
            "Use lowercase letters, digits, '-' or '_' (2-63 chars).",
            details={"project_id": project_id},
        )
    return cleaned


def validate_cli_safe_text(value: str, *, field_name: str = "value") -> str:
    """Reject CR, LF, and null bytes in single-line Cisco IOS CLI arguments."""
    if not isinstance(value, str):
        raise ValidationError(
            f"{field_name} must be a string.",
            details={"field_name": field_name},
        )
    if any(ch in value for ch in ("\r", "\n", "\x00")):
        raise ValidationError(
            f"{field_name} contains illegal control or newline characters.",
            details={"field_name": field_name},
            remediation=f"Remove newline/carriage-return/null characters from {field_name}.",
        )
    return value


def validate_ping_target(target: str) -> str:
    """Validate an IPv4/IPv6 address or single-token hostname for ping/traceroute."""
    raw = validate_cli_safe_text(target, field_name="ping target")
    cleaned = raw.strip()
    if not cleaned or any(ch.isspace() for ch in cleaned):
        raise ValidationError(
            f"Invalid ping target {target!r}: must be a non-empty IP or hostname without spaces.",
            details={"target": target},
            remediation="Provide a single IPv4/IPv6 address or hostname (e.g. '10.0.0.1').",
        )
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        pass
    if not _PING_HOST_RE.match(cleaned):
        raise ValidationError(
            f"Invalid ping target {target!r}.",
            details={"target": target},
            remediation="Provide a valid IPv4/IPv6 address or safe hostname.",
        )
    return cleaned


def safe_resolve_path(
    target_path: str | Path,
    *,
    base_dir: Path | None = None,
    allow_outside_base: bool = True,
) -> Path:
    """Resolve a path while blocking null bytes and optional traversal outside base_dir."""
    raw = str(target_path)
    if "\x00" in raw:
        raise ValidationError("Path contains illegal null byte.", details={"path": raw})

    resolved = Path(raw).expanduser().resolve()
    if base_dir is not None and not allow_outside_base:
        base_resolved = base_dir.expanduser().resolve()
        try:
            resolved.relative_to(base_resolved)
        except ValueError as exc:
            raise ValidationError(
                f"Path '{resolved}' escapes allowed directory '{base_resolved}'.",
                details={"path": str(resolved), "base_dir": str(base_resolved)},
            ) from exc
    return resolved


def safe_output_path(
    target_path: str | Path,
    *,
    default_base_dir: Path,
    allow_outside_base: bool = False,
) -> Path:
    """Resolve an output path, confining writes to `default_base_dir` unless explicitly allowed."""
    raw = str(target_path)
    if "\x00" in raw:
        raise ValidationError("Path contains illegal null byte.", details={"path": raw})
    base_resolved = default_base_dir.expanduser().resolve()
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = base_resolved / candidate
    return safe_resolve_path(
        candidate,
        base_dir=base_resolved,
        allow_outside_base=allow_outside_base,
    )
