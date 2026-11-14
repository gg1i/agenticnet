"""Input sanitization and safe filesystem boundary checks."""

from __future__ import annotations

import re
from pathlib import Path

from netforge.core.exceptions import ValidationError

_DEVICE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,62}$")
_PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")


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
