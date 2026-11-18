"""Versioned project bundle schema and migration utilities."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from agenticnet import __schema_version__
from agenticnet.core.exceptions import StorageError
from agenticnet.core.models import DiagnosticRecord
from agenticnet.core.models import ProjectMetadata as _CoreProjectMetadata
from agenticnet.ios.models import ConfigSnapshot
from agenticnet.ipam.models import IPAMState
from agenticnet.topology.models import TopologyModel


class ProjectMetadata(_CoreProjectMetadata):
    """Project metadata extended with target execution mode isolation."""

    target_mode: str = "packet_tracer"


class ProjectBundle(BaseModel):
    """Portable, versioned AgenticNet project representation."""

    schema_version: str = __schema_version__
    metadata: ProjectMetadata
    topology: TopologyModel = Field(default_factory=TopologyModel)
    ipam: IPAMState = Field(default_factory=IPAMState)
    config_snapshots: list[ConfigSnapshot] = Field(default_factory=list)
    diagnostics: list[DiagnosticRecord] = Field(default_factory=list)
    recovery_checkpoint: str | None = None


def migrate_project_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate and migrate an older project JSON/YAML payload to current schema_version."""
    version = str(
        payload.get("schema_version")
        or payload.get("metadata", {}).get("schema_version")
        or "1.0.0"
    )
    supported_majors = {"1"}
    major = version.split(".")[0]
    if major not in supported_majors:
        raise StorageError(
            f"Unsupported project schema version {version!r}; current server supports 1.x.",
            details={"found_version": version, "current_version": __schema_version__},
            remediation="Upgrade AgenticNet or migrate the project export to schema 1.0.0.",
        )

    migrated = dict(payload)
    migrated.setdefault("schema_version", __schema_version__)
    migrated.setdefault("topology", {})
    migrated.setdefault("ipam", {})
    migrated.setdefault("config_snapshots", [])
    migrated.setdefault("diagnostics", [])
    if "metadata" in migrated and isinstance(migrated["metadata"], dict):
        migrated["metadata"].setdefault("schema_version", __schema_version__)
        migrated["metadata"].setdefault("target_mode", "packet_tracer")
    return migrated
