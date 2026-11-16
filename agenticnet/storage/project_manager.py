"""High-level ProjectManager coordinating topology, IPAM, IOS history, and SQLite backups."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

import yaml

from agenticnet import __schema_version__
from agenticnet.core.enums import StateLevel
from agenticnet.core.exceptions import ProjectNotOpenError, StorageError, ValidationError
from agenticnet.core.models import DiagnosticRecord, ProjectMetadata
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.devices import DEFAULT_CATALOG, DeviceCatalog
from agenticnet.ios.history import ConfigHistory
from agenticnet.ios.models import RenderedCommandSequence
from agenticnet.ipam.engine import IPAMEngine
from agenticnet.security.redaction import redact_cli_text
from agenticnet.security.validation import safe_resolve_path, validate_project_id
from agenticnet.storage.models import ProjectBundle, migrate_project_payload
from agenticnet.storage.sqlite_store import SQLiteStore
from agenticnet.topology.engine import TopologyEngine


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    if len(slug) < 2:
        slug = f"project-{slug or 'net'}"
    return slug[:60]


class ProjectManager:
    """Coordinates active project state across Topology, IPAM, ConfigHistory, and SQLite."""

    def __init__(
        self,
        settings: AgenticNetSettings | None = None,
        *,
        catalog: DeviceCatalog | None = None,
    ) -> None:
        self.settings = settings or AgenticNetSettings.from_env()
        self.catalog = catalog or DEFAULT_CATALOG
        self.store = SQLiteStore(self.settings.db_path)

        self._active_metadata: ProjectMetadata | None = None
        self._topology: TopologyEngine | None = None
        self._ipam: IPAMEngine | None = None
        self._history: ConfigHistory | None = None
        self._diagnostics: list[DiagnosticRecord] = []
        self._recovery_checkpoint: str | None = None

    @property
    def has_active_project(self) -> bool:
        """Return True if a project is currently open."""
        return self._active_metadata is not None

    @property
    def active_project_id(self) -> str | None:
        """Return the currently open project's ID or None."""
        return self._active_metadata.project_id if self._active_metadata else None

    def require_active(self) -> tuple[ProjectMetadata, TopologyEngine, IPAMEngine, ConfigHistory]:
        """Return active engines, auto-initializing a workspace when configured."""
        if self._active_metadata is None and getattr(self.settings, "auto_create_project", False):
            existing = self.store.list_projects()
            if existing:
                self.open_project(existing[0].project_id)
            else:
                self.create_project(
                    "Default Workspace",
                    project_id="default-workspace",
                    description="Auto-initialized AgenticNet workspace",
                )
        if (
            self._active_metadata is None
            or self._topology is None
            or self._ipam is None
            or self._history is None
        ):
            raise ProjectNotOpenError(
                "No AgenticNet project is currently open.",
                remediation="Call project_create or project_open first.",
            )
        return self._active_metadata, self._topology, self._ipam, self._history

    def create_project(
        self,
        name: str,
        *,
        project_id: str | None = None,
        description: str = "",
        author: str = "",
        packet_tracer_file: str | None = None,
        tags: list[str] | None = None,
    ) -> ProjectBundle:
        """Create and activate a new AgenticNet project persisted in SQLite."""
        pid = validate_project_id(project_id or _slugify(name))
        meta = ProjectMetadata(
            project_id=pid,
            name=name.strip(),
            description=description.strip(),
            schema_version=__schema_version__,
            packet_tracer_file=packet_tracer_file,
            author=author.strip(),
            tags=tags or [],
        )
        bundle = ProjectBundle(schema_version=__schema_version__, metadata=meta)
        self.store.save_bundle(bundle, create_only=True)
        self._activate_bundle(bundle)
        return bundle

    def open_project(self, project_id: str) -> ProjectBundle:
        """Load a project from SQLite and set it active."""
        pid = validate_project_id(project_id)
        bundle = self.store.load_bundle(pid)
        self._activate_bundle(bundle)
        return bundle

    def _activate_bundle(self, bundle: ProjectBundle) -> None:
        self._active_metadata = bundle.metadata.model_copy(deep=True)
        self._topology = TopologyEngine(model=bundle.topology, catalog=self.catalog)
        self._ipam = IPAMEngine(state=bundle.ipam)
        self._history = ConfigHistory(snapshots=bundle.config_snapshots)
        self._diagnostics = list(bundle.diagnostics)
        self._recovery_checkpoint = bundle.recovery_checkpoint

    def current_bundle(self) -> ProjectBundle:
        """Build an immutable ProjectBundle from current in-memory engines."""
        meta, topo, ipam, history = self.require_active()
        return ProjectBundle(
            schema_version=__schema_version__,
            metadata=meta.model_copy(deep=True),
            topology=topo.model.model_copy(deep=True),
            ipam=ipam.state.model_copy(deep=True),
            config_snapshots=history.list_snapshots(),
            diagnostics=list(self._diagnostics),
            recovery_checkpoint=self._recovery_checkpoint,
        )

    def save_project(
        self, *, create_backup: bool = True, checkpoint_label: str | None = None
    ) -> dict[str, Any]:
        """Persist active project state to SQLite and optionally write a JSON backup."""
        if checkpoint_label is not None:
            self._recovery_checkpoint = checkpoint_label
        bundle = self.current_bundle()
        self.store.save_bundle(bundle, create_only=False)
        self._active_metadata = bundle.metadata

        backup_path: str | None = None
        if create_backup:
            self.settings.backup_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            target = self.settings.backup_dir / f"{bundle.metadata.project_id}_{stamp}.json"
            target.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
            backup_path = str(target)

        return {
            "project_id": bundle.metadata.project_id,
            "updated_at": bundle.metadata.updated_at.isoformat(),
            "db_path": str(self.settings.db_path),
            "backup_path": backup_path,
        }

    def close_project(self, *, save_first: bool = True) -> str | None:
        """Close the active project (saving to SQLite by default)."""
        if not self.has_active_project:
            return None
        closed_id = self.active_project_id
        if save_first:
            self.save_project(create_backup=False)
        self._active_metadata = None
        self._topology = None
        self._ipam = None
        self._history = None
        self._diagnostics = []
        self._recovery_checkpoint = None
        return closed_id

    def export_project(
        self, *, fmt: str = "json", output_path: str | None = None
    ) -> dict[str, Any]:
        """Export the active project as portable JSON or YAML."""
        bundle = self.current_bundle()
        payload = bundle.model_dump(mode="json")
        fmt_lower = fmt.strip().lower()
        if fmt_lower == "json":
            content = json.dumps(payload, indent=2)
        elif fmt_lower in {"yaml", "yml"}:
            content = yaml.safe_dump(payload, sort_keys=False)
        else:
            raise ValidationError(f"Unsupported export format {fmt!r}. Use 'json' or 'yaml'.")

        written_path: str | None = None
        if output_path:
            resolved = safe_resolve_path(output_path)
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text(content, encoding="utf-8")
            written_path = str(resolved)

        return {
            "project_id": bundle.metadata.project_id,
            "format": fmt_lower,
            "file_path": written_path,
            "content": content,
        }

    def import_project(
        self,
        *,
        content: str | None = None,
        file_path: str | None = None,
        overwrite: bool = False,
        activate: bool = True,
    ) -> ProjectBundle:
        """Import, migrate, validate, and store a JSON/YAML project bundle."""
        if content is None and file_path is None:
            raise ValidationError("Provide either 'content' or 'file_path' to import a project.")

        if content is None and file_path is not None:
            resolved = safe_resolve_path(file_path)
            if not resolved.exists():
                raise StorageError(f"Import file '{resolved}' does not exist.")
            content = resolved.read_text(encoding="utf-8")

        assert content is not None
        stripped = content.lstrip()
        raw_obj = json.loads(content) if stripped.startswith("{") else yaml.safe_load(content)
        if not isinstance(raw_obj, dict):
            raise ValidationError("Imported project content must be a JSON or YAML object.")

        migrated = migrate_project_payload(raw_obj)
        bundle = ProjectBundle.model_validate(migrated)
        self.store.save_bundle(bundle, create_only=not overwrite)
        if activate:
            self._activate_bundle(bundle)
        return bundle

    def record_generated_sequence(self, seq: RenderedCommandSequence, *, note: str = "") -> str:
        """Record generated IOS commands safely as a PLANNED snapshot (secrets redacted)."""
        _, _, _, history = self.require_active()
        redacted_text = "\n".join(redact_cli_text(cmd) for cmd in seq.commands_redacted)
        snap = history.add_snapshot(
            seq.device_name,
            redacted_text,
            state_level=StateLevel.PLANNED,
            source=f"ios_generator:{seq.feature}",
            commands=list(seq.commands_redacted),
            note=note or f"Planned {seq.feature} configuration for {seq.device_name}",
        )
        return snap.snapshot_id

    def status_summary(self) -> dict[str, Any]:
        """Return project status with explicit Planned vs Executed vs Verified counts."""
        if not self.has_active_project:
            stored = self.store.list_projects()
            return {
                "active_project": None,
                "stored_projects": [
                    {
                        "project_id": p.project_id,
                        "name": p.name,
                        "updated_at": p.updated_at.isoformat(),
                    }
                    for p in stored
                ],
                "db_path": str(self.settings.db_path),
            }

        meta, topo, ipam, history = self.require_active()
        device_states = {level.value: 0 for level in StateLevel}
        for dev in topo.model.devices.values():
            device_states[dev.state_level.value] += 1

        link_states = {level.value: 0 for level in StateLevel}
        for link in topo.model.connections.values():
            link_states[link.state_level.value] += 1

        snap_states = {level.value: 0 for level in StateLevel}
        for snap in history.list_snapshots():
            snap_states[snap.state_level.value] += 1

        return {
            "active_project": meta.model_dump(mode="json"),
            "counts": {
                "devices": len(topo.model.devices),
                "connections": len(topo.model.connections),
                "ipam_pools": len(ipam.state.pools),
                "ipam_allocations": len(ipam.state.allocations),
                "config_snapshots": len(history.list_snapshots()),
                "execution_logs": self.store.count_logs_for_project(meta.project_id),
            },
            "state_separation": {
                "devices": device_states,
                "connections": link_states,
                "config_snapshots": snap_states,
            },
            "packet_tracer_backend": "offline_planning",
            "recovery_checkpoint": self._recovery_checkpoint,
            "db_path": str(self.settings.db_path),
        }
