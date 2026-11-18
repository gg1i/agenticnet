"""SQLite persistence layer for AgenticNet projects, snapshots, logs, and diagnostics."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agenticnet import __schema_version__
from agenticnet.core.exceptions import ProjectAlreadyExistsError, ProjectNotFoundError, StorageError
from agenticnet.core.models import DiagnosticRecord, ExecutionLogEntry
from agenticnet.ios.models import ConfigSnapshot
from agenticnet.security.redaction import redact_cli_text, redact_secrets
from agenticnet.storage.models import ProjectBundle, ProjectMetadata, migrate_project_payload

_SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    schema_version TEXT NOT NULL,
    packet_tracer_file TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    recovery_checkpoint TEXT,
    bundle_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    project_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    model TEXT NOT NULL,
    category TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT '',
    pos_x REAL NOT NULL,
    pos_y REAL NOT NULL,
    state_level TEXT NOT NULL,
    PRIMARY KEY (project_id, device_name),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS connections (
    project_id TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    source_device TEXT NOT NULL,
    source_interface TEXT NOT NULL,
    target_device TEXT NOT NULL,
    target_interface TEXT NOT NULL,
    cable_type TEXT NOT NULL,
    state_level TEXT NOT NULL,
    PRIMARY KEY (project_id, connection_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS config_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    state_level TEXT NOT NULL,
    source TEXT NOT NULL,
    commands_json TEXT NOT NULL,
    config_text TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS execution_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL,
    project_id TEXT,
    tool_name TEXT NOT NULL,
    permission_tier TEXT NOT NULL,
    status TEXT NOT NULL,
    state_level TEXT NOT NULL,
    summary TEXT NOT NULL,
    params_redacted_json TEXT NOT NULL,
    duration_ms REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS diagnostic_results (
    diagnostic_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    target_device TEXT,
    probable_cause TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    proposed_fix TEXT,
    resolved INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS workspace_preferences (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


class SQLiteStore:
    """Thread-safe SQLite repository managing AgenticNet projects and audit history."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    @contextmanager
    def _transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """Open a SQLite connection, manage commit/rollback, and always close the handle."""
        conn = self._connect()
        try:
            if immediate:
                conn.execute("BEGIN IMMEDIATE;")
            yield conn
            conn.commit()
        except Exception:
            with suppress(sqlite3.Error):
                conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        try:
            with self._transaction() as conn:
                with suppress(sqlite3.Error):
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=NORMAL;")
                conn.executescript(_SCHEMA_SQL)
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (__schema_version__, datetime.now(UTC).isoformat()),
                )
        except sqlite3.Error as exc:
            raise StorageError(
                f"Failed to initialize SQLite database at {self.db_path}: {exc}"
            ) from exc

    def project_exists(self, project_id: str) -> bool:
        """Check whether a project ID exists in SQLite."""
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT 1 FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
        return row is not None

    def save_bundle(self, bundle: ProjectBundle, *, create_only: bool = False) -> None:
        """Persist a ProjectBundle and synchronize normalized inventory/snapshot tables."""
        bundle.metadata.updated_at = datetime.now(UTC)

        # Redact any credentials before writing snapshots or bundles to SQLite.
        safe_bundle = bundle.model_copy(deep=True)
        for snap in safe_bundle.config_snapshots:
            snap.config_text = redact_cli_text(snap.config_text)
            snap.commands = [redact_cli_text(c) for c in snap.commands]

        bundle_json = safe_bundle.model_dump_json()

        try:
            with self._transaction(immediate=True) as conn:
                if create_only:
                    try:
                        conn.execute(
                            """
                            INSERT INTO projects (
                                project_id, name, description, schema_version, packet_tracer_file,
                                created_at, updated_at, recovery_checkpoint, bundle_json
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                safe_bundle.metadata.project_id,
                                safe_bundle.metadata.name,
                                safe_bundle.metadata.description,
                                safe_bundle.schema_version,
                                safe_bundle.metadata.packet_tracer_file,
                                safe_bundle.metadata.created_at.isoformat(),
                                safe_bundle.metadata.updated_at.isoformat(),
                                safe_bundle.recovery_checkpoint,
                                bundle_json,
                            ),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise ProjectAlreadyExistsError(
                            f"Project '{safe_bundle.metadata.project_id}' already exists.",
                            details={"project_id": safe_bundle.metadata.project_id},
                            remediation=(
                                "Open the existing project or choose a different project_id."
                            ),
                        ) from exc
                else:
                    conn.execute(
                        """
                        INSERT INTO projects (
                            project_id, name, description, schema_version, packet_tracer_file,
                            created_at, updated_at, recovery_checkpoint, bundle_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(project_id) DO UPDATE SET
                            name = excluded.name,
                            description = excluded.description,
                            schema_version = excluded.schema_version,
                            packet_tracer_file = excluded.packet_tracer_file,
                            updated_at = excluded.updated_at,
                            recovery_checkpoint = excluded.recovery_checkpoint,
                            bundle_json = excluded.bundle_json
                        """,
                        (
                            safe_bundle.metadata.project_id,
                            safe_bundle.metadata.name,
                            safe_bundle.metadata.description,
                            safe_bundle.schema_version,
                            safe_bundle.metadata.packet_tracer_file,
                            safe_bundle.metadata.created_at.isoformat(),
                            safe_bundle.metadata.updated_at.isoformat(),
                            safe_bundle.recovery_checkpoint,
                            bundle_json,
                        ),
                    )

                pid = safe_bundle.metadata.project_id
                conn.execute("DELETE FROM devices WHERE project_id = ?", (pid,))
                conn.executemany(
                    """
                    INSERT INTO devices (
                        project_id, device_name, model, category, role, pos_x, pos_y, state_level
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            pid,
                            dev.name,
                            dev.model,
                            dev.category.value,
                            dev.role,
                            dev.position.x,
                            dev.position.y,
                            dev.state_level.value,
                        )
                        for dev in safe_bundle.topology.devices.values()
                    ],
                )

                conn.execute("DELETE FROM connections WHERE project_id = ?", (pid,))
                conn.executemany(
                    """
                    INSERT INTO connections (
                        project_id, connection_id, source_device, source_interface,
                        target_device, target_interface, cable_type, state_level
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            pid,
                            link.connection_id,
                            link.source_device,
                            link.source_interface,
                            link.target_device,
                            link.target_interface,
                            link.cable_type.value,
                            link.state_level.value,
                        )
                        for link in safe_bundle.topology.connections.values()
                    ],
                )

                conn.execute("DELETE FROM config_snapshots WHERE project_id = ?", (pid,))
                conn.executemany(
                    """
                    INSERT INTO config_snapshots (
                        snapshot_id, project_id, device_name, state_level, source,
                        commands_json, config_text, note, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            snap.snapshot_id,
                            pid,
                            snap.device_name,
                            snap.state_level.value,
                            snap.source,
                            json.dumps(snap.commands),
                            snap.config_text,
                            snap.note,
                            snap.created_at.isoformat(),
                        )
                        for snap in safe_bundle.config_snapshots
                    ],
                )

                conn.execute("DELETE FROM diagnostic_results WHERE project_id = ?", (pid,))
                conn.executemany(
                    """
                    INSERT INTO diagnostic_results (
                        diagnostic_id, project_id, category, severity, target_device,
                        probable_cause, evidence_json, proposed_fix, resolved, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            diag.diagnostic_id,
                            pid,
                            diag.category,
                            diag.severity,
                            diag.target_device,
                            diag.probable_cause,
                            json.dumps(diag.evidence),
                            diag.proposed_fix,
                            1 if diag.resolved else 0,
                            diag.created_at.isoformat(),
                        )
                        for diag in safe_bundle.diagnostics
                    ],
                )
        except ProjectAlreadyExistsError:
            raise
        except sqlite3.Error as exc:
            raise StorageError(
                f"Failed to persist project '{bundle.metadata.project_id}': {exc}"
            ) from exc

    def load_bundle(self, project_id: str) -> ProjectBundle:
        """Load and validate a ProjectBundle from SQLite."""
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT bundle_json FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
        if row is None:
            raise ProjectNotFoundError(
                f"Project '{project_id}' was not found in SQLite store.",
                details={"project_id": project_id},
                remediation="Use project_create to initialize it or verify the project_id.",
            )
        payload = json.loads(row["bundle_json"])
        migrated = migrate_project_payload(payload)
        return ProjectBundle.model_validate(migrated)

    def list_projects(self) -> list[ProjectMetadata]:
        """List stored projects ordered by most recently updated."""
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT bundle_json FROM projects ORDER BY updated_at DESC"
            ).fetchall()
        results: list[ProjectMetadata] = []
        for row in rows:
            payload = json.loads(row["bundle_json"])
            if "metadata" in payload:
                results.append(ProjectMetadata.model_validate(payload["metadata"]))
        return results

    def delete_project(self, project_id: str) -> None:
        """Delete a project and cascaded records from SQLite."""
        with self._transaction(immediate=True) as conn:
            cur = conn.execute("DELETE FROM projects WHERE project_id = ?", (project_id,))
            if cur.rowcount == 0:
                raise ProjectNotFoundError(f"Project '{project_id}' was not found.")

    def append_execution_log(self, entry: ExecutionLogEntry) -> None:
        """Record a redacted execution audit entry in SQLite."""
        safe_params = redact_secrets(entry.params_redacted)
        safe_summary = redact_cli_text(entry.summary)
        try:
            with self._transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO execution_logs (
                        operation_id, project_id, tool_name, permission_tier, status,
                        state_level, summary, params_redacted_json, duration_ms, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.operation_id,
                        entry.project_id,
                        entry.tool_name,
                        entry.permission_tier.value,
                        entry.status.value,
                        entry.state_level.value,
                        safe_summary,
                        json.dumps(safe_params, default=str),
                        entry.duration_ms,
                        entry.created_at.isoformat(),
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to append execution audit log: {exc}") from exc

    def list_execution_logs(
        self, *, project_id: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Query recent execution log records."""
        with self._transaction() as conn:
            if project_id is not None:
                rows = conn.execute(
                    """
                    SELECT operation_id, project_id, tool_name, permission_tier, status,
                           state_level, summary, params_redacted_json, duration_ms, created_at
                    FROM execution_logs
                    WHERE project_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (project_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT operation_id, project_id, tool_name, permission_tier, status,
                           state_level, summary, params_redacted_json, duration_ms, created_at
                    FROM execution_logs
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()

        return [
            {
                "operation_id": r["operation_id"],
                "project_id": r["project_id"],
                "tool_name": r["tool_name"],
                "permission_tier": r["permission_tier"],
                "status": r["status"],
                "state_level": r["state_level"],
                "summary": r["summary"],
                "params": json.loads(r["params_redacted_json"]),
                "duration_ms": r["duration_ms"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def count_logs_for_project(self, project_id: str) -> int:
        """Count execution logs recorded for a project."""
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM execution_logs WHERE project_id = ?",
                (project_id,),
            ).fetchone()
        return int(row["cnt"]) if row else 0

    def set_preference(self, key: str, value: Any) -> dict[str, Any]:
        """Store or update a standing workspace preference in SQLite."""
        cleaned_key = str(key or "").strip()
        if not cleaned_key:
            raise StorageError("Workspace preference key must not be empty.")
        now_iso = datetime.now(UTC).isoformat()
        safe_val = redact_secrets(value)
        try:
            with self._transaction(immediate=True) as conn:
                conn.execute(
                    """
                    INSERT INTO workspace_preferences (key, value_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value_json = excluded.value_json,
                        updated_at = excluded.updated_at
                    """,
                    (cleaned_key, json.dumps(safe_val, default=str), now_iso),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"Failed to persist preference '{cleaned_key}': {exc}") from exc
        return {"key": cleaned_key, "value": safe_val, "updated_at": now_iso}

    def get_preference(self, key: str, default: Any = None) -> Any:
        """Read a standing workspace preference from SQLite, returning `default` if absent."""
        cleaned_key = str(key or "").strip()
        if not cleaned_key:
            return default
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT value_json FROM workspace_preferences WHERE key = ?",
                (cleaned_key,),
            ).fetchone()
        if row is None:
            return default
        return json.loads(row["value_json"])

    def list_preferences(self) -> dict[str, Any]:
        """Return all stored standing workspace preferences keyed by name."""
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT key, value_json, updated_at FROM workspace_preferences ORDER BY key ASC"
            ).fetchall()
        return {
            r["key"]: {
                "value": json.loads(r["value_json"]),
                "updated_at": r["updated_at"],
            }
            for r in rows
        }

    def list_snapshots(
        self, project_id: str, device_name: str | None = None
    ) -> list[ConfigSnapshot]:
        """Load persisted configuration snapshots for a project."""
        bundle = self.load_bundle(project_id)
        if device_name is None:
            return bundle.config_snapshots
        return [s for s in bundle.config_snapshots if s.device_name == device_name]

    def list_diagnostics(self, project_id: str) -> list[DiagnosticRecord]:
        """Load persisted diagnostic records for a project."""
        return self.load_bundle(project_id).diagnostics
