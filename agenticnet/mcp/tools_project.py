"""MCP tools for AgenticNet project lifecycle management (category: project)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from agenticnet.core.enums import PermissionTier, StateLevel
from agenticnet.core.exceptions import ValidationError
from agenticnet.core.models import OperationResult
from agenticnet.mcp.registry import AgenticNetRuntime
from agenticnet.security.validation import safe_output_path


def register_project_tools(server: MCPServer, runtime: AgenticNetRuntime) -> None:
    """Register project_* tools onto the MCPServer."""

    def project_create(
        name: str,
        project_id: str | None = None,
        description: str = "",
        author: str = "",
        packet_tracer_file: str | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create and activate a new AgenticNet project backed by SQLite storage."""
        params = {
            "name": name,
            "project_id": project_id,
            "description": description,
            "author": author,
            "packet_tracer_file": packet_tracer_file,
            "tags": tags,
        }

        def _run() -> OperationResult:
            bundle = runtime.manager.create_project(
                name,
                project_id=project_id,
                description=description,
                author=author,
                packet_tracer_file=packet_tracer_file,
                tags=tags,
            )
            return OperationResult.ok(
                "project_create",
                f"Created and activated project '{bundle.metadata.project_id}'.",
                data={
                    "project": bundle.metadata.model_dump(mode="json"),
                    "db_path": str(runtime.settings.db_path),
                },
                state_level=StateLevel.PLANNED,
                evidence=[f"Persisted project '{bundle.metadata.project_id}' to SQLite."],
            )

        return runtime.execute("project_create", PermissionTier.PLANNING, params, _run)

    def project_open(project_id: str) -> dict[str, Any]:
        """Open an existing AgenticNet project from SQLite and make it active."""

        def _run() -> OperationResult:
            bundle = runtime.manager.open_project(project_id)
            return OperationResult.ok(
                "project_open",
                f"Opened project '{bundle.metadata.project_id}'.",
                data=runtime.manager.status_summary(),
                state_level=StateLevel.PLANNED,
                evidence=[f"Loaded project '{bundle.metadata.project_id}' from SQLite."],
            )

        return runtime.execute(
            "project_open", PermissionTier.PLANNING, {"project_id": project_id}, _run
        )

    def project_save(
        create_backup: bool = True,
        checkpoint_label: str | None = None,
    ) -> dict[str, Any]:
        """Persist the active AgenticNet project to SQLite and optionally create a JSON backup."""
        params = {"create_backup": create_backup, "checkpoint_label": checkpoint_label}

        def _run() -> OperationResult:
            saved = runtime.manager.save_project(
                create_backup=create_backup,
                checkpoint_label=checkpoint_label,
            )
            return OperationResult.ok(
                "project_save",
                f"Saved project '{saved['project_id']}' to SQLite.",
                data=saved,
                state_level=StateLevel.PLANNED,
                evidence=[
                    f"SQLite committed at {saved['updated_at']}",
                    *(
                        [f"Backup written to {saved['backup_path']}"]
                        if saved.get("backup_path")
                        else []
                    ),
                ],
            )

        return runtime.execute("project_save", PermissionTier.PLANNING, params, _run)

    def project_close(save_first: bool = True) -> dict[str, Any]:
        """Close the currently active AgenticNet project cleanly."""

        def _run() -> OperationResult:
            closed_id = runtime.manager.close_project(save_first=save_first)
            if closed_id is None:
                return OperationResult.ok(
                    "project_close",
                    "No active project was open.",
                    data={"closed_project_id": None},
                )
            return OperationResult.ok(
                "project_close",
                f"Closed project '{closed_id}'.",
                data={"closed_project_id": closed_id, "saved_first": save_first},
                evidence=[f"Closed '{closed_id}' cleanly."],
            )

        return runtime.execute(
            "project_close", PermissionTier.PLANNING, {"save_first": save_first}, _run
        )

    def project_export(
        fmt: Literal["json", "yaml"] = "json",
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """Export the active project (topology, IPAM, snapshots, metadata) to JSON or YAML."""
        params = {"fmt": fmt, "output_path": output_path}

        def _run() -> OperationResult:
            safe_target: str | None = None
            if output_path is not None:
                raw_out = Path(output_path).expanduser()
                target_in = (
                    (runtime.settings.data_dir / "exports" / raw_out)
                    if not raw_out.is_absolute()
                    else raw_out
                )
                resolved = safe_output_path(
                    target_in,
                    default_base_dir=runtime.settings.data_dir,
                    allow_outside_base=False,
                )
                safe_target = str(resolved)
            exported = runtime.manager.export_project(fmt=fmt, output_path=safe_target)
            return OperationResult.ok(
                "project_export",
                f"Exported project '{exported['project_id']}' as {exported['format'].upper()}.",
                data=exported,
                state_level=StateLevel.PLANNED,
                evidence=[f"Serialized versioned ProjectBundle ({exported['format']})."],
            )

        tier = PermissionTier.PLANNING if output_path else PermissionTier.READ_ONLY
        return runtime.execute("project_export", tier, params, _run)

    def project_import(
        content: str | None = None,
        file_path: str | None = None,
        overwrite: bool = False,
        activate: bool = True,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Import and schema-validate a portable JSON/YAML project bundle into SQLite."""
        params = {
            "has_content": content is not None,
            "file_path": file_path,
            "overwrite": overwrite,
            "activate": activate,
            "confirm": confirm,
        }
        tier = PermissionTier.DESTRUCTIVE if overwrite else PermissionTier.PLANNING

        def _run() -> OperationResult:
            bundle = runtime.manager.import_project(
                content=content,
                file_path=file_path,
                overwrite=overwrite,
                activate=activate,
            )
            return OperationResult.ok(
                "project_import",
                f"Imported project '{bundle.metadata.project_id}' "
                f"(schema {bundle.schema_version}).",
                data={
                    "project_id": bundle.metadata.project_id,
                    "devices": len(bundle.topology.devices),
                    "connections": len(bundle.topology.connections),
                    "activated": activate,
                },
                state_level=StateLevel.PLANNED,
                evidence=[f"Validated schema {bundle.schema_version} and saved to SQLite."],
            )

        return runtime.execute(
            "project_import",
            tier,
            params,
            _run,
            confirm=confirm,
            destructive_reason="Overwriting an existing SQLite project requires confirm=True.",
        )

    def project_status() -> dict[str, Any]:
        """Return active project status, stored projects, and Planned/Executed/Verified counts."""

        def _run() -> OperationResult:
            summary = runtime.manager.status_summary()
            has_gui = False
            try:
                has_gui = runtime.router.has_live_gui()
            except AttributeError:
                is_avail = getattr(runtime.gui, "is_available", None)
                has_gui = bool(is_avail()) if callable(is_avail) else False
            if runtime.router.has_live_script():
                live_backend = "script_backend"
            elif has_gui:
                live_backend = "gui_backend"
            else:
                live_backend = "offline_planning"
            summary["packet_tracer_backend"] = live_backend
            active = summary.get("active_project")
            msg = (
                f"Active project '{active['project_id']}' ({summary['counts']['devices']} devices)."
                if active
                else (
                    f"No active project. {len(summary['stored_projects'])} stored project(s) found."
                )
            )
            return OperationResult.ok(
                "project_status",
                msg,
                data=summary,
                state_level=StateLevel.PLANNED,
                evidence=["Queried active project state and SQLite store."],
            )

        return runtime.execute("project_status", PermissionTier.READ_ONLY, {}, _run)

    def workspace_preferences(
        action: Literal["get", "set", "list"] = "list",
        key: str | None = None,
        value: Any = None,
        default: Any = None,
    ) -> dict[str, Any]:
        """Get, set, or list persistent standing workspace preferences in SQLite."""
        params = {"action": action, "key": key, "value": value}
        tier = PermissionTier.READ_ONLY if action in {"get", "list"} else PermissionTier.PLANNING

        def _run() -> OperationResult:
            if action == "list":
                prefs = runtime.manager.store.list_preferences()
                return OperationResult.ok(
                    "workspace_preferences",
                    f"Listed {len(prefs)} workspace preference(s).",
                    data={"preferences": prefs, "count": len(prefs)},
                    state_level=StateLevel.PLANNED,
                    evidence=["Read workspace_preferences table from SQLite."],
                )
            cleaned_key = str(key or "").strip()
            if not cleaned_key:
                raise ValidationError(
                    f"workspace_preferences action='{action}' requires a non-empty 'key'."
                )
            if action == "get":
                all_prefs = runtime.manager.store.list_preferences()
                found = cleaned_key in all_prefs
                val = runtime.manager.store.get_preference(cleaned_key, default=default)
                return OperationResult.ok(
                    "workspace_preferences",
                    f"Read preference '{cleaned_key}' (found={found}).",
                    data={"key": cleaned_key, "value": val, "found": found},
                    state_level=StateLevel.PLANNED,
                    evidence=[f"Queried preference '{cleaned_key}' from SQLite."],
                )
            saved = runtime.manager.store.set_preference(cleaned_key, value)
            return OperationResult.ok(
                "workspace_preferences",
                f"Stored workspace preference '{cleaned_key}'.",
                data=saved,
                state_level=StateLevel.PLANNED,
                evidence=[f"Persisted preference '{cleaned_key}' in SQLite."],
            )

        return runtime.execute("workspace_preferences", tier, params, _run)

    specs = [
        (
            "project_create",
            PermissionTier.PLANNING,
            project_create.__doc__ or "",
            project_create,
            False,
            False,
        ),
        (
            "project_open",
            PermissionTier.PLANNING,
            project_open.__doc__ or "",
            project_open,
            False,
            False,
        ),
        (
            "project_save",
            PermissionTier.PLANNING,
            project_save.__doc__ or "",
            project_save,
            False,
            False,
        ),
        (
            "project_close",
            PermissionTier.PLANNING,
            project_close.__doc__ or "",
            project_close,
            False,
            False,
        ),
        (
            "project_export",
            PermissionTier.READ_ONLY,
            project_export.__doc__ or "",
            project_export,
            False,
            False,
        ),
        (
            "project_import",
            PermissionTier.PLANNING,
            project_import.__doc__ or "",
            project_import,
            False,
            False,
        ),
        (
            "project_status",
            PermissionTier.READ_ONLY,
            project_status.__doc__ or "",
            project_status,
            True,
            False,
        ),
        (
            "workspace_preferences",
            PermissionTier.PLANNING,
            workspace_preferences.__doc__ or "",
            workspace_preferences,
            False,
            False,
        ),
    ]
    for name, tier, desc, fn, ro, dest in specs:
        runtime.registry.register_tool(
            server,
            name=name,
            category="project",
            permission_tier=tier,
            description=desc,
            fn=fn,
            read_only=ro,
            destructive=dest,
        )
