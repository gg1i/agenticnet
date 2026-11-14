"""MCP tools for NetForge project lifecycle management (category: project)."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from netforge.core.enums import PermissionTier, StateLevel
from netforge.core.models import OperationResult
from netforge.mcp.registry import NetForgeRuntime


def register_project_tools(server: MCPServer, runtime: NetForgeRuntime) -> None:
    """Register project_* tools onto the MCPServer."""

    def project_create(
        name: str,
        project_id: str | None = None,
        description: str = "",
        author: str = "",
        packet_tracer_file: str | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create and activate a new NetForge project backed by SQLite storage."""
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
        """Open an existing NetForge project from SQLite and make it active."""

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
            "project_open", PermissionTier.READ_ONLY, {"project_id": project_id}, _run
        )

    def project_save(
        create_backup: bool = True,
        checkpoint_label: str | None = None,
    ) -> dict[str, Any]:
        """Persist the active NetForge project to SQLite and optionally create a JSON backup."""
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
        """Close the currently active NetForge project cleanly."""

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
            exported = runtime.manager.export_project(fmt=fmt, output_path=output_path)
            return OperationResult.ok(
                "project_export",
                f"Exported project '{exported['project_id']}' as {exported['format'].upper()}.",
                data=exported,
                state_level=StateLevel.PLANNED,
                evidence=[f"Serialized versioned ProjectBundle ({exported['format']})."],
            )

        return runtime.execute("project_export", PermissionTier.READ_ONLY, params, _run)

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
            PermissionTier.READ_ONLY,
            project_open.__doc__ or "",
            project_open,
            True,
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
            True,
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
