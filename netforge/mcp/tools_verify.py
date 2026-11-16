"""MCP tools exposing declarative lab verification requirements schema and `verify_lab`."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from pydantic import ValidationError as PydanticValidationError

from netforge.core.enums import PermissionTier, StateLevel
from netforge.core.exceptions import ValidationError
from netforge.core.models import OperationResult
from netforge.diagnostics.grader import grade_open_activity
from netforge.diagnostics.lab_runner import (
    build_snapshot_payload,
    collect_lab_snapshot,
    compute_lab_diff,
    create_original_backup,
    derive_working_copy_path,
    evaluate_lab_status,
    paths_refer_to_same_file,
    start_lab_session,
)
from netforge.diagnostics.verifier import LabVerifier
from netforge.diagnostics.verify_schema import get_verify_requirements_schema
from netforge.mcp.registry import NetForgeRuntime


def register_verify_tools(server: MCPServer, runtime: NetForgeRuntime) -> None:
    """Register Phase 3 live verification schema and `verify_lab` MCP tools."""

    def verify_requirements_schema() -> dict[str, Any]:
        """Return the declarative JSON schema and worked examples for `verify_lab`."""

        def _run() -> OperationResult:
            schema_doc = get_verify_requirements_schema()
            return OperationResult.ok(
                "verify_requirements_schema",
                (
                    "Returned declarative verification schema covering "
                    f"{len(schema_doc['supported_types'])} requirement types."
                ),
                data=schema_doc,
                state_level=StateLevel.PLANNED,
                execution_backend="offline_model",
                evidence=["Static JSON schema and examples generated from Pydantic models."],
            )

        return runtime.execute(
            "verify_requirements_schema",
            PermissionTier.READ_ONLY,
            {},
            _run,
        )

    def verify_lab(
        requirements: dict[str, Any] | list[dict[str, Any]],
        timeout_seconds: float = 25.0,
        poll_wait_seconds: float | None = None,
        include_activity_grade: bool = True,
        task_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Verify live Packet Tracer lab state against declarative requirements with evidence.

        ``poll_wait_seconds`` defaults to 45.0s per requirement on a live Packet Tracer bridge
        (0.0s in offline/mock runs) unless overridden explicitly.
        """

        def _run() -> OperationResult:
            try:
                report = LabVerifier(runtime.router).verify(
                    requirements,
                    timeout_seconds=timeout_seconds,
                    poll_wait_seconds=poll_wait_seconds,
                    include_activity_grade=include_activity_grade,
                    task_ids=task_ids,
                )
            except (PydanticValidationError, TypeError, ValueError) as exc:
                raise ValidationError(
                    f"Invalid verify_lab requirements payload: {exc}",
                    remediation="Call verify_requirements_schema to inspect the expected schema.",
                ) from exc

            summary_counts = report["summary"]
            warnings = [
                f"[{r['status']}] {r['type']} ({r['device']}): {r['reason']}"
                for r in report["results"]
                if r["status"] != "pass" and r.get("reason")
            ]
            cov = report.get("task_coverage")
            if cov and cov.get("uncovered_tasks"):
                warnings.append(
                    f"Uncovered task IDs with no requirement attached: {cov['uncovered_tasks']}."
                )
            ev = [
                (
                    f"[{r['status']}] {r['device']}:{r['command']} "
                    f"-> {len(str(r.get('evidence', '')))}c"
                )
                for r in report["results"]
            ]
            verdict = "PASSED" if report["passed"] else "FAILED"
            summary_msg = (
                f"verify_lab {verdict}: {summary_counts['passed']}/{summary_counts['total']} "
                f"passed, {summary_counts['failed']} failed, {summary_counts['errors']} error(s)."
            )
            return OperationResult.ok(
                "verify_lab",
                summary_msg,
                data=report,
                state_level=StateLevel(report["state_level"]),
                execution_backend=report["execution_backend"],
                warnings=warnings,
                evidence=ev,
            )

        return runtime.execute(
            "verify_lab",
            PermissionTier.READ_ONLY,
            {
                "timeout_seconds": timeout_seconds,
                "include_activity_grade": include_activity_grade,
                "task_ids": task_ids,
            },
            _run,
        )

    def grade_lab() -> dict[str, Any]:
        """Read native `.pka` activity score and unmet comparator leaves fail-closed."""

        def _run() -> OperationResult:
            grade = grade_open_activity(runtime.router)
            state = grade["state"]
            if state == "available":
                pct = grade["percentage_complete"]
                unmet = len(grade["unmet_items"])
                summary_msg = (
                    f"grade_lab {pct:.1f}% complete "
                    f"({grade['correct_items_count']}/{grade['items_count']} items, "
                    f"{unmet} unmet leaf item(s))."
                )
                warnings = [
                    (
                        f"[unmet] {item['path']}: "
                        f"{item['incorrect_feedback'] or item['value'] or 'incomplete'}"
                    )
                    for item in grade["unmet_items"][:20]
                ]
                evidence = [
                    (
                        f"PT ActivityFile score={pct:.1f}% "
                        f"leaves={grade['total_leaves']} unmet={unmet}"
                    )
                ]
            else:
                summary_msg = (
                    f"grade_lab unavailable ({grade.get('raw_state', 'unavailable')}): "
                    f"{grade.get('reason')}"
                )
                warnings = [
                    str(grade.get("reason") or "Activity grade unavailable; use verify_lab.")
                ]
                evidence = [f"Fail-closed fallback -> {grade.get('fallback', 'verify_lab')}."]
            return OperationResult.ok(
                "grade_lab",
                summary_msg,
                data=grade,
                state_level=StateLevel(grade["state_level"]),
                execution_backend=grade["execution_backend"],
                warnings=warnings,
                evidence=evidence,
            )

        return runtime.execute("grade_lab", PermissionTier.READ_ONLY, {}, _run)

    def lab_start(
        input_target: str,
        auto_approve: bool = False,
        watch_mode: bool = True,
        watch_pace_seconds: float = 0.15,
        copy_on_write: bool = True,
        working_copy_path: str | None = None,
        overwrite_original: bool = False,
        confirm_overwrite_original: bool = False,
        wait_seconds: float = 30.0,
        clarifications: str | None = None,
        devices: list[dict[str, Any]] | None = None,
        links: list[dict[str, Any]] | None = None,
        configs: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        """One-command live start for a `.pkt`/`.pka` file, `.md`/`.txt`/`.pdf` doc, or idea."""

        def _run() -> OperationResult:
            out = start_lab_session(
                runtime,
                input_target,
                auto_approve=auto_approve,
                watch_mode=watch_mode,
                watch_pace_seconds=watch_pace_seconds,
                copy_on_write=copy_on_write,
                working_copy_path=working_copy_path,
                overwrite_original=overwrite_original,
                confirm_overwrite_original=confirm_overwrite_original,
                wait_seconds=wait_seconds,
                clarifications=clarifications,
                devices=devices,
                links=links,
                configs=configs,
            )
            state = str(out.get("state", "ready"))
            if state == "awaiting_plan_approval":
                return OperationResult.ok(
                    "lab_start",
                    str(out.get("message") or "Prepared plan; awaiting user approval."),
                    data=out,
                    state_level=StateLevel.PLANNED,
                    execution_backend="offline_model",
                    evidence=list(out.get("narration_log") or []),
                )
            if state == "waiting_for_user_launch":
                return OperationResult.fail(
                    "lab_start",
                    str(out["message"]),
                    error_code="NON_INTERACTIVE_SESSION",
                    details=out,
                    remediation="Open Cisco Packet Tracer manually on your desktop and retry.",
                )
            if state == "waiting_for_login":
                return OperationResult.fail(
                    "lab_start",
                    str(out["message"]),
                    error_code="LOGIN_WALL",
                    details=out,
                    remediation="Sign in or accept Guest in the open PT window, then retry.",
                )
            if state == "bridge_timeout":
                return OperationResult.fail(
                    "lab_start",
                    str(out["message"]),
                    error_code="BRIDGE_TIMEOUT",
                    details=out,
                    remediation=(
                        "Check Packet Tracer Extensions -> Scripting for com.netforge.bridge."
                    ),
                )
            ev = list(out.get("narration_log") or [])
            if out.get("working_copy_path"):
                ev.append(f"Copy-on-write working file: {out['working_copy_path']}")
            return OperationResult.ok(
                "lab_start",
                str(out.get("message") or "Live lab session ready."),
                data=out,
                state_level=StateLevel.EXECUTED,
                execution_backend=out.get("execution_backend", "script_backend"),
                evidence=ev,
            )

        return runtime.execute(
            "lab_start",
            PermissionTier.CONFIGURATION,
            {
                "input_target": input_target,
                "auto_approve": auto_approve,
                "watch_mode": watch_mode,
                "copy_on_write": copy_on_write,
                "working_copy_path": working_copy_path,
                "overwrite_original": overwrite_original,
            },
            _run,
        )

    def lab_open(
        path: str,
        timeout_seconds: float = 30.0,
        dry_run: bool = False,
        copy_on_write: bool = False,
        working_copy_path: str | None = None,
    ) -> dict[str, Any]:
        """Open a `.pkt` or `.pka` lab inside Packet Tracer via the bridge (`fileOpen`)."""

        def _run() -> OperationResult:
            cleaned = str(path or "").strip()
            if not cleaned:
                raise ValidationError("Lab file path must not be empty.")
            if dry_run:
                work_preview = (
                    derive_working_copy_path(cleaned, working_copy_path)
                    if copy_on_write
                    else cleaned
                )
                return OperationResult.ok(
                    "lab_open",
                    f"Planned opening '{cleaned}' via script bridge fileOpen (dry_run).",
                    data={
                        "dry_run": True,
                        "path": cleaned,
                        "copy_on_write": copy_on_write,
                        "working_copy_path": work_preview,
                        "method": "fileOpen",
                    },
                    state_level=StateLevel.PLANNED,
                    execution_backend="offline_model",
                    evidence=[f"Dry-run: would dispatch ipc.appWindow().fileOpen('{cleaned}')."],
                )
            runtime.router.clear_aliases()
            backend, data, ev, warnings = runtime.router.open_file(
                cleaned,
                timeout_seconds=timeout_seconds,
            )
            runtime.router.active_original_path = cleaned
            if "is_activity_file" in data:
                runtime.router.active_is_activity = bool(data["is_activity_file"])
            elif cleaned.lower().endswith(".pka"):
                runtime.router.active_is_activity = None
            else:
                runtime.router.active_is_activity = False
            if copy_on_write:
                work_path = derive_working_copy_path(cleaned, working_copy_path)
                if not paths_refer_to_same_file(cleaned, work_path):
                    _, _, save_ev, _ = runtime.router.save_file(
                        work_path,
                        overwrite=True,
                        timeout_seconds=timeout_seconds,
                    )
                    ev = [*ev, *save_ev]
                runtime.router.active_working_path = work_path
                data["original_path"] = cleaned
                data["working_copy_path"] = work_path
                data["copy_on_write"] = True
            else:
                runtime.router.active_working_path = None
            try:
                _, snap_data, snap_ev, _ = runtime.router.list_devices(
                    timeout_seconds=min(timeout_seconds, 15.0)
                )
                snap = build_snapshot_payload(
                    snap_data, cli_log=runtime.router.executed_cli_log
                )
                if runtime.router.initial_snapshot is None:
                    runtime.router.initial_snapshot = snap
                runtime.router.latest_snapshot = snap
                data["discovered_devices"] = {
                    "device_count": snap["device_count"],
                    "link_count": snap["link_count"],
                    "devices": snap["devices"],
                    "links": snap["links"],
                }
                ev = [*ev, *snap_ev]
            except Exception:
                pass
            return OperationResult.ok(
                "lab_open",
                f"Opened '{cleaned}' in Packet Tracer via {backend}.",
                data=data,
                state_level=StateLevel.EXECUTED,
                execution_backend=backend,
                warnings=warnings,
                evidence=ev,
            )

        return runtime.execute(
            "lab_open",
            PermissionTier.CONFIGURATION,
            {
                "path": path,
                "timeout_seconds": timeout_seconds,
                "dry_run": dry_run,
                "copy_on_write": copy_on_write,
                "working_copy_path": working_copy_path,
            },
            _run,
        )

    def lab_save(
        path: str | None = None,
        overwrite: bool = True,
        overwrite_original: bool = False,
        confirm_overwrite_original: bool = False,
        timeout_seconds: float = 30.0,
        include_diff: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Save the active Packet Tracer lab via bridge (`fileSave` or `fileSaveAsNoPrompt`)."""

        def _run() -> OperationResult:
            cleaned = str(path).strip() if path is not None else None
            if path is not None and not cleaned:
                raise ValidationError("Destination path must not be blank when provided.")
            effective_path = (
                cleaned if cleaned is not None else runtime.router.active_working_path
            )
            method = "fileSaveAsNoPrompt" if effective_path else "fileSave"
            if dry_run:
                return OperationResult.ok(
                    "lab_save",
                    f"Planned saving Packet Tracer lab via {method} (dry_run).",
                    data={
                        "dry_run": True,
                        "path": effective_path,
                        "overwrite": overwrite,
                        "overwrite_original": overwrite_original,
                        "method": method,
                    },
                    state_level=StateLevel.PLANNED,
                    execution_backend="offline_model",
                    evidence=[f"Dry-run: would dispatch {method} via script bridge."],
                )
            backup_path: str | None = None
            orig_path = runtime.router.active_original_path
            if (
                orig_path
                and effective_path
                and paths_refer_to_same_file(effective_path, orig_path)
            ):
                if not (overwrite_original and confirm_overwrite_original):
                    raise ValidationError(
                        "Refusing to overwrite the original .pkt/.pka file without explicit "
                        "request (overwrite_original=True, confirm_overwrite_original=True).",
                        details={
                            "original_path": orig_path,
                            "working_copy_path": runtime.router.active_working_path,
                        },
                        remediation=(
                            "Save to the working copy (path=None or *_netforge.pkt), or pass "
                            "overwrite_original=True and confirm_overwrite_original=True."
                        ),
                    )
                backup_path = create_original_backup(orig_path)
                runtime.router.active_backup_path = backup_path

            backend, data, ev, warnings = runtime.router.save_file(
                effective_path,
                overwrite=overwrite,
                timeout_seconds=timeout_seconds,
            )
            if backup_path:
                data["backup_path"] = backup_path
                ev = [*ev, f"Created backup before overwrite: {backup_path}"]
            if include_diff and runtime.router.initial_snapshot is not None:
                try:
                    _, final_snap, snap_ev, _ = collect_lab_snapshot(
                        runtime.router, timeout_seconds=min(timeout_seconds, 15.0)
                    )
                    diff = compute_lab_diff(
                        runtime.router.initial_snapshot,
                        final_snap,
                        cli_log=runtime.router.executed_cli_log,
                    )
                    data["final_snapshot"] = final_snap
                    data["lab_diff"] = diff
                    ev = [*ev, *snap_ev, diff["readable_summary"]]
                except Exception:
                    pass
            return OperationResult.ok(
                "lab_save",
                f"Saved Packet Tracer lab via {backend} ({method}).",
                data=data,
                state_level=StateLevel.EXECUTED,
                execution_backend=backend,
                warnings=warnings,
                evidence=ev,
            )

        return runtime.execute(
            "lab_save",
            PermissionTier.CONFIGURATION,
            {
                "path": path,
                "overwrite": overwrite,
                "overwrite_original": overwrite_original,
                "timeout_seconds": timeout_seconds,
                "include_diff": include_diff,
                "dry_run": dry_run,
            },
            _run,
        )

    def lab_status(
        requirements: dict[str, Any] | list[dict[str, Any]] | None = None,
        task_ids: list[str] | None = None,
        include_activity_grade: bool = True,
        timeout_seconds: float = 25.0,
        poll_wait_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Combine `verify_lab`, `grade_lab`, and task coverage, listing what is left.

        ``poll_wait_seconds`` defaults to 45.0s per requirement on a live Packet Tracer bridge
        (0.0s in offline/mock runs) unless overridden explicitly.
        """

        def _run() -> OperationResult:
            try:
                status = evaluate_lab_status(
                    runtime.router,
                    requirements=requirements,
                    task_ids=task_ids,
                    include_activity_grade=include_activity_grade,
                    timeout_seconds=timeout_seconds,
                    poll_wait_seconds=poll_wait_seconds,
                )
            except (PydanticValidationError, TypeError, ValueError) as exc:
                raise ValidationError(
                    f"Invalid lab_status requirements payload: {exc}",
                    remediation="Call verify_requirements_schema to inspect the expected schema.",
                ) from exc

            left = status["what_is_left"]
            warnings: list[str] = []
            for item in left["failing_requirements"]:
                warnings.append(
                    f"[{item['status']}] {item['type']} ({item['device']}): {item['reason']}"
                )
            for item in left["unmet_grader_items"][:20]:
                warnings.append(
                    f"[unmet] {item['path']}: "
                    f"{item.get('incorrect_feedback') or item.get('value') or 'incomplete'}"
                )
            if left["uncovered_tasks"]:
                warnings.append(
                    f"Uncovered task IDs with no requirement attached: {left['uncovered_tasks']}."
                )
            if left["grader_unavailable_reason"] and status["verify"] is None:
                warnings.append(str(left["grader_unavailable_reason"]))

            verdict = "PASSED" if status["overall_passed"] else "INCOMPLETE"
            summary_msg = (
                f"lab_status {verdict}: "
                f"{len(left['failing_requirements'])} failing requirement(s), "
                f"{len(left['unmet_grader_items'])} unmet grader item(s), "
                f"{len(left['uncovered_tasks'])} uncovered task(s)."
            )
            return OperationResult.ok(
                "lab_status",
                summary_msg,
                data=status,
                state_level=StateLevel(status["state_level"]),
                execution_backend=status["execution_backend"],
                warnings=warnings,
                evidence=status["raw_evidence"],
            )

        return runtime.execute(
            "lab_status",
            PermissionTier.READ_ONLY,
            {
                "task_ids": task_ids,
                "include_activity_grade": include_activity_grade,
                "timeout_seconds": timeout_seconds,
            },
            _run,
        )

    def list_devices(
        timeout_seconds: float = 25.0,
    ) -> dict[str, Any]:
        """List live devices in Packet Tracer: canvas name, model, IOS hostname, and type."""

        def _run() -> OperationResult:
            backend, data, ev, warnings = runtime.router.list_devices(
                timeout_seconds=timeout_seconds,
            )
            raw_devs = data.get("devices", [])
            summary_devs = [
                {
                    "name": d.get("name"),
                    "model": d.get("model"),
                    "hostname": d.get("hostname"),
                    "type": d.get("type"),
                    "type_code": d.get("type_code"),
                    "port_count": d.get("port_count", len(d.get("ports", []))),
                }
                for d in raw_devs
            ]
            return OperationResult.ok(
                "list_devices",
                f"Listed {len(summary_devs)} live device(s) from Packet Tracer via {backend}.",
                data={"device_count": len(summary_devs), "devices": summary_devs},
                state_level=StateLevel.VERIFIED,
                execution_backend=backend,
                warnings=warnings,
                evidence=ev,
            )

        return runtime.execute(
            "list_devices",
            PermissionTier.READ_ONLY,
            {"timeout_seconds": timeout_seconds},
            _run,
        )

    def lab_snapshot(
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        """Capture live lab snapshot: devices, models, IOS hostnames, links, and interfaces."""

        def _run() -> OperationResult:
            backend, snapshot, ev, warnings = collect_lab_snapshot(
                runtime.router,
                timeout_seconds=timeout_seconds,
            )
            return OperationResult.ok(
                "lab_snapshot",
                (
                    f"Captured live lab snapshot: {snapshot['device_count']} device(s), "
                    f"{snapshot['link_count']} link(s), "
                    f"{snapshot['active_interface_count']} active interface(s)."
                ),
                data=snapshot,
                state_level=StateLevel.VERIFIED,
                execution_backend=backend,
                warnings=warnings,
                evidence=ev,
            )

        return runtime.execute(
            "lab_snapshot",
            PermissionTier.READ_ONLY,
            {"timeout_seconds": timeout_seconds},
            _run,
        )

    def lab_diff(
        before_snapshot: dict[str, Any] | None = None,
        after_snapshot: dict[str, Any] | None = None,
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        """Return a readable diff of device, link, interface, and CLI config changes."""

        def _run() -> OperationResult:
            before = before_snapshot or runtime.router.initial_snapshot
            if before is None:
                raise ValidationError(
                    "No baseline lab snapshot is available yet.",
                    remediation="Call lab_start or lab_snapshot before running lab_diff.",
                )
            backend: str = "offline_model"
            ev: list[str] = []
            warnings: list[str] = []
            if after_snapshot is not None:
                after = after_snapshot
            else:
                backend, after, ev, warnings = collect_lab_snapshot(
                    runtime.router, timeout_seconds=timeout_seconds
                )
            diff = compute_lab_diff(before, after, cli_log=runtime.router.executed_cli_log)
            return OperationResult.ok(
                "lab_diff",
                diff["readable_summary"],
                data=diff,
                state_level=StateLevel.VERIFIED if after_snapshot is None else StateLevel.PLANNED,
                execution_backend=backend,
                warnings=warnings,
                evidence=[*ev, diff["readable_summary"]],
            )

        return runtime.execute(
            "lab_diff",
            PermissionTier.READ_ONLY,
            {"has_before": before_snapshot is not None, "has_after": after_snapshot is not None},
            _run,
        )

    specs = [
        ("verify_requirements_schema", verify_requirements_schema, PermissionTier.READ_ONLY, True),
        ("verify_lab", verify_lab, PermissionTier.READ_ONLY, True),
        ("grade_lab", grade_lab, PermissionTier.READ_ONLY, True),
        ("lab_start", lab_start, PermissionTier.CONFIGURATION, False),
        ("lab_open", lab_open, PermissionTier.CONFIGURATION, False),
        ("lab_save", lab_save, PermissionTier.CONFIGURATION, False),
        ("lab_status", lab_status, PermissionTier.READ_ONLY, True),
        ("list_devices", list_devices, PermissionTier.READ_ONLY, True),
        ("lab_snapshot", lab_snapshot, PermissionTier.READ_ONLY, True),
        ("lab_diff", lab_diff, PermissionTier.READ_ONLY, True),
    ]
    for name, fn, tier, ro in specs:
        runtime.registry.register_tool(
            server,
            name=name,
            category="diagnostics",
            permission_tier=tier,
            description=(fn.__doc__ or name).strip(),
            fn=fn,
            read_only=ro,
            idempotent=ro,
        )
