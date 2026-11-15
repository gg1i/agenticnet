"""MCP tools exposing declarative lab verification requirements schema and `verify_lab`."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from pydantic import ValidationError as PydanticValidationError

from netforge.core.enums import PermissionTier, StateLevel
from netforge.core.exceptions import ValidationError
from netforge.core.models import OperationResult
from netforge.diagnostics.grader import grade_open_activity
from netforge.diagnostics.lab_runner import evaluate_lab_status
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
        include_activity_grade: bool = True,
        task_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Verify live Packet Tracer lab state against declarative requirements with evidence."""

        def _run() -> OperationResult:
            try:
                report = LabVerifier(runtime.router).verify(
                    requirements,
                    timeout_seconds=timeout_seconds,
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

    def lab_open(
        path: str,
        timeout_seconds: float = 30.0,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Open a `.pkt` or `.pka` lab inside Packet Tracer via the bridge (`fileOpen`)."""

        def _run() -> OperationResult:
            cleaned = str(path or "").strip()
            if not cleaned:
                raise ValidationError("Lab file path must not be empty.")
            if dry_run:
                return OperationResult.ok(
                    "lab_open",
                    f"Planned opening '{cleaned}' via script bridge fileOpen (dry_run).",
                    data={"dry_run": True, "path": cleaned, "method": "fileOpen"},
                    state_level=StateLevel.PLANNED,
                    execution_backend="offline_model",
                    evidence=[f"Dry-run: would dispatch ipc.appWindow().fileOpen('{cleaned}')."],
                )
            backend, data, ev, warnings = runtime.router.open_file(
                cleaned,
                timeout_seconds=timeout_seconds,
            )
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
            {"path": path, "timeout_seconds": timeout_seconds, "dry_run": dry_run},
            _run,
        )

    def lab_save(
        path: str | None = None,
        overwrite: bool = True,
        timeout_seconds: float = 30.0,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Save the active Packet Tracer lab via bridge (`fileSave` or `fileSaveAsNoPrompt`)."""

        def _run() -> OperationResult:
            cleaned = str(path).strip() if path is not None else None
            if path is not None and not cleaned:
                raise ValidationError("Destination path must not be blank when provided.")
            method = "fileSaveAsNoPrompt" if cleaned else "fileSave"
            if dry_run:
                return OperationResult.ok(
                    "lab_save",
                    f"Planned saving Packet Tracer lab via {method} (dry_run).",
                    data={
                        "dry_run": True,
                        "path": cleaned,
                        "overwrite": overwrite,
                        "method": method,
                    },
                    state_level=StateLevel.PLANNED,
                    execution_backend="offline_model",
                    evidence=[f"Dry-run: would dispatch {method} via script bridge."],
                )
            backend, data, ev, warnings = runtime.router.save_file(
                cleaned,
                overwrite=overwrite,
                timeout_seconds=timeout_seconds,
            )
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
                "timeout_seconds": timeout_seconds,
                "dry_run": dry_run,
            },
            _run,
        )

    def lab_status(
        requirements: dict[str, Any] | list[dict[str, Any]] | None = None,
        task_ids: list[str] | None = None,
        include_activity_grade: bool = True,
        timeout_seconds: float = 25.0,
    ) -> dict[str, Any]:
        """Combine `verify_lab`, `grade_lab`, and task coverage, listing what is left."""

        def _run() -> OperationResult:
            try:
                status = evaluate_lab_status(
                    runtime.router,
                    requirements=requirements,
                    task_ids=task_ids,
                    include_activity_grade=include_activity_grade,
                    timeout_seconds=timeout_seconds,
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

    specs = [
        ("verify_requirements_schema", verify_requirements_schema, PermissionTier.READ_ONLY, True),
        ("verify_lab", verify_lab, PermissionTier.READ_ONLY, True),
        ("grade_lab", grade_lab, PermissionTier.READ_ONLY, True),
        ("lab_open", lab_open, PermissionTier.CONFIGURATION, False),
        ("lab_save", lab_save, PermissionTier.CONFIGURATION, False),
        ("lab_status", lab_status, PermissionTier.READ_ONLY, True),
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
