"""Phase 5 lab-runner status aggregation combining `verify_lab`, `grade_lab`, and task coverage."""

from __future__ import annotations

from typing import Any

from netforge.adapters.router import BackendRouter
from netforge.core.enums import StateLevel
from netforge.core.models import ExecutionBackend
from netforge.diagnostics.grader import grade_open_activity
from netforge.diagnostics.verifier import LabVerifier


def evaluate_lab_status(
    router: BackendRouter,
    *,
    requirements: dict[str, Any] | list[dict[str, Any]] | None = None,
    task_ids: list[str] | None = None,
    include_activity_grade: bool = True,
    timeout_seconds: float = 25.0,
    poll_wait_seconds: float | None = None,
    poll_interval_seconds: float = 3.0,
) -> dict[str, Any]:
    """Combine `verify_lab`, `grade_lab` (if available), and `task_ids` coverage into one view.

    Returns a structured status dictionary highlighting ``what_is_left``:
    - ``failing_requirements``: requirement checks not in ``pass`` state (with raw evidence)
    - ``unmet_grader_items``: comparator tree leaves from open ``.pka`` (when readable)
    - ``uncovered_tasks``: expected ``task_ids`` missing from requirements
    """
    verify_report: dict[str, Any] | None = None
    if requirements is not None:
        verify_report = LabVerifier(router).verify(
            requirements,
            timeout_seconds=timeout_seconds,
            poll_wait_seconds=poll_wait_seconds,
            poll_interval_seconds=poll_interval_seconds,
            include_activity_grade=False,
            task_ids=task_ids,
        )

    grade_report: dict[str, Any] | None = None
    if include_activity_grade:
        grade_report = grade_open_activity(router)

    failing_requirements: list[dict[str, Any]] = []
    if verify_report is not None:
        for res in verify_report.get("results", []):
            if res.get("status") != "pass":
                failing_requirements.append(
                    {
                        "index": res.get("index"),
                        "id": res.get("id"),
                        "task_id": res.get("task_id"),
                        "type": res.get("type"),
                        "device": res.get("device"),
                        "status": res.get("status"),
                        "reason": res.get("reason"),
                        "command": res.get("command"),
                        "evidence": res.get("evidence"),
                    }
                )

    task_coverage = verify_report.get("task_coverage") if verify_report else None
    uncovered_tasks: list[str] = (
        list(task_coverage.get("uncovered_tasks", [])) if task_coverage else []
    )

    # Also catch task_ids when requirements were omitted altogether
    if verify_report is None and task_ids:
        cleaned_tasks = [str(t).strip() for t in task_ids if str(t).strip()]
        seen: list[str] = list(dict.fromkeys(cleaned_tasks))
        if seen:
            uncovered_tasks = seen
            task_coverage = {
                "expected_tasks": seen,
                "covered_tasks": [],
                "uncovered_tasks": seen,
                "extra_requirement_tasks": [],
                "coverage_ratio": 0.0,
                "all_tasks_covered": False,
            }

    grade_available = bool(
        grade_report is not None
        and grade_report.get("state") == "available"
        and grade_report.get("readable")
    )
    unmet_grader_items: list[dict[str, Any]] = (
        list(grade_report.get("unmet_items", [])) if grade_available and grade_report else []
    )
    grader_unavailable_reason = (
        None
        if (grade_report is None or grade_available)
        else grade_report.get("reason")
    )

    verify_ok = True if verify_report is None else bool(verify_report.get("passed"))
    coverage_ok = True if task_coverage is None else bool(task_coverage.get("all_tasks_covered"))
    grade_pct = (
        grade_report.get("percentage_complete") if (grade_available and grade_report) else None
    )
    grade_ok = True
    if grade_available and grade_report is not None:
        grade_ok = bool(
            isinstance(grade_pct, (int, float))
            and float(grade_pct) >= 100.0
            and len(unmet_grader_items) == 0
        )

    has_signal = (verify_report is not None) or grade_available
    overall_passed = bool(has_signal and verify_ok and coverage_ok and grade_ok)

    if verify_report is not None:
        exec_backend: ExecutionBackend = verify_report["execution_backend"]
        state_level = verify_report["state_level"]
    elif grade_report is not None:
        exec_backend = grade_report["execution_backend"]
        state_level = grade_report["state_level"]
    else:
        exec_backend = "script_backend" if router.has_live_script() else "offline_model"
        state_level = StateLevel.PLANNED.value

    if verify_report is not None and grade_available and not grade_ok:
        # Keep honest verification state level while overall_passed stays False.
        state_level = (
            StateLevel.VERIFIED.value if verify_report.get("verified_live") else state_level
        )

    raw_evidence: list[str] = []
    if verify_report is not None:
        for res in verify_report.get("results", []):
            cmd = res.get("command") or res.get("type")
            ev_text = str(res.get("evidence") or "")
            raw_evidence.append(f"[{res.get('status')}] {res.get('device')}:{cmd}\n{ev_text}")
    if grade_report is not None:
        if grade_available:
            met_cnt = grade_report.get("correct_items_count")
            tot_cnt = grade_report.get("items_count")
            raw_evidence.append(f"[grader] {grade_pct:.1f}% ({met_cnt}/{tot_cnt} items)")
        else:
            raw_evidence.append(f"[grader] unavailable: {grader_unavailable_reason}")

    return {
        "overall_passed": overall_passed,
        "has_verification_signal": has_signal,
        "state_level": state_level,
        "execution_backend": exec_backend,
        "verify": verify_report,
        "grade": grade_report,
        "task_coverage": task_coverage,
        "what_is_left": {
            "failing_requirements": failing_requirements,
            "unmet_grader_items": unmet_grader_items,
            "uncovered_tasks": uncovered_tasks,
            "grader_unavailable_reason": grader_unavailable_reason,
            "is_empty": overall_passed
            and len(failing_requirements) == 0
            and len(unmet_grader_items) == 0
            and len(uncovered_tasks) == 0,
        },
        "raw_evidence": raw_evidence,
    }
