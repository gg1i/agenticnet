"""Native Packet Tracer `.pka` activity grader with fail-closed lock handling."""

from __future__ import annotations

from typing import Any

from netforge.adapters.router import BackendRouter
from netforge.core.enums import StateLevel
from netforge.core.exceptions import NetForgeError
from netforge.core.models import ExecutionBackend


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, bool):
            return int(value)
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        if isinstance(value, bool):
            return float(int(value))
        return float(value)
    except (TypeError, ValueError):
        return default


def _classify_leaf(leaf: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """Classify one comparator tree leaf into `(is_met, normalized_item)`."""
    path = str(leaf.get("path", "") or leaf.get("name", ""))
    name = str(leaf.get("name", ""))
    value = str(leaf.get("value", ""))
    leaf_count = _to_int(leaf.get("leafCount"), 1)
    check_leaf_count = _to_int(leaf.get("checkLeafCount"), 0)
    total_points = _to_float(leaf.get("totalLeafPoints"), 0.0)
    check_points = _to_float(leaf.get("checkLeafPoints"), 0.0)
    feedback = str(leaf.get("incorrectFeedback", "") or "")

    if leaf_count > 0:
        met = check_leaf_count >= leaf_count
    elif total_points > 0:
        met = check_points >= total_points
    else:
        met = not bool(feedback.strip())

    item = {
        "path": path,
        "name": name,
        "value": value,
        "met": met,
        "leaf_count": leaf_count,
        "checked_leaf_count": check_leaf_count,
        "total_points": total_points,
        "checked_points": check_points,
        "incorrect_feedback": feedback,
    }
    return met, item


def grade_open_activity(router: BackendRouter) -> dict[str, Any]:
    """Read PT's native `.pka` completion score and comparator tree leaves fail-closed."""
    if not router.has_live_script():
        return {
            "state": "unavailable",
            "readable": False,
            "is_activity_file": None,
            "locked": False,
            "percentage_complete": None,
            "percentage_complete_score": None,
            "items_count": None,
            "correct_items_count": None,
            "score_count": None,
            "correct_score_count": None,
            "met_items": [],
            "unmet_items": [],
            "total_leaves": 0,
            "fallback": "verify_lab",
            "reason": "Script bridge is not connected to Packet Tracer.",
            "state_level": StateLevel.PLANNED.value,
            "execution_backend": "offline_model",
        }

    try:
        raw = router.read_activity_status()
    except NetForgeError as exc:
        return {
            "state": "unavailable",
            "readable": False,
            "is_activity_file": None,
            "locked": False,
            "percentage_complete": None,
            "percentage_complete_score": None,
            "items_count": None,
            "correct_items_count": None,
            "score_count": None,
            "correct_score_count": None,
            "met_items": [],
            "unmet_items": [],
            "total_leaves": 0,
            "fallback": "verify_lab",
            "reason": f"Failed to query live Packet Tracer activity status: {exc}",
            "state_level": StateLevel.EXECUTED.value,
            "execution_backend": "script_backend",
        }

    exec_backend: ExecutionBackend = raw.get("execution_backend", "script_backend")
    raw_state = str(raw.get("state") or "unavailable")
    locked = bool(raw.get("locked"))
    readable = bool(raw.get("readable", False))
    is_activity = bool(raw.get("is_activity_file", False))

    if locked or not readable or not is_activity or raw_state != "available":
        effective_raw_state = "not_activity" if (not is_activity and not locked) else raw_state
        default_reason = (
            "Open Packet Tracer file is not a .pka activity file; use verify_lab."
            if not is_activity and not locked
            else "Activity grading is unavailable (locked, password-protected, Assessment-mode, "
            "or unreadable); never bypass locks — use verify_lab instead."
        )
        return {
            "state": "unavailable",
            "raw_state": effective_raw_state,
            "readable": False,
            "is_activity_file": is_activity,
            "locked": locked,
            "percentage_complete": None,
            "percentage_complete_score": None,
            "items_count": None,
            "correct_items_count": None,
            "score_count": None,
            "correct_score_count": None,
            "met_items": [],
            "unmet_items": [],
            "total_leaves": 0,
            "fallback": "verify_lab",
            "reason": str(raw.get("reason") or default_reason),
            "state_level": StateLevel.VERIFIED.value,
            "execution_backend": exec_backend,
        }

    raw_leaves = raw.get("leaves")
    leaves_list = raw_leaves if isinstance(raw_leaves, list) else []
    met_items: list[dict[str, Any]] = []
    unmet_items: list[dict[str, Any]] = []
    for raw_leaf in leaves_list:
        if not isinstance(raw_leaf, dict):
            continue
        is_met, item = _classify_leaf(raw_leaf)
        if is_met:
            met_items.append(item)
        else:
            unmet_items.append(item)

    pct = _to_float(raw.get("percentage_complete"), 0.0)
    pct_score = _to_float(raw.get("percentage_complete_score"), pct)
    return {
        "state": "available",
        "raw_state": "available",
        "readable": True,
        "is_activity_file": True,
        "locked": False,
        "percentage_complete": pct,
        "percentage_complete_score": pct_score,
        "items_count": _to_int(raw.get("items_count"), len(leaves_list)),
        "correct_items_count": _to_int(raw.get("correct_items_count"), len(met_items)),
        "score_count": _to_float(raw.get("score_count"), 0.0),
        "correct_score_count": _to_float(raw.get("correct_score_count"), 0.0),
        "met_items": met_items,
        "unmet_items": unmet_items,
        "total_leaves": len(met_items) + len(unmet_items),
        "passed": pct >= 100.0 and len(unmet_items) == 0,
        "fallback": None,
        "reason": None,
        "state_level": StateLevel.VERIFIED.value,
        "execution_backend": exec_backend,
    }
