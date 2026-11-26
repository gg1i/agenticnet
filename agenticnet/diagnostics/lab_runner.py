"""Phase 5 lab-runner status aggregation combining `verify_lab`, `grade_lab`, and task coverage."""

from __future__ import annotations

import re
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agenticnet.adapters.discovery import (
    is_packet_tracer_running,
    require_interactive_desktop_for_launch,
)
from agenticnet.adapters.router import BackendRouter
from agenticnet.adapters.script_bridge import (
    HttpScriptBridgeBackend,
    resolve_connect_type,
    resolve_device_type,
)
from agenticnet.core.enums import StateLevel
from agenticnet.core.exceptions import AdapterUnavailableError, ValidationError
from agenticnet.core.models import ExecutionBackend
from agenticnet.core.settings import canonical_pt_bridge_data_dir
from agenticnet.diagnostics.grader import grade_open_activity
from agenticnet.diagnostics.verifier import LabVerifier


def evaluate_lab_status(
    router: BackendRouter,
    *,
    requirements: dict[str, Any] | list[dict[str, Any]] | None = None,
    task_ids: list[str] | None = None,
    include_activity_grade: bool = True,
    timeout_seconds: float = 25.0,
    poll_wait_seconds: float | None = None,
    poll_interval_seconds: float | None = None,
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
        if getattr(router, "active_is_activity", None) is False:
            grade_report = {
                "state": "unavailable",
                "raw_state": "not_activity",
                "readable": False,
                "is_activity_file": False,
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
                "fallback": "cli_verification",
                "reason": "Open Packet Tracer file is not a .pka activity file; use verify_lab.",
                "state_level": StateLevel.VERIFIED.value,
                "execution_backend": (
                    "script_backend" if router.has_live_script() else "offline_model"
                ),
            }
        else:
            grade_report = grade_open_activity(router)
            if (
                getattr(router, "active_is_activity", None) is None
                and isinstance(grade_report, dict)
                and grade_report.get("is_activity_file") is False
            ):
                router.active_is_activity = False

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
        None if (grade_report is None or grade_available) else grade_report.get("reason")
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


def paths_refer_to_same_file(first: str | None, second: str | None) -> bool:
    """Compare two file path strings safely after normalizing separators and case."""
    if not first or not second:
        return False
    norm_a = str(first).strip().replace("\\", "/").lower()
    norm_b = str(second).strip().replace("\\", "/").lower()
    if norm_a == norm_b:
        return True
    try:
        return (
            Path(first).expanduser().resolve().as_posix().lower()
            == Path(second).expanduser().resolve().as_posix().lower()
        )
    except OSError:
        return False


def derive_working_copy_path(
    original_path: str,
    explicit_working_copy: str | None = None,
) -> str:
    """Return a non-destructive copy-on-write sibling path (`<name>_agenticnet.<ext>`)."""
    if explicit_working_copy is not None:
        cleaned = str(explicit_working_copy).strip()
        if cleaned:
            return cleaned
    cleaned_orig = str(original_path).strip()
    use_slash = "/" in cleaned_orig and "\\" not in cleaned_orig
    p = Path(cleaned_orig)
    suffix = p.suffix or ".pkt"
    stem_lower = p.stem.lower()
    if stem_lower.endswith(("_agenticnet", "_netforge")):
        out = p
    else:
        out = p.with_name(f"{p.stem}_agenticnet{suffix}")
    return out.as_posix() if use_slash else str(out)


def create_original_backup(original_path: str) -> str:
    """Create a timestamped sibling backup before overwriting an original lab file."""
    orig = Path(original_path).expanduser().resolve()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    suffix = orig.suffix or ".pkt"
    backup = orig.with_name(f"{orig.stem}.backup_{stamp}{suffix}")
    if orig.is_file():
        shutil.copy2(orig, backup)
    return str(backup)


def build_snapshot_payload(
    data: dict[str, Any],
    *,
    cli_log: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Normalize live `list_devices` output into a structured `lab_snapshot` dictionary."""
    devices = list(data.get("devices", []))
    links = list(data.get("links", []))
    iface_table: list[dict[str, Any]] = []
    for dev in devices:
        d_name = dev.get("name", "")
        d_host = dev.get("hostname", d_name)
        for port in dev.get("ports", []):
            ip = port.get("ip_address")
            mask = port.get("subnet_mask")
            if ip or port.get("port_up") or port.get("has_link"):
                iface_table.append(
                    {
                        "device": d_name,
                        "hostname": d_host,
                        "interface": port.get("name"),
                        "ip_address": ip or None,
                        "subnet_mask": mask or None,
                        "port_up": port.get("port_up"),
                        "protocol_up": port.get("protocol_up"),
                        "remote_device": port.get("remote_device_name") or None,
                        "remote_interface": port.get("remote_port_name") or None,
                    }
                )
    copied_cli = {k: list(v) for k, v in (cli_log or {}).items() if v}
    return {
        "device_count": len(devices),
        "link_count": len(links),
        "active_interface_count": len(iface_table),
        "devices": devices,
        "links": links,
        "active_interfaces": iface_table,
        "executed_cli_commands": copied_cli,
    }


def collect_lab_snapshot(
    router: BackendRouter,
    *,
    timeout_seconds: float = 30.0,
) -> tuple[ExecutionBackend, dict[str, Any], list[str], list[str]]:
    """Capture a live snapshot and track baseline `initial_snapshot` / `latest_snapshot`."""
    backend, data, ev, warnings = router.list_devices(timeout_seconds=timeout_seconds)
    snapshot = build_snapshot_payload(data, cli_log=router.executed_cli_log)
    if router.initial_snapshot is None:
        router.initial_snapshot = snapshot
    router.latest_snapshot = snapshot
    if router.watch_mode:
        router.record_watch_action(
            "lab_snapshot",
            (
                f"Captured live state ({snapshot['device_count']} devices, "
                f"{snapshot['link_count']} links)."
            ),
            evidence=ev,
            pace=False,
        )
    return backend, snapshot, ev, warnings


def _canonical_link_key(link: dict[str, Any]) -> tuple[tuple[str, str], tuple[str, str]]:
    ep1 = (str(link.get("device1", "")), str(link.get("port1", "")))
    ep2 = (str(link.get("device2", "")), str(link.get("port2", "")))
    return (ep1, ep2) if ep1 <= ep2 else (ep2, ep1)


def _format_link(link: dict[str, Any]) -> str:
    return (
        f"{link.get('device1')}:{link.get('port1')} <-> {link.get('device2')}:{link.get('port2')}"
    )


def compute_lab_diff(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    cli_log: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Compute a readable diff of device, link, interface, and CLI config changes."""
    before_devs = {str(d.get("name", "")): d for d in before.get("devices", [])}
    after_devs = {str(d.get("name", "")): d for d in after.get("devices", [])}

    devices_added: list[dict[str, Any]] = []
    devices_removed: list[dict[str, Any]] = []
    devices_modified: list[dict[str, Any]] = []

    for name in sorted(after_devs.keys() - before_devs.keys()):
        d = after_devs[name]
        devices_added.append(
            {
                "name": name,
                "model": d.get("model"),
                "hostname": d.get("hostname"),
                "type": d.get("type"),
            }
        )
    for name in sorted(before_devs.keys() - after_devs.keys()):
        d = before_devs[name]
        devices_removed.append(
            {
                "name": name,
                "model": d.get("model"),
                "hostname": d.get("hostname"),
                "type": d.get("type"),
            }
        )
    for name in sorted(before_devs.keys() & after_devs.keys()):
        db = before_devs[name]
        da = after_devs[name]
        if db.get("hostname") != da.get("hostname") or db.get("model") != da.get("model"):
            devices_modified.append(
                {
                    "name": name,
                    "before_model": db.get("model"),
                    "after_model": da.get("model"),
                    "before_hostname": db.get("hostname"),
                    "after_hostname": da.get("hostname"),
                }
            )

    before_links = {_canonical_link_key(lnk): lnk for lnk in before.get("links", [])}
    after_links = {_canonical_link_key(lnk): lnk for lnk in after.get("links", [])}
    links_added = [dict(after_links[k]) for k in sorted(after_links.keys() - before_links.keys())]
    links_removed = [
        dict(before_links[k]) for k in sorted(before_links.keys() - after_links.keys())
    ]

    def _port_map(snap: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
        out: dict[tuple[str, str], dict[str, Any]] = {}
        for dev in snap.get("devices", []):
            d_name = str(dev.get("name", ""))
            for port in dev.get("ports", []):
                p_name = str(port.get("name", ""))
                out[(d_name, p_name)] = {
                    "ip_address": str(port.get("ip_address") or ""),
                    "subnet_mask": str(port.get("subnet_mask") or ""),
                    "port_up": bool(port.get("port_up", False)),
                    "protocol_up": bool(port.get("protocol_up", False)),
                    "remote_device_name": str(port.get("remote_device_name") or ""),
                    "remote_port_name": str(port.get("remote_port_name") or ""),
                }
        return out

    before_ports = _port_map(before)
    after_ports = _port_map(after)
    interface_changes: list[dict[str, Any]] = []
    for key in sorted(set(before_ports) | set(after_ports)):
        b_state = before_ports.get(key)
        a_state = after_ports.get(key)
        if b_state != a_state:
            interface_changes.append(
                {
                    "device": key[0],
                    "interface": key[1],
                    "before": b_state,
                    "after": a_state,
                }
            )

    before_cli: dict[str, list[str]] = dict(before.get("executed_cli_commands") or {})
    after_cli: dict[str, list[str]] = (
        {k: list(v) for k, v in cli_log.items()}
        if cli_log is not None
        else dict(after.get("executed_cli_commands") or {})
    )
    config_changes: dict[str, dict[str, Any]] = {}
    for dev in sorted(set(before_cli) | set(after_cli)):
        b_cmds = list(before_cli.get(dev, []))
        a_cmds = list(after_cli.get(dev, []))
        if a_cmds != b_cmds:
            delta = a_cmds[len(b_cmds) :] if len(a_cmds) >= len(b_cmds) else a_cmds
            config_changes[dev] = {
                "commands_added": delta,
                "command_count": len(delta),
            }

    lines: list[str] = []
    if devices_added:
        lines.append(
            "Devices added: "
            + ", ".join(f"{d['name']} ({d.get('model') or 'unknown'})" for d in devices_added)
        )
    if devices_removed:
        lines.append(
            "Devices removed: "
            + ", ".join(f"{d['name']} ({d.get('model') or 'unknown'})" for d in devices_removed)
        )
    if devices_modified:
        lines.append(
            "Devices updated: "
            + ", ".join(
                f"{d['name']} ({d.get('before_hostname')} -> {d.get('after_hostname')})"
                for d in devices_modified
            )
        )
    if links_added:
        lines.append("Links added: " + ", ".join(_format_link(lnk) for lnk in links_added))
    if links_removed:
        lines.append("Links removed: " + ", ".join(_format_link(lnk) for lnk in links_removed))
    if interface_changes:
        iface_strs: list[str] = []
        for ic in interface_changes[:12]:
            after_s = ic.get("after") or {}
            ip_s = after_s.get("ip_address") or "unassigned"
            state_s = (
                "up/up"
                if (after_s.get("port_up") and after_s.get("protocol_up"))
                else ("up/down" if after_s.get("port_up") else "down")
            )
            iface_strs.append(f"{ic['device']}:{ic['interface']} ({ip_s}, {state_s})")
        extra = f" (+{len(interface_changes) - 12} more)" if len(interface_changes) > 12 else ""
        lines.append("Interface changes: " + ", ".join(iface_strs) + extra)
    if config_changes:
        cfg_strs = [
            f"{dev} ({info['command_count']} cmd(s))" for dev, info in config_changes.items()
        ]
        lines.append("Config changes applied: " + ", ".join(cfg_strs))

    has_changes = bool(
        devices_added
        or devices_removed
        or devices_modified
        or links_added
        or links_removed
        or interface_changes
        or config_changes
    )
    readable_summary = "\n".join(lines) if lines else "No device, link, or config changes detected."

    return {
        "has_changes": has_changes,
        "summary_counts": {
            "devices_added": len(devices_added),
            "devices_removed": len(devices_removed),
            "devices_modified": len(devices_modified),
            "links_added": len(links_added),
            "links_removed": len(links_removed),
            "interface_changes": len(interface_changes),
            "devices_configured": len(config_changes),
        },
        "devices_added": devices_added,
        "devices_removed": devices_removed,
        "devices_modified": devices_modified,
        "links_added": links_added,
        "links_removed": links_removed,
        "interface_changes": interface_changes,
        "config_changes": config_changes,
        "readable_summary": readable_summary,
    }


def _read_document_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".md", ".markdown", ".txt"}:
        return path.read_text(encoding="utf-8", errors="replace")
    if suffix == ".pdf":
        raw = path.read_bytes()
        # Extract readable ASCII/UTF-8 text segments without external heavy dependencies
        chunks = re.findall(r"[A-Za-z0-9][A-Za-z0-9 \t.,:/_\-\(\)]{5,}", raw.decode("latin-1"))
        return "\n".join(chunks[:400])
    return path.read_text(encoding="utf-8", errors="replace")


def detect_lab_input(target: str) -> dict[str, Any]:
    """Classify input into `lab_file` (.pkt/.pka), `document` (.md/.txt/.pdf), or `idea` text."""
    cleaned = str(target or "").strip().strip('"').strip("'")
    if not cleaned:
        raise ValidationError("lab_start input must not be empty.")

    lower = cleaned.lower()
    is_multiline = "\n" in cleaned
    if not is_multiline and lower.endswith((".pkt", ".pka")):
        ext = "pka" if lower.endswith(".pka") else "pkt"
        p = Path(cleaned).expanduser()
        return {
            "kind": "lab_file",
            "file_type": ext,
            "path": str(p),
            "exists": p.is_file(),
        }

    if not is_multiline and lower.endswith((".md", ".markdown", ".txt", ".pdf")):
        p = Path(cleaned).expanduser()
        text = _read_document_text(p) if p.is_file() else ""
        return {
            "kind": "document",
            "file_type": p.suffix.lower().lstrip("."),
            "path": str(p),
            "exists": p.is_file(),
            "text": text,
        }

    return {
        "kind": "idea",
        "file_type": "text",
        "path": None,
        "exists": False,
        "text": cleaned,
    }


def build_idea_or_doc_plan(text: str, *, source_label: str = "idea") -> dict[str, Any]:
    """Draft a compact topology/addressing/task plan (plus <=3 clarifying questions if vague)."""
    raw = str(text or "").strip()
    low = raw.lower()
    words = re.findall(r"[A-Za-z0-9_./-]+", raw)

    # Extract IPv4 blocks mentioned in prompt/doc
    mentioned_cidrs = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", raw)
    base_cidr = mentioned_cidrs[0] if mentioned_cidrs else "192.168.10.0/24"

    router_matches = re.findall(r"\bR\d+\b", raw)
    multi_router_cues = ("ospf", "rip", "wan", "routing", "two routers")
    single_router_cues = ("router", "ospf", "rip", "eigrp", "routing", "wan", "dhcp", "nat")
    router_count = max(
        len(set(router_matches)),
        2 if any(k in low for k in multi_router_cues) else 1,
    )
    if not any(k in low for k in single_router_cues) and router_matches == []:
        router_count = 1

    has_vlan = any(k in low for k in ("vlan", "trunk", "802.1q", "dot1q", "svi", "inter-vlan"))
    has_l3_switch = any(k in low for k in ("3560", "multilayer", "l3 switch", "svi"))
    has_dhcp = "dhcp" in low
    has_voip = any(k in low for k in ("voip", "7960", "ip phone", "telephony", "ephone", "cme"))
    has_ospf = "ospf" in low
    has_rip = "rip" in low
    has_eigrp = "eigrp" in low
    has_nat = any(k in low for k in ("nat", "pat", "overload"))

    devices: list[dict[str, str]] = []
    for idx in range(1, min(router_count, 6) + 1):
        devices.append({"name": f"R{idx}", "model": "2911", "role": "router"})

    switch_model = "3560-24PS" if has_l3_switch else "2960-24TT"
    switch_count = 2 if (router_count >= 2 or has_vlan) else 1
    for idx in range(1, switch_count + 1):
        devices.append({"name": f"SW{idx}", "model": switch_model, "role": "switch"})

    pc_count = 2 if not has_voip else 1
    for idx in range(1, pc_count + 1):
        devices.append({"name": f"PC{idx}", "model": "PC-PT", "role": "host"})

    if has_voip:
        devices.append({"name": "Phone1", "model": "7960", "role": "ip_phone"})

    addressing: list[str] = [f"Supernet: {base_cidr}"]
    if router_count >= 2:
        addressing.append("Point-to-point router transit link(s): /30 subnetworks")
    if has_vlan:
        addressing.append("Access VLAN subnets (e.g. VLAN 10 / VLAN 20) via VLSM")
    if has_dhcp:
        addressing.append("Router DHCP pool(s) with excluded gateway addresses")

    tasks: list[str] = [
        (
            "Verify device hardware capabilities (`device_capabilities`) and place "
            "topology (`device_add`, `connection_create`)."
        ),
        "Configure interface IP addressing and bring links up (`console_execute`).",
    ]
    if has_vlan:
        tasks.append("Configure switch VLANs, trunking, and inter-VLAN gateway/subinterfaces.")
    if has_ospf:
        tasks.append("Configure OSPF routing and verify full neighbor adjacencies.")
    elif has_rip:
        tasks.append("Configure RIPv2 routing (`no auto-summary`) and verify learned routes.")
    elif has_eigrp:
        tasks.append("Configure EIGRP routing and verify neighbor table and routes.")
    elif router_count >= 2:
        tasks.append("Configure static/dynamic routing between LANs.")
    if has_dhcp:
        tasks.append("Configure DHCP server pools and verify client lease bindings.")
    if has_nat:
        tasks.append("Configure NAT/PAT inside/outside interfaces and translations.")
    if has_voip:
        tasks.append("Power 7960 IP Phone(s) and configure CME extensions + verify registration.")
    tasks.append(
        "Verify all requirements via `verify_lab` / `lab_status`, inspect `lab_diff`, "
        "and save via `lab_save`."
    )

    specificity_cues = sum(
        [
            bool(mentioned_cidrs),
            bool(router_matches),
            has_vlan,
            has_dhcp,
            has_voip,
            has_ospf or has_rip or has_eigrp,
            has_nat,
            len(words) >= 12,
        ]
    )
    is_vague = len(raw) > 0 and (len(words) < 10 and specificity_cues <= 1)

    clarifying_questions: list[str] = []
    if is_vague:
        if not mentioned_cidrs:
            clarifying_questions.append(
                "Which IPv4 address block / VLSM scheme should we assign "
                "(for example 192.168.10.0/24 or 10.0.0.0/16)?"
            )
        if not (router_matches or has_vlan or has_voip):
            clarifying_questions.append(
                "How many routers, switches, VLANs, and end hosts should be in the topology?"
            )
        if not (has_ospf or has_rip or has_eigrp or has_dhcp or has_nat):
            clarifying_questions.append(
                "Which protocols or services are required "
                "(static routes, OSPF, RIPv2, DHCP, NAT, VoIP)?"
            )
        clarifying_questions = clarifying_questions[:3]

    dev_list_str = ", ".join(f"{d['name']} ({d['model']})" for d in devices)
    plan_md = "\n".join(
        [
            f"### Proposed Lab Plan ({source_label})",
            f"- **Devices:** {dev_list_str}",
            "- **Addressing:** " + "; ".join(addressing),
            "- **Tasks:**",
            *[f"  {i}. {t}" for i, t in enumerate(tasks, start=1)],
        ]
    )

    return {
        "source": source_label,
        "is_vague": is_vague,
        "clarifying_questions": clarifying_questions,
        "devices": devices,
        "addressing": addressing,
        "tasks": tasks,
        "plan_markdown": plan_md,
    }


def _detect_login_wall(detection: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(detection, dict):
        return []
    return [
        dlg
        for dlg in detection.get("dialogs", [])
        if str(dlg.get("dialog_type", "")).lower() == "login_wall"
    ]


def _safe_detect_gui(gui: Any) -> dict[str, Any] | None:
    try:
        try:
            res = gui.detect_application(include_dialog_buttons=False)
        except TypeError:
            res = gui.detect_application()
        return dict(res) if isinstance(res, dict) else None
    except Exception:
        return None


def _launch_pt_visibly(gui: Any, *, wait_seconds: float) -> dict[str, Any]:
    try:
        return dict(gui.launch_application(wait_seconds=wait_seconds, background=False))
    except TypeError:
        return dict(gui.launch_application(wait_seconds=wait_seconds))


def _infer_is_activity(path: str | None, open_data: Any) -> bool | None:
    if isinstance(open_data, dict) and "is_activity_file" in open_data:
        return bool(open_data["is_activity_file"])
    if path and path.lower().endswith(".pka"):
        return None
    return False


def _infer_dev_type_code(model: str, category: Any) -> int:
    cat_str = category.value if hasattr(category, "value") else str(category)
    model_key = str(model).strip().lower()
    if model_key in {"7960", "ip_phone", "cisco ip phone", "ip phone"}:
        cat_str = "ip_phone"
    elif "3650" in model_key:
        cat_str = "switch_3650"
    elif model_key in {"lap-pt", "lap", "3702i", "air-cap3702i", "cap3702i", "lightweight_ap"}:
        cat_str = "lap"
    elif model_key in {"5505", "5506-x", "5506"} or model_key.startswith("asa"):
        cat_str = "asa"
    elif model_key in {"2504", "3504"} or model_key.startswith("wlc"):
        cat_str = "wlc"
    elif model_key.startswith("cloud"):
        cat_str = "cloud"
    elif model_key in {"ata"} or model_key.startswith(("home-voip", "home_voip")):
        cat_str = "home_voip"
    elif model_key.startswith(("analog-phone", "analog_phone")):
        cat_str = "analog_phone"
    elif model_key.startswith("laptop"):
        cat_str = "laptop"
    elif model_key.startswith("tablet"):
        cat_str = "tablet_pc"
    elif model_key.startswith("smartphone"):
        cat_str = "smartphone"
    elif model_key in {"dlc100"} or model_key.startswith(
        ("homegateway", "home-gateway", "home_gateway")
    ):
        cat_str = "home_gateway"
    elif model_key.startswith("server"):
        cat_str = "server"
    elif model_key.startswith("printer"):
        cat_str = "printer"
    try:
        return resolve_device_type(cat_str)
    except Exception:
        return 0


def _apply_batch_build(
    runtime: Any,
    router: BackendRouter,
    *,
    devices: list[dict[str, Any]] | None = None,
    links: list[dict[str, Any]] | None = None,
    configs: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Place devices, wire links, and push CLI configs in one fast orchestrated pass."""
    _, topo, _, _ = runtime.manager.require_active()
    built_devices: list[dict[str, Any]] = []
    built_links: list[dict[str, Any]] = []
    config_reports: dict[str, dict[str, Any]] = {}
    failed_devices: set[str] = set()

    dev_list = list(devices or [])
    link_list = list(links or [])

    # Pre-register valid topology entries while remembering which were newly added for rollback.
    dev_entries: list[tuple[dict[str, Any], Any, bool]] = []
    for dev in dev_list:
        d_name = str(dev["name"])
        d_model = str(dev.get("model", "2911"))
        d_role = str(dev.get("role", ""))
        d_x = dev.get("x")
        d_y = dev.get("y")
        added_offline = d_name not in topo.model.devices
        dev_node = (
            topo.add_device(d_name, d_model, x=d_x, y=d_y, role=d_role)
            if added_offline
            else topo.model.devices[d_name]
        )
        dev_entries.append((dev, dev_node, added_offline))

    batch_applied = False
    is_http_bridge = (
        router.has_live_script()
        and isinstance(router.script_backend, HttpScriptBridgeBackend)
        and "batch_ops" in router.script_backend.backend_status().capabilities
    )
    host_cfg_count = sum(
        1
        for dev, _, _ in dev_entries
        if dev.get("dhcp") or dev.get("ip") or dev.get("ip_address")
    )
    if is_http_bridge and (len(dev_entries) + len(link_list) + host_cfg_count) > 1:
        ops: list[dict[str, Any]] = []
        op_meta: list[tuple[str, int]] = []
        for idx, (dev, dev_node, _) in enumerate(dev_entries):
            d_name = str(dev["name"])
            d_model = str(dev.get("model", "2911"))
            ops.append(
                {
                    "op": "add_device",
                    "alias": d_name,
                    "params": {
                        "device_type": _infer_dev_type_code(d_model, dev_node.category),
                        "model": d_model,
                        "display_name": d_name,
                        "x": float(dev_node.position.x),
                        "y": float(dev_node.position.y),
                    },
                }
            )
            op_meta.append(("dev", idx))
            if dev.get("dhcp") or dev.get("ip") or dev.get("ip_address"):
                host_params: dict[str, Any] = {
                    "device_name": d_name,
                    "port": str(dev.get("port", "FastEthernet0")),
                    "dhcp": bool(dev.get("dhcp", False)),
                    "ip": str(dev.get("ip") or dev.get("ip_address") or ""),
                    "subnet_mask": str(dev.get("subnet_mask", "")),
                    "default_gateway": str(
                        dev.get("default_gateway") or dev.get("gateway") or ""
                    ),
                }
                dns_val = str(dev.get("dns_server") or dev.get("dns") or "").strip()
                if dns_val:
                    host_params["dns_server"] = dns_val
                ops.append({"op": "configure_host", "params": host_params})
                op_meta.append(("host", idx))

        preconnected_links: dict[int, Any] = {}
        for lidx, link in enumerate(link_list):
            src = str(link.get("source_device") or link.get("device1") or "")
            src_if = str(link.get("source_interface") or link.get("port1") or "")
            dst = str(link.get("target_device") or link.get("device2") or "")
            dst_if = str(link.get("target_interface") or link.get("port2") or "")
            cable = str(link.get("cable_type") or link.get("conn_type") or "auto")
            clock_rate = link.get("clock_rate")
            topo_link = topo.connect(
                src, src_if, dst, dst_if, cable_type=cable, clock_rate=clock_rate
            )
            preconnected_links[lidx] = topo_link
            try:
                conn_code = resolve_connect_type(topo_link.cable_type.value)
            except Exception:
                conn_code = 8100
            ops.append(
                {
                    "op": "create_link",
                    "params": {
                        "device1": src,
                        "port1": src_if,
                        "device2": dst,
                        "port2": dst_if,
                        "conn_type": conn_code,
                    },
                }
            )
            op_meta.append(("link", lidx))

        batch_res = router.batch_ops(ops, timeout_seconds=max(30.0, len(ops) * 1.5))
        if isinstance(batch_res, dict) and isinstance(batch_res.get("results"), list):
            batch_applied = True
            raw_results: list[dict[str, Any]] = list(batch_res["results"])
            dev_results_by_idx: dict[int, dict[str, Any]] = {}
            link_results_by_idx: dict[int, dict[str, Any]] = {}
            for m_idx, (kind_tag, item_idx) in enumerate(op_meta):
                res_item = raw_results[m_idx] if m_idx < len(raw_results) else {}
                if kind_tag == "dev":
                    dev_results_by_idx[item_idx] = res_item
                elif kind_tag == "link":
                    link_results_by_idx[item_idx] = res_item

            for idx, (dev, _dev_node, added_offline) in enumerate(dev_entries):
                d_name = str(dev["name"])
                d_model = str(dev.get("model", "2911"))
                live_res = dict(dev_results_by_idx.get(idx, {}))
                live_data = live_res.get("data") if isinstance(live_res.get("data"), dict) else {}
                raw_pt_name = str(
                    live_res.get("device_name") or live_data.get("device_name") or ""
                ).strip()
                pt_name = raw_pt_name or router.resolve_pt_device_name(d_name)
                failed = live_res.get("ok") is False or not raw_pt_name
                errs: list[str] = []
                if failed:
                    failed_devices.add(d_name)
                    errs.append(
                        str(live_res.get("error") or f"Packet Tracer failed to add '{d_name}'.")
                    )
                    if added_offline:
                        with suppress(Exception):
                            topo.remove_device(d_name)
                built_devices.append(
                    {
                        "name": d_name,
                        "pt_name": pt_name,
                        "model": d_model,
                        "backend": "script_backend",
                        "errors": errs,
                        "live": live_res,
                    }
                )
            if router.watch_mode:
                router.record_watch_action(
                    "batch_ops",
                    (
                        f"Created {len(dev_entries) - len(failed_devices)}/{len(dev_entries)} "
                        f"device(s) and {len(link_list)} link(s) in batch."
                    ),
                    data={"devices": len(dev_entries), "links": len(link_list)},
                    pace=False,
                )

            for lidx, link in enumerate(link_list):
                src = str(link.get("source_device") or link.get("device1") or "")
                src_if = str(link.get("source_interface") or link.get("port1") or "")
                dst = str(link.get("target_device") or link.get("device2") or "")
                dst_if = str(link.get("target_interface") or link.get("port2") or "")
                topo_link = preconnected_links[lidx]
                cable = topo_link.cable_type.value
                live_res = dict(link_results_by_idx.get(lidx, {}))
                errs = []
                if src in failed_devices or dst in failed_devices:
                    errs.append(f"Skipped link {src}<->{dst}: endpoint device creation failed.")
                    with suppress(Exception):
                        topo.remove_connection(topo_link.connection_id)
                elif live_res.get("ok") is False:
                    errs.append(str(live_res.get("error") or f"Failed link {src}<->{dst} in PT."))
                    with suppress(Exception):
                        topo.remove_connection(topo_link.connection_id)
                built_links.append(
                    {
                        "source_device": src,
                        "source_interface": src_if,
                        "target_device": dst,
                        "target_interface": dst_if,
                        "cable_type": cable,
                        "backend": "script_backend",
                        "errors": errs,
                        "live": live_res,
                    }
                )
        else:
            # Older `.pts` returned unsupported opcode for `batch_ops`; undo pre-links first.
            for topo_link in preconnected_links.values():
                with suppress(Exception):
                    topo.remove_connection(topo_link.connection_id)

    if not batch_applied:
        for dev, dev_node, added_offline in dev_entries:
            d_name = str(dev["name"])
            d_model = str(dev.get("model", "2911"))
            backend_used, live_res, _ev, errs = router.add_device(
                d_name,
                d_model,
                category=dev_node.category,
                x=dev_node.position.x,
                y=dev_node.position.y,
            )
            add_failed = backend_used == "script_backend" and (
                (isinstance(live_res, dict) and live_res.get("ok") is False)
                or not str((live_res or {}).get("device_name", "")).strip()
            )
            if add_failed:
                failed_devices.add(d_name)
                if added_offline:
                    with suppress(Exception):
                        topo.remove_device(d_name)
            elif dev.get("dhcp") or dev.get("ip") or dev.get("ip_address"):
                router.configure_host(
                    d_name,
                    port=str(dev.get("port", "FastEthernet0")),
                    dhcp=bool(dev.get("dhcp", False)),
                    ip=str(dev.get("ip") or dev.get("ip_address") or "") or None,
                    subnet_mask=str(dev.get("subnet_mask", "")) or None,
                    default_gateway=str(dev.get("default_gateway") or dev.get("gateway") or "")
                    or None,
                    console_engine=runtime.console,
                )
            built_devices.append(
                {
                    "name": d_name,
                    "pt_name": router.resolve_pt_device_name(d_name),
                    "model": d_model,
                    "backend": backend_used,
                    "errors": errs,
                    "live": live_res,
                }
            )

        for link in link_list:
            src = str(link.get("source_device") or link.get("device1") or "")
            src_if = str(link.get("source_interface") or link.get("port1") or "")
            dst = str(link.get("target_device") or link.get("device2") or "")
            dst_if = str(link.get("target_interface") or link.get("port2") or "")
            cable = str(link.get("cable_type") or link.get("conn_type") or "auto")
            clock_rate = link.get("clock_rate")
            if src in failed_devices or dst in failed_devices:
                built_links.append(
                    {
                        "source_device": src,
                        "source_interface": src_if,
                        "target_device": dst,
                        "target_interface": dst_if,
                        "cable_type": cable,
                        "backend": "script_backend",
                        "errors": [f"Skipped link {src}<->{dst}: endpoint device creation failed."],
                        "live": {"ok": False},
                    }
                )
                continue
            topo_link = topo.connect(
                src, src_if, dst, dst_if, cable_type=cable, clock_rate=clock_rate
            )
            backend_used, live_res, _ev, errs = router.create_link(
                src, src_if, dst, dst_if, cable_type=cable
            )
            if backend_used == "script_backend" and (
                errs or (isinstance(live_res, dict) and live_res.get("ok") is False)
            ):
                with suppress(Exception):
                    topo.remove_connection(topo_link.connection_id)
            built_links.append(
                {
                    "source_device": src,
                    "source_interface": src_if,
                    "target_device": dst,
                    "target_interface": dst_if,
                    "cable_type": cable,
                    "backend": backend_used,
                    "errors": errs,
                    "live": live_res,
                }
            )

    cfg_map = dict(configs or {})
    if cfg_map:
        resolved_models = {
            dev_name: (
                topo.model.devices[dev_name].model if dev_name in topo.model.devices else "2911"
            )
            for dev_name in cfg_map
        }

        def _push_cfg(dev_name: str, cmds: list[str]) -> dict[str, Any]:
            return runtime.console.execute_commands(
                dev_name,
                list(cmds),
                model=resolved_models[dev_name],
                target_mode="preserve",
            )

        if (
            len(cfg_map) > 1
            and router.has_live_script()
            and isinstance(router.script_backend, HttpScriptBridgeBackend)
        ):
            with ThreadPoolExecutor(max_workers=min(len(cfg_map), 6)) as pool:
                futures = {
                    dev_name: pool.submit(_push_cfg, dev_name, list(cmds))
                    for dev_name, cmds in cfg_map.items()
                }
                for dev_name, fut in futures.items():
                    rep = fut.result()
                    if router.watch_mode:
                        router.record_watch_action(
                            "console_execute",
                            f"Executed {len(cfg_map[dev_name])} CLI command(s) on '{dev_name}'.",
                            data=rep,
                            pace=False,
                        )
                    config_reports[dev_name] = rep
        else:
            for dev_name, cmds in cfg_map.items():
                rep = _push_cfg(dev_name, list(cmds))
                if router.watch_mode:
                    router.record_watch_action(
                        "console_execute",
                        f"Executed {len(cmds)} CLI command(s) on '{dev_name}'.",
                        data=rep,
                        pace=False,
                    )
                config_reports[dev_name] = rep

    return {
        "devices": built_devices,
        "links": built_links,
        "configs": config_reports,
    }


def _mirror_session_descriptor(runtime: Any) -> None:
    """Mirror `bridge_session.json` to `%LOCALAPPDATA%/netforge` for `netforge_bridge.pts`."""
    settings = getattr(runtime, "settings", None)
    if settings is None:
        return
    src_session = Path(settings.data_dir) / "bridge_session.json"
    canonical_session = canonical_pt_bridge_data_dir() / "bridge_session.json"
    if src_session.is_file() and src_session.resolve() != canonical_session.resolve():
        with suppress(OSError):
            canonical_session.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src_session, canonical_session)


def start_lab_session(
    runtime: Any,
    input_target: str,
    *,
    auto_approve: bool = False,
    watch_mode: bool = True,
    watch_pace_seconds: float = 0.0,
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
    """One-command live start: detect input, draft/approve plan, attach PT, copy-on-write."""
    router: BackendRouter = runtime.router
    router.configure_watch_mode(enabled=watch_mode, pace_seconds=watch_pace_seconds)
    router.narration_log = []
    router.executed_cli_log = {}
    router.initial_snapshot = None
    router.latest_snapshot = None
    if hasattr(router, "_verifier_unsupported_cli"):
        router._verifier_unsupported_cli.clear()
    if hasattr(router, "unsupported_cli_commands") and isinstance(
        router.unsupported_cli_commands, dict
    ):
        router.unsupported_cli_commands.clear()

    runtime.manager.require_active()
    detected = detect_lab_input(input_target)
    kind = detected["kind"]

    plan: dict[str, Any] | None = None
    if kind in {"idea", "document"}:
        plan_text = detected.get("text") or ""
        if clarifications and clarifications.strip():
            plan_text = f"{plan_text}\n{clarifications.strip()}".strip()
        if kind == "document" and not detected.get("exists") and not plan_text:
            raise ValidationError(
                f"Lab document does not exist: {detected['path']}",
                details={"path": detected["path"]},
            )
        source_label = detected["path"] or "idea"
        plan = build_idea_or_doc_plan(plan_text, source_label=source_label)
        if not auto_approve:
            narration = router.record_watch_action(
                "plan",
                (
                    f"Prepared plan for '{source_label}' "
                    f"({len(plan['devices'])} device(s), {len(plan['tasks'])} task(s)). "
                    "Awaiting user OK."
                ),
                pace=False,
            )
            return {
                "state": "awaiting_plan_approval",
                "ready": False,
                "touched_packet_tracer": False,
                "input": detected,
                "plan": plan,
                "clarifying_questions": plan["clarifying_questions"],
                "watch_mode": router.watch_mode,
                "narration_log": [narration],
                "message": (
                    "Review the proposed topology/addressing/task plan below"
                    + (
                        " and answer up to 3 clarifying questions"
                        if plan["clarifying_questions"]
                        else ""
                    )
                    + ". Re-run `lab_start` with `auto_approve=True` once approved to touch "
                    "live PT."
                ),
            }

    # Mirror session descriptors before checking/launching PT so the bridge finds them immediately.
    _mirror_session_descriptor(runtime)

    bridge_connected = router.has_live_script()
    if bridge_connected:
        pt_running = True
        pt_status = "reused_running_instance"
    else:
        # Check live Packet Tracer GUI state only when bridge is not already connected.
        det = _safe_detect_gui(runtime.gui)
        login_dialogs = _detect_login_wall(det)
        if login_dialogs:
            return {
                "state": "waiting_for_login",
                "ready": False,
                "pt_status": "login_wall_detected",
                "touched_gui_clicks": False,
                "input": detected,
                "plan": plan,
                "dialogs": login_dialogs,
                "watch_mode": router.watch_mode,
                "message": (
                    "Packet Tracer is showing a Login / Guest screen. Sign in or accept Guest in "
                    "the PT window on your desktop, then re-run `lab_start` "
                    "(AgenticNet will not spam clicks)."
                ),
            }

        if isinstance(det, dict) and "running" in det:
            pt_running = bool(det.get("running"))
        else:
            pt_running = is_packet_tracer_running()

        if pt_running:
            pt_status = "reused_running_instance"
        else:
            try:
                require_interactive_desktop_for_launch("lab_start")
            except AdapterUnavailableError as exc:
                return {
                    "state": "waiting_for_user_launch",
                    "ready": False,
                    "pt_status": "non_interactive_session",
                    "error_code": exc.error_code,
                    "input": detected,
                    "plan": plan,
                    "watch_mode": router.watch_mode,
                    "message": (
                        "This MCP server is running in a non-interactive session and refuses "
                        "hidden launches. Please open Cisco Packet Tracer visibly from your Start "
                        "Menu / desktop, wait ~5 seconds, and call `lab_start` again."
                    ),
                }

            launch_out = _launch_pt_visibly(
                runtime.gui, wait_seconds=min(float(wait_seconds), 20.0)
            )
            launch_login = _detect_login_wall(launch_out.get("detection"))
            if launch_login:
                return {
                    "state": "waiting_for_login",
                    "ready": False,
                    "pt_status": "login_wall_detected",
                    "touched_gui_clicks": False,
                    "input": detected,
                    "plan": plan,
                    "dialogs": launch_login,
                    "watch_mode": router.watch_mode,
                    "message": (
                        "Packet Tracer opened onto a Login / Guest screen. Sign in on your desktop "
                        "window, then re-run `lab_start`."
                    ),
                }
            pt_status = (
                "reused_running_instance"
                if launch_out.get("already_running")
                else "launched_visibly"
            )

    # Wait for the live Script Module bridge to connect (with throttled login-wall checks).
    deadline = time.monotonic() + max(float(wait_seconds), 0.05)
    last_gui_check = time.monotonic()
    while not router.has_live_script():
        now = time.monotonic()
        if (now - last_gui_check) >= 0.8 or now >= deadline:
            last_gui_check = now
            det_poll = _safe_detect_gui(runtime.gui)
            login_poll = _detect_login_wall(det_poll)
            if login_poll:
                return {
                    "state": "waiting_for_login",
                    "ready": False,
                    "pt_status": "login_wall_detected",
                    "touched_gui_clicks": False,
                    "input": detected,
                    "plan": plan,
                    "dialogs": login_poll,
                    "watch_mode": router.watch_mode,
                    "message": (
                        "Packet Tracer is waiting on a Login / Guest screen. Complete login on "
                        "your desktop, then re-run `lab_start`."
                    ),
                }
        if now >= deadline:
            return {
                "state": "bridge_timeout",
                "ready": False,
                "pt_status": pt_status,
                "input": detected,
                "plan": plan,
                "watch_mode": router.watch_mode,
                "message": (
                    f"Timed out after {wait_seconds:.1f}s waiting for the AgenticNet Script "
                    "Module bridge to connect. Verify `netforge_bridge.pts` (com.netforge.bridge) "
                    "is enabled 'On Startup' in Packet Tracer -> Extensions -> Scripting."
                ),
            }
        time.sleep(min(0.1, max(0.02, deadline - time.monotonic())))

    original_path: str | None = None
    active_working_path: str | None = None
    backup_path: str | None = None

    if kind == "lab_file":
        router.clear_aliases()
        original_path = str(detected["path"])
        open_data: Any = {}
        if overwrite_original:
            if not confirm_overwrite_original:
                raise ValidationError(
                    "Overwriting the original .pkt/.pka file requires explicit approval "
                    "(confirm_overwrite_original=True).",
                    details={"original_path": original_path},
                    remediation=(
                        "Leave overwrite_original=False to work in a copy-on-write sibling."
                    ),
                )
            backup_path = create_original_backup(original_path)
            _, open_data, _, _ = router.open_file(original_path, timeout_seconds=wait_seconds)
            active_working_path = original_path
        else:
            _, open_data, _, _ = router.open_file(original_path, timeout_seconds=wait_seconds)
            if copy_on_write:
                active_working_path = derive_working_copy_path(original_path, working_copy_path)
                if not paths_refer_to_same_file(original_path, active_working_path):
                    router.save_file(
                        active_working_path,
                        overwrite=True,
                        timeout_seconds=wait_seconds,
                    )
            else:
                active_working_path = original_path

        router.active_original_path = original_path
        router.active_working_path = active_working_path
        router.active_backup_path = backup_path
        router.active_is_activity = _infer_is_activity(original_path, open_data)
    else:
        router.clear_aliases()
        router.active_original_path = None
        cleaned_wc = str(working_copy_path).strip() if working_copy_path else ""
        active_working_path = cleaned_wc or None
        router.active_working_path = active_working_path
        router.active_backup_path = None
        router.active_is_activity = False

    _, initial_snapshot, _, _ = collect_lab_snapshot(router, timeout_seconds=wait_seconds)
    batch_build: dict[str, Any] | None = None
    if devices or links or configs:
        batch_build = _apply_batch_build(
            runtime, router, devices=devices, links=links, configs=configs
        )
    msg = (
        f"Live lab session ready ({pt_status}). Working copy: {active_working_path} "
        f"(original preserved: {original_path})."
        if original_path and active_working_path and not overwrite_original
        else f"Live lab session ready ({pt_status}) with watch_mode={router.watch_mode}."
    )
    result: dict[str, Any] = {
        "state": "ready",
        "ready": True,
        "pt_status": pt_status,
        "execution_backend": "script_backend",
        "input": detected,
        "plan": plan,
        "original_path": original_path,
        "working_copy_path": active_working_path,
        "backup_path": backup_path,
        "copy_on_write": bool(copy_on_write and not overwrite_original),
        "watch_mode": router.watch_mode,
        "watch_pace_seconds": router.watch_pace_seconds,
        "initial_snapshot": initial_snapshot,
        "narration_log": list(router.narration_log),
        "message": msg,
    }
    if batch_build is not None:
        result["batch_build"] = batch_build
    return result


def _extract_drill_steps(step_spec: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """Normalize primary + optional secondary `{device, commands}` entries for a drill step."""
    steps: list[tuple[str, list[str]]] = []
    dev = str(step_spec.get("device", "")).strip()
    cmds = [str(c) for c in step_spec.get("commands", []) if str(c).strip()]
    if dev and cmds:
        steps.append((dev, cmds))
    sec = step_spec.get("secondary")
    if isinstance(sec, dict):
        s_dev = str(sec.get("device", "")).strip()
        s_cmds = [str(c) for c in sec.get("commands", []) if str(c).strip()]
        if s_dev and s_cmds:
            steps.append((s_dev, s_cmds))
    elif isinstance(sec, list):
        for item in sec:
            if isinstance(item, dict):
                s_dev = str(item.get("device", "")).strip()
                s_cmds = [str(c) for c in item.get("commands", []) if str(c).strip()]
                if s_dev and s_cmds:
                    steps.append((s_dev, s_cmds))
    return steps


def run_failure_drill(
    router: BackendRouter,
    lab_spec: dict[str, Any] | None = None,
    *,
    requirements: dict[str, Any] | list[dict[str, Any]] | None = None,
    break_step: dict[str, Any] | None = None,
    fix_step: dict[str, Any] | None = None,
    task_ids: list[str] | None = None,
    dry_run: bool = False,
    require_healthy_baseline: bool = True,
    settle_scale: float = 1.0,
    timeout_seconds: float = 25.0,
    poll_wait_seconds: float | None = 0.0,
    recovery_poll_wait_seconds: float | None = 0.0,
) -> dict[str, Any]:
    """Execute a reversible fault-injection and recovery verification drill.

    Runs:
    1) Baseline `evaluate_lab_status` check
    2) Controlled `break_step` CLI injection
    3) Outage verification (`expected_failing_ids` must fail)
    4) Guaranteed reversible `fix_step` restoration (`try ... finally`)
    5) Post-recovery `evaluate_lab_status` verification + timing telemetry
    """
    spec = lab_spec or {}
    resolved_reqs = requirements or spec.get("verification") or spec.get("requirements")
    resolved_break = break_step or spec.get("break_step")
    resolved_fix = fix_step or spec.get("fix_step")
    resolved_tasks = task_ids if task_ids is not None else spec.get("task_ids")

    if not resolved_reqs:
        raise ValidationError("run_failure_drill requires verification requirements.")
    if not isinstance(resolved_break, dict) or not _extract_drill_steps(resolved_break):
        raise ValidationError(
            "run_failure_drill requires a valid `break_step` with device/commands."
        )
    if not isinstance(resolved_fix, dict) or not _extract_drill_steps(resolved_fix):
        raise ValidationError("run_failure_drill requires a valid `fix_step` with device/commands.")

    break_ops = _extract_drill_steps(resolved_break)
    fix_ops = _extract_drill_steps(resolved_fix)
    expected_failing = [str(fid) for fid in resolved_break.get("expected_failing_ids", [])]

    if dry_run:
        return {
            "drill_passed": False,
            "dry_run": True,
            "state_level": StateLevel.PLANNED.value,
            "execution_backend": "offline_model",
            "break_operations": [{"device": d, "commands": c} for d, c in break_ops],
            "fix_operations": [{"device": d, "commands": c} for d, c in fix_ops],
            "expected_failing_ids": expected_failing,
        }

    if not router.has_live_script() or router.script_backend is None:
        raise AdapterUnavailableError(
            "run_failure_drill requires a connected Packet Tracer ScriptBackend (or dry_run=True)."
        )

    t_start = time.monotonic()
    t0 = time.monotonic()
    baseline = evaluate_lab_status(
        router,
        requirements=resolved_reqs,
        task_ids=resolved_tasks,
        include_activity_grade=False,
        timeout_seconds=timeout_seconds,
        poll_wait_seconds=poll_wait_seconds,
    )
    baseline_ms = round((time.monotonic() - t0) * 1000.0, 2)
    baseline_ok = bool(baseline.get("overall_passed"))

    if require_healthy_baseline and not baseline_ok:
        return {
            "drill_passed": False,
            "aborted_unhealthy_baseline": True,
            "reversible_restored": True,
            "state_level": baseline.get("state_level", StateLevel.EXECUTED.value),
            "execution_backend": "script_backend",
            "baseline": baseline,
            "timings_ms": {"baseline_ms": baseline_ms, "total_ms": baseline_ms},
        }

    break_transcripts: list[dict[str, Any]] = []
    fix_transcripts: list[dict[str, Any]] = []
    outage_status: dict[str, Any] = {}
    break_ms = 0.0
    outage_verify_ms = 0.0
    fix_ms = 0.0

    def _run_drill_ops(ops: list[tuple[str, list[str]]]) -> list[dict[str, Any]]:
        assert router.script_backend is not None
        if len(ops) > 1 and isinstance(router.script_backend, HttpScriptBridgeBackend):
            grouped: dict[str, list[tuple[int, str, str, list[str]]]] = {}
            for idx, (dev_name, cmds) in enumerate(ops):
                pt_dev = router.resolve_pt_device_name(dev_name)
                grouped.setdefault(pt_dev, []).append((idx, dev_name, pt_dev, cmds))

            def _exec_group(
                items: list[tuple[int, str, str, list[str]]],
            ) -> list[tuple[int, dict[str, Any]]]:
                out_items: list[tuple[int, dict[str, Any]]] = []
                for idx, dev_name, pt_dev, cmds in items:
                    res = router.script_backend.execute_cli(  # type: ignore[union-attr]
                        pt_dev, cmds, timeout_seconds=timeout_seconds
                    )
                    out_items.append(
                        (idx, {"device": dev_name, "pt_device": pt_dev, "result": res})
                    )
                return out_items

            ordered: list[dict[str, Any] | None] = [None] * len(ops)
            with ThreadPoolExecutor(max_workers=min(len(grouped), 6)) as pool:
                for chunk in pool.map(_exec_group, grouped.values()):
                    for idx, rec in chunk:
                        ordered[idx] = rec
            return [r for r in ordered if r is not None]

        out: list[dict[str, Any]] = []
        for dev_name, cmds in ops:
            pt_dev = router.resolve_pt_device_name(dev_name)
            res = router.script_backend.execute_cli(pt_dev, cmds, timeout_seconds=timeout_seconds)
            out.append({"device": dev_name, "pt_device": pt_dev, "result": res})
        return out

    try:
        tb = time.monotonic()
        break_transcripts = _run_drill_ops(break_ops)
        break_ms = round((time.monotonic() - tb) * 1000.0, 2)

        to = time.monotonic()
        outage_status = evaluate_lab_status(
            router,
            requirements=resolved_reqs,
            task_ids=resolved_tasks,
            include_activity_grade=False,
            timeout_seconds=timeout_seconds,
            poll_wait_seconds=0.0,
        )
        outage_verify_ms = round((time.monotonic() - to) * 1000.0, 2)
    finally:
        tf = time.monotonic()
        fix_transcripts = _run_drill_ops(fix_ops)
        settle_s = float(resolved_fix.get("settle_seconds", 0.0)) * max(0.0, float(settle_scale))
        if settle_s > 0:
            time.sleep(settle_s)
        fix_ms = round((time.monotonic() - tf) * 1000.0, 2)

    tr = time.monotonic()
    recovery_status = evaluate_lab_status(
        router,
        requirements=resolved_reqs,
        task_ids=resolved_tasks,
        include_activity_grade=False,
        timeout_seconds=timeout_seconds,
        poll_wait_seconds=recovery_poll_wait_seconds,
    )
    recovery_verify_ms = round((time.monotonic() - tr) * 1000.0, 2)
    total_ms = round((time.monotonic() - t_start) * 1000.0, 2)

    observed_failing = [
        str(item.get("id"))
        for item in outage_status.get("what_is_left", {}).get("failing_requirements", [])
        if item.get("id") is not None
    ]
    missing_expected = [fid for fid in expected_failing if fid not in observed_failing]
    outage_detected = not bool(outage_status.get("overall_passed"))
    expected_matched = len(missing_expected) == 0
    recovered = bool(recovery_status.get("overall_passed"))
    drill_passed = bool(baseline_ok and outage_detected and expected_matched and recovered)

    return {
        "drill_passed": drill_passed,
        "reversible_restored": recovered,
        "outage_detected": outage_detected,
        "expected_failing_ids": expected_failing,
        "observed_failing_ids": observed_failing,
        "missing_expected_failures": missing_expected,
        "state_level": recovery_status.get("state_level", StateLevel.EXECUTED.value),
        "execution_backend": "script_backend",
        "timings_ms": {
            "baseline_ms": baseline_ms,
            "break_ms": break_ms,
            "outage_verify_ms": outage_verify_ms,
            "fix_ms": fix_ms,
            "recovery_verify_ms": recovery_verify_ms,
            "total_ms": total_ms,
        },
        "break_transcripts": break_transcripts,
        "fix_transcripts": fix_transcripts,
        "baseline": baseline,
        "outage": outage_status,
        "recovery": recovery_status,
    }
