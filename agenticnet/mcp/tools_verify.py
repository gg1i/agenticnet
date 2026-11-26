"""MCP tools exposing declarative lab verification requirements schema and `verify_lab`."""

from __future__ import annotations

import re
from contextlib import suppress
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from pydantic import ValidationError as PydanticValidationError

from agenticnet.adapters.discovery import validate_lab_file_path
from agenticnet.core.enums import PermissionTier, PortMedia, StateLevel
from agenticnet.core.exceptions import (
    ApprovalRequiredError,
    DeviceModelError,
    ProjectNotOpenError,
    ValidationError,
)
from agenticnet.core.models import OperationResult
from agenticnet.diagnostics.grader import grade_open_activity
from agenticnet.diagnostics.lab_runner import (
    build_snapshot_payload,
    collect_lab_snapshot,
    compute_lab_diff,
    create_original_backup,
    derive_working_copy_path,
    evaluate_lab_status,
    paths_refer_to_same_file,
    run_failure_drill,
    start_lab_session,
)
from agenticnet.diagnostics.verifier import LabVerifier
from agenticnet.diagnostics.verify_schema import get_verify_requirements_schema
from agenticnet.ipam.engine import IPAMEngine
from agenticnet.mcp.registry import AgenticNetRuntime
from agenticnet.topology.engine import TopologyEngine
from agenticnet.topology.models import InterfaceState

_FALLBACK_MODEL_BY_TYPE: dict[str, str] = {
    "router": "2911",
    "switch": "2960-24TT",
    "l2_switch": "2960-24TT",
    "multilayer_switch": "3560-24PS",
    "switch_3650": "3650-24PS",
    "l3_switch": "3560-24PS",
    "pc": "PC-PT",
    "laptop": "Laptop-PT",
    "server": "Server-PT",
    "printer": "Printer-PT",
    "ip_phone": "7960",
    "home_voip": "Home-VOIP-PT",
    "wireless_router": "WRT300N",
    "home_gateway": "WRT300N",
    "access_point": "AccessPoint-PT",
    "lightweight_ap": "LAP-PT",
    "lap": "LAP-PT",
    "wlc": "WLC-2504",
    "asa": "5505",
    "firewall": "5505",
    "cloud": "Cloud-PT",
}


def _infer_port_media(port_name: str) -> PortMedia:
    low = port_name.lower()
    if low.startswith(("serial", "se")):
        return PortMedia.SERIAL
    if low.startswith(("tengigabit", "te")):
        return PortMedia.TEN_GIGABIT_ETHERNET
    if low.startswith(("gigabit", "gi")):
        return PortMedia.GIGABIT_ETHERNET
    if low.startswith(("wireless", "wlan", "dot11")):
        return PortMedia.WIRELESS
    if low.startswith("vlan"):
        return PortMedia.SVI
    if low.startswith("loopback"):
        return PortMedia.LOOPBACK
    return PortMedia.FAST_ETHERNET


def _sanitize_topo_device_name(raw_name: str, existing: set[str]) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw_name.strip()).strip("_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = f"D_{cleaned or 'dev'}"
    base = cleaned[:58]
    candidate = base
    idx = 1
    while candidate in existing:
        candidate = f"{base}_{idx}"
        idx += 1
    return candidate


def _ensure_hydrated_interface(
    runtime: AgenticNetRuntime,
    dev_node: Any,
    raw_port_name: str,
) -> str:
    cleaned = raw_port_name.strip()
    if not cleaned:
        return ""
    try:
        canon = runtime.catalog.normalize_interface_name(
            dev_node.model, cleaned, allow_logical=True
        )
    except Exception:
        canon = cleaned
    if canon not in dev_node.interfaces:
        media = _infer_port_media(canon)
        speed = (
            1000
            if media == PortMedia.GIGABIT_ETHERNET
            else (10000 if media == PortMedia.TEN_GIGABIT_ETHERNET else 100)
        )
        dev_node.interfaces[canon] = InterfaceState(
            name=canon,
            short_name=canon,
            media=media,
            speed_mbps=speed,
            admin_up=True,
            state_level=StateLevel.VERIFIED,
        )
    return canon


def _hydrate_topology_from_live_snapshot(
    runtime: AgenticNetRuntime,
    snap_data: dict[str, Any],
    lab_path: str,
) -> dict[str, Any] | None:
    """Populate active ProjectManager TopologyEngine, IPAMEngine, and aliases from PT snapshot."""
    raw_devs = list(snap_data.get("devices") or [])
    if not raw_devs:
        return None

    try:
        meta, topo, ipam, _ = runtime.manager.require_active()
    except ProjectNotOpenError:
        stem = re.sub(r"[^a-z0-9]+", "-", Path(lab_path).stem.lower()).strip("-")
        if len(stem) < 2:
            stem = f"lab-{stem or 'open'}"
        runtime.manager.create_project(
            Path(lab_path).stem or "Opened Lab",
            project_id=stem[:60],
            packet_tracer_file=lab_path,
        )
        meta, topo, ipam, _ = runtime.manager.require_active()

    staged_topo = TopologyEngine(catalog=runtime.catalog)
    staged_ipam = IPAMEngine()

    raw_pt_names = {str(d.get("name") or "").strip() for d in raw_devs if d.get("name")}
    hostname_counts: dict[str, int] = {}
    for d in raw_devs:
        h = str(d.get("hostname") or "").strip()
        if h:
            hostname_counts[h] = hostname_counts.get(h, 0) + 1

    pt_to_topo: dict[str, str] = {}
    used_names: set[str] = set()

    for d in raw_devs:
        pt_name = str(d.get("name") or "").strip()
        if not pt_name:
            continue
        topo_name = _sanitize_topo_device_name(pt_name, used_names)
        used_names.add(topo_name)

        raw_model = str(d.get("model") or "").strip()
        type_str = str(d.get("type") or "").strip().lower()
        try:
            resolved_model = runtime.catalog.resolve_model_name(raw_model)
        except (DeviceModelError, Exception):
            fallback_cand = _FALLBACK_MODEL_BY_TYPE.get(type_str, "PC-PT")
            resolved_model = runtime.catalog.resolve_model_name(fallback_cand)

        raw_x = d.get("x")
        raw_y = d.get("y")
        pos_x = float(raw_x) if isinstance(raw_x, (int, float)) and float(raw_x) >= 0 else None
        pos_y = float(raw_y) if isinstance(raw_y, (int, float)) and float(raw_y) >= 0 else None
        hostname = str(d.get("hostname") or "").strip()

        node = staged_topo.add_device(
            topo_name,
            resolved_model,
            x=pos_x,
            y=pos_y,
            role=hostname if hostname and hostname != topo_name else "",
            metadata={"pt_name": pt_name, "hostname": hostname, "raw_model": raw_model},
        )
        node.state_level = StateLevel.VERIFIED
        pt_to_topo[pt_name] = node.name

        if node.name != pt_name:
            runtime.router.device_aliases[node.name] = pt_name
        if (
            hostname
            and hostname != pt_name
            and hostname not in raw_pt_names
            and hostname_counts.get(hostname, 0) == 1
        ):
            runtime.router.device_aliases[hostname] = pt_name

        dev_gw = str(d.get("default_gateway") or d.get("gateway") or "").strip()
        if dev_gw in {"0.0.0.0", "unassigned"}:
            dev_gw = ""

        for p in d.get("ports") or []:
            canon_p = _ensure_hydrated_interface(runtime, node, str(p.get("name") or ""))
            if not canon_p:
                continue
            iface = node.interfaces[canon_p]
            iface.state_level = StateLevel.VERIFIED
            ip_val = str(p.get("ip_address") or "").strip()
            mask_val = str(p.get("subnet_mask") or "").strip()
            gw_val = str(p.get("default_gateway") or p.get("gateway") or dev_gw).strip()

            if ip_val and ip_val.lower() not in {"0.0.0.0", "unassigned"}:
                iface.ip_address = ip_val
            if mask_val and mask_val.lower() not in {"0.0.0.0", "unassigned"}:
                iface.subnet_mask = mask_val
            if gw_val and gw_val.lower() not in {"0.0.0.0", "unassigned"}:
                iface.default_gateway = gw_val

            if p.get("admin_down") is True:
                iface.admin_up = False
            elif "port_up" in p and (iface.ip_address or p.get("has_link")):
                iface.admin_up = bool(p.get("port_up"))

            if iface.ip_address and iface.subnet_mask:
                alloc_kind = (
                    "svi"
                    if canon_p.startswith("Vlan")
                    else ("loopback" if canon_p.startswith("Loopback") else "static")
                )
                with suppress(Exception):
                    staged_ipam.allocate_address(
                        node.name,
                        canon_p,
                        iface.ip_address,
                        subnet_mask=iface.subnet_mask,
                        gateway=iface.default_gateway,
                        allocation_type=alloc_kind,
                    )

    for lnk in snap_data.get("links") or []:
        d1_pt = str(lnk.get("device1") or "").strip()
        d2_pt = str(lnk.get("device2") or "").strip()
        p1_raw = str(lnk.get("port1") or "").strip()
        p2_raw = str(lnk.get("port2") or "").strip()
        src_name = pt_to_topo.get(d1_pt)
        dst_name = pt_to_topo.get(d2_pt)
        if not src_name or not dst_name or not p1_raw or not p2_raw:
            continue
        src_node = staged_topo.model.devices[src_name]
        dst_node = staged_topo.model.devices[dst_name]
        c_p1 = _ensure_hydrated_interface(runtime, src_node, p1_raw)
        c_p2 = _ensure_hydrated_interface(runtime, dst_node, p2_raw)
        with suppress(Exception):
            edge = staged_topo.connect(src_name, c_p1, dst_name, c_p2, cable_type="auto")
            edge.state_level = StateLevel.VERIFIED

    meta.packet_tracer_file = lab_path
    topo.model = staged_topo.model
    topo._rebuild_graph()
    ipam.state = staged_ipam.state
    return {
        "project_id": meta.project_id,
        "hydrated_devices": len(topo.model.devices),
        "hydrated_connections": len(topo.model.connections),
    }


def register_verify_tools(server: MCPServer, runtime: AgenticNetRuntime) -> None:
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

        Pass ``poll_wait_seconds=0.0`` for instant single-pass verification once configs have
        settled, or a short deadline (e.g., ``10.0``) when waiting for DHCP/OSPF/CME convergence.
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
        """One-command live start for `.pkt`/`.pka` files, docs, or specs.

        Fast path: pass `auto_approve=True` with full `devices`, `links`, and `configs`
        (`{device: [cli_cmds]}`) to attach PT, place all devices/links in 1 `batch_ops` call,
        and push multi-device IOS configs in parallel in a single turn.
        """

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
            validate_lab_file_path(cleaned, must_exist=False)
            if working_copy_path is not None and str(working_copy_path).strip():
                validate_lab_file_path(str(working_copy_path).strip(), must_exist=False)
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
                hydration = _hydrate_topology_from_live_snapshot(
                    runtime, snap_data, cleaned
                )
                if hydration is not None:
                    data["topology_hydration"] = hydration
                    ev.append(
                        f"Hydrated active project '{hydration['project_id']}' with "
                        f"{hydration['hydrated_devices']} device(s) and "
                        f"{hydration['hydrated_connections']} link(s)."
                    )
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
        confirm: bool = False,
        timeout_seconds: float = 30.0,
        include_diff: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Save active PT lab; pass `include_diff=False` to skip post-save snapshot."""

        def _run() -> OperationResult:
            cleaned = str(path).strip() if path is not None else None
            if path is not None and not cleaned:
                raise ValidationError("Destination path must not be blank when provided.")
            effective_path = (
                cleaned if cleaned is not None else runtime.router.active_working_path
            )
            if effective_path is not None:
                validate_lab_file_path(effective_path, must_exist=False)
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
            work_path = runtime.router.active_working_path
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
                            "working_copy_path": work_path,
                        },
                        remediation=(
                            "Save to the working copy (path=None or *_agenticnet.pkt), or pass "
                            "overwrite_original=True and confirm_overwrite_original=True."
                        ),
                    )
                backup_path = create_original_backup(orig_path)
                runtime.router.active_backup_path = backup_path
            elif (
                effective_path
                and not (work_path and paths_refer_to_same_file(effective_path, work_path))
                and Path(effective_path).expanduser().is_file()
            ):
                if not overwrite:
                    raise ValidationError(
                        f"Destination lab file '{effective_path}' already exists "
                        "and overwrite=False.",
                        details={"path": effective_path},
                        remediation="Choose a new path or pass overwrite=True and confirm=True.",
                    )
                if not confirm:
                    raise ApprovalRequiredError(
                        f"Overwriting existing lab file '{effective_path}' requires confirm=True.",
                        details={"path": effective_path},
                        remediation=(
                            "Pass confirm=True to overwrite the existing lab file, "
                            "or save to a new path."
                        ),
                    )

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
                "confirm": confirm,
                "timeout_seconds": timeout_seconds,
                "include_diff": include_diff,
                "dry_run": dry_run,
            },
            _run,
            confirm=confirm,
        )

    def lab_status(
        requirements: dict[str, Any] | list[dict[str, Any]] | None = None,
        task_ids: list[str] | None = None,
        include_activity_grade: bool = True,
        timeout_seconds: float = 25.0,
        poll_wait_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Combine `verify_lab`, `grade_lab`, and task coverage, listing what is left.

        Pass ``poll_wait_seconds=0.0`` for instant single-pass verification or a short deadline
        (e.g., ``10.0``) when waiting for protocol convergence.
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

    def lab_failure_drill(
        requirements: dict[str, Any] | list[dict[str, Any]] | None = None,
        break_step: dict[str, Any] | None = None,
        fix_step: dict[str, Any] | None = None,
        lab_spec: dict[str, Any] | None = None,
        task_ids: list[str] | None = None,
        dry_run: bool = False,
        require_healthy_baseline: bool = True,
        settle_scale: float = 1.0,
        timeout_seconds: float = 25.0,
        poll_wait_seconds: float | None = 0.0,
        recovery_poll_wait_seconds: float | None = 0.0,
    ) -> dict[str, Any]:
        """Run a reversible fault-injection and convergence recovery drill on a live lab."""
        params = {
            "has_requirements": requirements is not None,
            "has_break_step": break_step is not None,
            "has_fix_step": fix_step is not None,
            "has_lab_spec": lab_spec is not None,
            "dry_run": dry_run,
            "require_healthy_baseline": require_healthy_baseline,
        }

        def _run() -> OperationResult:
            drill = run_failure_drill(
                runtime.router,
                lab_spec,
                requirements=requirements,
                break_step=break_step,
                fix_step=fix_step,
                task_ids=task_ids,
                dry_run=dry_run,
                require_healthy_baseline=require_healthy_baseline,
                settle_scale=settle_scale,
                timeout_seconds=timeout_seconds,
                poll_wait_seconds=poll_wait_seconds,
                recovery_poll_wait_seconds=recovery_poll_wait_seconds,
            )
            lvl = StateLevel(drill.get("state_level", StateLevel.PLANNED.value))
            backend = drill.get("execution_backend", "offline_model")
            if dry_run:
                summary = "Planned reversible failure drill (dry_run=True)."
            elif drill.get("drill_passed"):
                summary = (
                    "Failure drill passed: baseline healthy, outage verified, "
                    "and recovery restored."
                )
            else:
                summary = (
                    "Failure drill completed with unmet assertions "
                    f"(reversible_restored={drill.get('reversible_restored')})."
                )
            return OperationResult.ok(
                "lab_failure_drill",
                summary,
                data=drill,
                state_level=lvl,
                execution_backend=backend,
                evidence=[summary],
            )

        return runtime.execute(
            "lab_failure_drill",
            PermissionTier.CONFIGURATION,
            params,
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
        ("lab_failure_drill", lab_failure_drill, PermissionTier.CONFIGURATION, False),
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
