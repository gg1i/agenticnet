"""Live CLI verification engine (`verify_lab`) backed by Packet Tracer ScriptBackend."""

from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from agenticnet.adapters.router import BackendRouter
from agenticnet.adapters.script_bridge import HttpScriptBridgeBackend
from agenticnet.core.enums import StateLevel
from agenticnet.core.exceptions import AgenticNetError
from agenticnet.core.models import ExecutionBackend
from agenticnet.diagnostics.verify_schema import (
    ConfigContainsRequirement,
    DhcpBindingRequirement,
    EphoneRegisteredRequirement,
    InterfaceUpRequirement,
    IpAssignedRequirement,
    LabRequirement,
    ReachableRequirement,
    RouteExistsRequirement,
    TelephonyServiceRequirement,
    VerifyLabRequest,
    VlanExistsRequirement,
    normalize_requirements_payload,
)
from agenticnet.security.redaction import redact_cli_text
from agenticnet.simulation.parsers import (
    canonicalize_interface_name,
    detect_cli_read_error,
    parse_ping_output,
    parse_running_config_sections,
    parse_show_ephone,
    parse_show_ip_dhcp_binding,
    parse_show_ip_int_brief,
    parse_show_ip_route,
    parse_show_telephony_service,
    parse_show_vlan_brief,
)


@dataclass(slots=True)
class _CliReadOutcome:
    command: str
    raw_evidence: str
    error: str | None = None
    timed_out: bool = False


def _strip_prefix(ip_or_cidr: str) -> str:
    return ip_or_cidr.split("/", 1)[0].strip()


def _command_for_requirement(req: LabRequirement) -> tuple[str, str, bool]:
    """Return `(device_name, ios_command, cacheable)` for a requirement."""
    if isinstance(req, (InterfaceUpRequirement, IpAssignedRequirement)):
        return (req.device, "show ip interface brief", True)
    if isinstance(req, RouteExistsRequirement):
        return (req.device, "show ip route", True)
    if isinstance(req, VlanExistsRequirement):
        return (req.device, "show vlan brief", True)
    if isinstance(req, DhcpBindingRequirement):
        return (req.device, "show ip dhcp binding", True)
    if isinstance(req, ReachableRequirement):
        return (req.source, f"ping {req.target}", False)
    if isinstance(req, ConfigContainsRequirement):
        return (req.device, "show running-config", True)
    if isinstance(req, TelephonyServiceRequirement):
        return (req.device, "show telephony-service", True)
    if isinstance(req, EphoneRegisteredRequirement):
        return (req.device, "show ephone", True)
    raise TypeError(f"Unsupported requirement type: {type(req)!r}")


def _evaluate_requirement(req: LabRequirement, read: _CliReadOutcome) -> dict[str, Any]:
    """Evaluate one parsed requirement strictly against captured CLI evidence."""
    base: dict[str, Any] = {
        "id": req.id,
        "task_id": req.task_id,
        "type": req.type,
        "device": req.source if isinstance(req, ReachableRequirement) else req.device,
        "command": read.command,
        "evidence": read.raw_evidence,
    }
    if req.description:
        base["description"] = req.description

    if read.error is not None or not read.raw_evidence.strip():
        return {
            **base,
            "status": "error",
            "reason": read.error or "No raw CLI evidence captured from Packet Tracer.",
            "parsed": None,
        }

    if isinstance(req, InterfaceUpRequirement):
        rows = parse_show_ip_int_brief(read.raw_evidence)
        target_canon = canonicalize_interface_name(req.interface)
        matched = next(
            (r for r in rows if canonicalize_interface_name(r.interface) == target_canon),
            None,
        )
        if matched is None:
            return {
                **base,
                "status": "fail",
                "reason": f"Interface '{req.interface}' not found in `show ip interface brief`.",
                "parsed": {"interfaces_seen": [r.interface for r in rows]},
            }
        ok = (
            matched.status.lower() == req.expected_status.lower()
            and matched.protocol.lower() == req.expected_protocol.lower()
        )
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": (
                None
                if ok
                else (
                    f"Interface '{matched.interface}' is {matched.status}/{matched.protocol}, "
                    f"expected {req.expected_status}/{req.expected_protocol}."
                )
            ),
            "parsed": matched.model_dump(mode="json"),
        }

    if isinstance(req, IpAssignedRequirement):
        rows = parse_show_ip_int_brief(read.raw_evidence)
        target_canon = canonicalize_interface_name(req.interface)
        expected_ip = _strip_prefix(req.ip)
        matched = next(
            (r for r in rows if canonicalize_interface_name(r.interface) == target_canon),
            None,
        )
        if matched is None:
            return {
                **base,
                "status": "fail",
                "reason": f"Interface '{req.interface}' not found in `show ip interface brief`.",
                "parsed": {"interfaces_seen": [r.interface for r in rows]},
            }
        ip_ok = matched.ip_address == expected_ip
        up_ok = True if not req.require_up else matched.is_up_up
        ok = ip_ok and up_ok
        reasons: list[str] = []
        if not ip_ok:
            reasons.append(f"IP is '{matched.ip_address}', expected '{expected_ip}'.")
        if not up_ok:
            reasons.append(
                f"Interface state is {matched.status}/{matched.protocol}, expected up/up."
            )
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": " ".join(reasons) if reasons else None,
            "parsed": matched.model_dump(mode="json"),
        }

    if isinstance(req, RouteExistsRequirement):
        parsed_table = parse_show_ip_route(read.raw_evidence)
        routes = parsed_table["routes"]

        def _filter_route_attrs(items: list[Any]) -> list[Any]:
            filtered = list(items)
            if req.protocol_code:
                code_u = req.protocol_code.strip().upper()
                filtered = [r for r in filtered if r.code.upper().startswith(code_u)]
            if req.next_hop:
                filtered = [r for r in filtered if r.next_hop == req.next_hop.strip()]
            if req.outgoing_interface:
                want_if = canonicalize_interface_name(req.outgoing_interface)
                filtered = [
                    r
                    for r in filtered
                    if r.outgoing_interface
                    and canonicalize_interface_name(r.outgoing_interface) == want_if
                ]
            return filtered

        candidates = _filter_route_attrs([r for r in routes if r.network == req.network])
        if not candidates and "/" in req.network:
            try:
                target_net = ipaddress.ip_network(req.network, strict=False)
                if isinstance(target_net, ipaddress.IPv4Network):
                    host_candidates: list[Any] = []
                    for r in _filter_route_attrs(routes):
                        if "/" in r.network and r.network.endswith("/32"):
                            try:
                                route_net = ipaddress.ip_network(r.network, strict=False)
                            except ValueError:
                                continue
                            if (
                                isinstance(route_net, ipaddress.IPv4Network)
                                and route_net.subnet_of(target_net)
                            ):
                                host_candidates.append(r)
                    candidates = host_candidates
            except ValueError:
                pass

        ok = len(candidates) > 0
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": (
                None
                if ok
                else f"No matching route for '{req.network}' found in `show ip route`."
            ),
            "parsed": {
                "gateway_of_last_resort": parsed_table["gateway_of_last_resort"],
                "matched_routes": [r.model_dump(mode="json") for r in candidates],
                "total_routes_parsed": len(routes),
            },
        }

    if isinstance(req, VlanExistsRequirement):
        vlans = parse_show_vlan_brief(read.raw_evidence)
        matched = next((v for v in vlans if v.vlan_id == req.vlan_id), None)
        if matched is None:
            return {
                **base,
                "status": "fail",
                "reason": f"VLAN {req.vlan_id} not present in `show vlan brief`.",
                "parsed": {"vlan_ids_seen": [v.vlan_id for v in vlans]},
            }
        reasons = []
        if req.name is not None and matched.name != req.name:
            reasons.append(f"VLAN {req.vlan_id} name is '{matched.name}', expected '{req.name}'.")
        if matched.status.lower() != req.status.lower():
            reasons.append(
                f"VLAN {req.vlan_id} status is '{matched.status}', expected '{req.status}'."
            )
        if req.ports:
            have_ports = {canonicalize_interface_name(p) for p in matched.ports}
            missing_ports = [
                p for p in req.ports if canonicalize_interface_name(p) not in have_ports
            ]
            if missing_ports:
                reasons.append(f"VLAN {req.vlan_id} missing ports: {missing_ports}.")
        ok = len(reasons) == 0
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": " ".join(reasons) if reasons else None,
            "parsed": matched.model_dump(mode="json"),
        }

    if isinstance(req, DhcpBindingRequirement):
        bindings = parse_show_ip_dhcp_binding(read.raw_evidence)
        filtered = bindings
        if req.ip:
            filtered = [b for b in filtered if b.ip_address == req.ip.strip()]
        if req.client_id:
            want_cid = req.client_id.strip().lower()
            filtered = [b for b in filtered if want_cid in b.client_id.lower()]
        ok = len(filtered) >= req.min_bindings
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": (
                None
                if ok
                else (
                    f"Found {len(filtered)} matching DHCP binding(s), "
                    f"expected >= {req.min_bindings}."
                )
            ),
            "parsed": {
                "matched_bindings": [b.model_dump(mode="json") for b in filtered],
                "total_bindings": len(bindings),
            },
        }

    if isinstance(req, ReachableRequirement):
        summary = parse_ping_output(read.raw_evidence, target_ip=req.target)
        if summary.transmitted == 0 and not summary.reached:
            return {
                **base,
                "status": "error",
                "reason": "Ping output lacked summary statistics; command did not finish cleanly.",
                "parsed": summary.model_dump(mode="json"),
            }
        ok = summary.received >= req.min_received
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": (
                None
                if ok
                else (
                    f"Ping from '{req.source}' to '{req.target}' received "
                    f"{summary.received}/{summary.transmitted} replies "
                    f"(needed >= {req.min_received})."
                )
            ),
            "parsed": summary.model_dump(mode="json"),
        }

    if isinstance(req, ConfigContainsRequirement):
        sections = parse_running_config_sections(read.raw_evidence, section=req.section)
        if req.section is not None and not sections:
            return {
                **base,
                "status": "fail",
                "reason": f"Running-config section matching '{req.section}' not found.",
                "parsed": {"matched_sections": []},
            }
        haystack = (
            "\n".join(s.text for s in sections)
            if req.section is not None
            else read.raw_evidence
        )
        missing = [pat for pat in req.contains if pat not in haystack]
        forbidden = [pat for pat in req.must_not_contain if pat in haystack]
        reasons = []
        if missing:
            reasons.append(f"Missing required snippet(s): {missing}.")
        if forbidden:
            reasons.append(f"Forbidden snippet(s) present: {forbidden}.")
        ok = len(reasons) == 0
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": " ".join(reasons) if reasons else None,
            "parsed": {
                "section_filter": req.section,
                "matched_sections": [s.header for s in sections],
                "missing": missing,
                "forbidden_present": forbidden,
            },
        }

    if isinstance(req, TelephonyServiceRequirement):
        tel = parse_show_telephony_service(read.raw_evidence)
        reasons = []
        if not tel.configured:
            reasons.append("CME telephony-service is not configured/active.")
        if req.source_address is not None and tel.source_address != req.source_address:
            reasons.append(
                f"ip source-address is {tel.source_address!r}, expected {req.source_address!r}."
            )
        if req.source_port is not None and tel.source_port != req.source_port:
            reasons.append(f"source port is {tel.source_port!r}, expected {req.source_port!r}.")
        if req.min_ephones is not None and (tel.max_ephones or 0) < req.min_ephones:
            reasons.append(f"max-ephones is {tel.max_ephones!r}, expected >= {req.min_ephones}.")
        if req.min_dn is not None and (tel.max_dn or 0) < req.min_dn:
            reasons.append(f"max-dn is {tel.max_dn!r}, expected >= {req.min_dn}.")
        ok = len(reasons) == 0
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": " ".join(reasons) if reasons else None,
            "parsed": tel.model_dump(mode="json"),
        }

    if isinstance(req, EphoneRegisteredRequirement):
        ephones = parse_show_ephone(read.raw_evidence)
        candidates = ephones
        if req.ephone_id is not None:
            candidates = [e for e in candidates if e.ephone_id == req.ephone_id]
        if req.mac_address is not None:
            want_mac = req.mac_address.strip().lower()
            candidates = [
                e for e in candidates if e.mac_address and want_mac in e.mac_address.lower()
            ]
        if req.number is not None:
            candidates = [
                e for e in candidates if any(b.number == req.number for b in e.buttons)
            ]
        if req.require_registered:
            candidates = [e for e in candidates if e.status.upper() == "REGISTERED"]
        ok = len(candidates) > 0
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": (
                None
                if ok
                else "No matching ephone entry satisfied registration/extension criteria."
            ),
            "parsed": {
                "matched_ephones": [e.model_dump(mode="json") for e in candidates],
                "total_ephones": len(ephones),
            },
        }

    raise TypeError(f"Unsupported requirement type: {type(req)!r}")


def _build_task_coverage(
    expected_task_ids: list[str] | None,
    requirements: list[LabRequirement],
) -> dict[str, Any] | None:
    """Compute requirement-to-task coverage against declared `task_ids`."""
    if expected_task_ids is None:
        return None
    normalized_expected: list[str] = []
    seen: set[str] = set()
    for tid in expected_task_ids:
        cleaned = str(tid).strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            normalized_expected.append(cleaned)

    by_task: dict[str, list[str]] = {tid: [] for tid in normalized_expected}
    extra_task_ids: list[str] = []
    untagged_requirements = 0
    for idx, req in enumerate(requirements, start=1):
        req_key = req.id or f"req_{idx}"
        if req.task_id is None or not req.task_id.strip():
            untagged_requirements += 1
            continue
        tid = req.task_id.strip()
        if tid in by_task:
            by_task[tid].append(req_key)
        else:
            by_task.setdefault(tid, []).append(req_key)
            if tid not in extra_task_ids:
                extra_task_ids.append(tid)

    covered = [tid for tid in normalized_expected if by_task.get(tid)]
    uncovered = [tid for tid in normalized_expected if not by_task.get(tid)]
    total = len(normalized_expected)
    return {
        "expected_tasks": normalized_expected,
        "covered_tasks": covered,
        "uncovered_tasks": uncovered,
        "extra_task_ids": extra_task_ids,
        "untagged_requirements": untagged_requirements,
        "requirements_by_task": by_task,
        "coverage_ratio": round(len(covered) / total, 3) if total else 1.0,
        "all_tasks_covered": len(uncovered) == 0,
    }


class PacedDeviceCliQueue:
    """Serializes and paces CLI requests per device with bounded retries."""

    def __init__(self, pacing_seconds: float = 0.25, max_retries: int = 2) -> None:
        self.pacing_seconds = max(0.0, float(pacing_seconds))
        self.max_retries = max(0, int(max_retries))
        self._last_call: dict[str, float] = {}

    def pace(self, device_name: str) -> None:
        now = time.monotonic()
        last = self._last_call.get(device_name, 0.0)
        elapsed = now - last
        if elapsed < self.pacing_seconds:
            time.sleep(self.pacing_seconds - elapsed)
        self._last_call[device_name] = time.monotonic()

    def record_call(self, device_name: str) -> None:
        self._last_call[device_name] = time.monotonic()


class LabVerifier:
    """Evaluates declarative lab requirements strictly from live PT CLI read-backs."""

    def __init__(
        self,
        router: BackendRouter,
        *,
        cli_pacing_seconds: float | None = None,
        max_cli_retries: int = 2,
    ) -> None:
        self.router = router
        effective_pacing = (
            (0.02 if isinstance(router.script_backend, HttpScriptBridgeBackend) else 0.0)
            if cli_pacing_seconds is None
            else float(cli_pacing_seconds)
        )
        self.cli_queue = PacedDeviceCliQueue(
            pacing_seconds=effective_pacing,
            max_retries=max_cli_retries,
        )

    def _read_cli(
        self,
        device_name: str,
        command: str,
        *,
        timeout_seconds: float,
        max_retries: int | None = None,
    ) -> _CliReadOutcome:
        if not self.router.has_live_script() or self.router.script_backend is None:
            return _CliReadOutcome(
                command=command,
                raw_evidence="",
                error="Live Packet Tracer ScriptBackend is not connected.",
            )

        pt_name = self.router.resolve_pt_device_name(device_name)
        retries = self.cli_queue.max_retries if max_retries is None else max_retries
        retry_sleep = (
            0.15 if isinstance(self.router.script_backend, HttpScriptBridgeBackend) else 0.0
        )
        attempts = 0
        last_outcome: _CliReadOutcome | None = None
        mode_normalized = False

        while attempts <= retries:
            attempts += 1
            self.cli_queue.pace(pt_name)
            try:
                res = self.router.script_backend.execute_cli(
                    pt_name,
                    [command],
                    timeout_seconds=max(float(timeout_seconds), 25.0),
                )
            except AgenticNetError as exc:
                last_outcome = _CliReadOutcome(
                    command=command,
                    raw_evidence=redact_cli_text(str(exc.message)),
                    error=f"CLI execution error on '{pt_name}': {exc.message}",
                )
                if attempts <= retries:
                    if retry_sleep > 0:
                        time.sleep(retry_sleep)
                    continue
                return last_outcome
            except Exception as exc:
                last_outcome = _CliReadOutcome(
                    command=command,
                    raw_evidence="",
                    error=f"Unexpected CLI read error on '{pt_name}': {exc}",
                )
                if attempts <= retries:
                    if retry_sleep > 0:
                        time.sleep(retry_sleep)
                    continue
                return last_outcome

            timed_out = bool(res.get("timed_out", False))
            raw_out = str(res.get("raw_output", ""))
            prompt = str(res.get("prompt", "")).strip()
            redacted = redact_cli_text(raw_out)

            if timed_out:
                last_outcome = _CliReadOutcome(
                    command=command,
                    raw_evidence=redacted,
                    error=f"Timed out executing '{command}' on '{pt_name}'.",
                    timed_out=True,
                )
                if attempts <= retries:
                    if retry_sleep > 0:
                        time.sleep(retry_sleep)
                    continue
                return last_outcome

            statuses = res.get("command_statuses", [])
            cmd_failed = False
            if isinstance(statuses, list):
                for entry in statuses:
                    if (
                        isinstance(entry, dict)
                        and entry.get("command", "").strip().lower() == command.strip().lower()
                        and int(entry.get("status", 0)) != 0
                    ):
                        cmd_failed = True
                        break

            err_msg = detect_cli_read_error(raw_out)
            # Distinguish clean prompt return with empty table (e.g. 0 DHCP bindings/ephones)
            # from genuinely empty output: preserve raw redacted prompt output as evidence.
            if (
                err_msg == "Empty CLI output received from device."
                and prompt
                and not cmd_failed
                and raw_out.strip()
            ):
                err_msg = None

            if cmd_failed and err_msg is None:
                err_msg = f"Command '{command}' returned non-zero IOS status on '{pt_name}'."

            # Auto-normalize IOS Exec mode once (e.g., User Exec '>' -> 'enable' after PT
            # file reopen, or config submode '(config)#' -> 'end') and re-read cleanly.
            if (
                (err_msg is not None or cmd_failed)
                and not mode_normalized
                and (prompt.endswith(">") or ("(" in prompt and prompt.endswith("#")))
            ):
                mode_normalized = True
                mode_cmd = "enable" if prompt.endswith(">") else "end"
                self.cli_queue.pace(pt_name)
                try:
                    self.router.script_backend.execute_cli(
                        pt_name,
                        [mode_cmd],
                        timeout_seconds=max(float(timeout_seconds), 10.0),
                    )
                    attempts = max(0, attempts - 1)
                    continue
                except Exception:
                    pass

            return _CliReadOutcome(
                command=command,
                raw_evidence=redacted,
                error=err_msg,
                timed_out=False,
            )

        return last_outcome or _CliReadOutcome(
            command=command,
            raw_evidence="",
            error=f"Failed executing '{command}' on '{pt_name}' after {retries} retries.",
        )

    def verify(
        self,
        requirements: dict[str, Any] | list[dict[str, Any]] | VerifyLabRequest,
        *,
        timeout_seconds: float = 25.0,
        poll_wait_seconds: float | None = None,
        poll_interval_seconds: float = 0.8,
        include_activity_grade: bool = True,
        task_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run live CLI verification across all declared requirements and keep raw evidence.

        When ``poll_wait_seconds`` is ``None`` (default), sweeps and polls failing requirements
        under a shared ``45.0``-second convergence deadline when connected to a real
        ``HttpScriptBridgeBackend`` (live PT), and ``0.0`` seconds for offline/mock backends.
        """
        spec = normalize_requirements_payload(requirements)
        expected_tasks = task_ids if task_ids is not None else spec.task_ids
        task_coverage = _build_task_coverage(expected_tasks, spec.requirements)
        has_script = self.router.has_live_script()
        exec_backend: ExecutionBackend = "script_backend" if has_script else "offline_model"
        is_real_http_bridge = (
            self.router is not None
            and has_script
            and isinstance(self.router.script_backend, HttpScriptBridgeBackend)
        )
        if poll_wait_seconds is None:
            effective_poll_wait = 45.0 if is_real_http_bridge else 0.0
        else:
            effective_poll_wait = max(0.0, float(poll_wait_seconds)) if has_script else 0.0

        req_meta = [_command_for_requirement(req) for req in spec.requirements]
        cache: dict[tuple[str, str], _CliReadOutcome] = {}
        results_by_idx: list[dict[str, Any] | None] = [None] * len(spec.requirements)
        pending_indices = list(range(len(spec.requirements)))
        start_time = time.monotonic()
        deadline = start_time + effective_poll_wait

        while pending_indices:
            next_pending: list[int] = []
            keys_to_invalidate: set[tuple[str, str]] = set()
            prefetched_by_key: dict[tuple[str, str], _CliReadOutcome] = {}
            prefetched_by_idx: dict[int, _CliReadOutcome] = {}

            if is_real_http_bridge and len(pending_indices) > 1:
                tasks_by_device: dict[
                    str, list[tuple[int, str, str, tuple[str, str], bool]]
                ] = {}
                seen_cache_keys: set[tuple[str, str]] = set()
                for idx in pending_indices:
                    dev_name, command, cacheable = req_meta[idx]
                    pt_dev_name = self.router.resolve_pt_device_name(dev_name)
                    key = (pt_dev_name, command)
                    if cacheable:
                        if key in cache or key in seen_cache_keys:
                            continue
                        seen_cache_keys.add(key)
                    tasks_by_device.setdefault(pt_dev_name, []).append(
                        (idx, dev_name, command, key, cacheable)
                    )

                if len(tasks_by_device) > 1:
                    def _run_device_reads(
                        items: list[tuple[int, str, str, tuple[str, str], bool]],
                    ) -> list[tuple[int, tuple[str, str], bool, _CliReadOutcome]]:
                        out: list[tuple[int, tuple[str, str], bool, _CliReadOutcome]] = []
                        for item_idx, dev_name, command, key, cacheable in items:
                            res_outcome = self._read_cli(
                                dev_name, command, timeout_seconds=timeout_seconds
                            )
                            out.append((item_idx, key, cacheable, res_outcome))
                        return out

                    with ThreadPoolExecutor(max_workers=min(len(tasks_by_device), 6)) as pool:
                        futures = [
                            pool.submit(_run_device_reads, dev_items)
                            for dev_items in tasks_by_device.values()
                        ]
                        for fut in futures:
                            for item_idx, key, cacheable, res_outcome in fut.result():
                                if cacheable:
                                    prefetched_by_key[key] = res_outcome
                                    if res_outcome.error is None:
                                        cache[key] = res_outcome
                                else:
                                    prefetched_by_idx[item_idx] = res_outcome

            for idx in pending_indices:
                req = spec.requirements[idx]
                dev_name, command, cacheable = req_meta[idx]
                pt_dev_name = self.router.resolve_pt_device_name(dev_name)
                key = (pt_dev_name, command)

                if cacheable and key in cache:
                    outcome = cache[key]
                elif cacheable and key in prefetched_by_key:
                    outcome = prefetched_by_key[key]
                elif idx in prefetched_by_idx:
                    outcome = prefetched_by_idx[idx]
                else:
                    outcome = self._read_cli(dev_name, command, timeout_seconds=timeout_seconds)
                    if cacheable and outcome.error is None:
                        cache[key] = outcome

                if (
                    isinstance(req, TelephonyServiceRequirement)
                    and outcome.error is not None
                    and any(
                        tok in outcome.error.lower()
                        for tok in ("% invalid", "% unrecognized", "% unknown")
                    )
                ):
                    cfg_key = (pt_dev_name, "show running-config")
                    cfg_outcome = cache.get(cfg_key)
                    if cfg_outcome is None:
                        cfg_outcome = self._read_cli(
                            dev_name,
                            "show running-config",
                            timeout_seconds=timeout_seconds,
                        )
                        if cfg_outcome.error is None:
                            cache[cfg_key] = cfg_outcome
                    if cfg_outcome.error is None:
                        sections = parse_running_config_sections(
                            cfg_outcome.raw_evidence,
                            section="telephony-service",
                        )
                        sec_text = (
                            sections[0].text
                            if sections
                            else "% Telephony-service is not configured"
                        )
                        outcome = _CliReadOutcome(
                            command=(
                                "show telephony-service -> fallback: show running-config "
                                "(telephony-service section)"
                            ),
                            raw_evidence=(
                                sec_text if sections else cfg_outcome.raw_evidence
                            ),
                        )
                        if cacheable:
                            cache[key] = outcome

                evaluated = _evaluate_requirement(req, outcome)
                evaluated["index"] = idx + 1
                results_by_idx[idx] = evaluated
                if evaluated["status"] != "pass":
                    next_pending.append(idx)
                    if cacheable:
                        keys_to_invalidate.add(key)
                        if isinstance(req, TelephonyServiceRequirement):
                            keys_to_invalidate.add((pt_dev_name, "show running-config"))

            if not next_pending or not has_script or effective_poll_wait <= 0:
                break
            now = time.monotonic()
            if now >= deadline:
                break
            for stale_key in keys_to_invalidate:
                cache.pop(stale_key, None)
            time.sleep(min(poll_interval_seconds, max(0.05, deadline - now)))
            pending_indices = next_pending

        results = [r for r in results_by_idx if r is not None]

        passed_count = sum(1 for r in results if r["status"] == "pass")
        failed_count = sum(1 for r in results if r["status"] == "fail")
        error_count = sum(1 for r in results if r["status"] == "error")
        all_have_evidence = all(bool(str(r.get("evidence", "")).strip()) for r in results)

        # Never report verified state unless every requirement was read live with raw evidence
        if not has_script or error_count > 0 or not all_have_evidence:
            state_level = (
                StateLevel.EXECUTED
                if (has_script and passed_count + failed_count > 0)
                else StateLevel.PLANNED
            )
            verified_live = False
        else:
            state_level = StateLevel.VERIFIED
            verified_live = True

        overall_passed = bool(
            verified_live and len(results) > 0 and failed_count == 0 and error_count == 0
        )

        activity_grade: dict[str, Any] | None = None
        if include_activity_grade and has_script:
            if getattr(self.router, "active_is_activity", None) is False:
                activity_grade = {
                    "is_activity": False,
                    "state": "unavailable",
                    "readable": False,
                    "locked": False,
                    "score": None,
                    "fallback": "cli_verification",
                    "reason": "Active workspace is not a Packet Tracer .pka activity file.",
                    "execution_backend": "script_backend",
                }
            else:
                # Optional extra evidence only; never overrides CLI verification results.
                activity_grade = self.router.read_activity_status()

        return {
            "lab_name": spec.lab_name,
            "passed": overall_passed,
            "verified_live": verified_live,
            "state_level": state_level.value,
            "execution_backend": exec_backend,
            "summary": {
                "total": len(results),
                "passed": passed_count,
                "failed": failed_count,
                "errors": error_count,
            },
            "results": results,
            "task_coverage": task_coverage,
            "activity_grade": activity_grade,
        }
