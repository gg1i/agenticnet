"""Live CLI verification engine (`verify_lab`) backed by Packet Tracer ScriptBackend."""

from __future__ import annotations

import inspect
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from agenticnet.adapters.router import BackendRouter
from agenticnet.adapters.script_bridge import HttpScriptBridgeBackend
from agenticnet.console.engine import _split_batch_output
from agenticnet.core.enums import StateLevel
from agenticnet.core.exceptions import AgenticNetError
from agenticnet.core.models import ExecutionBackend
from agenticnet.diagnostics.verify_schema import (
    ConfigContainsRequirement,
    DhcpBindingRequirement,
    EphoneRegisteredRequirement,
    HostIpconfigRequirement,
    InterfaceUpRequirement,
    IpAssignedRequirement,
    LabRequirement,
    ReachableRequirement,
    RouteExistsRequirement,
    StpRootRequirement,
    TelephonyServiceRequirement,
    TracerouteHopsRequirement,
    TrunkExistsRequirement,
    VerifyLabRequest,
    VlanExistsRequirement,
    normalize_requirements_payload,
)
from agenticnet.security.redaction import redact_cli_text
from agenticnet.simulation.parsers import (
    canonicalize_interface_name,
    detect_cli_read_error,
    parse_ipconfig_all,
    parse_ping_output,
    parse_running_config_sections,
    parse_show_ephone,
    parse_show_interfaces_trunk,
    parse_show_ip_dhcp_binding,
    parse_show_ip_int_brief,
    parse_show_ip_route,
    parse_show_spanning_tree,
    parse_show_telephony_service,
    parse_show_vlan_brief,
    parse_traceroute_output,
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
    if isinstance(req, TracerouteHopsRequirement):
        return (req.source, f"traceroute {req.target}", False)
    if isinstance(req, TrunkExistsRequirement):
        return (req.device, "show interfaces trunk", True)
    if isinstance(req, StpRootRequirement):
        return (req.device, "show spanning-tree", True)
    if isinstance(req, HostIpconfigRequirement):
        return (req.device, "ipconfig /all", True)
    raise TypeError(f"Unsupported requirement type: {type(req)!r}")


def _evaluate_requirement(req: LabRequirement, read: _CliReadOutcome) -> dict[str, Any]:
    """Evaluate one parsed requirement strictly against captured CLI evidence."""
    base: dict[str, Any] = {
        "id": req.id,
        "task_id": req.task_id,
        "type": req.type,
        "device": (
            req.source
            if isinstance(req, (ReachableRequirement, TracerouteHopsRequirement))
            else req.device
        ),
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
                            if isinstance(route_net, ipaddress.IPv4Network) and route_net.subnet_of(
                                target_net
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
                None if ok else f"No matching route for '{req.network}' found in `show ip route`."
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
            "\n".join(s.text for s in sections) if req.section is not None else read.raw_evidence
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
            candidates = [e for e in candidates if any(b.number == req.number for b in e.buttons)]
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

    if isinstance(req, TracerouteHopsRequirement):
        trace = parse_traceroute_output(read.raw_evidence, target_ip=req.target)
        reasons = []
        if req.require_completed and not trace.completed:
            reasons.append(f"Traceroute to '{req.target}' did not reach target.")
        if req.max_hops is not None and len(trace.hops) > req.max_hops:
            reasons.append(f"Hop count {len(trace.hops)} exceeded max_hops={req.max_hops}.")
        if req.expected_hops:
            observed_ips = [h.ip_address for h in trace.hops if h.ip_address]
            cursor = 0
            missing_hops: list[str] = []
            for want_hop in req.expected_hops:
                try:
                    pos = observed_ips.index(want_hop.strip(), cursor)
                    cursor = pos + 1
                except ValueError:
                    missing_hops.append(want_hop.strip())
            if missing_hops:
                reasons.append(f"Missing or out-of-order traceroute hop(s): {missing_hops}.")
        ok = len(reasons) == 0
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": " ".join(reasons) if reasons else None,
            "parsed": trace.model_dump(mode="json"),
        }

    if isinstance(req, TrunkExistsRequirement):
        trunks = parse_show_interfaces_trunk(read.raw_evidence)
        want_canon = canonicalize_interface_name(req.interface)
        matched = next(
            (t for t in trunks if canonicalize_interface_name(t.port) == want_canon),
            None,
        )
        if matched is None:
            return {
                **base,
                "status": "fail",
                "reason": (
                    f"Interface '{req.interface}' is not trunking in `show interfaces trunk`."
                ),
                "parsed": {"trunks_seen": [t.port for t in trunks]},
            }
        reasons = []
        if matched.status != "trunking":
            reasons.append(f"Trunk status is '{matched.status}', expected 'trunking'.")
        if req.native_vlan is not None and matched.native_vlan != req.native_vlan:
            reasons.append(f"Native VLAN is {matched.native_vlan}, expected {req.native_vlan}.")
        if req.allowed_vlans:
            missing_vlans = [v for v in req.allowed_vlans if v not in matched.allowed_vlans]
            if missing_vlans:
                reasons.append(f"Missing allowed VLAN(s) on trunk: {missing_vlans}.")
        ok = len(reasons) == 0
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": " ".join(reasons) if reasons else None,
            "parsed": matched.model_dump(mode="json"),
        }

    if isinstance(req, StpRootRequirement):
        stp_instances = parse_show_spanning_tree(read.raw_evidence)
        matched = next((s for s in stp_instances if s.vlan_id == req.vlan_id), None)
        if matched is None:
            return {
                **base,
                "status": "fail",
                "reason": f"VLAN {req.vlan_id} not found in `show spanning-tree`.",
                "parsed": {"vlans_seen": [s.vlan_id for s in stp_instances]},
            }
        ok = matched.is_root_bridge == req.expect_root
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": (
                None
                if ok
                else (
                    f"Device root-bridge state for VLAN {req.vlan_id} is "
                    f"{matched.is_root_bridge}, expected {req.expect_root}."
                )
            ),
            "parsed": matched.model_dump(mode="json"),
        }

    if isinstance(req, HostIpconfigRequirement):
        adapters = parse_ipconfig_all(read.raw_evidence)
        if not adapters:
            return {
                **base,
                "status": "fail",
                "reason": "No adapter configuration parsed from `ipconfig /all`.",
                "parsed": {"adapters": []},
            }
        reasons = []
        candidates = list(adapters)
        if req.ip:
            want_ip = _strip_prefix(req.ip)
            candidates = [a for a in candidates if a.ipv4_address == want_ip]
            if not candidates:
                reasons.append(f"Host IP '{want_ip}' not found in `ipconfig /all`.")
        if candidates and req.default_gateway:
            want_gw = req.default_gateway.strip()
            if not any(a.default_gateway == want_gw for a in candidates):
                reasons.append(f"Default gateway '{want_gw}' not matched in `ipconfig /all`.")
        if candidates and req.dns_server:
            want_dns = req.dns_server.strip()
            if not any(want_dns in a.dns_servers for a in candidates):
                reasons.append(f"DNS server '{want_dns}' not matched in `ipconfig /all`.")
        ok = len(reasons) == 0
        return {
            **base,
            "status": "pass" if ok else "fail",
            "reason": " ".join(reasons) if reasons else None,
            "parsed": {"adapters": [a.model_dump(mode="json") for a in adapters]},
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


_TELEPHONY_FALLBACK_COMMAND = (
    "show telephony-service -> fallback: show running-config (telephony-service section)"
)
_DETERMINISTIC_BRIDGE_ERR_TOKENS: tuple[str, ...] = (
    "device not found",
    "has no terminalline",
    "disallowed script opcode",
    "unsupported opcode",
    "live packet tracer scriptbackend is not connected",
)
_UNSUPPORTED_CLI_ERR_TOKENS: tuple[str, ...] = (
    "% invalid",
    "% unrecognized",
    "% unknown",
    "% incomplete",
    "% ambiguous",
)
_SLOW_CONVERGE_TYPES = (
    EphoneRegisteredRequirement,
    StpRootRequirement,
    DhcpBindingRequirement,
    HostIpconfigRequirement,
)
_PC_DEVICE_TYPES: frozenset[str] = frozenset({"pc", "laptop", "server"})
_PC_MODEL_PREFIXES: tuple[str, ...] = ("pc", "laptop", "server")


def _is_deterministic_bridge_error(message: str) -> bool:
    low = message.lower()
    return any(tok in low for tok in _DETERMINISTIC_BRIDGE_ERR_TOKENS)


def _is_unsupported_cli_error(message: str | None) -> bool:
    if not message:
        return False
    low = message.lower()
    return any(tok in low for tok in _UNSUPPORTED_CLI_ERR_TOKENS)


def _is_convergeable_failure(req: LabRequirement, outcome: _CliReadOutcome) -> bool:
    """Return True only when waiting/re-polling in Packet Tracer can realistically resolve it."""
    if outcome.error is not None:
        if _is_deterministic_bridge_error(outcome.error):
            return False
        err_low = outcome.error.lower()
        if _is_unsupported_cli_error(outcome.error) or "non-zero ios status" in err_low:
            return False
        return not outcome.timed_out
    # Static running-config text will not change while verify_lab sleeps.
    return not isinstance(req, ConfigContainsRequirement)


def _resolve_device_snapshot_info(
    router: BackendRouter, device_name: str, pt_dev_name: str
) -> tuple[str | None, str | None]:
    """Return `(model_lower, type_lower)` from router snapshots if known."""
    snaps = (getattr(router, "latest_snapshot", None), getattr(router, "initial_snapshot", None))
    for snap in snaps:
        if not isinstance(snap, dict):
            continue
        for dev in snap.get("devices", []):
            if not isinstance(dev, dict):
                continue
            d_name = str(dev.get("name") or "")
            d_host = str(dev.get("hostname") or "")
            if d_name in {pt_dev_name, device_name} or d_host in {pt_dev_name, device_name}:
                model = str(dev.get("model") or "").strip().lower() or None
                dtype = str(dev.get("type") or "").strip().lower() or None
                return model, dtype
    return None, None


def _is_pt_desktop_host(router: BackendRouter, device_name: str, pt_dev_name: str) -> bool:
    model, dtype = _resolve_device_snapshot_info(router, device_name, pt_dev_name)
    if dtype in _PC_DEVICE_TYPES:
        return True
    return bool(model and model.startswith(_PC_MODEL_PREFIXES))


def _get_router_unsupported_cache(router: BackendRouter) -> set[tuple[str, str, str]]:
    """Return session-scoped `(pt_dev_name, model, cmd)` unsupported command cache on `router`."""
    sig = (
        getattr(router, "active_original_path", None),
        getattr(router, "active_working_path", None),
    )
    prev_sig = getattr(router, "_verifier_unsupported_sig", None)
    cache = getattr(router, "_verifier_unsupported_cli", None)
    if not isinstance(cache, set) or prev_sig != sig:
        cache = set()
        router._verifier_unsupported_cli = cache  # type: ignore[attr-defined]
        router._verifier_unsupported_sig = sig  # type: ignore[attr-defined]
    return cache


class PacedDeviceCliQueue:
    """Serializes and paces CLI requests per device with bounded retries."""

    def __init__(self, pacing_seconds: float = 0.25, max_retries: int = 1) -> None:
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
        max_cli_retries: int = 1,
    ) -> None:
        self.router = router
        effective_pacing = 0.0 if cli_pacing_seconds is None else float(cli_pacing_seconds)
        self.cli_queue = PacedDeviceCliQueue(
            pacing_seconds=effective_pacing,
            max_retries=max_cli_retries,
        )
        self._unsupported_commands: set[tuple[str, str]] = set()

    def _is_command_unsupported(self, pt_dev_name: str, command: str) -> bool:
        cmd_norm = command.strip().lower()
        if (pt_dev_name, cmd_norm) in self._unsupported_commands:
            return True
        router_check = getattr(self.router, "is_cli_command_unsupported", None)
        if callable(router_check) and router_check(pt_dev_name, cmd_norm):
            return True
        model, _ = _resolve_device_snapshot_info(self.router, pt_dev_name, pt_dev_name)
        cache = _get_router_unsupported_cache(self.router)
        return (pt_dev_name, model or "", cmd_norm) in cache

    def _mark_command_unsupported(self, pt_dev_name: str, command: str) -> None:
        cmd_norm = command.strip().lower()
        self._unsupported_commands.add((pt_dev_name, cmd_norm))
        router_mark = getattr(self.router, "mark_cli_command_unsupported", None)
        if callable(router_mark):
            router_mark(pt_dev_name, cmd_norm)
        model, _ = _resolve_device_snapshot_info(self.router, pt_dev_name, pt_dev_name)
        cache = _get_router_unsupported_cache(self.router)
        cache.add((pt_dev_name, model or "", cmd_norm))

    def _build_outcome_from_output(
        self,
        *,
        command: str,
        raw_out: str,
        prompt: str,
        cmd_failed: bool,
        pt_name: str,
    ) -> tuple[_CliReadOutcome, bool]:
        """Convert raw CLI output + status into `_CliReadOutcome` and `needs_mode_norm`."""
        redacted = redact_cli_text(raw_out)
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

        needs_norm = bool(
            (err_msg is not None or cmd_failed)
            and not prompt.lower().startswith("c:")
            and (prompt.endswith(">") or ("(" in prompt and prompt.endswith("#")))
        )
        return (
            _CliReadOutcome(
                command=command,
                raw_evidence=redacted,
                error=err_msg,
                timed_out=False,
            ),
            needs_norm,
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
        is_http = isinstance(self.router.script_backend, HttpScriptBridgeBackend)
        retry_sleep = 0.05 if is_http else 0.0
        cmd_low = command.strip().lower()
        min_timeout = 12.0 if cmd_low.startswith(("ping ", "traceroute ", "tracert ")) else 8.0
        effective_timeout = max(float(timeout_seconds), min_timeout)
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
                    timeout_seconds=effective_timeout,
                )
            except AgenticNetError as exc:
                err_text = f"CLI execution error on '{pt_name}': {exc.message}"
                last_outcome = _CliReadOutcome(
                    command=command,
                    raw_evidence=redact_cli_text(str(exc.message)),
                    error=err_text,
                )
                if _is_deterministic_bridge_error(str(exc.message)):
                    return last_outcome
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
                # Do not burn repeated full-timeout waits on an already-long read timeout.
                if effective_timeout >= 15.0 or attempts > retries:
                    return last_outcome
                if retry_sleep > 0:
                    time.sleep(retry_sleep)
                continue

            statuses = res.get("command_statuses", [])
            cmd_failed = False
            if isinstance(statuses, list):
                for entry in statuses:
                    if (
                        isinstance(entry, dict)
                        and entry.get("command", "").strip().lower() == cmd_low
                        and int(entry.get("status", 0)) != 0
                    ):
                        cmd_failed = True
                        break

            outcome, needs_norm = self._build_outcome_from_output(
                command=command,
                raw_out=raw_out,
                prompt=prompt,
                cmd_failed=cmd_failed,
                pt_name=pt_name,
            )

            # Auto-normalize IOS Exec mode once (e.g., User Exec '>' -> 'enable' after PT
            # file reopen, or config submode '(config)#' -> 'end') and re-read cleanly.
            if needs_norm and not mode_normalized:
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

            return outcome

        return last_outcome or _CliReadOutcome(
            command=command,
            raw_evidence="",
            error=f"Failed executing '{command}' on '{pt_name}' after {retries} retries.",
        )

    def _read_cli_batch(
        self,
        device_name: str,
        commands: list[str],
        *,
        timeout_seconds: float,
    ) -> dict[str, _CliReadOutcome]:
        """Execute multiple commands on one device in a single bridge round-trip."""
        unique_cmds = list(dict.fromkeys(commands))
        if not unique_cmds:
            return {}
        if len(unique_cmds) == 1:
            cmd0 = unique_cmds[0]
            return {cmd0: self._read_cli(device_name, cmd0, timeout_seconds=timeout_seconds)}

        if not self.router.has_live_script() or self.router.script_backend is None:
            err = _CliReadOutcome(
                command=unique_cmds[0],
                raw_evidence="",
                error="Live Packet Tracer ScriptBackend is not connected.",
            )
            return {
                c: _CliReadOutcome(command=c, raw_evidence="", error=err.error)
                for c in unique_cmds
            }

        pt_name = self.router.resolve_pt_device_name(device_name)
        slow_cmds = sum(
            1
            for c in unique_cmds
            if c.strip().lower().startswith(("ping ", "traceroute ", "tracert "))
        )
        batch_timeout = (
            max(float(timeout_seconds), 10.0) + slow_cmds * 6.0 + len(unique_cmds) * 0.25
        )

        exec_fn = self.router.script_backend.execute_cli
        exec_kwargs: dict[str, Any] = {"timeout_seconds": batch_timeout}
        try:
            if "stop_on_error" in inspect.signature(exec_fn).parameters:
                exec_kwargs["stop_on_error"] = False
        except (TypeError, ValueError):
            pass

        self.cli_queue.pace(pt_name)
        try:
            res = exec_fn(pt_name, unique_cmds, **exec_kwargs)
        except AgenticNetError as exc:
            err_text = f"CLI execution error on '{pt_name}': {exc.message}"
            if _is_deterministic_bridge_error(str(exc.message)):
                redacted_err = redact_cli_text(str(exc.message))
                return {
                    c: _CliReadOutcome(command=c, raw_evidence=redacted_err, error=err_text)
                    for c in unique_cmds
                }
            return {
                c: self._read_cli(device_name, c, timeout_seconds=timeout_seconds)
                for c in unique_cmds
            }
        except Exception:
            return {
                c: self._read_cli(device_name, c, timeout_seconds=timeout_seconds)
                for c in unique_cmds
            }

        cmd_outputs = res.get("command_outputs")
        raw_out = str(res.get("raw_output", ""))
        prompt = str(res.get("prompt", "")).strip()
        timed_out = bool(res.get("timed_out", False))
        statuses = res.get("command_statuses", [])
        status_list = (
            [e for e in statuses if isinstance(e, dict)] if isinstance(statuses, list) else []
        )

        slices: list[str] | None = None
        if isinstance(cmd_outputs, list) and len(cmd_outputs) > 0:
            slices = [str(x) for x in cmd_outputs]
        elif raw_out.strip() and not timed_out:
            candidate_slices = _split_batch_output(raw_out, unique_cmds)
            if all(bool(s.strip()) for s in candidate_slices):
                slices = candidate_slices

        if slices is None:
            if timed_out and not raw_out.strip():
                return {
                    c: _CliReadOutcome(
                        command=c,
                        raw_evidence="",
                        error=f"Timed out executing '{c}' on '{pt_name}'.",
                        timed_out=True,
                    )
                    for c in unique_cmds
                }
            # Fallback to single-command reads if mock HTTP backend omitted command_outputs.
            return {
                c: self._read_cli(device_name, c, timeout_seconds=timeout_seconds)
                for c in unique_cmds
            }

        outcomes: dict[str, _CliReadOutcome] = {}
        retry_for_mode: list[str] = []
        s_cursor = 0
        for idx, cmd in enumerate(unique_cmds):
            cmd_low = cmd.strip().lower()
            cmd_failed = False
            for probe in range(s_cursor, len(status_list)):
                if str(status_list[probe].get("command", "")).strip().lower() == cmd_low:
                    cmd_failed = int(status_list[probe].get("status", 0)) != 0 and not bool(
                        status_list[probe].get("non_fatal", False)
                    )
                    s_cursor = probe + 1
                    break

            if idx < len(slices):
                outcome, needs_norm = self._build_outcome_from_output(
                    command=cmd,
                    raw_out=slices[idx],
                    prompt=prompt,
                    cmd_failed=cmd_failed,
                    pt_name=pt_name,
                )
                outcomes[cmd] = outcome
                if needs_norm:
                    retry_for_mode.append(cmd)
            elif timed_out:
                outcomes[cmd] = _CliReadOutcome(
                    command=cmd,
                    raw_evidence="",
                    error=f"Timed out executing '{cmd}' on '{pt_name}'.",
                    timed_out=True,
                )
            else:
                outcomes[cmd] = self._read_cli(device_name, cmd, timeout_seconds=timeout_seconds)

        if retry_for_mode and prompt and not prompt.lower().startswith("c:"):
            mode_cmd = "enable" if prompt.endswith(">") else "end"
            self.cli_queue.pace(pt_name)
            try:
                self.router.script_backend.execute_cli(
                    pt_name,
                    [mode_cmd],
                    timeout_seconds=max(float(timeout_seconds), 10.0),
                )
                if len(retry_for_mode) == 1:
                    c0 = retry_for_mode[0]
                    outcomes[c0] = self._read_cli(
                        device_name, c0, timeout_seconds=timeout_seconds, max_retries=0
                    )
                else:
                    retried = self._read_cli_batch_once(
                        device_name,
                        pt_name,
                        retry_for_mode,
                        timeout_seconds=timeout_seconds,
                    )
                    outcomes.update(retried)
            except Exception:
                pass

        return outcomes

    def _read_cli_batch_once(
        self,
        device_name: str,
        pt_name: str,
        commands: list[str],
        *,
        timeout_seconds: float,
    ) -> dict[str, _CliReadOutcome]:
        """Run one mode-normalized retry batch without recursive mode normalization."""
        slow_cmds = sum(
            1
            for c in commands
            if c.strip().lower().startswith(("ping ", "traceroute ", "tracert "))
        )
        batch_timeout = max(float(timeout_seconds), 10.0) + slow_cmds * 6.0 + len(commands) * 0.25
        exec_fn = self.router.script_backend.execute_cli  # type: ignore[union-attr]
        exec_kwargs: dict[str, Any] = {"timeout_seconds": batch_timeout}
        try:
            if "stop_on_error" in inspect.signature(exec_fn).parameters:
                exec_kwargs["stop_on_error"] = False
        except (TypeError, ValueError):
            pass
        self.cli_queue.pace(pt_name)
        res = exec_fn(pt_name, commands, **exec_kwargs)
        cmd_outputs = res.get("command_outputs")
        prompt = str(res.get("prompt", "")).strip()
        statuses = res.get("command_statuses", [])
        status_list = (
            [e for e in statuses if isinstance(e, dict)] if isinstance(statuses, list) else []
        )
        if not isinstance(cmd_outputs, list) or len(cmd_outputs) == 0:
            return {
                c: self._read_cli(device_name, c, timeout_seconds=timeout_seconds, max_retries=0)
                for c in commands
            }
        out: dict[str, _CliReadOutcome] = {}
        for idx, cmd in enumerate(commands):
            cmd_failed = (
                idx < len(status_list)
                and int(status_list[idx].get("status", 0)) != 0
                and not bool(status_list[idx].get("non_fatal", False))
            )
            if idx < len(cmd_outputs):
                outcome, _ = self._build_outcome_from_output(
                    command=cmd,
                    raw_out=str(cmd_outputs[idx]),
                    prompt=prompt,
                    cmd_failed=cmd_failed,
                    pt_name=pt_name,
                )
                out[cmd] = outcome
            else:
                out[cmd] = _CliReadOutcome(
                    command=cmd,
                    raw_evidence="",
                    error=f"Timed out executing '{cmd}' on '{pt_name}'.",
                    timed_out=bool(res.get("timed_out", False)),
                )
        return out

    def _telephony_fallback_outcome(
        self,
        dev_name: str,
        pt_dev_name: str,
        *,
        cache: dict[tuple[str, str], _CliReadOutcome],
        timeout_seconds: float,
    ) -> _CliReadOutcome | None:
        """Read `telephony-service` section from `show running-config` with caching."""
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
        if cfg_outcome.error is not None:
            return None
        sections = parse_running_config_sections(
            cfg_outcome.raw_evidence,
            section="telephony-service",
        )
        sec_text = sections[0].text if sections else "% Telephony-service is not configured"
        return _CliReadOutcome(
            command=_TELEPHONY_FALLBACK_COMMAND,
            raw_evidence=(sec_text if sections else cfg_outcome.raw_evidence),
        )

    def verify(
        self,
        requirements: dict[str, Any] | list[dict[str, Any]] | VerifyLabRequest,
        *,
        timeout_seconds: float = 25.0,
        poll_wait_seconds: float | None = None,
        poll_interval_seconds: float | None = None,
        include_activity_grade: bool = True,
        task_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run live CLI verification across all declared requirements and keep raw evidence.

        When ``poll_wait_seconds`` is ``None`` (default), sweeps and polls convergeable failing
        requirements under an adaptive convergence deadline (``8.0``-``15.0``s on a live
        ``HttpScriptBridgeBackend``, ``0.0``s for offline/mock backends), while failing fast on
        deterministic CLI/device errors and static config mismatches.
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
        explicit_poll_wait = poll_wait_seconds is not None
        if explicit_poll_wait:
            effective_poll_wait = max(0.0, float(poll_wait_seconds)) if has_script else 0.0
        else:
            effective_poll_wait = 15.0 if is_real_http_bridge else 0.0

        req_meta = [_command_for_requirement(req) for req in spec.requirements]
        cache: dict[tuple[str, str], _CliReadOutcome] = {}
        results_by_idx: list[dict[str, Any] | None] = [None] * len(spec.requirements)
        pending_indices = list(range(len(spec.requirements)))
        start_time = time.monotonic()
        deadline: float | None = (
            start_time + effective_poll_wait if explicit_poll_wait else None
        )
        poll_cycle = 0

        while pending_indices:
            next_pending: list[int] = []
            convergeable_pending: list[int] = []
            keys_to_invalidate: set[tuple[str, str]] = set()
            prefetched_by_key: dict[tuple[str, str], _CliReadOutcome] = {}

            # Resolve actual commands per requirement (handling remembered unsupported
            # `show telephony-service` and concise PC `ping -n`).
            resolved_for_idx: dict[int, tuple[str, str, str, bool, bool]] = {}
            for idx in pending_indices:
                req = spec.requirements[idx]
                dev_name, command, cacheable = req_meta[idx]
                pt_dev_name = self.router.resolve_pt_device_name(dev_name)
                telephony_via_cfg = False
                if (
                    isinstance(req, TelephonyServiceRequirement)
                    and self._is_command_unsupported(pt_dev_name, "show telephony-service")
                ):
                    command = "show running-config"
                    telephony_via_cfg = True
                elif (
                    isinstance(req, ReachableRequirement)
                    and is_real_http_bridge
                    and _is_pt_desktop_host(self.router, dev_name, pt_dev_name)
                ):
                    ping_cnt = max(2, req.min_received)
                    command = (
                        f"ping -n {ping_cnt} {req.target}"
                        if ping_cnt != 4
                        else f"ping {req.target}"
                    )
                resolved_for_idx[idx] = (
                    dev_name,
                    pt_dev_name,
                    command,
                    cacheable,
                    telephony_via_cfg,
                )

            if is_real_http_bridge:
                cmds_by_device: dict[str, tuple[str, list[str]]] = {}
                for idx in pending_indices:
                    dev_name, pt_dev_name, command, cacheable, _ = resolved_for_idx[idx]
                    key = (pt_dev_name, command)
                    if cacheable and key in cache:
                        continue
                    if pt_dev_name not in cmds_by_device:
                        cmds_by_device[pt_dev_name] = (dev_name, [])
                    dev_cmds = cmds_by_device[pt_dev_name][1]
                    if command not in dev_cmds:
                        dev_cmds.append(command)

                def _fetch_device_batch(
                    item: tuple[str, str, list[str]],
                ) -> tuple[str, dict[str, _CliReadOutcome]]:
                    pt_dev, raw_dev, cmds = item
                    return pt_dev, self._read_cli_batch(
                        raw_dev, cmds, timeout_seconds=timeout_seconds
                    )

                if len(cmds_by_device) == 1:
                    pt_dev, (raw_dev, cmds) = next(iter(cmds_by_device.items()))
                    batch_outcomes = self._read_cli_batch(
                        raw_dev, cmds, timeout_seconds=timeout_seconds
                    )
                    for cmd_str, res_outcome in batch_outcomes.items():
                        key = (pt_dev, cmd_str)
                        prefetched_by_key[key] = res_outcome
                        if res_outcome.error is None and not cmd_str.startswith(
                            ("ping ", "traceroute ")
                        ):
                            cache[key] = res_outcome
                elif len(cmds_by_device) > 1:
                    batch_inputs = [
                        (pt_dev, raw_dev, cmds)
                        for pt_dev, (raw_dev, cmds) in cmds_by_device.items()
                    ]
                    with ThreadPoolExecutor(max_workers=min(len(batch_inputs), 6)) as pool:
                        for pt_dev, batch_outcomes in pool.map(_fetch_device_batch, batch_inputs):
                            for cmd_str, res_outcome in batch_outcomes.items():
                                key = (pt_dev, cmd_str)
                                prefetched_by_key[key] = res_outcome
                                if res_outcome.error is None and not cmd_str.startswith(
                                    ("ping ", "traceroute ")
                                ):
                                    cache[key] = res_outcome

            for idx in pending_indices:
                req = spec.requirements[idx]
                dev_name, pt_dev_name, command, cacheable, telephony_via_cfg = resolved_for_idx[
                    idx
                ]
                key = (pt_dev_name, command)

                if cacheable and key in cache:
                    outcome = cache[key]
                elif key in prefetched_by_key:
                    outcome = prefetched_by_key[key]
                else:
                    outcome = self._read_cli(dev_name, command, timeout_seconds=timeout_seconds)
                    if cacheable and outcome.error is None:
                        cache[key] = outcome

                if telephony_via_cfg and outcome.error is None:
                    sections = parse_running_config_sections(
                        outcome.raw_evidence,
                        section="telephony-service",
                    )
                    sec_text = (
                        sections[0].text
                        if sections
                        else "% Telephony-service is not configured"
                    )
                    outcome = _CliReadOutcome(
                        command=_TELEPHONY_FALLBACK_COMMAND,
                        raw_evidence=(sec_text if sections else outcome.raw_evidence),
                    )
                elif (
                    isinstance(req, TelephonyServiceRequirement)
                    and outcome.error is not None
                    and _is_unsupported_cli_error(outcome.error)
                ):
                    self._mark_command_unsupported(pt_dev_name, "show telephony-service")
                    fallback_outcome = self._telephony_fallback_outcome(
                        dev_name,
                        pt_dev_name,
                        cache=cache,
                        timeout_seconds=timeout_seconds,
                    )
                    if fallback_outcome is not None:
                        outcome = fallback_outcome
                        if cacheable:
                            cache[(pt_dev_name, "show telephony-service")] = fallback_outcome

                evaluated = _evaluate_requirement(req, outcome)
                evaluated["index"] = idx + 1
                results_by_idx[idx] = evaluated
                if evaluated["status"] != "pass":
                    next_pending.append(idx)
                    if _is_convergeable_failure(req, outcome):
                        convergeable_pending.append(idx)
                    if cacheable:
                        keys_to_invalidate.add(key)
                        if isinstance(req, TelephonyServiceRequirement):
                            keys_to_invalidate.add((pt_dev_name, "show running-config"))

            if not next_pending or not has_script or effective_poll_wait <= 0:
                break
            if not convergeable_pending:
                break

            if deadline is None:
                needs_slow_window = any(
                    isinstance(spec.requirements[i], _SLOW_CONVERGE_TYPES)
                    for i in convergeable_pending
                )
                effective_poll_wait = 15.0 if needs_slow_window else 8.0
                deadline = start_time + effective_poll_wait

            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0.05:
                break

            for stale_key in keys_to_invalidate:
                cache.pop(stale_key, None)

            if poll_interval_seconds is not None:
                sleep_step = float(poll_interval_seconds)
            else:
                adaptive_steps = (0.25, 0.4, 0.6, 0.8)
                sleep_step = adaptive_steps[min(poll_cycle, len(adaptive_steps) - 1)]
            poll_cycle += 1
            time.sleep(min(sleep_step, max(0.05, remaining)))
            pending_indices = convergeable_pending

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
                if (
                    getattr(self.router, "active_is_activity", None) is None
                    and isinstance(activity_grade, dict)
                    and activity_grade.get("is_activity_file") is False
                ):
                    self.router.active_is_activity = False

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
