"""Live CLI verification engine (`verify_lab`) backed by Packet Tracer ScriptBackend."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from netforge.adapters.router import BackendRouter
from netforge.core.enums import StateLevel
from netforge.core.exceptions import NetForgeError
from netforge.core.models import ExecutionBackend
from netforge.diagnostics.verify_schema import (
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
from netforge.security.redaction import redact_cli_text
from netforge.simulation.parsers import (
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
        candidates = [r for r in routes if r.network == req.network]
        if req.protocol_code:
            code_u = req.protocol_code.strip().upper()
            candidates = [r for r in candidates if r.code.upper().startswith(code_u)]
        if req.next_hop:
            candidates = [r for r in candidates if r.next_hop == req.next_hop.strip()]
        if req.outgoing_interface:
            want_if = canonicalize_interface_name(req.outgoing_interface)
            candidates = [
                r
                for r in candidates
                if r.outgoing_interface
                and canonicalize_interface_name(r.outgoing_interface) == want_if
            ]
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


class LabVerifier:
    """Evaluates declarative lab requirements strictly from live PT CLI read-backs."""

    def __init__(self, router: BackendRouter) -> None:
        self.router = router

    def _read_cli(
        self,
        device_name: str,
        command: str,
        *,
        timeout_seconds: float,
    ) -> _CliReadOutcome:
        if not self.router.has_live_script() or self.router.script_backend is None:
            return _CliReadOutcome(
                command=command,
                raw_evidence="",
                error="Live Packet Tracer ScriptBackend is not connected.",
            )

        pt_name = self.router.resolve_pt_device_name(device_name)
        try:
            res = self.router.script_backend.execute_cli(
                pt_name,
                [command],
                timeout_seconds=max(float(timeout_seconds), 25.0),
            )
        except NetForgeError as exc:
            return _CliReadOutcome(
                command=command,
                raw_evidence=redact_cli_text(str(exc.message)),
                error=f"CLI execution error on '{pt_name}': {exc.message}",
            )
        except Exception as exc:
            return _CliReadOutcome(
                command=command,
                raw_evidence="",
                error=f"Unexpected CLI read error on '{pt_name}': {exc}",
            )

        timed_out = bool(res.get("timed_out", False))
        raw_out = str(res.get("raw_output", ""))
        prompt = str(res.get("prompt", "")).strip()
        redacted = redact_cli_text(raw_out)

        if timed_out:
            return _CliReadOutcome(
                command=command,
                raw_evidence=redacted,
                error=f"Timed out executing '{command}' on '{pt_name}'.",
                timed_out=True,
            )

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

        return _CliReadOutcome(
            command=command,
            raw_evidence=redacted,
            error=err_msg,
            timed_out=False,
        )

    def verify(
        self,
        requirements: dict[str, Any] | list[dict[str, Any]] | VerifyLabRequest,
        *,
        timeout_seconds: float = 25.0,
        include_activity_grade: bool = True,
    ) -> dict[str, Any]:
        """Run live CLI verification across all declared requirements and keep raw evidence."""
        spec = normalize_requirements_payload(requirements)
        has_script = self.router.has_live_script()
        exec_backend: ExecutionBackend = "script_backend" if has_script else "offline_model"

        cache: dict[tuple[str, str], _CliReadOutcome] = {}
        results: list[dict[str, Any]] = []

        for idx, req in enumerate(spec.requirements, start=1):
            dev_name, command, cacheable = _command_for_requirement(req)
            key = (dev_name, command)
            if cacheable and key in cache:
                outcome = cache[key]
            else:
                outcome = self._read_cli(dev_name, command, timeout_seconds=timeout_seconds)
                if (
                    isinstance(req, TelephonyServiceRequirement)
                    and outcome.error is not None
                    and any(
                        tok in outcome.error.lower()
                        for tok in ("% invalid", "% unrecognized", "% unknown")
                    )
                ):
                    cfg_key = (dev_name, "show running-config")
                    cfg_outcome = cache.get(cfg_key)
                    if cfg_outcome is None:
                        cfg_outcome = self._read_cli(
                            dev_name,
                            "show running-config",
                            timeout_seconds=timeout_seconds,
                        )
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
                            raw_evidence=sec_text
                            if sections
                            else cfg_outcome.raw_evidence,
                        )
                if cacheable:
                    cache[key] = outcome

            evaluated = _evaluate_requirement(req, outcome)
            evaluated["index"] = idx
            results.append(evaluated)

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
            "activity_grade": activity_grade,
        }
