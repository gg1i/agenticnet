"""MCP tools for Packet Tracer simulation controls, PDU tracing, and connectivity tests."""

from __future__ import annotations

import inspect
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from agenticnet.adapters.router import transport_to_execution_backend
from agenticnet.adapters.script_bridge import HttpScriptBridgeBackend
from agenticnet.console.engine import _split_batch_output
from agenticnet.console.models import ConsoleInteractionKind
from agenticnet.console.profiles import get_console_profile
from agenticnet.core.enums import PermissionTier, StateLevel
from agenticnet.core.exceptions import ValidationError
from agenticnet.core.models import ExecutionBackend, OperationResult
from agenticnet.mcp.registry import AgenticNetRuntime
from agenticnet.security.redaction import redact_cli_text
from agenticnet.security.validation import validate_ping_target
from agenticnet.simulation.models import ConnectivityCheckReport, PDUProtocol, SimulationSource
from agenticnet.simulation.parsers import detect_cli_read_error, parse_ping_output


def register_simulation_tools(server: MCPServer, runtime: AgenticNetRuntime) -> None:
    """Register Packet Tracer simulation mode and verification tools."""

    def _mode_backend(data: dict[str, Any]) -> ExecutionBackend:
        details = data.get("details") if isinstance(data.get("details"), dict) else {}
        if data.get("dispatched_to_script") or details.get("dispatched_to_script"):
            return "script_backend"
        if data.get("dispatched_to_gui") or details.get("dispatched_to_gui"):
            return "gui_backend"
        raw_backend = data.get("execution_backend") or details.get("execution_backend")
        if raw_backend in {"offline_model", "script_backend", "gui_backend", "hybrid"}:
            return raw_backend  # type: ignore[return-value]
        return "offline_model"

    def simulation_mode(mode: Literal["realtime", "simulation"]) -> dict[str, Any]:
        """Switch Packet Tracer between 'realtime' and 'simulation' clock modes."""

        def _run() -> OperationResult:
            data = runtime.simulation.set_mode(mode)
            lvl = StateLevel(data.get("state_level", StateLevel.PLANNED.value))
            return OperationResult.ok(
                "simulation_mode",
                f"Switched Packet Tracer mode to '{mode}'.",
                data=data,
                state_level=lvl,
                execution_backend=_mode_backend(data),
                evidence=[f"Mode transition to {mode} requested."],
            )

        return runtime.execute(
            "simulation_mode",
            PermissionTier.GUI_CONTROL,
            {"mode": mode},
            _run,
        )

    def simulation_start() -> dict[str, Any]:
        """Activate Simulation Mode in Packet Tracer."""

        def _run() -> OperationResult:
            data = runtime.simulation.start_simulation()
            lvl = StateLevel(data.get("state_level", StateLevel.PLANNED.value))
            return OperationResult.ok(
                "simulation_start",
                "Simulation mode activated.",
                data=data,
                state_level=lvl,
                execution_backend=_mode_backend(data),
                evidence=["Simulation mode enabled."],
            )

        return runtime.execute(
            "simulation_start",
            PermissionTier.GUI_CONTROL,
            {},
            _run,
        )

    def simulation_stop() -> dict[str, Any]:
        """Return Packet Tracer to Realtime Mode."""

        def _run() -> OperationResult:
            data = runtime.simulation.stop_simulation()
            lvl = StateLevel(data.get("state_level", StateLevel.PLANNED.value))
            return OperationResult.ok(
                "simulation_stop",
                "Realtime mode restored.",
                data=data,
                state_level=lvl,
                execution_backend=_mode_backend(data),
                evidence=["Realtime mode restored."],
            )

        return runtime.execute(
            "simulation_stop",
            PermissionTier.GUI_CONTROL,
            {},
            _run,
        )

    def packet_create(
        source_device: str,
        destination_ip: str,
        protocol: Literal["ICMP", "ARP", "TCP", "UDP", "HTTP", "DNS", "DHCP"] = "ICMP",
        source_ip: str | None = None,
        destination_port: int | None = None,
    ) -> dict[str, Any]:
        """Create and track a test PDU packet specification for Simulation Mode."""

        def _run() -> OperationResult:
            data = runtime.simulation.create_packet(
                source_device=source_device,
                destination_ip=destination_ip,
                protocol=protocol,
                source_ip=source_ip,
                destination_port=destination_port,
            )
            pkt = data["packet"]
            return OperationResult.ok(
                "packet_create",
                (
                    f"Created {protocol} test packet {pkt['packet_id']} "
                    f"({source_device} -> {destination_ip})."
                ),
                data=data,
                state_level=StateLevel.PLANNED,
                evidence=[f"Registered test packet spec {pkt['packet_id']}."],
            )

        return runtime.execute(
            "packet_create",
            PermissionTier.PLANNING,
            {
                "source_device": source_device,
                "destination_ip": destination_ip,
                "protocol": protocol,
            },
            _run,
        )

    def packet_inspect(
        packet_id: str | None = None,
        event_log_text: str | None = None,
    ) -> dict[str, Any]:
        """Inspect tracked test packets and optionally parse Simulation Event List output."""

        def _run() -> OperationResult:
            data = runtime.simulation.inspect_packet_events(
                packet_id=packet_id,
                event_log_text=event_log_text,
            )
            lvl = StateLevel(data.get("state_level", StateLevel.PLANNED.value))
            event_count = len(data.get("parsed_events", []))
            summary = (
                f"Tracked packets={len(data.get('tracked_packets', []))}, "
                f"parsed events={event_count}."
            )
            ev = [f"Parsed {event_count} simulation event records."] if event_count else []
            return OperationResult.ok(
                "packet_inspect",
                summary,
                data=data,
                state_level=lvl,
                evidence=ev,
            )

        return runtime.execute(
            "packet_inspect",
            PermissionTier.READ_ONLY,
            {"packet_id": packet_id, "has_log_text": bool(event_log_text)},
            _run,
        )

    def connectivity_test(
        source_device: str = "",
        destination_ip: str = "",
        count: int = 2,
        allow_offline_estimation: bool = True,
        checks: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Run one or multiple (parallel) connectivity ping checks via live PT CLI or topology.

        Pass `checks=[{"source_device": "PC-A1", "destination_ip": "10.10.20.11"}, ...]` to run
        an entire ping verification matrix in parallel across devices (and batched per device)
        in a single round-trip.
        """
        if count < 1 or count > 100:
            raise ValidationError(
                f"Invalid ping count {count!r}: expected an integer between 1 and 100.",
                details={"count": count},
            )
        params: dict[str, Any] = {
            "source_device": source_device,
            "destination_ip": destination_ip,
            "count": count,
        }
        if checks is not None:
            params["checks_count"] = len(checks)

        def _ping_command_for_source(src: str, clean_dest: str, topo: Any) -> str:
            resolved_model = runtime.simulation._resolve_source_model(src, topology=topo)
            prof = get_console_profile(resolved_model, catalog=runtime.catalog)
            if prof.interaction_kind == ConsoleInteractionKind.PT_DESKTOP_CMD:
                return f"ping -n {count} {clean_dest}" if count != 4 else f"ping {clean_dest}"
            return f"ping {clean_dest}"

        def _report_from_ping_output(
            src: str, cmd: str, clean_dest: str, output_text: str
        ) -> dict[str, Any]:
            summary = parse_ping_output(output_text, target_ip=clean_dest)
            ev = [
                f"Executed '{cmd}' on live console of {src}: "
                f"received={summary.received}/{summary.transmitted}, "
                f"loss={summary.loss_percent}%."
            ]
            report = ConnectivityCheckReport(
                source_device=src,
                destination_ip=clean_dest,
                protocol=PDUProtocol.ICMP,
                simulation_source=SimulationSource.PACKET_TRACER_CLI,
                verified_in_pt=True,
                state_level=StateLevel.VERIFIED,
                reachable=summary.reached,
                ping_summary=summary,
                evidence=ev,
                warnings=[],
            )
            return report.model_dump(mode="json")

        def _run_http_source_batch(
            pt_src: str,
            items: list[tuple[str, str]],
            topo: Any,
        ) -> dict[tuple[str, str], dict[str, Any]]:
            """Batch all ping checks for a single PT source device in 1 `execute_cli` call."""
            if len(items) == 1:
                src0, dst0 = items[0]
                return {
                    (src0, dst0): runtime.simulation.run_connectivity_check(
                        source=src0,
                        destination_ip=dst0,
                        topology=topo,
                        count=count,
                        allow_offline_estimation=allow_offline_estimation,
                    )
                }

            cmds = [_ping_command_for_source(src, dst, topo) for src, dst in items]
            batch_timeout = max(25.0, 12.0 + len(cmds) * 8.0)
            script_backend = runtime.router.script_backend
            assert script_backend is not None

            exec_fn = script_backend.execute_cli
            exec_kwargs: dict[str, Any] = {"timeout_seconds": batch_timeout}
            try:
                if "stop_on_error" in inspect.signature(exec_fn).parameters:
                    exec_kwargs["stop_on_error"] = False
            except (TypeError, ValueError):
                pass

            try:
                res = dict(exec_fn(pt_src, cmds, **exec_kwargs))
            except Exception:
                return {
                    (src, dst): runtime.simulation.run_connectivity_check(
                        source=src,
                        destination_ip=dst,
                        topology=topo,
                        count=count,
                        allow_offline_estimation=allow_offline_estimation,
                    )
                    for src, dst in items
                }

            prompt = str(res.get("prompt", "")).strip()
            raw_out = str(res.get("raw_output", ""))
            timed_out = bool(res.get("timed_out", False))
            raw_cmd_outputs = res.get("command_outputs")
            slices: list[str] | None = None
            if isinstance(raw_cmd_outputs, list) and len(raw_cmd_outputs) > 0:
                slices = [str(x) for x in raw_cmd_outputs]
            elif raw_out.strip() and not timed_out:
                candidate = _split_batch_output(raw_out, cmds)
                if all(bool(s.strip()) for s in candidate):
                    slices = candidate

            if slices is None:
                return {
                    (src, dst): runtime.simulation.run_connectivity_check(
                        source=src,
                        destination_ip=dst,
                        topology=topo,
                        count=count,
                        allow_offline_estimation=allow_offline_estimation,
                    )
                    for src, dst in items
                }

            with runtime.router._state_lock:
                log = runtime.router.executed_cli_log.setdefault(pt_src, [])
                for c in cmds[: len(slices)]:
                    cleaned = redact_cli_text(c.strip())
                    if cleaned:
                        log.append(cleaned)

            # If device was left in config submode `(config)#`, exit to Exec and retry failed pings.
            in_config_mode = (
                bool(prompt)
                and not prompt.lower().startswith("c:")
                and "(" in prompt
                and prompt.endswith("#")
            )
            if in_config_mode and any(
                detect_cli_read_error(s) is not None for s in slices[: len(items)]
            ):
                try:
                    script_backend.execute_cli(pt_src, ["end"], timeout_seconds=10.0)
                    res2 = dict(exec_fn(pt_src, cmds, **exec_kwargs))
                    raw2 = res2.get("command_outputs")
                    if isinstance(raw2, list) and len(raw2) > 0:
                        slices = [str(x) for x in raw2]
                except Exception:
                    pass

            out: dict[tuple[str, str], dict[str, Any]] = {}
            for idx, (src, dst) in enumerate(items):
                cmd = cmds[idx]
                if idx < len(slices):
                    slice_text = slices[idx]
                    out[(src, dst)] = _report_from_ping_output(src, cmd, dst, slice_text)
                elif timed_out:
                    summary = parse_ping_output("", target_ip=dst)
                    out[(src, dst)] = ConnectivityCheckReport(
                        source_device=src,
                        destination_ip=dst,
                        protocol=PDUProtocol.ICMP,
                        simulation_source=SimulationSource.PACKET_TRACER_CLI,
                        verified_in_pt=False,
                        state_level=StateLevel.EXECUTED,
                        reachable=False,
                        ping_summary=summary,
                        evidence=[
                            f"Dispatched '{cmd}' on {src}; batch timed out before completion."
                        ],
                        warnings=[f"Live CLI ping '{cmd}' on '{src}' timed out."],
                    ).model_dump(mode="json")
                else:
                    out[(src, dst)] = runtime.simulation.run_connectivity_check(
                        source=src,
                        destination_ip=dst,
                        topology=topo,
                        count=count,
                        allow_offline_estimation=allow_offline_estimation,
                    )
            return out

        def _run() -> OperationResult:
            topo = None
            if runtime.manager.has_active_project:
                _, topo, _, _ = runtime.manager.require_active()

            if checks is not None:
                if not checks:
                    raise ValidationError(
                        "checks must contain at least one {source_device, destination_ip} entry."
                    )
                normalized_checks: list[tuple[str, str]] = []
                for item in checks:
                    src = str(item.get("source_device") or item.get("source") or "").strip()
                    dst = str(item.get("destination_ip") or item.get("destination") or "").strip()
                    if not src or not dst:
                        raise ValidationError(
                            "Each item in checks must provide 'source_device' and 'destination_ip'."
                        )
                    clean_dst = validate_ping_target(dst)
                    normalized_checks.append((src, clean_dst))

                # Deduplicate identical (source_device, destination_ip) pairs, keeping order.
                unique_pairs = list(dict.fromkeys(normalized_checks))

                can_batch_http = (
                    runtime.router.ensure_live_script()
                    and isinstance(runtime.router.script_backend, HttpScriptBridgeBackend)
                    and runtime.console.transport.is_available()
                )
                pair_results: dict[tuple[str, str], dict[str, Any]] = {}
                if can_batch_http:
                    by_pt_source: dict[str, list[tuple[str, str]]] = {}
                    for src, dst in unique_pairs:
                        pt_src = runtime.router.resolve_pt_device_name(src)
                        by_pt_source.setdefault(pt_src, []).append((src, dst))

                    if len(by_pt_source) == 1:
                        pt_src, src_items = next(iter(by_pt_source.items()))
                        pair_results.update(_run_http_source_batch(pt_src, src_items, topo))
                    else:
                        with ThreadPoolExecutor(max_workers=min(len(by_pt_source), 6)) as pool:
                            futures = [
                                pool.submit(_run_http_source_batch, pt_src, src_items, topo)
                                for pt_src, src_items in by_pt_source.items()
                            ]
                            for fut in futures:
                                pair_results.update(fut.result())
                else:
                    for src, dst in unique_pairs:
                        pair_results[(src, dst)] = runtime.simulation.run_connectivity_check(
                            source=src,
                            destination_ip=dst,
                            topology=topo,
                            count=count,
                            allow_offline_estimation=allow_offline_estimation,
                        )

                results = [dict(pair_results[pair]) for pair in normalized_checks]
                passed = sum(1 for r in results if r.get("reachable"))
                all_verified = all(r.get("verified_in_pt") for r in results)
                backend: ExecutionBackend = (
                    transport_to_execution_backend(runtime.console.transport.transport_name)
                    if any(r.get("verified_in_pt") for r in results)
                    else "offline_model"
                )
                all_warnings = [w for r in results for w in r.get("warnings", [])]
                all_evidence = [e for r in results for e in r.get("evidence", [])]
                return OperationResult.ok(
                    "connectivity_test",
                    f"Batch connectivity: {passed}/{len(results)} reachable.",
                    data={
                        "results": results,
                        "total": len(results),
                        "reachable_count": passed,
                        "all_reachable": passed == len(results),
                    },
                    state_level=StateLevel.VERIFIED if all_verified else StateLevel.PLANNED,
                    execution_backend=backend,
                    warnings=all_warnings,
                    evidence=all_evidence,
                )

            if not source_device.strip() or not destination_ip.strip():
                raise ValidationError(
                    "Provide source_device and destination_ip, or a checks list."
                )

            data = runtime.simulation.run_connectivity_check(
                source=source_device,
                destination_ip=destination_ip,
                topology=topo,
                count=count,
                allow_offline_estimation=allow_offline_estimation,
            )
            lvl = StateLevel(data.get("state_level", StateLevel.PLANNED.value))
            backend = (
                transport_to_execution_backend(runtime.console.transport.transport_name)
                if data.get("verified_in_pt")
                else "offline_model"
            )
            status_word = "REACHABLE" if data.get("reachable") else "UNREACHABLE"
            summary = (
                f"Connectivity {source_device} -> {destination_ip}: "
                f"{status_word} ({data.get('simulation_source')})."
            )
            return OperationResult.ok(
                "connectivity_test",
                summary,
                data=data,
                state_level=lvl,
                execution_backend=backend,
                warnings=data.get("warnings", []),
                evidence=data.get("evidence", []),
            )

        return runtime.execute(
            "connectivity_test",
            PermissionTier.READ_ONLY,
            params,
            _run,
        )

    specs = [
        ("simulation_mode", simulation_mode, PermissionTier.GUI_CONTROL, False),
        ("simulation_start", simulation_start, PermissionTier.GUI_CONTROL, False),
        ("simulation_stop", simulation_stop, PermissionTier.GUI_CONTROL, False),
        ("packet_create", packet_create, PermissionTier.PLANNING, False),
        ("packet_inspect", packet_inspect, PermissionTier.READ_ONLY, True),
        ("connectivity_test", connectivity_test, PermissionTier.READ_ONLY, True),
    ]
    for name, fn, tier, ro in specs:
        runtime.registry.register_tool(
            server,
            name=name,
            category="simulation",
            permission_tier=tier,
            description=(fn.__doc__ or name).strip(),
            fn=fn,
            read_only=ro,
            idempotent=ro,
        )
