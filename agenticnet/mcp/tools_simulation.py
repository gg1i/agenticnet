"""MCP tools for Packet Tracer simulation controls, PDU tracing, and connectivity tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from agenticnet.adapters.router import transport_to_execution_backend
from agenticnet.adapters.script_bridge import HttpScriptBridgeBackend
from agenticnet.core.enums import PermissionTier, StateLevel
from agenticnet.core.exceptions import ValidationError
from agenticnet.core.models import ExecutionBackend, OperationResult
from agenticnet.mcp.registry import AgenticNetRuntime


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
        an entire ping verification matrix in parallel in a single round-trip.
        """
        params: dict[str, Any] = {
            "source_device": source_device,
            "destination_ip": destination_ip,
            "count": count,
        }
        if checks is not None:
            params["checks_count"] = len(checks)

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
                    normalized_checks.append((src, dst))

                def _run_one(pair: tuple[str, str]) -> dict[str, Any]:
                    return runtime.simulation.run_connectivity_check(
                        source=pair[0],
                        destination_ip=pair[1],
                        topology=topo,
                        count=count,
                        allow_offline_estimation=allow_offline_estimation,
                    )

                use_parallel = (
                    len(normalized_checks) > 1
                    and runtime.router.ensure_live_script()
                    and isinstance(runtime.router.script_backend, HttpScriptBridgeBackend)
                )
                if use_parallel:
                    with ThreadPoolExecutor(max_workers=min(len(normalized_checks), 6)) as pool:
                        results = list(pool.map(_run_one, normalized_checks))
                else:
                    results = [_run_one(pair) for pair in normalized_checks]

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
