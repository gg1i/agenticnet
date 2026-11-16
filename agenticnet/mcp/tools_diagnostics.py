"""MCP tools for intelligent network diagnostics, root-cause analysis, and self-repair."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from agenticnet.core.enums import PermissionTier, StateLevel
from agenticnet.core.models import OperationResult
from agenticnet.diagnostics.models import DiagnosticCategory
from agenticnet.mcp.registry import AgenticNetRuntime


def register_diagnostics_tools(server: MCPServer, runtime: AgenticNetRuntime) -> None:
    """Register intelligent network diagnostics and self-repair tools."""

    def network_diagnose() -> dict[str, Any]:
        """Run a full diagnostic audit across addressing, interfaces, VLANs, and routing."""

        def _run() -> OperationResult:
            _, topo, ipam, _ = runtime.manager.require_active()
            report = runtime.diagnostics.run_diagnostics(topology=topo, ipam=ipam)
            finding_count = len(report.findings)
            summary = (
                "Diagnostic audit clean: no configuration errors detected."
                if report.clean
                else f"Diagnostic audit completed: {finding_count} issue(s) detected."
            )
            return OperationResult.ok(
                "network_diagnose",
                summary,
                data=report.model_dump(mode="json"),
                state_level=report.state_level,
                warnings=[f"{f.code}: {f.summary}" for f in report.findings],
                evidence=[f"Evaluated {finding_count} diagnostic findings."],
            )

        return runtime.execute(
            "network_diagnose",
            PermissionTier.READ_ONLY,
            {},
            _run,
        )

    def routing_diagnose(device_name: str | None = None) -> dict[str, Any]:
        """Inspect routing tables, static routes, and OSPF adjacencies for routing errors."""

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            target_devices = [device_name] if device_name else list(topo.model.devices.keys())
            routing_data: dict[str, Any] = {}
            for d in target_devices:
                dev = topo.model.devices.get(d)
                if dev and dev.category.value in {"router", "l3_switch"}:
                    routing_data[d] = {
                        "routes": runtime.simulation.inspect_routing_table(d),
                        "ospf": runtime.simulation.inspect_ospf_neighbors(d),
                    }
            return OperationResult.ok(
                "routing_diagnose",
                f"Diagnosed routing tables and adjacencies for {len(routing_data)} router(s).",
                data=routing_data,
                state_level=StateLevel.VERIFIED if routing_data else StateLevel.PLANNED,
                evidence=[f"Queried routing status on {list(routing_data.keys())}."],
            )

        return runtime.execute(
            "routing_diagnose",
            PermissionTier.READ_ONLY,
            {"device_name": device_name},
            _run,
        )

    def vlan_diagnose() -> dict[str, Any]:
        """Audit VLAN assignments, trunk links, and native VLAN consistency."""

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            report = runtime.diagnostics.run_diagnostics(
                topology=topo,
                categories=[DiagnosticCategory.VLAN_TRUNKING],
            )
            return OperationResult.ok(
                "vlan_diagnose",
                f"VLAN/Trunk diagnostic completed ({len(report.findings)} finding(s)).",
                data=report.model_dump(mode="json"),
                state_level=report.state_level,
                evidence=["Evaluated VLAN and trunk configurations."],
            )

        return runtime.execute(
            "vlan_diagnose",
            PermissionTier.READ_ONLY,
            {},
            _run,
        )

    def interface_diagnose() -> dict[str, Any]:
        """Audit physical and logical interface status (shutdown vs up/up, duplex, IPs)."""

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            report = runtime.diagnostics.run_diagnostics(
                topology=topo,
                categories=[DiagnosticCategory.INTERFACE_PHYSICAL],
            )
            return OperationResult.ok(
                "interface_diagnose",
                f"Interface diagnostics completed ({len(report.findings)} issue(s)).",
                data=report.model_dump(mode="json"),
                state_level=report.state_level,
                evidence=["Audited interface administrative states and assigned IPs."],
            )

        return runtime.execute(
            "interface_diagnose",
            PermissionTier.READ_ONLY,
            {},
            _run,
        )

    def network_repair_propose() -> dict[str, Any]:
        """Generate safe, ranked self-repair proposals for all detected network findings."""

        def _run() -> OperationResult:
            _, topo, ipam, _ = runtime.manager.require_active()
            report = runtime.diagnostics.run_diagnostics(topology=topo, ipam=ipam)
            proposals = report.proposed_repairs
            return OperationResult.ok(
                "network_repair_propose",
                f"Generated {len(proposals)} repair proposal(s) with concrete CLI commands.",
                data={"proposals": [p.model_dump(mode="json") for p in proposals]},
                state_level=StateLevel.PLANNED,
                evidence=[f"{p.proposal_id}: {p.summary}" for p in proposals],
            )

        return runtime.execute(
            "network_repair_propose",
            PermissionTier.PLANNING,
            {},
            _run,
        )

    def network_repair_execute(proposal_id: str, confirm: bool = False) -> dict[str, Any]:
        """Execute an approved self-repair proposal and sync repaired state."""

        def _run() -> OperationResult:
            _, topo, _, _ = runtime.manager.require_active()
            res = runtime.diagnostics.execute_repair(
                proposal_id=proposal_id,
                confirm=confirm,
                topology=topo,
            )
            lvl = StateLevel(res.get("state_level", StateLevel.EXECUTED.value))
            return OperationResult.ok(
                "network_repair_execute",
                f"Executed repair proposal {proposal_id} (actions={res.get('actions_executed')}).",
                data=res,
                state_level=lvl,
                evidence=[f"Executed repair proposal {proposal_id}."],
            )

        return runtime.execute(
            "network_repair_execute",
            PermissionTier.CONFIGURATION,
            {"proposal_id": proposal_id, "confirm": confirm},
            _run,
            confirm=confirm,
        )

    def network_verify() -> dict[str, Any]:
        """Run post-repair verification checks and return overall health status."""

        def _run() -> OperationResult:
            _, topo, ipam, _ = runtime.manager.require_active()
            report = runtime.diagnostics.run_diagnostics(topology=topo, ipam=ipam)
            status_str = "HEALTHY" if report.clean else "DEGRADED"
            return OperationResult.ok(
                "network_verify",
                f"Network health status: {status_str} (unresolved issues: {len(report.findings)}).",
                data=report.model_dump(mode="json"),
                state_level=report.state_level,
                evidence=["Re-ran diagnostic rule suite against current network state."],
            )

        return runtime.execute(
            "network_verify",
            PermissionTier.READ_ONLY,
            {},
            _run,
        )

    specs = [
        ("network_diagnose", network_diagnose, PermissionTier.READ_ONLY, True),
        ("routing_diagnose", routing_diagnose, PermissionTier.READ_ONLY, True),
        ("vlan_diagnose", vlan_diagnose, PermissionTier.READ_ONLY, True),
        ("interface_diagnose", interface_diagnose, PermissionTier.READ_ONLY, True),
        ("network_repair_propose", network_repair_propose, PermissionTier.PLANNING, False),
        ("network_repair_execute", network_repair_execute, PermissionTier.CONFIGURATION, False),
        ("network_verify", network_verify, PermissionTier.READ_ONLY, True),
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
