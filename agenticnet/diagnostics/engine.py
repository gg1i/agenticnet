"""Self-repair and intelligent diagnostic engine for Packet Tracer networks."""

from __future__ import annotations

from typing import Any

from agenticnet.console.engine import DeviceConsoleEngine
from agenticnet.core.enums import StateLevel
from agenticnet.core.exceptions import AgenticNetError, ApprovalRequiredError
from agenticnet.diagnostics.models import (
    DiagnosticCategory,
    DiagnosticFinding,
    DiagnosticReport,
    RepairProposal,
)
from agenticnet.diagnostics.rules import (
    check_disabled_interfaces_with_ip,
    check_link_subnet_mismatch,
    check_missing_default_gateways,
    check_trunk_mode_mismatch,
    check_vlan_trunk_native_mismatch,
)
from agenticnet.ipam.engine import IPAMEngine
from agenticnet.simulation.engine import SimulationEngine
from agenticnet.topology.engine import TopologyEngine


class DiagnosticsEngine:
    """Orchestrates evidence-backed root cause analysis, ranked proposals, and verified repair."""

    def __init__(
        self,
        *,
        console_engine: DeviceConsoleEngine | None = None,
        simulation_engine: SimulationEngine | None = None,
    ) -> None:
        self.console = console_engine
        self.simulation = simulation_engine
        self._cached_proposals: dict[str, RepairProposal] = {}

    def run_diagnostics(
        self,
        topology: TopologyEngine,
        ipam: IPAMEngine | None = None,
        *,
        categories: list[DiagnosticCategory] | None = None,
    ) -> DiagnosticReport:
        """Run all diagnostic rule checks against the active topology and IPAM state."""
        findings: list[DiagnosticFinding] = []
        proposals: list[RepairProposal] = []
        active_cats = set(categories) if categories else None

        # Rule 1: Disabled interfaces with IP assigned
        if not active_cats or DiagnosticCategory.INTERFACE_PHYSICAL in active_cats:
            for f, p in check_disabled_interfaces_with_ip(topology):
                findings.append(f)
                proposals.append(p)
                self._cached_proposals[p.proposal_id] = p

        # Rule 2: End devices missing default gateways
        if not active_cats or DiagnosticCategory.ADDRESSING_IPAM in active_cats:
            for f, p in check_missing_default_gateways(topology, ipam):
                findings.append(f)
                proposals.append(p)
                self._cached_proposals[p.proposal_id] = p

        # Rule 3: Subnet mismatch on connected links
        if not active_cats or DiagnosticCategory.ADDRESSING_IPAM in active_cats:
            for f, p in check_link_subnet_mismatch(topology):
                findings.append(f)
                proposals.append(p)
                self._cached_proposals[p.proposal_id] = p

        # Rule 4: Native VLAN & mode mismatches on trunks
        if not active_cats or DiagnosticCategory.VLAN_TRUNKING in active_cats:
            for f, p in check_vlan_trunk_native_mismatch(topology):
                findings.append(f)
                proposals.append(p)
                self._cached_proposals[p.proposal_id] = p
            for f, p in check_trunk_mode_mismatch(topology):
                findings.append(f)
                proposals.append(p)
                self._cached_proposals[p.proposal_id] = p

        is_clean = len(findings) == 0
        state_lvl = (
            StateLevel.VERIFIED
            if (self.console and self.console.transport.is_available())
            else StateLevel.PLANNED
        )
        return DiagnosticReport(
            state_level=state_lvl,
            findings=findings,
            proposed_repairs=proposals,
            clean=is_clean,
        )

    def execute_repair(
        self,
        proposal_id: str,
        *,
        confirm: bool = False,
        topology: TopologyEngine | None = None,
    ) -> dict[str, Any]:
        """Execute an approved repair proposal.

        Enforces confirmation gates for disruptive changes, executes via console,
        and synchronizes changes back into the topology engine.
        """
        proposal = self._cached_proposals.get(proposal_id)
        if not proposal:
            raise AgenticNetError(
                f"Repair proposal '{proposal_id}' not found.",
                error_code="PROPOSAL_NOT_FOUND",
                remediation="Run network_repair_propose or network_diagnose first.",
            )

        if proposal.requires_approval and not confirm:
            raise ApprovalRequiredError(
                f"Disruptive repair '{proposal.summary}' requires explicit confirmation.",
                details={"proposal_id": proposal_id, "reason": proposal.approval_reason},
                remediation="Review proposed command sequence and invoke with confirm=True.",
            )

        executed_actions: list[dict[str, Any]] = []
        all_succeeded = True

        for act in proposal.actions:
            if self.console and self.console.transport.is_available():
                res = self.console.execute_commands(
                    device_name=act.target_device,
                    commands=act.command_sequence,
                    target_mode="global_config",
                    verification_commands=act.verification_commands,
                )
                executed_actions.append(res)
                if not res.get("all_commands_succeeded", True):
                    all_succeeded = False
            else:
                executed_actions.append(
                    {
                        "target_device": act.target_device,
                        "commands": act.command_sequence,
                        "offline_simulated": True,
                    }
                )

            # Synchronize repaired state in topology model if provided
            if topology is not None and act.target_interface:
                dev = topology.model.devices.get(act.target_device)
                if dev and act.target_interface in dev.interfaces:
                    iface = dev.interfaces[act.target_interface]
                    if "no shutdown" in act.command_sequence:
                        iface.admin_up = True
                    for cmd in act.command_sequence:
                        if cmd.startswith("ip address "):
                            parts = cmd.split()
                            if len(parts) >= 4:
                                iface.ipv4_address = parts[2]
                                iface.subnet_mask = parts[3]

        proposal.executed = True
        proposal.verified = all_succeeded
        proposal.state_level = (
            StateLevel.VERIFIED
            if (self.console and self.console.transport.is_available())
            else StateLevel.EXECUTED
        )

        return {
            "proposal_id": proposal_id,
            "all_succeeded": all_succeeded,
            "actions_executed": len(executed_actions),
            "details": executed_actions,
            "state_level": proposal.state_level.value,
        }
