"""Self-repair and intelligent diagnostic engine for Packet Tracer networks."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agenticnet.console.engine import DeviceConsoleEngine
from agenticnet.core.enums import ConfigCapability, DeviceCategory, StateLevel
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
    evaluate_live_cli_diagnostics,
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
        # Offline topology/IPAM rules inspect planned state only; never claim live verification.
        return DiagnosticReport(
            state_level=StateLevel.PLANNED,
            findings=findings,
            proposed_repairs=proposals,
            clean=is_clean,
        )

    def _collect_console_cli(self, device_name: str, commands: list[str]) -> dict[str, str]:
        """Collect live CLI show outputs for `device_name` via `self.console`."""
        if not self.console or not self.console.transport.is_available():
            return {}
        res = self.console.execute_commands(
            device_name=device_name,
            commands=commands,
            target_mode="privileged_exec",
        )
        captured: dict[str, str] = {}
        transcripts = res.get("transcripts", [])
        if not isinstance(transcripts, list):
            return captured
        for cmd in commands:
            want = cmd.strip().lower()
            for tr in transcripts:
                if isinstance(tr, dict) and want in str(tr.get("command", "")).strip().lower():
                    captured[cmd] = str(tr.get("raw_output", ""))
                    break
        return captured

    def run_live_diagnostics(
        self,
        topology: TopologyEngine,
        ipam: IPAMEngine | None = None,
        *,
        categories: list[DiagnosticCategory] | None = None,
        cli_reader: Callable[[str, str], str] | None = None,
        live_snapshots: dict[str, dict[str, str]] | None = None,
    ) -> DiagnosticReport:
        """Run root-cause diagnostics against live IOS CLI outputs (`StateLevel.VERIFIED`)."""
        _ = ipam
        active_cats = set(categories) if categories else None
        snapshots: dict[str, dict[str, str]] = {}
        live_reads_succeeded = 0

        if live_snapshots is not None:
            for d_name, cmd_map in live_snapshots.items():
                non_empty = {k: v for k, v in cmd_map.items() if str(v).strip()}
                if non_empty:
                    snapshots[d_name] = non_empty
                    live_reads_succeeded += len(non_empty)
        elif cli_reader is not None or (self.console and self.console.transport.is_available()):
            for d_name, dev in topology.model.devices.items():
                try:
                    profile = topology.catalog.get_profile(dev.model)
                    if not profile.supports(ConfigCapability.IOS_CLI):
                        continue
                except Exception:
                    if dev.category not in {
                        DeviceCategory.ROUTER,
                        DeviceCategory.L2_SWITCH,
                        DeviceCategory.L3_SWITCH,
                    }:
                        continue

                cmds = ["show ip interface brief", "show running-config", "show access-lists"]
                if dev.category in {DeviceCategory.L2_SWITCH, DeviceCategory.L3_SWITCH}:
                    cmds.append("show interfaces trunk")
                if dev.category in {DeviceCategory.ROUTER, DeviceCategory.L3_SWITCH}:
                    cmds.extend(["show ip ospf neighbor", "show ip route"])

                dev_snaps: dict[str, str] = {}
                if cli_reader is not None:
                    for cmd in cmds:
                        try:
                            out = cli_reader(d_name, cmd)
                            if out and out.strip():
                                dev_snaps[cmd] = out
                                live_reads_succeeded += 1
                        except Exception:
                            continue
                else:
                    try:
                        collected = self._collect_console_cli(d_name, cmds)
                        for cmd, out in collected.items():
                            if out and out.strip():
                                dev_snaps[cmd] = out
                                live_reads_succeeded += 1
                    except Exception:
                        continue
                if dev_snaps:
                    snapshots[d_name] = dev_snaps

        findings: list[DiagnosticFinding] = []
        proposals: list[RepairProposal] = []
        if snapshots:
            for f, p in evaluate_live_cli_diagnostics(topology, snapshots, categories=active_cats):
                findings.append(f)
                proposals.append(p)
                self._cached_proposals[p.proposal_id] = p

        verified = live_reads_succeeded > 0
        return DiagnosticReport(
            state_level=StateLevel.VERIFIED if verified else StateLevel.PLANNED,
            findings=findings,
            proposed_repairs=proposals,
            clean=len(findings) == 0,
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
            is_host_cmd = bool(
                act.command_sequence
                and act.command_sequence[0].strip().lower().startswith("ipconfig")
            )
            if self.console and self.console.transport.is_available():
                res = self.console.execute_commands(
                    device_name=act.target_device,
                    commands=act.command_sequence,
                    target_mode="preserve" if is_host_cmd else "global_config",
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
                    for cmd in act.command_sequence:
                        stripped = cmd.strip()
                        low = stripped.lower()
                        if low == "no shutdown":
                            iface.admin_up = True
                        elif low == "shutdown":
                            iface.admin_up = False
                        elif low.startswith("ip address "):
                            parts = stripped.split()
                            if len(parts) >= 4:
                                iface.ipv4_address = parts[2]
                                iface.subnet_mask = parts[3]
                        elif low.startswith("ipconfig "):
                            parts = stripped.split()
                            if len(parts) >= 3:
                                iface.ipv4_address = parts[1]
                                iface.subnet_mask = parts[2]
                            if len(parts) >= 4:
                                iface.default_gateway = parts[3]
                        elif low == "switchport mode trunk":
                            iface.is_trunk = True
                            iface.vlan_mode = "trunk"
                        elif low.startswith("switchport trunk native vlan "):
                            parts = stripped.split()
                            if len(parts) >= 5 and parts[4].isdigit():
                                n_vid = int(parts[4])
                                iface.native_vlan = n_vid
                                iface.vlan_id = n_vid

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
