"""Packet Tracer simulation mode and connectivity verification engine."""

from __future__ import annotations

from typing import Any

import networkx as nx

from agenticnet.adapters.base import GuiBackend, SimulationBackend
from agenticnet.console.engine import DeviceConsoleEngine
from agenticnet.core.enums import StateLevel
from agenticnet.core.exceptions import AgenticNetError, DeviceNotFoundError, ValidationError
from agenticnet.devices import DEFAULT_CATALOG, DeviceCatalog
from agenticnet.gui.windows_backend import WindowsGuiBackend
from agenticnet.security.validation import validate_ping_target
from agenticnet.simulation.models import (
    ConnectivityCheckReport,
    ParsedArpEntry,
    ParsedInterfaceBrief,
    ParsedOspfNeighbor,
    ParsedRouteEntry,
    ParsedVlanEntry,
    PDUProtocol,
    SimulationSource,
    SimulatorMode,
    TestPacketSpec,
)
from agenticnet.simulation.parsers import (
    parse_ping_output,
    parse_show_arp,
    parse_show_ip_int_brief,
    parse_show_ip_ospf_neighbor,
    parse_show_ip_route,
    parse_show_vlan_brief,
    parse_simulation_event_lines,
)
from agenticnet.topology.engine import TopologyEngine


class SimulationEngine(SimulationBackend):
    """Engine orchestrating mode switches, in-simulator pings, and route/ARP inspections."""

    def __init__(
        self,
        *,
        gui_backend: GuiBackend | None = None,
        console_engine: DeviceConsoleEngine | None = None,
        catalog: DeviceCatalog | None = None,
    ) -> None:
        self.gui = gui_backend
        self.console = console_engine
        self.catalog = catalog or DEFAULT_CATALOG
        self._current_mode = SimulatorMode.REALTIME
        self._tracked_packets: dict[str, TestPacketSpec] = {}

    @property
    def current_mode(self) -> SimulatorMode:
        """Return the current tracked simulator clock mode."""
        return self._current_mode

    def set_mode(self, mode: str) -> dict[str, Any]:
        """Switch between 'realtime' and 'simulation' mode in Packet Tracer."""
        normalized = mode.strip().lower()
        if normalized not in {SimulatorMode.REALTIME.value, SimulatorMode.SIMULATION.value}:
            raise AgenticNetError(
                f"Invalid simulation mode {mode!r}. Expected 'realtime' or 'simulation'.",
                error_code="INVALID_SIMULATION_MODE",
                remediation="Choose 'realtime' or 'simulation'.",
            )

        target_enum = SimulatorMode(normalized)
        clicked = False
        anchor = "mode_simulation" if target_enum == SimulatorMode.SIMULATION else "mode_realtime"

        if isinstance(self.gui, WindowsGuiBackend):
            try:
                det = self.gui.detect_application()
                if det.get("running") and det.get("window"):
                    self.gui.click(anchor_name=anchor, dry_run=False)
                    clicked = True
            except Exception:
                clicked = False

        self._current_mode = target_enum
        return {
            "mode": target_enum.value,
            "dispatched_to_gui": clicked,
            "state_level": (StateLevel.EXECUTED.value if clicked else StateLevel.PLANNED.value),
        }

    def start_simulation(self) -> dict[str, Any]:
        """Ensure simulation mode is active and running."""
        res = self.set_mode(SimulatorMode.SIMULATION.value)
        return {
            "status": "simulation_active",
            "details": res,
            "state_level": res["state_level"],
        }

    def stop_simulation(self) -> dict[str, Any]:
        """Switch back to realtime mode."""
        res = self.set_mode(SimulatorMode.REALTIME.value)
        return {
            "status": "realtime_active",
            "details": res,
            "state_level": res["state_level"],
        }

    def _extract_command_output(self, res: dict[str, Any], expected_command: str) -> str:
        """Extract raw_output for the matching command transcript rather than transcripts[0]."""
        transcripts = res.get("transcripts", [])
        if not isinstance(transcripts, list) or not transcripts:
            return ""
        want = expected_command.strip().lower()
        for tr in transcripts:
            if isinstance(tr, dict) and want in str(tr.get("command", "")).strip().lower():
                return str(tr.get("raw_output", ""))
        for tr in reversed(transcripts):
            if isinstance(tr, dict) and str(tr.get("raw_output", "")).strip():
                return str(tr.get("raw_output", ""))
        last = transcripts[-1]
        return str(last.get("raw_output", "")) if isinstance(last, dict) else ""

    def create_packet(
        self,
        source_device: str,
        destination_ip: str,
        *,
        protocol: str = "ICMP",
        source_ip: str | None = None,
        destination_port: int | None = None,
    ) -> dict[str, Any]:
        """Create and register a test PDU packet specification."""
        clean_dest = validate_ping_target(destination_ip)
        proto = PDUProtocol(protocol.upper())
        spec = TestPacketSpec(
            source_device=source_device,
            destination_ip=clean_dest,
            protocol=proto,
            source_ip=source_ip,
            destination_port=destination_port,
            status="registered",
            created_in_pt=False,
        )
        self._tracked_packets[spec.packet_id] = spec
        return {
            "packet": spec.model_dump(mode="json"),
            "state_level": StateLevel.PLANNED.value,
        }

    def inspect_packet_events(
        self,
        packet_id: str | None = None,
        *,
        event_log_text: str | None = None,
    ) -> dict[str, Any]:
        """Inspect tracked test packets and optionally parse raw PT Simulation Event lines."""
        parsed_events = parse_simulation_event_lines(event_log_text) if event_log_text else []
        tracked = (
            [self._tracked_packets[packet_id].model_dump(mode="json")]
            if packet_id and packet_id in self._tracked_packets
            else [p.model_dump(mode="json") for p in self._tracked_packets.values()]
        )
        return {
            "tracked_packets": tracked,
            "parsed_events": [e.model_dump(mode="json") for e in parsed_events],
            "state_level": (
                StateLevel.VERIFIED.value if parsed_events else StateLevel.PLANNED.value
            ),
        }

    def run_connectivity_check(
        self,
        source: str,
        destination_ip: str,
        *,
        topology: TopologyEngine | None = None,
        count: int = 4,
        allow_offline_estimation: bool = True,
    ) -> dict[str, Any]:
        """Run an end-to-end connectivity test.

        Executes via device CLI if available; falls back to graph reachability estimation
        only when offline and allowed, clearly tagging the evidence source.
        """
        clean_dest = validate_ping_target(destination_ip)
        if count < 1 or count > 100:
            raise ValidationError(
                f"Invalid ping count {count!r}: expected an integer between 1 and 100.",
                details={"count": count},
            )
        evidence: list[str] = []
        warnings: list[str] = []

        if self.console and self.console.transport.is_available():
            try:
                if count == 4:
                    cmd = f"ping {clean_dest}"
                else:
                    profiles = getattr(self.console, "_profiles", {})
                    prof = profiles.get(source) if isinstance(profiles, dict) else None
                    if (
                        prof is not None
                        and getattr(prof, "interaction_kind", "") == "pt_desktop_cmd"
                    ):
                        cmd = f"ping -n {count} {clean_dest}"
                    else:
                        cmd = f"ping {clean_dest} repeat {count}"
                res = self.console.execute_commands(
                    device_name=source,
                    commands=[cmd],
                    target_mode="preserve",
                )
                output_text = self._extract_command_output(res, cmd)
                summary = parse_ping_output(output_text, target_ip=clean_dest)
                evidence.append(
                    f"Executed '{cmd}' on live console of {source}: "
                    f"received={summary.received}/{summary.transmitted}, "
                    f"loss={summary.loss_percent}%."
                )
                report = ConnectivityCheckReport(
                    source_device=source,
                    destination_ip=clean_dest,
                    protocol=PDUProtocol.ICMP,
                    simulation_source=SimulationSource.PACKET_TRACER_CLI,
                    verified_in_pt=True,
                    state_level=StateLevel.VERIFIED,
                    reachable=summary.reached,
                    ping_summary=summary,
                    evidence=evidence,
                    warnings=warnings,
                )
                return report.model_dump(mode="json")
            except Exception as exc:
                warnings.append(f"Live CLI ping on '{source}' failed: {exc}")

        # Offline / Topology Graph Path Analysis Fallback
        if topology is not None and allow_offline_estimation:
            if source not in topology.model.devices:
                raise DeviceNotFoundError(f"Source device '{source}' not found in topology.")

            # Identify target device matching destination_ip across topology node interfaces
            target_device_name: str | None = None
            for d_name, dev in topology.model.devices.items():
                for iface in dev.interfaces.values():
                    if iface.ipv4_address == clean_dest:
                        target_device_name = d_name
                        break
                if target_device_name:
                    break

            hops: list[str] = []
            reachable = False
            if target_device_name:
                try:
                    hops = nx.shortest_path(
                        topology.graph, source=source, target=target_device_name
                    )
                    reachable = len(hops) > 0
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    reachable = False
                evidence.append(
                    f"Analyzed topology graph reachability from {source} to "
                    f"{target_device_name} ({clean_dest}): hops={hops}."
                )
            else:
                warnings.append(
                    f"Destination IP {clean_dest} is not assigned to any known topology device."
                )

            warnings.append(
                "Result based on offline topology graph validation; "
                "NOT live Packet Tracer execution."
            )
            report = ConnectivityCheckReport(
                source_device=source,
                destination_ip=clean_dest,
                protocol=PDUProtocol.ICMP,
                simulation_source=SimulationSource.OFFLINE_TOPOLOGY_CHECK,
                verified_in_pt=False,
                state_level=StateLevel.PLANNED,
                reachable=reachable,
                path_hops=hops,
                evidence=evidence,
                warnings=warnings,
            )
            return report.model_dump(mode="json")

        raise AgenticNetError(
            f"Cannot run connectivity check from '{source}' to {clean_dest}: "
            "no live console attached and topology estimation disabled.",
            error_code="CONNECTIVITY_CHECK_UNAVAILABLE",
            remediation="Attach a live console transport or provide active topology model.",
        )

    def inspect_routing_table(self, device_name: str) -> dict[str, Any]:
        """Fetch and parse `show ip route` from a live or seeded device console."""
        if not self.console or not self.console.transport.is_available():
            return {
                "device_name": device_name,
                "routes": [],
                "gateway_of_last_resort": None,
                "state_level": StateLevel.PLANNED.value,
                "evidence": ["Console transport offline; no live routing table captured."],
            }

        res = self.console.execute_commands(
            device_name=device_name,
            commands=["show ip route"],
            target_mode="privileged_exec",
        )
        raw = self._extract_command_output(res, "show ip route")
        parsed = parse_show_ip_route(raw)
        routes: list[ParsedRouteEntry] = parsed.get("routes", [])  # type: ignore[assignment]
        return {
            "device_name": device_name,
            "routes": [r.model_dump(mode="json") for r in routes],
            "gateway_of_last_resort": parsed.get("gateway_of_last_resort"),
            "state_level": StateLevel.VERIFIED.value,
            "evidence": [f"Parsed {len(routes)} route(s) from 'show ip route'."],
        }

    def inspect_arp_table(self, device_name: str) -> dict[str, Any]:
        """Fetch and parse `show arp` from a device console."""
        if not self.console or not self.console.transport.is_available():
            return {
                "device_name": device_name,
                "arp_entries": [],
                "state_level": StateLevel.PLANNED.value,
            }

        res = self.console.execute_commands(
            device_name=device_name,
            commands=["show arp"],
            target_mode="privileged_exec",
        )
        raw = self._extract_command_output(res, "show arp")
        entries: list[ParsedArpEntry] = parse_show_arp(raw)
        return {
            "device_name": device_name,
            "arp_entries": [e.model_dump(mode="json") for e in entries],
            "state_level": StateLevel.VERIFIED.value,
            "evidence": [f"Parsed {len(entries)} ARP mapping(s)."],
        }

    def inspect_interface_status(self, device_name: str) -> dict[str, Any]:
        """Fetch and parse `show ip interface brief` from a device console."""
        if not self.console or not self.console.transport.is_available():
            return {
                "device_name": device_name,
                "interfaces": [],
                "state_level": StateLevel.PLANNED.value,
            }

        res = self.console.execute_commands(
            device_name=device_name,
            commands=["show ip interface brief"],
            target_mode="privileged_exec",
        )
        raw = self._extract_command_output(res, "show ip interface brief")
        rows: list[ParsedInterfaceBrief] = parse_show_ip_int_brief(raw)
        return {
            "device_name": device_name,
            "interfaces": [r.model_dump(mode="json") for r in rows],
            "state_level": StateLevel.VERIFIED.value,
            "evidence": [f"Parsed {len(rows)} interface status line(s)."],
        }

    def inspect_vlan_status(self, device_name: str) -> dict[str, Any]:
        """Fetch and parse `show vlan brief` from a switch console."""
        if not self.console or not self.console.transport.is_available():
            return {
                "device_name": device_name,
                "vlans": [],
                "state_level": StateLevel.PLANNED.value,
            }

        res = self.console.execute_commands(
            device_name=device_name,
            commands=["show vlan brief"],
            target_mode="privileged_exec",
        )
        raw = self._extract_command_output(res, "show vlan brief")
        vlans: list[ParsedVlanEntry] = parse_show_vlan_brief(raw)
        return {
            "device_name": device_name,
            "vlans": [v.model_dump(mode="json") for v in vlans],
            "state_level": StateLevel.VERIFIED.value,
            "evidence": [f"Parsed {len(vlans)} VLAN definition(s)."],
        }

    def inspect_ospf_neighbors(self, device_name: str) -> dict[str, Any]:
        """Fetch and parse `show ip ospf neighbor` from a router console."""
        if not self.console or not self.console.transport.is_available():
            return {
                "device_name": device_name,
                "neighbors": [],
                "state_level": StateLevel.PLANNED.value,
            }

        res = self.console.execute_commands(
            device_name=device_name,
            commands=["show ip ospf neighbor"],
            target_mode="privileged_exec",
        )
        raw = self._extract_command_output(res, "show ip ospf neighbor")
        nbrs: list[ParsedOspfNeighbor] = parse_show_ip_ospf_neighbor(raw)
        return {
            "device_name": device_name,
            "neighbors": [n.model_dump(mode="json") for n in nbrs],
            "state_level": StateLevel.VERIFIED.value,
            "evidence": [f"Parsed {len(nbrs)} OSPF neighbor(s)."],
        }
