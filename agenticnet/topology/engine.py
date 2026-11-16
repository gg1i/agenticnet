"""NetworkX-backed topology engine for building, validating, analyzing, and visualizing networks."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import networkx as nx
import yaml

from agenticnet.core.enums import CableType, DeviceCategory, PortMedia, StateLevel
from agenticnet.core.exceptions import (
    DeviceNotFoundError,
    InterfaceError,
    TopologyConflictError,
    ValidationError,
)
from agenticnet.devices import DEFAULT_CATALOG, DeviceCatalog
from agenticnet.security.validation import validate_device_name
from agenticnet.topology.models import (
    DeviceNode,
    InterfaceState,
    LinkEdge,
    Position2D,
    TopologyAnalysis,
    TopologyModel,
    TopologyValidationIssue,
)

_COPPER_ETHERNET_MEDIA: set[PortMedia] = {
    PortMedia.FAST_ETHERNET,
    PortMedia.GIGABIT_ETHERNET,
    PortMedia.TEN_GIGABIT_ETHERNET,
}

# MDI devices transmit on pins 1-2 (Routers, Hosts, Wireless Router Internet port).
_MDI_CATEGORIES: set[DeviceCategory] = {
    DeviceCategory.ROUTER,
    DeviceCategory.PC,
    DeviceCategory.LAPTOP,
    DeviceCategory.SERVER,
    DeviceCategory.PRINTER,
}

# MDI-X devices transmit on pins 3-6 (Switches, Access Points).
_MDIX_CATEGORIES: set[DeviceCategory] = {
    DeviceCategory.L2_SWITCH,
    DeviceCategory.L3_SWITCH,
    DeviceCategory.ACCESS_POINT,
}


def _is_mdi_endpoint(category: DeviceCategory, interface_name: str) -> bool:
    """Determine whether an Ethernet port uses MDI (host/router) or MDI-X (switch) pinout."""
    if category == DeviceCategory.WIRELESS_ROUTER:
        return interface_name.lower() == "internet"
    return category in _MDI_CATEGORIES


class TopologyEngine:
    """Maintains a normalized NetworkX MultiGraph topology synchronized with Pydantic models."""

    def __init__(
        self,
        model: TopologyModel | None = None,
        *,
        catalog: DeviceCatalog | None = None,
    ) -> None:
        self.catalog = catalog or DEFAULT_CATALOG
        self.model = model.model_copy(deep=True) if model else TopologyModel()
        self._graph: nx.MultiGraph = nx.MultiGraph()
        self._rebuild_graph()

    def _rebuild_graph(self) -> None:
        """Synchronize internal NetworkX graph from the Pydantic TopologyModel."""
        self._graph.clear()
        for dev_name, dev in self.model.devices.items():
            self._graph.add_node(dev_name, model=dev.model, category=dev.category.value)
        for conn_id, link in self.model.connections.items():
            self._graph.add_edge(
                link.source_device,
                link.target_device,
                key=conn_id,
                connection_id=conn_id,
                source_interface=link.source_interface,
                target_interface=link.target_interface,
                cable_type=link.cable_type.value,
            )

    @property
    def graph(self) -> nx.MultiGraph:
        """Access the underlying NetworkX graph structure."""
        return self._graph

    def _next_default_position(self, category: DeviceCategory) -> Position2D:
        """Pick a non-overlapping default canvas coordinate grouped by device layer."""
        tier_y = {
            DeviceCategory.ROUTER: 120.0,
            DeviceCategory.WIRELESS_ROUTER: 120.0,
            DeviceCategory.L3_SWITCH: 260.0,
            DeviceCategory.L2_SWITCH: 400.0,
            DeviceCategory.ACCESS_POINT: 400.0,
            DeviceCategory.SERVER: 540.0,
            DeviceCategory.PC: 540.0,
            DeviceCategory.LAPTOP: 540.0,
            DeviceCategory.PRINTER: 540.0,
        }.get(category, 300.0)
        same_tier_count = sum(
            1 for d in self.model.devices.values() if abs(d.position.y - tier_y) < 40.0
        )
        return Position2D(
            x=120.0 + (same_tier_count % 8) * 140.0, y=tier_y + (same_tier_count // 8) * 90.0
        )

    def add_device(
        self,
        name: str,
        model_name: str,
        *,
        x: float | None = None,
        y: float | None = None,
        role: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> DeviceNode:
        """Add a device from the verified DeviceCatalog with populated interfaces."""
        clean_name = validate_device_name(name)
        if clean_name in self.model.devices:
            raise TopologyConflictError(
                f"Device '{clean_name}' already exists in the topology.",
                details={"device_name": clean_name},
                remediation="Choose a unique device hostname or inspect the existing device.",
            )

        profile = self.catalog.get_profile(model_name)
        pos = (
            Position2D(x=x, y=y)
            if x is not None and y is not None
            else self._next_default_position(profile.category)
        )
        interfaces = {
            tmpl.name: InterfaceState(
                name=tmpl.name,
                short_name=tmpl.short_name,
                media=tmpl.media,
                speed_mbps=tmpl.speed_mbps,
                admin_up=True,
                state_level=StateLevel.PLANNED,
            )
            for tmpl in profile.interfaces
        }
        node = DeviceNode(
            name=clean_name,
            model=profile.model,
            category=profile.category,
            role=role,
            position=pos,
            interfaces=interfaces,
            state_level=StateLevel.PLANNED,
            metadata=metadata or {},
        )
        self.model.devices[clean_name] = node
        self._graph.add_node(clean_name, model=profile.model, category=profile.category.value)
        return node

    def get_device(self, name: str) -> DeviceNode:
        """Return a device node or raise DeviceNotFoundError."""
        node = self.model.devices.get(name)
        if node is None:
            raise DeviceNotFoundError(
                f"Device '{name}' does not exist in the active topology.",
                details={"device_name": name, "known_devices": sorted(self.model.devices)},
                remediation="Use device_list to see available devices or device_add to create it.",
            )
        return node

    def remove_device(self, name: str) -> dict[str, Any]:
        """Remove a device and clean up all connected links."""
        self.get_device(name)
        removed_connections = [
            conn_id
            for conn_id, link in list(self.model.connections.items())
            if link.source_device == name or link.target_device == name
        ]
        for conn_id in removed_connections:
            self.remove_connection(conn_id)

        del self.model.devices[name]
        if self._graph.has_node(name):
            self._graph.remove_node(name)
        return {"removed_device": name, "removed_connections": removed_connections}

    def move_device(self, name: str, x: float, y: float) -> DeviceNode:
        """Move a device visually to new Logical Workspace coordinates."""
        if x < 0 or y < 0:
            raise ValidationError(
                "Canvas coordinates (x, y) must be non-negative.",
                details={"x": x, "y": y},
            )
        node = self.get_device(name)
        node.position = Position2D(x=x, y=y)
        return node

    def _resolve_physical_interface(
        self, device: DeviceNode, interface_name: str
    ) -> InterfaceState:
        canonical = self.catalog.normalize_interface_name(
            device.model, interface_name, allow_logical=False
        )
        iface = device.interfaces.get(canonical)
        if iface is None:
            raise InterfaceError(
                f"Interface '{canonical}' was not found on '{device.name}'.",
                details={"device": device.name, "interface": canonical},
            )
        return iface

    @staticmethod
    def _select_cable_type(
        src_dev: DeviceNode,
        src_iface: InterfaceState,
        dst_dev: DeviceNode,
        dst_iface: InterfaceState,
        requested: CableType | None,
    ) -> CableType:
        """Validate or automatically choose the correct Packet Tracer cable type."""
        src_media = src_iface.media
        dst_media = dst_iface.media

        # Media compatibility checks
        if src_media == PortMedia.WIRELESS or dst_media == PortMedia.WIRELESS:
            raise TopologyConflictError(
                "Wireless interfaces cannot be linked with physical wired cables.",
                details={"source_media": src_media.value, "target_media": dst_media.value},
                remediation="Associate wireless clients via SSID instead of wired links.",
            )

        both_serial = src_media == PortMedia.SERIAL and dst_media == PortMedia.SERIAL
        both_fiber = src_media == PortMedia.FIBER and dst_media == PortMedia.FIBER
        both_copper_eth = (
            src_media in _COPPER_ETHERNET_MEDIA and dst_media in _COPPER_ETHERNET_MEDIA
        )

        if not (both_serial or both_fiber or both_copper_eth):
            raise TopologyConflictError(
                f"Incompatible interface media: {src_dev.name}:{src_iface.name} "
                f"({src_media.value}) cannot connect to {dst_dev.name}:{dst_iface.name} "
                f"({dst_media.value}).",
                details={"source_media": src_media.value, "target_media": dst_media.value},
                remediation="Connect matching media (Ethernet-Ethernet or Serial-Serial).",
            )

        if requested is None or requested == CableType.AUTO:
            if both_serial:
                return CableType.SERIAL_DCE
            if both_fiber:
                return CableType.FIBER
            src_mdi = _is_mdi_endpoint(src_dev.category, src_iface.name)
            dst_mdi = _is_mdi_endpoint(dst_dev.category, dst_iface.name)
            return CableType.CROSSOVER if src_mdi == dst_mdi else CableType.STRAIGHT_THROUGH

        # Explicit cable validation
        if requested in {CableType.SERIAL_DCE, CableType.SERIAL_DTE} and not both_serial:
            raise TopologyConflictError(
                f"Cable type '{requested.value}' requires Serial interfaces on both endpoints.",
                details={"source_media": src_media.value, "target_media": dst_media.value},
            )
        if requested in {CableType.STRAIGHT_THROUGH, CableType.CROSSOVER} and not both_copper_eth:
            raise TopologyConflictError(
                f"Ethernet cable '{requested.value}' requires copper Ethernet interfaces.",
                details={"source_media": src_media.value, "target_media": dst_media.value},
            )
        if requested == CableType.FIBER and not both_fiber:
            raise TopologyConflictError(
                "Fiber cable requires fiber interfaces on both endpoints.",
                details={"source_media": src_media.value, "target_media": dst_media.value},
            )
        return requested

    def connect(
        self,
        source_device: str,
        source_interface: str,
        target_device: str,
        target_interface: str,
        *,
        cable_type: CableType | str | None = None,
        clock_rate: int | None = None,
        notes: str = "",
    ) -> LinkEdge:
        """Connect two unoccupied, media-compatible interfaces."""
        if source_device == target_device:
            raise TopologyConflictError(
                f"Cannot connect device '{source_device}' to itself.",
                details={"device": source_device},
            )

        src_dev = self.get_device(source_device)
        dst_dev = self.get_device(target_device)
        src_iface = self._resolve_physical_interface(src_dev, source_interface)
        dst_iface = self._resolve_physical_interface(dst_dev, target_interface)

        if src_iface.connected_to_connection_id is not None:
            raise InterfaceError(
                f"Interface {src_dev.name}:{src_iface.name} is already occupied "
                f"(connected to {src_iface.peer_device}:{src_iface.peer_interface}).",
                details={
                    "device": src_dev.name,
                    "interface": src_iface.name,
                    "existing_connection_id": src_iface.connected_to_connection_id,
                },
                remediation="Choose a free interface or remove the existing connection first.",
            )
        if dst_iface.connected_to_connection_id is not None:
            raise InterfaceError(
                f"Interface {dst_dev.name}:{dst_iface.name} is already occupied "
                f"(connected to {dst_iface.peer_device}:{dst_iface.peer_interface}).",
                details={
                    "device": dst_dev.name,
                    "interface": dst_iface.name,
                    "existing_connection_id": dst_iface.connected_to_connection_id,
                },
                remediation="Choose a free interface or remove the existing connection first.",
            )

        parsed_cable = CableType(cable_type) if isinstance(cable_type, str) else cable_type
        resolved_cable = self._select_cable_type(
            src_dev, src_iface, dst_dev, dst_iface, parsed_cable
        )

        dce_side: str | None = None
        resolved_clock = clock_rate
        if resolved_cable == CableType.SERIAL_DCE:
            dce_side = "source"
            resolved_clock = resolved_clock or 64000
        elif resolved_cable == CableType.SERIAL_DTE:
            dce_side = "target"
            resolved_clock = resolved_clock or 64000

        conn_id = f"link_{uuid4().hex[:10]}"
        edge = LinkEdge(
            connection_id=conn_id,
            source_device=src_dev.name,
            source_interface=src_iface.name,
            target_device=dst_dev.name,
            target_interface=dst_iface.name,
            cable_type=resolved_cable,
            dce_side=dce_side,
            clock_rate=resolved_clock,
            state_level=StateLevel.PLANNED,
            notes=notes,
        )
        self.model.connections[conn_id] = edge

        src_iface.connected_to_connection_id = conn_id
        src_iface.peer_device = dst_dev.name
        src_iface.peer_interface = dst_iface.name
        dst_iface.connected_to_connection_id = conn_id
        dst_iface.peer_device = src_dev.name
        dst_iface.peer_interface = src_iface.name

        self._graph.add_edge(
            src_dev.name,
            dst_dev.name,
            key=conn_id,
            connection_id=conn_id,
            source_interface=src_iface.name,
            target_interface=dst_iface.name,
            cable_type=resolved_cable.value,
        )
        return edge

    def remove_connection(self, connection_id: str) -> LinkEdge:
        """Remove a link and clear endpoint interface occupancy state."""
        edge = self.model.connections.get(connection_id)
        if edge is None:
            raise TopologyConflictError(
                f"Connection '{connection_id}' does not exist.",
                details={"connection_id": connection_id},
            )

        src_dev = self.model.devices.get(edge.source_device)
        if src_dev and edge.source_interface in src_dev.interfaces:
            iface = src_dev.interfaces[edge.source_interface]
            iface.connected_to_connection_id = None
            iface.peer_device = None
            iface.peer_interface = None

        dst_dev = self.model.devices.get(edge.target_device)
        if dst_dev and edge.target_interface in dst_dev.interfaces:
            iface = dst_dev.interfaces[edge.target_interface]
            iface.connected_to_connection_id = None
            iface.peer_device = None
            iface.peer_interface = None

        del self.model.connections[connection_id]
        if self._graph.has_edge(edge.source_device, edge.target_device, key=connection_id):
            self._graph.remove_edge(edge.source_device, edge.target_device, key=connection_id)
        return edge

    def auto_layout(self, strategy: str = "hierarchical") -> dict[str, Position2D]:
        """Compute clean non-overlapping canvas coordinates for all devices."""
        if not self.model.devices:
            return {}

        if strategy == "grid":
            cols = max(1, min(6, len(self.model.devices)))
            for idx, dev_name in enumerate(sorted(self.model.devices)):
                row, col = divmod(idx, cols)
                self.model.devices[dev_name].position = Position2D(
                    x=100.0 + col * 160.0, y=100.0 + row * 140.0
                )
        elif strategy == "hierarchical":
            tiers: list[list[str]] = [[], [], [], []]
            for dev_name in sorted(self.model.devices):
                cat = self.model.devices[dev_name].category
                if cat in {DeviceCategory.ROUTER, DeviceCategory.WIRELESS_ROUTER}:
                    tiers[0].append(dev_name)
                elif cat == DeviceCategory.L3_SWITCH:
                    tiers[1].append(dev_name)
                elif cat in {DeviceCategory.L2_SWITCH, DeviceCategory.ACCESS_POINT}:
                    tiers[2].append(dev_name)
                else:
                    tiers[3].append(dev_name)

            y_cursor = 100.0
            for tier_devices in tiers:
                if not tier_devices:
                    continue
                total_width = max(1, len(tier_devices) - 1) * 150.0
                start_x = max(100.0, 560.0 - total_width / 2.0)
                for idx, dev_name in enumerate(tier_devices):
                    self.model.devices[dev_name].position = Position2D(
                        x=round(start_x + idx * 150.0, 1),
                        y=y_cursor,
                    )
                y_cursor += 150.0
        else:
            raise ValidationError(
                f"Unknown layout strategy {strategy!r}. Use 'hierarchical' or 'grid'."
            )

        return {name: dev.position for name, dev in self.model.devices.items()}

    def validate(self) -> list[TopologyValidationIssue]:
        """Validate topology integrity, cable rules, serial clocking, and switching loops."""
        issues: list[TopologyValidationIssue] = []

        if not self.model.devices:
            issues.append(
                TopologyValidationIssue(
                    severity="warning",
                    code="EMPTY_TOPOLOGY",
                    message="Topology currently has no devices.",
                    remediation="Add devices using device_add or topology_create.",
                )
            )
            return issues

        isolated = [n for n, deg in self._graph.degree() if deg == 0]
        if isolated:
            issues.append(
                TopologyValidationIssue(
                    severity="warning",
                    code="ISOLATED_DEVICES",
                    message=f"{len(isolated)} device(s) have no physical connections.",
                    affected_devices=sorted(isolated),
                    remediation="Connect isolated devices using connection_create.",
                )
            )

        for conn_id, link in self.model.connections.items():
            src_dev = self.model.devices.get(link.source_device)
            dst_dev = self.model.devices.get(link.target_device)
            if src_dev is None or dst_dev is None:
                issues.append(
                    TopologyValidationIssue(
                        severity="error",
                        code="DANGLING_LINK",
                        message=f"Connection '{conn_id}' references missing device.",
                        affected_connections=[conn_id],
                    )
                )
                continue

            src_iface = src_dev.interfaces.get(link.source_interface)
            dst_iface = dst_dev.interfaces.get(link.target_interface)
            if src_iface and not src_iface.admin_up:
                issues.append(
                    TopologyValidationIssue(
                        severity="warning",
                        code="ADMIN_DOWN_ENDPOINT",
                        message=f"Port {src_dev.name}:{src_iface.name} is administratively down.",
                        affected_devices=[src_dev.name],
                        affected_connections=[conn_id],
                    )
                )
            if dst_iface and not dst_iface.admin_up:
                issues.append(
                    TopologyValidationIssue(
                        severity="warning",
                        code="ADMIN_DOWN_ENDPOINT",
                        message=f"Port {dst_dev.name}:{dst_iface.name} is administratively down.",
                        affected_devices=[dst_dev.name],
                        affected_connections=[conn_id],
                    )
                )

            if (
                link.cable_type in {CableType.SERIAL_DCE, CableType.SERIAL_DTE}
                and not link.clock_rate
            ):
                issues.append(
                    TopologyValidationIssue(
                        severity="warning",
                        code="MISSING_SERIAL_CLOCK_RATE",
                        message=f"Serial link '{conn_id}' lacks DCE clock_rate.",
                        affected_connections=[conn_id],
                    )
                )

        # Detect Layer 2 switching cycles that rely on STP
        switch_nodes = [
            name
            for name, dev in self.model.devices.items()
            if dev.category in {DeviceCategory.L2_SWITCH, DeviceCategory.L3_SWITCH}
        ]
        if len(switch_nodes) >= 3:
            simple_sw = nx.Graph(self._graph.subgraph(switch_nodes))
            cycles = nx.cycle_basis(simple_sw)
            for cycle in cycles:
                issues.append(
                    TopologyValidationIssue(
                        severity="info",
                        code="SWITCHING_LOOP_DETECTED",
                        message=(
                            f"Redundant Layer 2 loop detected among switches {cycle}; "
                            "ensure Rapid-PVST+ STP root bridge priority is configured."
                        ),
                        affected_devices=cycle,
                    )
                )

        return issues

    def analyze(self, *, source: str | None = None, target: str | None = None) -> TopologyAnalysis:
        """Compute graph topology metrics using NetworkX."""
        simple_graph = nx.Graph(self._graph)
        components = nx.number_connected_components(simple_graph) if simple_graph.nodes else 0
        isolated = sorted(n for n, deg in self._graph.degree() if deg == 0)
        bridges = sorted((min(u, v), max(u, v)) for u, v in nx.bridges(simple_graph))
        articulation = sorted(nx.articulation_points(simple_graph))

        switch_nodes = [
            name
            for name, dev in self.model.devices.items()
            if dev.category in {DeviceCategory.L2_SWITCH, DeviceCategory.L3_SWITCH}
        ]
        switching_cycles = nx.cycle_basis(nx.Graph(self._graph.subgraph(switch_nodes)))

        shortest: list[str] | None = None
        if source is not None and target is not None:
            self.get_device(source)
            self.get_device(target)
            try:
                shortest = nx.shortest_path(simple_graph, source=source, target=target)
            except nx.NetworkXNoPath:
                shortest = []

        return TopologyAnalysis(
            device_count=len(self.model.devices),
            connection_count=len(self.model.connections),
            connected_components=components,
            isolated_devices=isolated,
            bridges=bridges,
            articulation_points=articulation,
            switching_cycles=switching_cycles,
            degree_by_device={n: int(d) for n, d in sorted(self._graph.degree())},
            shortest_path=shortest,
        )

    def to_mermaid(self) -> str:
        """Render the current topology as a Mermaid flowchart diagram."""
        lines = ["flowchart LR"]
        for name in sorted(self.model.devices):
            dev = self.model.devices[name]
            safe_id = name.replace("-", "_").replace(".", "_")
            lines.append(f'    {safe_id}["{dev.name} ({dev.model})"]')
        for conn_id in sorted(self.model.connections):
            link = self.model.connections[conn_id]
            s_id = link.source_device.replace("-", "_").replace(".", "_")
            t_id = link.target_device.replace("-", "_").replace(".", "_")
            lines.append(
                f'    {s_id} ---|"{link.source_interface} <-> {link.target_interface} '
                f'[{link.cable_type.value}]"| {t_id}'
            )
        return "\n".join(lines)

    def to_ascii(self) -> str:
        """Render a concise ASCII adjacency summary."""
        if not self.model.devices:
            return "(empty topology)"
        lines = [
            f"Topology: {len(self.model.devices)} devices, {len(self.model.connections)} links"
        ]
        for name in sorted(self.model.devices):
            dev = self.model.devices[name]
            connected = [
                f"{iface.short_name}->{iface.peer_device}:{iface.peer_interface}"
                for iface in dev.interfaces.values()
                if iface.peer_device
            ]
            links_txt = ", ".join(connected) if connected else "no links"
            lines.append(
                f"  - {dev.name} [{dev.model} | {dev.category.value}] "
                f"@({dev.position.x:.0f},{dev.position.y:.0f}): {links_txt}"
            )
        return "\n".join(lines)

    def export_data(self, fmt: str = "json") -> str:
        """Serialize topology model to JSON or YAML."""
        payload = self.model.model_dump(mode="json")
        fmt_lower = fmt.strip().lower()
        if fmt_lower == "json":
            return json.dumps(payload, indent=2)
        if fmt_lower in {"yaml", "yml"}:
            return yaml.safe_dump(payload, sort_keys=False)
        raise ValidationError(f"Unsupported export format {fmt!r}. Use 'json' or 'yaml'.")

    @classmethod
    def from_exported_data(
        cls,
        raw_data: str,
        *,
        fmt: str = "auto",
        catalog: DeviceCatalog | None = None,
    ) -> TopologyEngine:
        """Load and validate a TopologyEngine from JSON or YAML text."""
        fmt_lower = fmt.strip().lower()
        if fmt_lower == "auto":
            parsed = (
                json.loads(raw_data)
                if raw_data.lstrip().startswith("{")
                else yaml.safe_load(raw_data)
            )
        elif fmt_lower == "json":
            parsed = json.loads(raw_data)
        elif fmt_lower in {"yaml", "yml"}:
            parsed = yaml.safe_load(raw_data)
        else:
            raise ValidationError(f"Unsupported import format {fmt!r}.")

        model = TopologyModel.model_validate(parsed)
        return cls(model=model, catalog=catalog)
