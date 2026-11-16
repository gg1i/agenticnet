---
name: network-architecture
description: >-
  Campus, branch, and WAN topology design using Cisco hierarchical principles,
  verified Packet Tracer device models, cable-media matching, and graph-based
  SPOF/loop analysis.
---

# Network Architecture

Design clean, scalable, maintainable topologies matched to Packet Tracer capabilities before pushing configurations.

## 1. Design Principles

- **Hierarchical Structure:**
  - *Access Layer:* `2960-24TT` (or `Switch-PT` for tiny labs) connecting end hosts (`PC-PT`, `Laptop-PT`, `Printer-PT`, `7960` IP Phones).
  - *Distribution / Core Layer:* `3560-24PS` or `3650-24PS` (remember `3650-24PS` requires PSU in PT) for L3 SVIs, inter-VLAN routing, and aggregation.
  - *Edge / WAN Layer:* `2911`, `1941`, `2811`, or `4321` routers for WAN serial/Ethernet transit, NAT/PAT, DHCP/CME services, or Router-on-a-Stick when no L3 switch is present.
- **Avoid Unnecessary Complexity:** Use the smallest model set that satisfies port density, speed, and protocol requirements. Always call `device_capabilities` to confirm interface names and protocol flags.
- **Structured Naming & Roles:** Use clear hostnames (`R-EDGE`, `SW-CORE`, `SW-ACC1`, `SRV-WEB`, `PC-ENG1`) and document every device's role and management IP.

## 2. Physical Interconnect & Cable Rules

AgenticNet's `TopologyEngine` validates port availability and media compatibility (`connection_create` with `cable_type="auto"` resolves MDI/MDI-X automatically, or choose explicitly):
- **Straight-through (`straight_through`):** Unlike devices (Host/Router <-> Switch).
- **Crossover (`crossover`):** Like devices (Switch <-> Switch, Router <-> Router, Router <-> Host).
- **Serial (`serial_dce` / `serial_dte`):** Router `Serial` <-> Router `Serial` (`HWIC-2T` on `2911`/`1941`/`2811`); DCE side requires `clock rate` (e.g., `clock rate 64000`).
- **Fiber (`fiber`):** Fiber media endpoints only.
- **Phone (`phone`):** `Home-VOIP-PT` `Phone` <-> `Analog-Phone-PT`; note `7960` uses Ethernet `Switch` port to switchport and `PC` port to `PC-PT` `FastEthernet0`.

## 3. Resilience, Redundancy & Graph Checks

- **In `solve_lab` profile:** Inspect connectivity and ports with `topology_inspect(include_interfaces=True)` and `list_devices`; check for isolated nodes, single-link bottlenecks, and unintended L2 loops manually.
- **In `advanced` profile:**
  - Build topologies atomically with `topology_create`.
  - Run `topology_validate` to flag `EMPTY_TOPOLOGY`, `ISOLATED_DEVICES`, `ADMIN_DOWN_ENDPOINT`, `MISSING_SERIAL_CLOCK_RATE`, and `SWITCHING_LOOP_DETECTED`.
  - Run `topology_analyze` to identify `bridges`, `articulation_points` (single points of failure), `connected_components`, and `switching_cycles`.
  - Export diagrams with `topology_visualize` (Mermaid/ASCII).
- Whenever redundant switch paths exist, explicitly design Rapid-PVST+ root primary/secondary switches or EtherChannel bundles to avoid suboptimal forwarding or broadcast storms.
