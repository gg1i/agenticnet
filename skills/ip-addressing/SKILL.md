---
name: ip-addressing
description: >-
  IPv4 and IPv6 CIDR subnetting, largest-first VLSM allocation, gateway and
  DHCP range planning, and IPAM conflict validation in NetForge MCP.
---

# IP Addressing & VLSM Design

Produce conflict-free, deterministic addressing plans before configuring interfaces or DHCP pools.

## 1. Addressing Workflow

1. **Calculate Subnets Deterministically:**
   - Call `subnet_calculate(cidr=...)` (available in both `solve_lab` and `advanced`) to verify `network_address`, `netmask`, `wildcard_mask`, `broadcast_address`, `usable_hosts`, `first_usable`, and `last_usable`. Never do mental binary math for non-trivial prefixes.
2. **VLSM Allocation (`vlsm_plan` in `advanced`, or manual `subnet_calculate` loop in `solve_lab`):**
   - **Always sort requirements largest-to-smallest** (host count descending) and allocate aligned power-of-2 blocks so subnets never overlap.
   - Account for router/SVI gateway + reserved servers/printers when sizing `required_hosts`:
     - `/24` -> `254` usable hosts
     - `/25` -> `126` usable hosts
     - `/26` -> `62` usable hosts
     - `/27` -> `30` usable hosts
     - `/28` -> `14` usable hosts
     - `/29` -> `6` usable hosts
     - `/30` -> `2` usable hosts (standard Cisco point-to-point transit links; avoid `/31` unless hardware/PT IOS build explicitly supports RFC 3021).
3. **Standard Address Assignment Convention:**
   - **Default Gateways (Router / SVI):** Consistently assign `first_usable` (e.g. `.1`) or `last_usable` across the entire lab.
   - **Infrastructure / Switches / Servers:** Reserve a contiguous low block (e.g., `.1`–`.10`) via `ip dhcp excluded-address <start> <end>` before defining DHCP pools.
   - **Loopbacks (`Loopback0`):** Use `/32` host masks (`255.255.255.255`) from a dedicated loopback supernet for OSPF router IDs and management.
   - **Point-to-Point Links:** Use dedicated `/30` blocks (never reuse LAN subnets on WAN/transit links).

## 2. IPAM Validation & Host Configuration

- **In `advanced` profile:**
  - Pass `register_pools=True` to `vlsm_plan` to persist pools in project IPAM.
  - Record interface IPs with `address_allocate`, run `address_validate` to catch duplicate IPs, overlapping pools, or out-of-subnet assignments, and export documentation with `ipam_report`.
- **On End Devices (`PC-PT`, `Laptop-PT`, `Server-PT`, `Printer-PT`):**
  - Use `host_configure` with either `dhcp=True` or explicit `ip_address`, `subnet_mask`, and `default_gateway`.
  - Always verify that `default_gateway` lies inside the host's own subnet (`ip & mask == gateway & mask`).

## 3. IPv6 Notes in Packet Tracer

- `subnet_calculate` and `vlsm_plan` support IPv6 prefix calculations.
- NetForge's `IOSGenerator` targets IPv4; if a Packet Tracer lab requires IPv6 (`ipv6 unicast-routing`, `ipv6 address ...`, OSPFv3), push verified commands via `console_execute` and validate with `show ipv6 interface brief` / `show ipv6 route`.
