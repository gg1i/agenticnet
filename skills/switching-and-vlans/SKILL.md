---
name: switching-and-vlans
description: >-
  Cisco Catalyst VLAN, 802.1Q trunking, Router-on-a-Stick vs L3 SVI routing,
  Rapid-PVST+ STP, EtherChannel, and L2 management configuration rules for
  Packet Tracer 8.2.2+.
---

# Switching and VLANs

Design and configure deterministic Layer 2 and multilayer switching in Cisco Packet Tracer without platform syntax traps.

## 1. VLAN & Access Port Standards

- Create VLANs explicitly with meaningful names (`vlan 10` / `name USERS`) before assigning ports, especially when validating `show vlan brief`.
- Configure host-facing ports explicitly as access ports:
  ```ios
  interface FastEthernet0/1
   switchport mode access
   switchport access vlan 10
   spanning-tree portfast
   no shutdown
  ```
- For Cisco `7960` IP Phones sharing an access port with a PC, configure `switchport voice vlan <voice_vlan>` alongside `switchport access vlan <data_vlan>`, and verify phone power via bridge auto-power or `gui_attach_ip_phone_power`.
- L2 switch management (`2960-24TT`, `Switch-PT`): assign management IP to `interface Vlan<mgmt_id>` (`no shutdown`) and configure global `ip default-gateway <gw_ip>` (never `ip routing` on L2 switches).

## 2. 802.1Q Trunking Platform Matrix (Critical)

| Model | `switchport trunk encapsulation dot1q` | Required Order |
|---|---|---|
| `2960-24TT` / `Switch-PT` | **Rejected** (`% Invalid input`) | Omit encap command; use `switchport mode trunk` directly |
| `3560-24PS` / `3650-24PS` | **Required** (`TRUNK_ENCAP_DOT1Q`) | Run `switchport trunk encapsulation dot1q` **before** `switchport mode trunk` |

- Keep **native VLAN** (`switchport trunk native vlan <id>`) and **allowed VLAN list** (`switchport trunk allowed vlan ...`) identical on both ends of every trunk link.
- Never place user access ports or untagged management traffic inconsistently across trunk native VLAN mismatches.

## 3. Inter-VLAN Routing Options

1. **Router-on-a-Stick (ROAS)** (`2911`, `1941`, `2811`, `4321`, `Router-PT`):
   - Keep parent physical interface `no shutdown` with **no IP address**.
   - Create subinterfaces (`interface GigabitEthernet0/0.10`), set `encapsulation dot1Q 10` (add `native` only if matching the switch's native VLAN), then `ip address <gw> <mask>`.
2. **Multilayer L3 Switch** (`3560-24PS`, `3650-24PS`):
   - Enable global `ip routing`.
   - Ensure every SVI's VLAN exists in the VLAN database and at least one active access/trunk port forwards that VLAN so the SVI reaches `up/up`.
   - For routed point-to-point links to an upstream router, convert the switch port with `no switchport` before assigning `ip address`.

## 4. STP & EtherChannel

- Use `spanning-tree mode rapid-pvst` and deterministically anchor root primary (`root primary` / priority `4096`) and secondary (`root secondary` / priority `8192`) on core/distribution switches—never leave root bridge election to lowest MAC luck.
- For **EtherChannel**, match channel-group mode (`active`/`passive` for LACP, `desirable`/`auto` for PAgP, or `on`), speed/duplex, trunk encapsulation, native VLAN, and allowed VLANs across all member ports, then apply trunk/access settings to `interface Port-channel<id>`.

## 5. Verification Checklist

- `show vlan brief` (or `verify_lab` `vlan_exists`) -> VLANs active and ports mapped.
- `show interfaces trunk` -> operational mode `on`/`trunking`, `802.1q`, matching native and allowed VLANs.
- `show spanning-tree summary` / `show spanning-tree vlan <id>` -> expected root bridge.
- `show etherchannel summary` -> `SU` (Layer 2) or `RU` (Layer 3) and `P` flags on member ports.
