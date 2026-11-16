# AgenticNet Engineering Skill Pack

Portable specialist skill modules (`SKILL.md`) for AI network engineers operating through **AgenticNet** and **Cisco Packet Tracer `8.2.2+`**.

## Selective Loading Guide

Load only the skills needed for the active task:

| Skill | Slug | When to Load |
|---|---|---|
| **Senior Network Engineer** | [`senior-network-engineer`](senior-network-engineer/SKILL.md) | End-to-end engineering workflow (Phases A–G), tool selection (`solve_lab` vs `advanced`), state hygiene, change control, and reporting |
| **Packet Tracer Lab Engineer** | [`packet-tracer-lab-engineer`](packet-tracer-lab-engineer/SKILL.md) | Live Packet Tracer `8.2.2` bridge operations (`lab_start`, `lab_open`, `lab_save`, `grade_lab`), copy-on-write safety, and hardware/IOS quirks across all 17 verified models |
| **Network Architecture** | [`network-architecture`](network-architecture/SKILL.md) | Campus/WAN/branch topology design, hierarchical layering, SPOF/cycle analysis, model choice, and cabling rules |
| **IP Addressing** | [`ip-addressing`](ip-addressing/SKILL.md) | IPv4/IPv6 CIDR math, VLSM allocation, P2P `/30` vs `/31` links, gateway/DHCP reservations, and conflict checks |
| **Switching and VLANs** | [`switching-and-vlans`](switching-and-vlans/SKILL.md) | VLAN segmentation, access/voice ports, 802.1Q trunks (`2960-24TT` vs `3560-24PS`/`3650-24PS`), ROAS vs L3 SVI routing, STP, and EtherChannel |
| **Routing** | [`routing`](routing/SKILL.md) | Static/default/floating routes, OSPFv2, EIGRP, RIPv2, wildcard calculations, and PT routing boundaries |
| **IOS Configuration Review** | [`ios-configuration-review`](ios-configuration-review/SKILL.md) | Pre-execution syntax/capability auditing, CLI mode safety, host-vs-IOS separation, snapshots/diffs, and secret redaction |
| **Troubleshooting and Verification** | [`troubleshooting-and-verification`](troubleshooting-and-verification/SKILL.md) | 10-step root-cause methodology, automated diagnostics, `verify_lab` declarative checks, `lab_status` iteration, and live `ping` proof |
| **Network Security Basics** | [`network-security-basics`](network-security-basics/SKILL.md) | Standard/extended ACLs, SSHv2 & management-plane hardening, L2 port security, and untrusted-lab safety rules |

## Profile Awareness

- Default `solve_lab` profile exposes **25** focused tools (`lab_*`, `project_*`, `device_*`, `connection_create`, `interface_status`, `host_configure`, `subnet_calculate`, `console_*`, `configuration_backup`, `connectivity_test`, `verify_*`, `grade_lab`, `gui_attach_ip_phone_power`).
- `AGENTICNET_TOOL_PROFILE=advanced` unlocks all **82** tools (including `vlsm_plan`, `address_*`, `topology_create`/`validate`/`analyze`/`visualize`, `configure_*`, `command_validate`, `network_diagnose`, `network_repair_*`, `simulation_*`, and `gui_*`).
- Every skill explicitly distinguishes tools available in both profiles from `advanced`-only tools.
