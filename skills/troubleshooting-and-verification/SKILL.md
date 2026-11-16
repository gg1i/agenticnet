---
name: troubleshooting-and-verification
description: >-
  Evidence-based 10-step network troubleshooting methodology, AgenticNet automated
  diagnostics, declarative verify_lab checks, and Packet Tracer root-cause
  isolation.
---

# Troubleshooting and Verification

Diagnose network failures systematically from observed evidence and verify every fix against live Packet Tracer state.

## 1. Evidence-Based Troubleshooting Workflow (10 Steps)

1. **Define symptoms** (exact failing source, destination, protocol/port, error message).
2. **Identify affected devices and path** (`list_devices`, `topology_inspect`).
3. **Establish expected behavior** (expected L1/L2 state, VLAN/trunk path, routes, NAT, ACLs).
4. **Generate ranked hypotheses** (never apply random edits).
5. **Gather raw diagnostic evidence** via `console_capture` / `console_execute` / `interface_status(live=True)` / `connectivity_test`.
6. **Test hypotheses bottom-up (OSI Layers 1 -> 3 -> 4/7):**
   - *L1/L2:* `show ip interface brief` (`up/up` vs `administratively down` vs `down/down`), `show vlan brief`, `show interfaces trunk`, `show spanning-tree`.
   - *L3 Addressing & Gateway:* `show arp`, host `ipconfig`, subnet mask and gateway alignment.
   - *L3 Routing:* `show ip route`, `show ip ospf neighbor`, `show ip eigrp neighbors`.
   - *Services & Security:* `show ip dhcp binding`, `show ip dhcp pool`, `show ip nat translations`, `show access-lists`, `show telephony-service`, `show ephone`.
7. **Isolate the root cause** with supporting CLI lines.
8. **Design the smallest safe correction** (prefer non-disruptive fixes like `no shutdown`; request confirmation for disruptive IP/link/ACL changes).
9. **Backup and apply** (`configuration_backup` -> `console_execute` or `host_configure`, or `network_repair_propose`/`execute` in `advanced`).
10. **Verify end-to-end** (`verify_lab`, `lab_status`, `connectivity_test`).

## 2. Automated AgenticNet Diagnostics (`advanced` & Core Rules)

- `DiagnosticsEngine` (`network_diagnose`, `vlan_diagnose`, `interface_diagnose` in `advanced`) checks topology/IPAM state for:
  - `INTERFACE_ADMIN_DOWN_WITH_IP` (missing `no shutdown`),
  - `HOST_MISSING_DEFAULT_GATEWAY` & `HOST_GATEWAY_OUTSIDE_SUBNET`,
  - `LINK_SUBNET_MISMATCH` (connected endpoints in different subnets),
  - `NATIVE_VLAN_MISMATCH` & `TRUNK_MODE_MISMATCH` (trunk vs access mismatch between switches).

## 3. Declarative Verification (`verify_lab` & `lab_status`)

Call `verify_requirements_schema` to inspect exact JSON formats for all `9` supported requirement types:
- `interface_up`, `ip_assigned`, `route_exists`, `vlan_exists`, `dhcp_binding`, `reachable` (`from`/`to`), `config_contains` (supports `section` and `must_not_contain`), `telephony_service`, `ephone_registered`.
- Attach `task_ids` to every requirement and loop on `lab_status(requirements=..., task_ids=...)` until `overall_passed == True`, `task_coverage.all_tasks_covered == True`, and (when `.pka` grading is readable) `grade.percentage_complete == 100.0`.
- Remember: offline `connectivity_test` falls back to `offline_topology_check` (`state_level="planned"`)—only report reachability as verified when `verified_in_pt == True` (`state_level="verified"`).
