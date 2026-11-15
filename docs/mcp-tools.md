# NetForge MCP Tool & Capability Ecosystem

NetForge MCP (`v0.1.0`, schema `1.0.0`) exposes **79 specialized MCP tools** (`22` enabled in default `solve_lab` profile; all `79` in `advanced` profile) organized across 10 functional categories, **7 read-only resources**, and **5 guided AI agent prompts** over `stdio` and HTTP transports.

<!-- Generated counts and tables below are synced by scripts/generate_manifest.py -->

Run `python -m netforge manifest` or read `netforge://manifest` for the live machine-readable JSON schema.

---

## 1. Tool Categories (79 Tools Total / 22 Default `solve_lab`)

| Category | Count | Tools | Primary Permission Tier(s) |
|---|---|---|---|
| **project** | 7 | `project_create`, `project_open`, `project_save`, `project_close`, `project_export`, `project_import`, `project_status` | `planning`, `read_only` |
| **topology** | 6 | `topology_create`, `topology_inspect`, `topology_validate`, `topology_export`, `topology_visualize`, `topology_analyze` | `planning`, `read_only` |
| **devices** | 6 | `device_add`, `device_remove`, `device_inspect`, `device_move`, `device_list`, `device_capabilities` | `planning`, `destructive`, `read_only` |
| **connections** | 5 | `connection_create`, `connection_remove`, `connection_inspect`, `interface_list`, `interface_status` | `planning`, `destructive`, `read_only` |
| **ipam** | 5 | `subnet_calculate`, `vlsm_plan`, `address_allocate`, `address_validate`, `ipam_report` | `read_only`, `planning` |
| **configuration** | 14 | `configure_interface`, `configure_vlan`, `configure_trunk`, `configure_routing`, `configure_ospf`, `configure_eigrp`, `configure_dhcp`, `configure_nat`, `configure_acl`, `configure_ssh`, `configure_stp`, `configure_etherchannel`, `configuration_backup`, `configuration_compare` | `configuration`, `read_only` |
| **cli** | 5 | `command_validate`, `console_open`, `console_execute`, `console_capture`, `console_inspect` | `read_only`, `gui_control`, `configuration` |
| **gui** | 10 | `packet_tracer_detect`, `packet_tracer_launch`, `gui_screenshot`, `gui_calibrate`, `gui_click`, `gui_keypress`, `gui_state_inspect`, `gui_recover`, `gui_batch`, `gui_attach_ip_phone_power` | `read_only`, `gui_control` |
| **simulation** | 6 | `simulation_mode`, `simulation_start`, `simulation_stop`, `packet_create`, `packet_inspect`, `connectivity_test` | `gui_control`, `planning`, `read_only` |
| **diagnostics** | 15 | `network_diagnose`, `routing_diagnose`, `vlan_diagnose`, `interface_diagnose`, `network_repair_propose`, `network_repair_execute`, `network_verify`, `verify_requirements_schema`, `verify_lab`, `grade_lab`, `lab_open`, `lab_save`, `lab_status`, `list_devices`, `lab_snapshot` | `read_only`, `planning`, `configuration` |

---

## 2. Resources (7)

- `netforge://manifest` — Machine-readable manifest of all 79 tools, tiers, transports, and 17 supported device models.
- `netforge://workflows/solve_lab` — Canonical closed-loop `solve_lab` workflow contract (22 default profile tools).
- `netforge://project/current` — Active project summary and Planned vs. Executed vs. Verified state counts.
- `netforge://project/topology` — Current normalized topology JSON export.
- `netforge://project/ipam` — IPAM pools, allocations, and utilization JSON report.
- `netforge://devices/catalog` — Verified Packet Tracer device profiles, physical interfaces, and capabilities.
- `netforge://logs/recent` — Recent redacted SQLite execution audit logs.

---

## 3. Workflow Prompts (5)

- `solve_lab` — Guided closed-loop lab solver (`lab_open` -> `verify_lab` / `grade_lab` / `lab_status` -> fix -> `lab_save`).
- `plan_network_architecture` — Step-by-step PLAN -> DESIGN -> VALIDATE -> BUILD -> CONFIGURE -> VERIFY guide.
- `design_campus_vlan_network` — Guided multi-building campus network design with VLANs, OSPF, DHCP, and NAT.
- `review_network_configurations` — Comprehensive audit workflow checking IPAM, topology loops, and configuration diffs.
- `troubleshoot_network_workflow` — Evidence-based troubleshooting dividing root-cause isolation from approved self-repair.

---

## 4. State Level Contract (`StateLevel`)

Every MCP tool returns an `OperationResult` envelope with explicit state separation:
- `planned`: Design intent validated inside NetForge.
- `executed`: Dispatched to Packet Tracer GUI or device console.
- `verified`: Independently confirmed via observed CLI output or simulation trace.
