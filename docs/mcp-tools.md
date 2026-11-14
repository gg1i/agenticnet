# NetForge MCP Tool & Capability Ecosystem

NetForge MCP (`v0.1.0`, schema `1.0.0`) exposes **69 specialized MCP tools** organized across 10 functional categories, **6 read-only resources**, and **4 guided AI agent prompts** over `stdio` and HTTP transports.

Run `python -m netforge manifest` or read `netforge://manifest` for the live machine-readable JSON schema.

---

## 1. Tool Categories (69 Tools)

| Category | Count | Tools | Primary Permission Tier(s) |
|---|---|---|---|
| **project** | 7 | `project_create`, `project_open`, `project_save`, `project_close`, `project_export`, `project_import`, `project_status` | `read_only`, `planning`, `destructive` |
| **topology** | 6 | `topology_create`, `topology_inspect`, `topology_validate`, `topology_export`, `topology_visualize`, `topology_analyze` | `read_only`, `planning`, `destructive` |
| **devices** | 6 | `device_add`, `device_remove`, `device_inspect`, `device_move`, `device_list`, `device_capabilities` | `read_only`, `planning`, `destructive` |
| **connections** | 5 | `connection_create`, `connection_remove`, `connection_inspect`, `interface_list`, `interface_status` | `read_only`, `planning`, `configuration`, `destructive` |
| **ipam** | 5 | `subnet_calculate`, `vlsm_plan`, `address_allocate`, `address_validate`, `ipam_report` | `read_only`, `planning` |
| **configuration** | 14 | `configure_interface`, `configure_vlan`, `configure_trunk`, `configure_routing`, `configure_ospf`, `configure_eigrp`, `configure_dhcp`, `configure_nat`, `configure_acl`, `configure_ssh`, `configure_stp`, `configure_etherchannel`, `configuration_backup`, `configuration_compare` | `read_only`, `configuration` |
| **cli** | 5 | `command_validate`, `console_open`, `console_execute`, `console_capture`, `console_inspect` | `read_only`, `configuration`, `gui_control` |
| **gui** | 8 | `packet_tracer_detect`, `packet_tracer_launch`, `gui_screenshot`, `gui_calibrate`, `gui_click`, `gui_keypress`, `gui_state_inspect`, `gui_recover` | `read_only`, `gui_control` |
| **simulation** | 6 | `simulation_mode`, `simulation_start`, `simulation_stop`, `packet_create`, `packet_inspect`, `connectivity_test` | `read_only`, `planning`, `gui_control` |
| **diagnostics** | 7 | `network_diagnose`, `routing_diagnose`, `vlan_diagnose`, `interface_diagnose`, `network_repair_propose`, `network_repair_execute`, `network_verify` | `read_only`, `planning`, `configuration` |

---

## 2. Resources

- `netforge://manifest` — Machine-readable manifest of all 69 tools, tiers, transports, and 15 supported device models.
- `netforge://project/current` — Active project summary and Planned vs. Executed vs. Verified state counts.
- `netforge://project/topology` — Current normalized topology JSON export.
- `netforge://project/ipam` — IPAM pools, allocations, and utilization JSON report.
- `netforge://devices/catalog` — Verified Packet Tracer device profiles, physical interfaces, and capabilities.
- `netforge://logs/recent` — Recent redacted SQLite execution audit logs.

---

## 3. Workflow Prompts

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
