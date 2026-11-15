# NetForge MCP — Target Hybrid Architecture

> **Status:** Phase 0 Architecture Audit (`netforge-mcp` v0.1.0 baseline)
> **Target Simulator:** Cisco Packet Tracer 8.2.2+ (`Place` / desktop edition)
> **MCP SDK:** Official Python `mcp` SDK (`mcp>=2.0.0`, verified `2.3.0` installed)

## 1. Product Positioning & Defensible Edge

**Positioning statement to prove:**
> *"Give an AI agent any Packet Tracer lab, including ones that need Physical-tab steps, and it keeps working until Packet Tracer's own checker says 100%."*

Public Packet Tracer MCP servers (`Mats2208/MCP-Packet-Tracer`, `kiskander/pt-mcp-server`) already cover natural-language topology generation, live script deployment, CLI execution, and simulation inspection. NetForge intentionally **does not** compete on prompt-to-topology generation breadth. Instead, NetForge invests in three defensible capabilities:

1. **GUI-Level Reach Beyond Scripting:** Win32 window/dialog automation (`WindowsGuiBackend`) handles steps that Packet Tracer's Script Engine / IPC API either restricts or cannot express cleanly — Physical-tab module & power-brick drags, non-CLI device dialogs (e.g., `Home VoIP0` `Server Address` fields), modal file/warning dialogs, and Simulation panel UI actions.
2. **Existing Lab In → Solved Lab Out:** Ingesting existing lab instructions plus `.pkt`/`.pka` files, synchronizing planned topology/IPAM/IOS state with the live simulator, configuring devices iteratively, verifying raw CLI state, and saving the completed `.pkt`.
3. **Native Grader Oracle (`ActivityFile` + CLI Fallback):** Using Packet Tracer's own Check Results / assessment item tree on `.pka` activities as the completion oracle, falling back automatically to raw-evidence CLI verification (`verify_lab`) when a lab is an ungraded `.pkt` or locks assessment reads.

<!-- BEGIN MANIFEST COUNTS -->
> **Current Live Registry Counts (`docs/manifest.json`):** `79` registered tools (`advanced` profile) / `22` default (`solve_lab` profile), `7` resources, `5` prompts, `17` device models.
<!-- END MANIFEST COUNTS -->

---

## 2. Current Baseline vs. Target Hybrid Architecture

### 2.1 Observed Baseline (`v0.1.0`)
In the current codebase (`70` live registered MCP tools across `10` categories, `6` resources, `4` prompts):
- **Offline Domain Core (`55` tools):** `project_*`, `topology_*`, `device_*`, `connection_*`, `interface_*`, `ipam_*`, `configure_*`, `configuration_*`, `command_validate`, `packet_create`, `packet_inspect`, and 5 of 7 `diagnostics_*` tools operate strictly on NetForge's in-memory NetworkX `MultiGraph`, `IPAMEngine`, `IOSGenerator`, and `SQLiteStore` (`StateLevel.PLANNED`). They **do not** mutate or query a running Packet Tracer instance.
- **GUI & Foreground Clipboard Live Path (`15` tools):**
  - `gui_*` (`9` tools) + `simulation_mode/start/stop` (`3` tools) drive `WindowsGuiBackend` (ctypes Win32 `PostMessage`/`SendInput`, `PrintWindow`, OpenCV template matching, hardcoded relative anchors).
  - `console_*` (`4` tools, overlapped with `connectivity_test`, `routing_diagnose`, `network_repair_execute`) drive `WindowsGuiConsoleTransport` via foreground window focusing (`SetForegroundWindow`) and `Ctrl+A`/`Ctrl+C` clipboard scraping of already-open device dialogs.

### 2.2 Target Hybrid Architecture (Phases 1–6)

```
+-------------------------------------------------------------------------+
|                           MCP Client / Agent                            |
+------------------------------------+------------------------------------+
                                     | stdio / Streamable HTTP (mcp 2.3+)
+------------------------------------v------------------------------------+
|                     NetForge MCP Server (MCPServer)                     |
|  ToolRegistry (Permission Tiers + Rate Limiter + Redaction + Provenance)|
+-------------+--------------------------------------------+--------------+
              |                                            |
              v                                            v
+---------------------------+                +----------------------------+
|   Offline Domain Engines  |                |       BackendRouter        |
| (Topology / IPAM / IOS /  |<-- state sync--|  Selects per-op backend,   |
|  Diagnostics / SQLite)    |                |  records execution_backend |
+---------------------------+                +-------+--------------+-----+
                                                     |              |
                          Primary (scripting-capable)|              | Fallback (GUI-only / disabled)
                                                     v              v
+----------------------------------+    +---------------------------------+
|          ScriptBackend           |    |           GuiBackend            |
| Localhost 127.0.0.1 HTTP + Token |    |  WindowsGuiBackend (Win32 + CV) |
| (fallback: local file-mailbox)   |    |  Gated by doctor + dry_run +    |
|                ^                 |    |  EmergencyStopController        |
+----------------|-----------------+    +----------------+----------------+
                 |                                       |
                 v                                       v
+-------------------------------------------------------------------------+
|              Cisco Packet Tracer 8.2.2+ (Live Process)                  |
|  - Companion .pts Script Module (typed opcodes over IpcAPI / Qt JS)     |
|  - Logical/Physical Canvas, Device Dialogs, Activity Check Results      |
+-------------------------------------------------------------------------+
```

### 2.3 Core Architectural Invariants
1. **Backend Abstraction (`netforge/adapters/base.py`):** Introduce `ScriptBackend` ABC alongside `GuiBackend`, `ConsoleBackend`, and `SimulationBackend`, unified under `BackendRouter`.
2. **Explicit Backend Attribution (`netforge/core/models.py`):** Every `OperationResult` must report which backend actually ran (`execution_backend`: `"offline_model" | "script_backend" | "gui_backend" | "hybrid"`).
3. **Honest `StateLevel` Separation:** `StateLevel.PLANNED` stays `planned` for offline edits; `StateLevel.EXECUTED` requires confirmed simulator dispatch; `StateLevel.VERIFIED` is permitted **only** when raw simulator read-back (or PT assessment read-back) confirms the post-condition.
4. **CLI First, Screenshot Never When Text Exists:** Never invoke `gui_screenshot` / OCR to inspect IOS state, interfaces, routes, DHCP bindings, or CME phones once structured CLI read-back is available.
5. **Empirical Capability Registry (`docs/CAPABILITIES.md`):** No behavior of Packet Tracer 8.2.2's Qt Script Engine or `IpcAPI` may be assumed from documentation alone; every capability (HTTP privilege prompts, module add/remove, CLI readback, `.pka` assessment tree access) is probed live in Phases 1 & 4 and recorded in `docs/CAPABILITIES.md`.

---

## 3. Complete 70-Tool Audit & Target Classification

Live introspection of `create_mcp_server()` shows **70 registered tools** (note: `README.md`, `docs/mcp-tools.md`, and `docs/manifest.json` currently lag at `69` tools because `gui_batch` is missing from static docs).

### Legend
- **Offline:** Pure local planning/math/SQLite/validation; zero live PT dependency.
- **Script (Primary):** Moves to `ScriptBackend` for live execution (often synced with offline SQLite/NetworkX model).
- **Script / GUI Hybrid:** `ScriptBackend` preferred where IpcAPI permits; per-operation fallback to `GuiBackend` when restricted or Physical/dialog-bound.
- **GUI-Only:** Requires OS windowing, desktop pixels, mouse drag, or raw Win32 input (`GuiBackend`).

| Category | Tool (`70` total) | Current Behavior | Target Classification & Migration Notes |
|---|---|---|---|
| **project (7)** | `project_create` | SQLite/workspace init only | **Offline** (creates workspace + initializes session) |
| | `project_open` | Opens local SQLite project | **Script / Offline** (Phase 5: sync/open associated `.pkt`/`.pka` via `AppWindow` when attached) |
| | `project_save` | Saves local SQLite state | **Script / Offline** (persist local project + optionally trigger `fileSave`/`fileSaveAsNoPrompt` in PT) |
| | `project_close` | Closes SQLite handle | **Offline** |
| | `project_export` | Exports JSON/YAML model | **Offline** |
| | `project_import` | Imports JSON/YAML model | **Offline** |
| | `project_status` | Reads local counts/status | **Offline** (enriches with live backend connection state when attached) |
| **topology (6)** | `topology_create` | Writes NetworkX graph only (`PLANNED`) | **Script (Primary) + Offline** (Phase 2: bulk-deploy planned nodes/links via `ScriptBackend` when live) |
| | `topology_inspect` | Inspects local NetworkX graph | **Script / Offline** (supports `live=True` delta compare against `Network` device/link list) |
| | `topology_validate` | Runs static graph/model rules | **Offline** |
| | `topology_export` | Serializes local graph | **Offline** |
| | `topology_visualize` | Renders ASCII/Mermaid diagram | **Offline** |
| | `topology_analyze` | Computes bridges/SPOFs/paths/loops | **Offline** |
| **devices (6)** | `device_add` | Adds node to NetworkX (`PLANNED`) | **Script (Primary) + GUI Fallback** (`LogicalWorkspace.addDevice`; module drags fall back to GUI if non-scriptable) |
| | `device_remove` | Removes node from NetworkX | **Script (Primary) + GUI Fallback** (`LogicalWorkspace.removeDevice`) |
| | `device_inspect` | Inspects local device + catalog specs | **Script / Offline** (queries live `Device` modules/ports/IPs via `ScriptBackend` when connected) |
| | `device_move` | Updates local `(x, y)` metadata | **Script (Primary)** (`Device.moveToLocation` / canvas coordinates) |
| | `device_list` | Lists local graph nodes | **Script / Offline** (optional live merge from `Network.getDeviceAt`) |
| | `device_capabilities` | Queries static `DeviceCatalog` | **Offline** |
| **connections (5)** | `connection_create` | Adds edge to NetworkX (`PLANNED`) | **Script (Primary) + GUI Fallback** (`LogicalWorkspace.createLink`) |
| | `connection_remove` | Removes edge from NetworkX | **Script (Primary) + GUI Fallback** (`LogicalWorkspace.deleteLink`) |
| | `connection_inspect` | Reads local edge metadata | **Script / Offline** (reads live link state via `ScriptBackend`) |
| | `interface_list` | Reads catalog/local ports | **Script / Offline** (reads live `Device.getPortAt` / `show ip int brief`) |
| | `interface_status` | Reads local link/admin status | **Script (Primary) + CLI Verify** (live port up/down + protocol status) |
| **ipam (5)** | `subnet_calculate` | Pure IPv4/IPv6 CIDR math | **Offline** |
| | `vlsm_plan` | Pure VLSM allocation solver | **Offline** |
| | `address_allocate` | Assigns IP in SQLite/IPAM | **Offline** |
| | `address_validate` | Validates planned IP constraints | **Offline** |
| | `ipam_report` | Renders addressing table | **Offline** |
| **configuration (14)** | `configure_interface` | Generates IOS lines locally (`PLANNED`) | **Script (Primary) + GUI Fallback** (`apply=True` executes over `ScriptBackend` `TerminalLine`) |
| | `configure_vlan` | Generates IOS VLAN commands | **Script (Primary) + GUI Fallback** |
| | `configure_trunk` | Generates switch trunk IOS | **Script (Primary) + GUI Fallback** |
| | `configure_routing` | Generates static/RIPv2 IOS | **Script (Primary) + GUI Fallback** |
| | `configure_ospf` | Generates OSPF IOS | **Script (Primary) + GUI Fallback** |
| | `configure_eigrp` | Generates EIGRP IOS | **Script (Primary) + GUI Fallback** |
| | `configure_dhcp` | Generates DHCP pool/excluded IOS | **Script (Primary) + GUI Fallback** |
| | `configure_nat` | Generates NAT/PAT IOS | **Script (Primary) + GUI Fallback** |
| | `configure_acl` | Generates Standard/Extended ACLs | **Script (Primary) + GUI Fallback** |
| | `configure_ssh` | Generates SSHv2/VTY IOS | **Script (Primary) + GUI Fallback** |
| | `configure_stp` | Generates STP IOS | **Script (Primary) + GUI Fallback** |
| | `configure_etherchannel` | Generates Port-Channel IOS | **Script (Primary) + GUI Fallback** |
| | `configuration_backup` | Snapshots local `ConfigHistory` | **Script / Offline** (captures live `show running-config` via `ScriptBackend` into snapshot) |
| | `configuration_compare` | Diffs two local snapshots | **Offline** (compares live running-config vs planned/saved snapshot) |
| **cli (5)** | `command_validate` | Syntax/safety check offline (`tools_ios.py`) | **Offline** |
| | `console_open` | Opens/attaches foreground HWND console | **Script (Primary) / GUI Fallback** (no open dialog required under `ScriptBackend`) |
| | `console_execute` | Types commands into focused dialog | **Script (Primary) / GUI Fallback** (dispatches to `Device`/`TerminalLine` directly; preserves dialog fallback) |
| | `console_capture` | `Ctrl+A`/`Ctrl+C` clipboard scrape | **Script (Primary) / GUI Fallback** (reads buffered `TerminalLine` output without clipboard/focus steal) |
| | `console_inspect` | Inspects prompt/mode/errors | **Script (Primary) / GUI Fallback** (`getPrompt`/`getMode`) |
| **gui (9)** | `packet_tracer_detect` | Enumerates processes/windows via Win32 | **GUI-Only** (OS process & window introspection) |
| | `packet_tracer_launch` | Spawns PT executable (`PermissionTier.DESTRUCTIVE`) | **GUI-Only** (process launch; Phase 6 OS/DPI gate applies) |
| | `gui_screenshot` | Offscreen `PrintWindow` + Pillow/CV layout stats | **GUI-Only** (banned when a CLI read satisfies the query) |
| | `gui_calibrate` | Creates/verifies DPI anchor profiles | **GUI-Only** (Phase 6 per-machine detection & calibration) |
| | `gui_click` | Mouse click via anchor/norm/px (`PostMessage`/`SendInput`) | **GUI-Only** (Physical tab, power bricks, non-scriptable dialogs) |
| | `gui_keypress` | Keyboard dispatch (`SendInput`/`WM_CHAR`) | **GUI-Only** |
| | `gui_state_inspect` | Active window + child dialogs inspection | **GUI-Only** |
| | `gui_recover` | Restores window, Esc, closes modals | **GUI-Only** (supports `dry_run`) |
| | `gui_batch` | Multi-step Win32 batch (`click`, `drag_dialog`, `paste_lines`, etc.) | **GUI-Only** (fallback engine for Physical tab & non-scriptable Qt dialogs) |
| **simulation (6)** | `simulation_mode` | Clicks `mode_simulation`/`mode_realtime` anchor | **Script (Primary) / GUI Fallback** (`Simulation.setSimulationMode`; GUI fallback if panel inspection needed) |
| | `simulation_start` | Clicks simulation capture/forward anchor | **Script (Primary) / GUI Fallback** (`Simulation.forward`) |
| | `simulation_stop` | Clicks reset/stop simulation anchor | **Script (Primary) / GUI Fallback** |
| | `packet_create` | Builds local `TrackedPacketSpec` only | **Script / Offline** (Phase 3/5: dispatch PDU / PC ping cleanly where supported) |
| | `packet_inspect` | Parses user-supplied packet/CLI text | **Script / Offline** (`Simulation.getFrameInstanceAt` structured PDU hop readback) |
| | `connectivity_test` | Runs CLI ping via console or NetworkX fallback | **Script (Primary) / GUI Fallback** (structured ping / PC `ipconfig`/`ping` via `ScriptBackend`) |
| **diagnostics (7)** | `network_diagnose` | Static 4-rule offline check (false `VERIFIED`) | **Script (Primary) + Offline** (fixes `StateLevel` honesty; checks live topology/interfaces) |
| | `routing_diagnose` | Live `show ip route` via console or offline fallback | **Script (Primary) / GUI Fallback** (structured `show ip route` + neighbor parsing) |
| | `vlan_diagnose` | Static VLAN/trunk offline check | **Script (Primary) + Offline** (parses live `show vlan brief` / `show interfaces trunk`) |
| | `interface_diagnose` | Static interface offline check | **Script (Primary) + Offline** (parses live `show ip interface brief` / `show interfaces`) |
| | `network_repair_propose` | Proposes IOS repair bundle offline | **Offline** |
| | `network_repair_execute` | Pushes repair commands via console | **Script (Primary) / GUI Fallback** |
| | `network_verify` | Re-runs offline `DiagnosticsEngine` | **Script (Primary) + Offline** (runs structured live read-back verification) |

### Planned New Tools (Phases 3–5, Not Yet Registered)
- **Phase 3 (`verify_lab`):** Accepts structured lab requirements (`interfaces`, `routes`, `dhcp`, `telephony`/`ephone`, `pings`) and returns per-requirement `PASS`/`FAIL` verdicts **with raw CLI command output as evidence**.
- **Phase 4 (`grade_lab`):** Reads Packet Tracer's native `.pka` assessment score, completion percentage, and unmet comparator items (`ActivityFile`), automatically degrading to Phase 3 `verify_lab` when running on `.pkt` files or locked activities.
- **Phase 5 (`solve_lab` / lab runner):** Ingests instructions + `.pkt`/`.pka`, plans, executes (hybrid Script + GUI), grades/verifies, repairs in a bounded retry loop, and saves the solved `.pkt`.

---

## 4. Known Brittleness Inventory (Observed in Code & Live VoIP Validation Lab Runs)

1. **Disconnection Between Domain Tools and Live Packet Tracer:** All `device_*`, `connection_*`, `topology_*`, and `configure_*` tools mutate only SQLite/NetworkX (`StateLevel.PLANNED`). Legacy coordinate automation scripts had to bypass the domain layer completely and hardcode raw Win32 coordinates inside `gui_batch`.
2. **Hardcoded Display Geometry & DPI Assumptions:** `DEFAULT_PT_ANCHORS` (`netforge/gui/calibration.py`) and legacy coordinate scripts assume a `1920x991` client area at `120 DPI` with default dock state. Meanwhile, `netforge doctor` (`netforge/cli.py`) only checks Python version, platform name, data directory, permission profile, and `PacketTracer.exe` presence — it never validates OS GUI support, PT version, DPI, or screen bounds.
3. **Foreground Focus Stealing & Clipboard Scraping Fragility:** `WindowsGuiConsoleTransport` (`netforge/console/transport.py`) requires a pre-opened device dialog, steals user focus with `SetForegroundWindow`, sends characters sequentially, and scrapes via `Ctrl+A` + `Ctrl+C` (`capture_text_from_focused_window`), breaking when scrollback trims older lines (`after.startswith(before)`) or another process touches the clipboard.
4. **Qt Window Timing & Inactive-Widget Quirks (Live VoIP Validation Lab Findings):**
   - `wait_dialog` polling can return within `~90ms` while Qt takes `~120–160ms` to finish constraining dialog `top` coordinates (`198 -> 131`).
   - Inactive Qt `QLineEdit` widgets (observed on `Home VoIP0` `Server Address`) silently ignore background `WM_CHAR` `PostMessage` calls until foreground focus / proper click focus is acquired.
   - Multi-line router IOS blocks drop `Enter` keystrokes in GUI paste unless throttled to `delay_ms >= 75–80` per line (or executed via `ScriptBackend` / `TerminalLine` instead of simulated keyboard).
5. **Silent `gui_batch` Schema Fallbacks & Error Swallowing:** Passing `x`/`y` to `_batch_step_click_dialog` in `netforge/gui/windows_backend.py` silently falls back to `offset_x=0, offset_y=0`; passing `target_dialog` to `_batch_step_screenshot` silently captures the main PT window rather than raising `ValidationError`; `_call_with_optional` in `netforge/mcp/tools_gui.py` swallows `TypeError`.
6. **Dishonest `StateLevel.VERIFIED` Reporting:** `DiagnosticsEngine.run_diagnostics` (`netforge/diagnostics/engine.py`) evaluates 4 static local topology rules and stamps the report `StateLevel.VERIFIED` solely because `console.transport.is_available()` is `True`, without executing a single live `show` command.
7. **Missing `execution_backend` Provenance & Inconsistent `dry_run` Plumb-Through:** `OperationResult` (`netforge/core/models.py`) has no `backend` field; `SimulationEngine.set_mode` (`netforge/simulation/engine.py`) invokes `click(dry_run=False)` without propagating dry-run settings and silently catches `Exception`.
8. **Configuration, Script, Repo & Lint Drift:**
   - The VoIP validation lab switch config originally omitted `no ip domain-lookup` (initially compensated in legacy scripts, alongside a workaround for switches echoing `"no"` at `initial configuration dialog`).
   - Static tool documentation (`README.md`, `docs/mcp-tools.md`, `docs/manifest.json`, `NetForgeRuntime.build_manifest`) lags the live `70`-tool `ToolRegistry` (`gui: 8` / `"Phase 5"` vs `gui: 9` / `70`).
   - Full `ruff check netforge tests/` currently fails with `39` pre-existing violations (`19` `E402` from `_enable_per_monitor_dpi_awareness()` before imports in `windows_backend.py`, plus `20` `E501` line-length violations across `windows_backend.py`, `tools_gui.py`, and `tests/gui/test_gui_backend.py`), and no `.git` repository is initialized in the workspace.
9. **Unverified PT 8.2.2 Runtime Script Privileges (Probe Item):** Packet Tracer `8.2.2`'s local Doxygen HTML (`help/default/IpcAPI/`) documents `LogicalWorkspace`, `Network`, `Device`, `TerminalLine`, `Simulation`, `ActivityFile`, `WebView`, `SystemFileManager`, and `IpcManager`, while shipped `.pts` files under `extensions/` are encoded binaries. Exact `8.2.2` security prompt behavior (`shouldPromptExternalNetworkAccess`), localhost HTTP access from `WebView`, and `.pka` assessment read access under active activities are **UNTESTED** live and will be recorded in `docs/CAPABILITIES.md` in Phases 1 & 4.

---

## 5. Review of Existing Public Packet Tracer MCP Projects

| Project | License | Transport / Bridge | Exposed Capability Scope | Key Design Lessons & Gaps |
|---|---|---|---|---|
| **`Mats2208/MCP-Packet-Tracer`** | **MIT** | Companion `MCPControlCenter.pts` Script Module polling a token-authenticated `127.0.0.1` HTTP bridge (plus file-mailbox fallback); executes generated/dynamic JS via `new Function()`. | ~79–100+ tools: natural-language topology planning (`pt_plan_topology`, `pt_full_build`), live deploy (`pt_live_deploy`), `pt_cli`, `pt_host_command`, ~15 cable types, live inspection, `pt_send_raw` (arbitrary JS), `.pka` exam building, `install-skill` CLI. | Proves `127.0.0.1` HTTP + token + `.pts` Script Module works cross-platform (`uvx`). However, exposing arbitrary `new Function()` JS (`pt_send_raw`) enlarges the local attack surface (requiring strict token/CORS defenses), and there is no GUI Physical-tab fallback or native `.pka` solver loop. |
| **`kiskander/pt-mcp-server`** | **BSD-2-Clause** | Connects externally to PT's native IPC / PTMP binary TCP interface (ExApp model, ports `38000`/`39000~`). | Full topology CRUD/export, live IOS CLI & running/startup config read/write, modular slot installation (`HWIC-2T`, `NIM-2T`, power cycle), PC CMD (`ping`, `ipconfig`, `tracert`), ping matrices, Simulation Mode PDU/OSI hop inspection, canvas notes, `.pka` instructions. | Demonstrates structured IPC inspection (including module installation and Simulation frame inspection). Intentionally blocks `.pka` assessment answers/scores for academic integrity, carries BSD-2-Clause notice obligations, and relies on reverse-engineered binary PTMP framing / `.pta` ExApp registration. |
| **`mcp-tracer` / `Builder.pts` wrappers** | OSS (`PTBuilder`-style) | Static `PTBuilder` JS snippet emission / manual `.pts` execution. | Device/link/config snippet generation. | Not suited for iterative read-back, structured verification, or automated multi-step repair loops. |

---

## 6. Hybrid Phase Roadmap & Gate Criteria

| Phase | Deliverable | Primary Proof Gate |
|---|---|---|
| **Phase 0 (Current)** | `docs/ARCHITECTURE.md`, `docs/DECISIONS.md` (audit only, zero code edits) | All 70 tools classified; competitor review & bridge ADR documented; baseline checks reported honestly. |
| **Phase 1** | `ScriptBackend` interface + `127.0.0.1` token-auth bridge + companion `.pts` probe + `docs/CAPABILITIES.md` | Live probe in PT 8.2.2 adds device, links it, executes IOS CLI, returns raw output; offline mocked-bridge tests pass. |
| **Phase 2** | `BackendRouter` + migration of scripting-capable tools; `execution_backend` provenance; GUI fallback + `dry_run` + `Switch_Site1.ios`/loader fix | All existing unit/integration tests green + new mocked router tests; live tool calls show backend provenance. |
| **Phase 3** | Structured CLI parsers (`interfaces`, `routes`, `dhcp`, `ephone`, `ping`) + `verify_lab` tool | `verify_lab(requirements)` returns per-item pass/fail **with raw IOS output evidence**; zero screenshots for CLI-readable checks. |
| **Phase 4** | `.pka` Grader Oracle (`grade_lab` via `ActivityFile`) + empirical reliability report + Phase 3 fallback | Live probe on sample `.pka` returns score + unmet comparator items; falls back to `verify_lab` cleanly when absent. |
| **Phase 5** | Lab Runner (`solve_lab` loop: ingest → plan → execute → grade/verify → repair → save `.pkt`, bounded iterations) + `scripts/e2e_voip_lab.py` | Clean offline runner tests + **10 consecutive live runs of `scripts/e2e_voip_lab.py`** reporting exact pass rate & mean runtime. |
| **Phase 6** | Portability & `netforge doctor` OS/PT/DPI/resolution checks + fail-closed GUI gate + dynamic calibration/detection | Doctor refuses unsupported GUI setups cleanly; calibrated/detected UI targets avoid mis-clicks. |
| **Phase 7** | Public release polish: `uvx` entrypoint, clean README & honest competitor matrix, `SECURITY.md`, MIT `LICENSE`/credits, CI (`ruff` clean = 0 errors + `pytest`), sample self-authored labs, MCP Registry metadata | Clean CI, zero bundled Cisco binaries or course-owned labs, verified `uvx` smoke install. |
