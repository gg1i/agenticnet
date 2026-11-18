# AgenticNet — Architecture Overview

AgenticNet pairs a **cross-platform network engineering core** (topology modeling, VLSM/CIDR IPAM, Cisco IOS generation & validation, diagnostics, and SQLite state management) with an **authenticated local Cisco Packet Tracer Script Bridge** and optional Windows GUI fallback.

<!-- BEGIN MANIFEST COUNTS -->
> **Current Live Registry Counts (`docs/manifest.json`):** `94` registered tools (`advanced` profile) / `26` default (`solve_lab` profile), `7` resources, `6` prompts, `30` device models.
<!-- END MANIFEST COUNTS -->

---

## 1. High-Level System Architecture

```text
+-------------------------------------------------------------------------+
|                    MCP Client (Claude, Cursor, etc.)                    |
+------------------------------------+------------------------------------+
                                     | stdio / Streamable HTTP
+------------------------------------v------------------------------------+
|                     AgenticNet MCP Server (MCPServer)                   |
|  Tool Profiles (solve_lab / advanced) + Permission Tiers + Redaction    |
+-------------+--------------------------------------------+--------------+
              |                                            |
              v                                            v
+---------------------------+                +----------------------------+
|   Offline Domain Engines  |                |       BackendRouter        |
| Topology / IPAM / IOS /   |<-- state sync--| Routes live ops to bridge  |
| Diagnostics / SQLite WAL  |                | or Windows GUI fallback    |
+---------------------------+                +-------+--------------+-----+
                                                     |              |
                                  Primary (HTTP/IPC) |              | Fallback (GUI-only)
                                                     v              v
+----------------------------------+    +---------------------------------+
|      HttpScriptBridgeBackend     |    |        WindowsGuiBackend        |
| 127.0.0.1 Keep-Alive + Token     |    |  Win32 / DPI / Visual Anchors   |
| (com.netforge.bridge .pts mod)   |    |  Emergency stop + dry_run gate  |
+----------------+-----------------+    +----------------+----------------+
                 |                                       |
                 v                                       v
+-------------------------------------------------------------------------+
|              Cisco Packet Tracer 8.2.2+ (Live Desktop)                  |
|   LogicalWorkspace / Network / TerminalLine / Simulation / ActivityFile |
+-------------------------------------------------------------------------+
```

---

## 2. Core Design Contracts

1. **Honest State Separation (`StateLevel`):**
   - `planned`: Evaluated locally in NetworkX / IPAM / IOS models only.
   - `executed`: Dispatched to Packet Tracer via `script_backend` or `gui_backend`.
   - `verified`: Confirmed by observed live CLI output (`show` / `ping`) or `.pka` activity state.
2. **Backend Provenance:** Every `OperationResult` identifies which backend executed the operation (`offline_model`, `script_backend`, `gui_backend`, or `hybrid`).
3. **Closed-Loop Lab Execution (`LabRunner`, `LabVerifier`, `ActivityGrader`):**
   - `lab_start`: Detects whether input is a `.pkt`/`.pka` file, text/PDF spec, or freeform prompt, drafts a concise plan before mutating Packet Tracer, tracks step-by-step snapshots (`lab_snapshot`), computes diffs (`lab_diff`), and saves copy-on-write `*_agenticnet.pkt` files.
   - `verify_lab` & `lab_status`: Executes multi-device CLI checks and ICMP pings in parallel where safe, parses structured outputs, redacts secrets, and reports remaining unmet requirements honestly.
   - `grade_lab`: Reads Packet Tracer's native `.pka` completion tree (`ActivityFile`) read-only when available, cleanly degrading to `verify_lab` when grading reads are unavailable or locked.
4. **Loopback-Only Security Boundary:**
   - The HTTP Script Bridge binds strictly to `127.0.0.1` (`localhost`), enforces a per-session CSPRNG `X-AgenticNet-Token` (and legacy `X-NetForge-Token`) header and origin/content-type checks, and uses allowlisted typed operations rather than unconstrained dynamic code evaluation (`eval` / `new Function`).
   - Five permission tiers (`read_only`, `planning`, `configuration`, `gui_control`, `destructive`), confirmation gates, audit logging, and secret scrubbing protect local environments.

---

## 3. Package Layout

```text
agenticnet/
├── core/         # StateLevel, OperationResult, exceptions, settings, logging
├── security/     # Permission tiers, confirmation gates, path safety, secret redaction
├── devices/      # Verified Packet Tracer device catalog & port normalization (30 models)
├── topology/     # NetworkX MultiGraph builder, Cisco cabling rules, layout, Mermaid/ASCII export
├── ipam/         # IPv4/IPv6 CIDR math, VLSM allocator, conflict detection, addressing tables
├── ios/          # Structured IOS generators, capability pre-validators, CLI parser, unified diff
├── storage/      # Versioned SQLite WAL repository, config snapshots, JSON/YAML import & export
├── adapters/     # Discovery, BackendRouter, HTTP Script Bridge, bundled .pts module assets
├── gui/          # Optional Windows Win32/ctypes GUI fallback adapter & safety failsafe
├── console/      # Console state-machine, prompt elevation, paging cleanup, paced queues
├── simulation/   # Simulation/realtime controls, PDU specs, show/ping/ephone CLI parsers
├── diagnostics/  # Root-cause rules, ranked repair proposals, LabRunner, LabVerifier, ActivityGrader
└── mcp/          # Official Python MCP SDK server, 94 tools (26 default), 7 resources, 6 prompts
netforge/         # Legacy Python/CLI compatibility shim redirecting cleanly to agenticnet
```

---

## 4. Acknowledgements & Prior Art

AgenticNet's clean-room companion `.pts` bridge architecture acknowledges earlier open-source Packet Tracer MCP pioneering work:
- **`Mats2208/MCP-Packet-Tracer`** (**MIT License**) for demonstrating companion `.pts` Script Module + `127.0.0.1` HTTP bridging with Packet Tracer.
- **`kiskander/pt-mcp-server`** (**BSD-2-Clause License**) as prior-art inspiration for broad Packet Tracer IPC object coverage.
