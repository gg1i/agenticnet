# NetForge MCP

**Open-Source AI-Native Network Automation Platform for Cisco Packet Tracer**

NetForge MCP is a modular Model Context Protocol (MCP) server and engineering engine enabling AI agents (Google Antigravity, Claude Desktop, and other MCP-compatible clients) to plan, design, validate, construct, configure, verify, diagnose, and document Cisco Packet Tracer network topologies.

> **Independent Community Project Disclaimer:** NetForge MCP is an independent open-source software project. It is **not affiliated with, sponsored by, or endorsed by Cisco Systems, Inc.** Cisco Packet Tracer is a trademark of Cisco Systems, Inc. This repository contains no Cisco proprietary binaries or copyrighted assets.

---

## Why NetForge MCP? (One-Command Live Lab Experience)

Hand your MCP agent (`Antigravity` or `Claude Desktop`) a networking idea, `.md`/`.txt`/PDF lab brief, or `.pkt`/`.pka` file with `lab_start` (`start_lab`), and watch Packet Tracer build and verify the lab live on your desktop:

- **Plan -> Build -> Watch Mode**: For ideas or lab specs, NetForge drafts a concise topology, IP plan, and task list for your OK before touching Packet Tracer, then executes step-by-step with narration.
- **Native PT Script Bridge (Not Brittle Macros)**: Dispatches `add_device`, `create_link`, `configure_host`, `batch_ops`, IOS/PC CLI execution, `list_devices`, and `fileOpen`/`fileSaveAsNoPrompt` over an authenticated `127.0.0.1` HTTP/WebView bridge inside Packet Tracer's own IPC (GUI automation stays fallback-only).
- **Zero-Risk Copy-on-Write + Diff**: Never overwrites your original `.pkt`/`.pka` by default; saves to a sibling `*_netforge.pkt` working copy, takes start/end snapshots, and returns a readable `lab_diff`.
- **Real CLI Verification (`planned` vs `executed` vs `verified`)**: `verify_lab` checks live `show ip interface brief`, `show ip route`, `show vlan brief`, `show telephony-service`, and real `ping` output — never claiming pass without observed evidence.
- **Curated Default Profile + Safe Parallel Speed**: Exposes **25** focused tools by default (`solve_lab`) or all **82** engineering/IPAM/IOS/diagnostics tools (`NETFORGE_TOOL_PROFILE=advanced`), with HTTP/1.1 keep-alive, single-round-trip `batch_ops`, SQLite WAL, and device-parallel CLI/verification.

> **Platform Scope:** Offline unit/protocol tests and planning tools run cleanly on Windows, Linux, and macOS CI. Live Packet Tracer automation is tested on **Windows 10/11 + Cisco Packet Tracer 8.2.2** on an unlocked interactive desktop session.

---

## Core Design Principles

1. **Plan -> Design -> Validate -> Build -> Configure -> Test -> Diagnose -> Repair -> Save -> Document**
2. **Explicit State Separation (`planned` vs. `executed` vs. `verified`)**: Every operation explicitly reports whether state exists only in NetForge's design model (`planned`), was dispatched to a simulator adapter (`executed`), or was independently observed on a running device (`verified`).
3. **Never Claim Success Without Evidence**: Tools return structured `OperationResult` envelopes containing `operation_id`, `status`, `state_level`, `evidence`, `warnings`, and typed `errors`.
4. **Device Capability Awareness**: Commands are validated against verified device profiles (`2911`, `1941`, `2960-24TT`, `3560-24PS`, `PC-PT`, `Server-PT`, `WRT300N`, etc.) before generation or execution.
5. **Security & Auditability**: Five-tier permission enforcement (`read_only`, `planning`, `configuration`, `gui_control`, `destructive`), destructive-action confirmation gates, SQLite audit trails, and automatic secret redaction.

---

## Current Roadmap Status

| Phase | Scope | Status |
|---|---|---|
| **Phase 1 — Core Foundation** | Package structure, official MCP SDK server, SQLite project store, NetworkX topology engine, IPv4/IPv6 + VLSM IPAM, structured IOS generators/validators, security layer, offline unit & protocol tests | **Implemented (`v0.1.0`)** |
| **Phase 2 — Packet Tracer Adapter** | Windows PyWin32/ctypes GUI detection, DPI-aware calibration, visual anchor matching, SendInput mouse/keyboard input, fail-safe emergency stop, device console state machine | **Implemented (`v0.1.0`)** |
| **Phase 3 — Live Network Automation** | Simulation/Realtime mode switching, PDU test packets, simulation event parsing, CLI ping execution, `show ip route` / `show arp` / `show ip int brief` table parsers | **Implemented (`v0.1.0`)** |
| **Phase 4 — Intelligent Diagnostics** | Automated rule evaluators (missing gateway, disabled interface with IP, link subnet mismatch, native VLAN mismatch), ranked proposals, approval gates, verified self-repair | **Implemented (`v0.1.0`)** |
| **Phase 5 — Public Release** | Multi-engine integration, capability manifest (`docs/manifest.json`), 82 MCP tools (25 in default `solve_lab` profile), 7 resources, 6 prompts, CI workflows, and complete documentation | **Implemented (`v0.1.0`)** |

---

## Architecture Overview

```text
netforge/
├── core/         # Enums, state separation, exceptions, OperationResult, settings, stderr logging
├── security/     # Permission tiers, destructive confirmation guardrails, secret redaction
├── devices/      # Verified Packet Tracer device catalog & interface normalization (17 models)
├── topology/     # NetworkX MultiGraph topology engine, cable rules, layout, Mermaid/ASCII export
├── ipam/         # IPv4/IPv6 CIDR math, VLSM allocator, conflict detection, addressing tables
├── ios/          # Structured IOS generators, capability pre-validators, CLI parser, unified diff
├── storage/      # Versioned SQLite repository, backups, JSON/YAML import & export
├── adapters/     # Discovery and abstract contracts for GUI, Console, and Simulation backends
├── gui/          # (Phase 2) Windows pywin32/ctypes GUI backend, calibration, safety abort
├── console/      # (Phase 2) Device console state-machine, prompt detection, paging cleanup
├── simulation/   # (Phase 3) Simulation mode, PDU tracking, CLI/offline connectivity checks
├── diagnostics/  # (Phase 4) Root-cause rules, ranked repair proposals, verified execution
└── mcp/          # Official Python MCP SDK server, 82 tools (25 default), 7 resources, 6 prompts, manifest
```

---

## Quickstart (Windows & Cross-Platform)

### Requirements
- Python **3.11+**
- Optional (for live Packet Tracer `8.2.2` automation):
  - Cisco Packet Tracer installed locally (e.g., `C:\Program Files\Cisco Packet Tracer 8.2.2\bin\PacketTracer.exe`) with the NetForge Script Module (module ID `com.netforge.bridge`) registered once via `netforge-mcp install-module`.
  - **Strict Non-Interactive Session Rule & Graceful Close:** Never start `PacketTracer.exe` from a non-interactive agent shell or isolated desktop (`WinSta0\exebox-*`, Session 0, or headless display); `packet_tracer_launch`, `WindowsGuiBackend.launch_application`, `HttpScriptBridgeBackend.ensure_connected`, and `run_live_pt_benchmark` automatically refuse with `NON_INTERACTIVE_SESSION`. Live test harnesses must close spawned instances via graceful close first (`WM_CLOSE` / `SIGTERM` before any forced cleanup) so `PT.conf` saves cleanly without leaving `PT-*.conf` temp files or orphan processes behind.
  - **One-Time Re-Registration (`com.netforge.bridge`):** After exporting/installing the updated `.pts` (`com.netforge.bridge`), open `Extensions -> Scripting -> Configure PT Script Modules...` in Packet Tracer, remove any previous bridge entry (or `com.yourcompany.newptscriptmodule0`), add `%LOCALAPPDATA%\netforge\netforge_bridge.pts`, enable `On Startup`, accept script privileges, and restart Packet Tracer normally from the Start Menu. Note: NetForge never edits `PT.conf` programmatically.
  - **Fail-Safe Bridge Startup:** `netforge_bridge.js` wraps every top-level function in `try/catch`, performs cheap ~5s idle file checks without spawning a `QWebView`, creates `QWebView` lazily only when a fresh `bridge_session.json` exists (`server_pid`, `created_at`, heartbeat within 60s), and destroys/blacklists the session after 3 consecutive failed polls.
  - **Unlocked interactive Windows desktop session** for GUI fallback steps (`gui_*`): foreground GUI automation (`SendInput` drags, `ImageGrab` screen captures, and Physical-tab actions such as `gui_attach_ip_phone_power` — **experimental: not yet validated by the 5-attempt live protocol**) requires an unlocked interactive desktop (never a locked/asleep session or isolated non-interactive desktop object), temporarily takes over the physical mouse pointer during foreground drags, and is calibrated for Packet Tracer `8.2.2` at the tested `1920x1080` / `120 DPI` (`125%`) display scaling until the Phase 6 `netforge-mcp doctor` calibration gate exists. The `ScriptBackend` HTTP bridge continues to operate cleanly without pointer input after initial `.pts` registration.

### Installation

```bash
# From source (editable development install)
pip install -e .[dev]

# Or core runtime only
pip install -e .
```

### Verify Environment & Capability Manifest

```bash
netforge-mcp version
netforge-mcp doctor
netforge-mcp manifest
```

### Run the MCP Server

```bash
# Default stdio transport (for Antigravity / Claude Desktop)
netforge-mcp serve --transport stdio

# Streamable HTTP transport (experimental / local daemon mode)
netforge-mcp serve --transport streamable-http --host 127.0.0.1 --port 8765
```

### Example Client Configurations

- **Google Antigravity**: See [`examples/antigravity_mcp_config.json`](examples/antigravity_mcp_config.json)
- **Claude Desktop**: See [`examples/claude_desktop_config.json`](examples/claude_desktop_config.json)

```json
{
  "mcpServers": {
    "netforge": {
      "command": "netforge-mcp",
      "args": ["serve", "--transport", "stdio"],
      "env": {
        "NETFORGE_PERMISSION_PROFILE": "standard",
        "NETFORGE_REQUIRE_CONFIRM": "true"
      }
    }
  }
}
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NETFORGE_DATA_DIR` | `./.netforge` | Directory storing SQLite database and backups |
| `NETFORGE_DB_NAME` | `netforge.sqlite` | SQLite database filename |
| `NETFORGE_PERMISSION_PROFILE` | `standard` | One of `read-only`, `planning`, `configuration`, `standard` |
| `NETFORGE_REQUIRE_CONFIRM` | `true` | Require `confirm=True` for destructive operations |
| `NETFORGE_LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `NETFORGE_TRANSPORT` | `stdio` | Transport (`stdio`, `streamable-http`, `sse`) |
| `NETFORGE_PT_PATH` | *(auto-detect)* | Explicit path to Cisco Packet Tracer executable |

---

## Documentation

- [Architecture Guide](docs/ARCHITECTURE.md)
- [Capabilities & Live Probe Log](docs/CAPABILITIES.md)
- [Benchmark Protocol & Reference Scoring](docs/BENCHMARK.md)
- [Stranger Test Release-Gate Checklist](docs/STRANGER_TEST.md)
- [MCP Tool, Resource & Prompt Reference](docs/mcp-tools.md)
- [Windows Setup Guide](docs/windows-setup.md)
- [Linux & macOS Compatibility Roadmap](docs/cross-platform-roadmap.md)

---

## Live Verification & Benchmark Results

Only **live** Cisco Packet Tracer (`8.2.2.0400`) results are reported here. Offline mocked runs (`"mock": true` / `mode: "offline_mock"`) are synthetic harness checks and are never reported as benchmark scores (see [Benchmark Protocol](docs/BENCHMARK.md) and [Test Report](docs/TEST_REPORT.md)).

| Evaluation Track | Mode | Result (Live Only) | Reference |
|---|---|---|---|
| Phase 1–4 Live PT Capabilities & Script Bridge Probes | `live_pt` | **Recorded** (bridge RPC, IOS CLI `verify_lab`, `.pka` comparator tree grading; `gui_attach_ip_phone_power` **verified live** via script-first `attach_ip_phone_power` / `7960` auto-power, with experimental `SendInput` fallback) | [CAPABILITIES.md](docs/CAPABILITIES.md) |
| Phase 5 `lab_open` / `lab_save` / `lab_status` Persistence & External `.pkt` Discovery (`list_devices` / `lab_snapshot`) | `live_pt` | **Verified Live** (`6/6` requirements pass pre-save & post-reopen after closing/restarting PT; `dhcp_reservation.pkt`: `10` devices, `4` links, `23` active interfaces) | [TEST_REPORT.md](docs/TEST_REPORT.md) |
| Phase 5 AI-Agent End-to-End Lab Benchmark (`01_static_routing`, `02_vlan_dhcp`, `03_small_voice`) | `live_pt` | **Verified Live (`3/3` labs, `18/18` checks — `100.0%`)**: `01_static_routing` (`8/8`, `67.1s`), `02_vlan_dhcp` (`5/5`, `79.2s`), `03_small_voice` (`5/5`, `50.1s`) with zero-touch PT auto-launch & `7960` power | [phase5_live_benchmark.json](docs/evidence/phase5_live_benchmark.json) |

---

## Testing

All Phase 1 unit tests and MCP protocol tests run completely offline with zero Packet Tracer installation required:

```bash
pytest
ruff check netforge tests
```

---

## License

Released under the [MIT License](LICENSE).
