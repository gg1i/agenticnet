# NetForge MCP

**Open-Source AI-Native Network Automation Platform for Cisco Packet Tracer**

NetForge MCP is a modular Model Context Protocol (MCP) server and engineering engine enabling AI agents (Google Antigravity, Claude Desktop, and other MCP-compatible clients) to plan, design, validate, construct, configure, verify, diagnose, and document Cisco Packet Tracer network topologies.

> **Independent Community Project Disclaimer:** NetForge MCP is an independent open-source software project. It is **not affiliated with, sponsored by, or endorsed by Cisco Systems, Inc.** Cisco Packet Tracer is a trademark of Cisco Systems, Inc. This repository contains no Cisco proprietary binaries or copyrighted assets.

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
| **Phase 5 — Public Release** | Multi-engine integration, capability manifest (`docs/manifest.json`), 69 MCP tools, 6 resources, 4 prompts, CI workflows, and complete documentation | **Implemented (`v0.1.0`)** |

---

## Architecture Overview

```text
netforge/
├── core/         # Enums, state separation, exceptions, OperationResult, settings, stderr logging
├── security/     # Permission tiers, destructive confirmation guardrails, secret redaction
├── devices/      # Verified Packet Tracer device catalog & interface normalization (15 models)
├── topology/     # NetworkX MultiGraph topology engine, cable rules, layout, Mermaid/ASCII export
├── ipam/         # IPv4/IPv6 CIDR math, VLSM allocator, conflict detection, addressing tables
├── ios/          # Structured IOS generators, capability pre-validators, CLI parser, unified diff
├── storage/      # Versioned SQLite repository, backups, JSON/YAML import & export
├── adapters/     # Discovery and abstract contracts for GUI, Console, and Simulation backends
├── gui/          # (Phase 2) Windows pywin32/ctypes GUI backend, calibration, safety abort
├── console/      # (Phase 2) Device console state-machine, prompt detection, paging cleanup
├── simulation/   # (Phase 3) Simulation mode, PDU tracking, CLI/offline connectivity checks
├── diagnostics/  # (Phase 4) Root-cause rules, ranked repair proposals, verified execution
└── mcp/          # Official Python MCP SDK server, 69 tools, 6 resources, 4 prompts, manifest
```

---

## Quickstart (Windows & Cross-Platform)

### Requirements
- Python **3.11+**
- Optional (for live Packet Tracer `8.2.2` automation):
  - Cisco Packet Tracer installed locally (e.g., `C:\Program Files\Cisco Packet Tracer 8.2.2\bin\PacketTracer.exe`) with the NetForge Script Module installed via `netforge install-module`.
  - **Unlocked interactive Windows desktop session** for GUI fallback steps (`gui_*`): foreground GUI automation (`SendInput` drags, `ImageGrab` screen captures, and Physical-tab actions such as `gui_attach_ip_phone_power` — **experimental: not yet validated by the 5-attempt live protocol**) requires an unlocked interactive desktop (never a locked/asleep session or isolated non-interactive desktop object), temporarily takes over the physical mouse pointer during foreground drags, and is calibrated for Packet Tracer `8.2.2` at the tested `1920x1080` / `120 DPI` (`125%`) display scaling until the Phase 6 `netforge doctor` calibration gate exists. The `ScriptBackend` HTTP bridge continues to operate cleanly without pointer input after initial `.pts` registration.

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

Only **live** Cisco Packet Tracer (`8.2.2.0400`) results are reported here. Offline mocked runs (`"mock": true` / `mode: "offline_mock"`) are synthetic harness checks and are never reported as benchmark scores (see [Benchmark Protocol](docs/BENCHMARK.md)).

| Evaluation Track | Mode | Result (Live Only) | Reference |
|---|---|---|---|
| Phase 1–4 Live PT Capabilities & Script Bridge Probes | `live_pt` | **Recorded** (bridge RPC, IOS CLI `verify_lab`, `.pka` comparator tree grading; `gui_attach_ip_phone_power` **experimental: not yet validated by the 5-attempt live protocol**) | [CAPABILITIES.md](docs/CAPABILITIES.md) |
| Phase 5 AI-Agent End-to-End Lab Benchmark (`01_static_routing`, `02_vlan_dhcp`, `03_small_voice`) | `live_pt` | **Pending live run** (awaiting live Phase 5 gate; zero live AI-agent benchmark runs recorded yet) | [BENCHMARK.md](docs/BENCHMARK.md) |

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
