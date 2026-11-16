# NetForge MCP

**AI-Native Network Automation & Live Cisco Packet Tracer MCP Server**

NetForge MCP connects AI assistants (Claude Desktop, Cursor, VS Code Copilot, Google Antigravity, and any MCP client) directly to **Cisco Packet Tracer `8.2.2+`** and a cross-platform network engineering engine so your AI can plan subnets, build topologies, push verified Cisco IOS configs, test live pings, grade `.pka` activities, and diagnose broken labs without overwriting your original `.pkt`/`.pka` files.

> **Independent Community Project:** NetForge MCP is an open-source MIT project and is **not affiliated with, sponsored by, or endorsed by Cisco Systems, Inc.** Cisco Packet Tracer is a trademark of Cisco Systems, Inc. This repository contains no Cisco binaries or copyrighted lab files.

---

## What You Can Ask Your AI To Do

- **"Open `my_lab.pka`, show me what is already configured vs. what is missing, fix the remaining tasks, verify connectivity, and save a working copy."**
- **"Design and build a 3-VLAN campus topology in live Packet Tracer using OSPF and DHCP (`10.10.0.0/22`), configure all switches/routers/PCs, and verify end-to-end pings."**
- **"PC1 cannot reach the web server in `broken.pkt` — inspect interfaces, VLAN trunks, routing tables, and ARP, diagnose the root cause, repair it, and show me a diff of what changed."**
- **"Plan a VLSM subnet allocation for 4 departments (offline, no Packet Tracer needed), validate the IOS configs, and export a Mermaid topology diagram."**

---

## Why NetForge MCP?

- **One-Command Live Lab Workflow (`lab_start` / `start_lab`):** Give your AI a `.pkt`/`.pka` file, PDF/Markdown lab brief, or plain-English description. NetForge drafts a concise plan for your confirmation first, builds and configures the lab live in Packet Tracer, narrates progress, and verifies every step.
- **Native Packet Tracer Script Bridge:** Uses an authenticated `127.0.0.1` HTTP bridge inside Packet Tracer (`com.netforge.bridge`) for reliable `add_device`, `create_link`, `configure_host`, `batch_ops`, `HWIC-2T` module attachment, `7960` IP phone powering, IOS CLI execution, and `.pkt`/`.pka` open/save (desktop mouse/keyboard GUI automation stays fallback-only).
- **Non-Destructive Copy-on-Write + Diffs:** Original `.pkt`/`.pka` files stay untouched by default (`*_netforge.pkt`), with before/after snapshots (`lab_snapshot`) and readable change summaries (`lab_diff`).
- **Evidence-First Verification (`planned` vs. `executed` vs. `verified`):** Never claims success without proof — `verify_lab` and `lab_status` inspect real `show ip interface brief`, `show ip route`, `show vlan brief`, `show telephony-service`, and live `ping` outputs.
- **Clean Default Profile + Power-User Mode:** Exposes **25** focused tools in the default `solve_lab` profile (reducing prompt clutter for agents) or all **82** engineering, IPAM, IOS, simulation, and GUI tools via `NETFORGE_TOOL_PROFILE=advanced`.

> **Platform Support:** Planning, VLSM IPAM, IOS generation/validation, SQLite persistence, and all unit/protocol tests run natively on **Windows, Linux, and macOS**. Live Cisco Packet Tracer automation runs on **Windows 10/11 + Cisco Packet Tracer 8.2.2+** on an unlocked interactive desktop session.

---

## Quick Start (3 Minutes)

### 1. Install NetForge MCP

Requires **Python 3.11+**.

```bash
git clone https://github.com/gg1i/netforge-mcp.git
cd netforge-mcp
pip install .
```

Optional extras:
- Windows GUI/vision fallback tools: `pip install ".[gui]"`
- Contributor dev/test tools (`pytest`, `ruff`): `pip install -e .[dev]`

### 2. Connect Cisco Packet Tracer (Windows, One-Time Setup)

Copy the bundled bridge script into `%LOCALAPPDATA%\netforge\netforge_bridge.pts`:

```bash
netforge-mcp install-module
```

Then register it once inside **Cisco Packet Tracer `8.2.2+`**:
1. Open **Extensions -> Scripting -> Configure PT Script Modules...**
2. Click **Add** and select `%LOCALAPPDATA%\netforge\netforge_bridge.pts`.
3. Check **On Startup**, click **Save**, and accept the one-time script privilege prompt.
4. Restart Packet Tracer cleanly.

Verify everything with:

```bash
netforge-mcp version
netforge-mcp doctor
```

> **Physical-Tab Fallback Note:** Standard topology, cabling, IOS CLI, host IP, `7960` power via script bridge, `.pka` grading, and verification require **no** mouse input. Only Physical-tab mouse-drag fallback actions (`gui_*` in `advanced` mode, plus `gui_attach_ip_phone_power` — *experimental: not yet validated by the 5-attempt live protocol*) require an unlocked interactive Windows desktop session.

### 3. Add to Your MCP Client

Add NetForge to **Claude Desktop**, **Cursor**, **VS Code**, **Windsurf**, or **Google Antigravity** (see [`examples/claude_desktop_config.json`](examples/claude_desktop_config.json) and [`examples/mcp_config.json`](examples/mcp_config.json)):

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

Or run the server directly from a terminal:

```bash
# Default stdio transport
netforge-mcp serve --transport stdio

# Local Streamable HTTP transport
netforge-mcp serve --transport streamable-http --host 127.0.0.1 --port 8765
```

---

## Features & Architecture

NetForge exposes **82 MCP tools (25 in default `solve_lab` profile)**, **7 resources, 6 prompts**, and verified device profiles across **17 models** (`2911`, `1941`, `2811`, `4321`, `Router-PT`, `2960-24TT`, `Switch-PT`, `3560-24PS`, `3650-24PS`, `PC-PT`, `Laptop-PT`, `Server-PT`, `Printer-PT`, `7960` IP Phone, `Home-VoIP-PT`, `WRT300N`, `AccessPoint-PT`):

```text
netforge/
├── core/         # State separation (planned/executed/verified), OperationResult, settings
├── security/     # 5-tier permission enforcement, confirmation gates, secret redaction
├── devices/      # Verified Packet Tracer device catalog & interface normalization (17 models)
├── topology/     # NetworkX MultiGraph topology engine, cable rules, layout, Mermaid/ASCII export
├── ipam/         # IPv4/IPv6 CIDR math, VLSM allocator, conflict detection, addressing tables
├── ios/          # Structured IOS generators, capability pre-validators, CLI parser, unified diff
├── storage/      # Versioned SQLite WAL repository, snapshots, backups, JSON/YAML import & export
├── adapters/     # PT binary discovery, BackendRouter, 127.0.0.1 HTTP Script Bridge, .pts assets
├── gui/          # Optional Windows Win32/ctypes GUI fallback backend & safety failsafe
├── console/      # Device console state-machine, prompt handling, paging cleanup, paced CLI queue
├── simulation/   # Simulation/realtime controls, PDU specs, show/ping/ephone CLI parsers
├── diagnostics/  # Root-cause rules, ranked repair proposals, LabRunner, LabVerifier, ActivityGrader
└── mcp/          # Official Python MCP SDK server, 82 tools (25 default), 7 resources, 6 prompts, manifest
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NETFORGE_TOOL_PROFILE` | `solve_lab` | `solve_lab` (`25` focused lab tools) or `advanced` (all `82` tools) |
| `NETFORGE_PERMISSION_PROFILE` | `standard` | One of `read-only`, `planning`, `configuration`, `standard` |
| `NETFORGE_REQUIRE_CONFIRM` | `true` | Require explicit `confirm=True` for destructive actions |
| `NETFORGE_DATA_DIR` | `%LOCALAPPDATA%\netforge` (Win) / `~/.netforge` | Directory storing SQLite DB, backups, and bridge runtime files |
| `NETFORGE_DB_NAME` | `netforge.sqlite` | SQLite database filename |
| `NETFORGE_LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `NETFORGE_TRANSPORT` | `stdio` | Transport (`stdio`, `streamable-http`, `sse`) |
| `NETFORGE_PT_PATH` | *(auto-detect)* | Explicit path to `PacketTracer.exe` |

---

## Documentation

- [Windows & Packet Tracer Setup Guide](docs/windows-setup.md)
- [MCP Tools, Resources & Prompts Reference](docs/mcp-tools.md)
- [Packet Tracer Compatibility & Troubleshooting](docs/CAPABILITIES.md)
- [Architecture Overview](docs/ARCHITECTURE.md)
- [Benchmark Protocol & Reference Scoring](docs/BENCHMARK.md)
- [Linux & macOS Compatibility Roadmap](docs/cross-platform-roadmap.md)

---

## Live Verification & Benchmark Results

Only real **live** Cisco Packet Tracer (`8.2.2`) runs (`mode: "live_pt"`) are reported below; offline mocked dry-runs (`"mock": true` / `mode: "offline_mock"`) are synthetic harness checks only and are never reported as benchmark scores (see [Benchmark Protocol](docs/BENCHMARK.md)).

| Lab Suite | Mode | Score | Notes |
|---|---|---|---|
| `01_static_routing` | `live_pt` | **8/8 (100%)** | Multi-router static routing, `HWIC-2T` serial link, end-to-end ping |
| `02_vlan_dhcp` | `live_pt` | **5/5 (100%)** | 802.1Q trunking, router-on-a-stick, DHCP pools, PC lease & ping |
| `03_small_voice` | `live_pt` | **5/5 (100%)** | Cisco CME (`telephony-service`), DHCP Option 150, `7960` phone `REGISTERED` |

---

## Testing & Development

All unit and MCP protocol tests run completely offline with no Packet Tracer installation required:

```bash
pip install -e .[dev]
pytest
ruff check netforge tests
```

See [Contributing](CONTRIBUTING.md) and [Security Policy](SECURITY.md) for guidelines.

---

## Acknowledgements

NetForge's clean-room companion `.pts` Script Module architecture acknowledges prior open-source Packet Tracer MCP projects:
- [`Mats2208/MCP-Packet-Tracer`](https://github.com/Mats2208/MCP-Packet-Tracer) (MIT) — Pioneered the companion `.pts` Script Module + `127.0.0.1` HTTP bridge pattern.
- [`kiskander/pt-mcp-server`](https://github.com/kiskander/pt-mcp-server) (BSD-2-Clause) — Prior-art reference for broad Packet Tracer IPC coverage.

---

## License

Released under the [MIT License](LICENSE).
