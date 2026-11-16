# Changelog

All notable changes to **NetForge MCP** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **One-Command Installer & `netforge-mcp setup`**: Added `netforge-mcp setup` CLI command (`--client`, `--tool-profile`, `--dry-run`, `--json`) to install/mirror `netforge_bridge.pts`, auto-detect Packet Tracer, check GUI dependencies, and safely merge `netforge` into Antigravity, Claude Desktop, Cursor, or VS Code MCP configs (with `.bak` backup), plus cross-platform bootstrap scripts (`scripts/install.ps1` and `scripts/install.sh`) and removed unused `pyautogui` from `[gui]` extras.
- **Portable Engineering Skill Pack (`skills/`)**: Added 9 specialist `SKILL.md` modules (`senior-network-engineer`, `packet-tracer-lab-engineer`, `network-architecture`, `ip-addressing`, `switching-and-vlans`, `routing`, `ios-configuration-review`, `troubleshooting-and-verification`, `network-security-basics`) plus `skills/README.md` and unit validation (`tests/unit/test_skills_pack.py`).
- **Diagnostics, IOS & GUI Fallback Hardening**: Added switch-to-switch `TRUNK_MODE_MISMATCH` and `HOST_GATEWAY_OUTSIDE_SUBNET` diagnostics (`netforge/diagnostics/rules.py`), `MISSING_TRUNK_ENCAP_DOT1Q`, `UNSUPPORTED_ROUTING_PROTOCOL`, `UNSUPPORTED_SUBINTERFACE_ENCAP`, and `INVALID_IP_OR_MASK` static IOS checks (`netforge/ios/validators.py`), and DPI-normalized `nx`/`ny` coordinate support for `click_dialog` and `drag_dialog` in `WindowsGuiBackend.execute_batch`.

### Fixed
- **IPAM Default Gateway Suggestion**: Fixed `check_missing_default_gateways` iterating over `ipam.state.pools` dict keys instead of `.values()`, restoring accurate pool gateway lookups.

## [0.1.0] - 2026-11-16

### Added
- **One-Command Live Lab Workflow (`lab_start` / `start_lab`)**: Accepts a natural-language topology brief, lab spec file (`.md` / `.txt` / PDF), or existing `.pkt` / `.pka` file; proposes a plan before modifying Packet Tracer; executes step-by-step with live snapshots (`lab_snapshot`), diffs (`lab_diff`), and copy-on-write `*_netforge.pkt` saving so original lab files stay untouched.
- **Native Packet Tracer Script Bridge (`com.netforge.bridge`)**: Localhost `127.0.0.1` HTTP/WebView bridge with persistent HTTP/1.1 keep-alive, per-session CSPRNG token authentication, single-round-trip `batch_ops`, automatic `HWIC-2T` serial module provisioning, Cisco `7960` IP phone auto-power, host IP/gateway configuration, and CLI execution.
- **Live Verification, Grading & Diagnostics**: Structured `verify_lab` CLI parsers (`show ip interface brief`, `show ip route`, `show vlan brief`, `show dhcp`, `show telephony-service`, live `ping`), read-only `.pka` assessment checking (`grade_lab`), `lab_status` task tracking, and root-cause `diagnostics` repair proposals.
- **Cross-Platform Network Engineering Core**: NetworkX topology builder with Cisco cable selection and Mermaid/ASCII export, IPv4/IPv6 VLSM/CIDR IPAM engine, validated Cisco IOS generator and pre-validator for 17 Packet Tracer device models, SQLite WAL storage with snapshot history and audit redaction, and permission profiles (`read_only`, `planning`, `configuration`, `gui_control`, `destructive`).
- **MCP Server & CLI**: Official Python MCP SDK (`mcp>=2.0.0`) server exposing **82** total tools (**25** curated default tools in `solve_lab` profile, full suite in `advanced`), **7** resources, **6** prompts, and `netforge-mcp` CLI (`serve`, `doctor`, `install-module`, `manifest`, `version`).
