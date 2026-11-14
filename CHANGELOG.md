# Changelog

All notable changes to **NetForge MCP** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13 (Phase 1: Core Foundation)

### Added
- Initial modular Python package structure (`netforge/` across `core`, `security`, `devices`, `topology`, `ipam`, `ios`, `storage`, `adapters`, `mcp`, and placeholder subpackages for upcoming Phases 2–4).
- Core runtime primitives: explicit truth/state separation (`planned`, `executed`, `verified`), operation IDs, structured `OperationResult` and `NetForgeError` taxonomy, stderr-safe logging, and environment settings (`NetForgeSettings`).
- Security subsystem: five-tier permission model (`read_only`, `planning`, `configuration`, `gui_control`, `destructive`), destructive-action confirmation guardrails, credential/secret redaction, and safe filesystem path resolution.
- Device capability registry (`DeviceCatalog`) covering verified Cisco Packet Tracer 8.2.x device profiles (`2911`, `1941`, `2811`, `4321`, `Router-PT`, `2960-24TT`, `Switch-PT`, `3560-24PS`, `3650-24PS`, `PC-PT`, `Laptop-PT`, `Server-PT`, `Printer-PT`, `WRT300N`, `AccessPoint-PT`) with interface normalization and capability checks.
- Graph-based `TopologyEngine` backed by NetworkX `MultiGraph`, supporting device CRUD, occupied-port detection, Cisco MDI/MDI-X cable selection, hierarchical auto-layout, graph analysis (bridges/SPOFs, shortest paths, switching cycles), Mermaid/ASCII visualization, and JSON/YAML import/export.
- Full IPAM engine (`IPAMEngine`) supporting IPv4/IPv6 CIDR math, VLSM allocation, gateway & DHCP pool planning, conflict detection, utilization reports, and exportable addressing tables.
- Structured Cisco IOS generator and validator (`IOSGenerator`, `validators`, `ConfigHistory`) supporting interfaces, subinterfaces, SVIs, VLANs, 2960 vs. 3560 trunking, static routes, RIPv2, OSPF, EIGRP, DHCP, NAT/PAT, Standard/Extended ACLs, SSHv2, CLI error detection, and unified config diffs.
- Versioned SQLite persistence (`SQLiteStore`) with schema migrations, immutable config snapshots, redacted execution audit logs, backups, and portable JSON/YAML project import/export.
- Official Python MCP SDK (`mcp>=2.0.0`, `MCPServer`) server exposing 42 real Phase 1 tools across `project`, `topology`, `devices`, `connections`, `ipam`, `configuration`, and `cli`, plus 6 MCP resources (including `netforge://manifest`), 4 agent workflow prompts, stdio transport, and HTTP-ready transport configuration.
- Comprehensive offline unit test suite, MCP in-memory protocol test, and Windows stdio subprocess handshake smoke test.
