# Windows Setup Guide

Windows 10/11 is the primary development and Packet Tracer testing platform for NetForge MCP.

## 1. Prerequisites

- **Python 3.11 or 3.12** (`python --version`)
- **Cisco Packet Tracer 8.2.x** (optional for Phase 1; required for Phases 2–3 desktop automation)

## 2. Install NetForge MCP

```powershell
cd "C:\path\to\netforge-mcp"
pip install -e .[dev]
```

Or without downloading optional extras if already satisfied:

```powershell
pip install --no-build-isolation --no-deps -e .
```

## 3. Verify Installation

```powershell
netforge-mcp doctor
```

Expected output reports Python version, `data_dir`, permission profile, and whether `PacketTracer.exe` was detected (e.g., `C:\Program Files\Cisco Packet Tracer 8.2.2\bin\PacketTracer.exe`).

## 4. Configure Antigravity or Claude Desktop

Copy `examples/antigravity_mcp_config.json` or `examples/claude_desktop_config.json` into your client's MCP configuration.
