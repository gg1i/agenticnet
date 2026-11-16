# Windows Setup Guide (Cisco Packet Tracer 8.2.2)

Windows 10/11 is required for live Cisco Packet Tracer desktop automation. Offline planning, IPAM, IOS validation/generation, and MCP server tests work without Packet Tracer on any OS.

---

## 1. Prerequisites

- **Python 3.11 or 3.12** (`python --version`)
- **Cisco Packet Tracer 8.2.2+** installed locally (default path checked: `C:\Program Files\Cisco Packet Tracer 8.2.2\bin\PacketTracer.exe`; override with `AGENTICNET_PT_PATH` or legacy `NETFORGE_PT_PATH` if installed elsewhere)

---

## 2. One-Command Install & MCP Client Setup

From the cloned repository root in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -WithGui -Client antigravity
```

- Replace `-Client antigravity` with `claude`, `cursor`, `vscode`, or omit `-Client` to print the ready-to-paste MCP JSON snippet without modifying client files.
- Add `-ToolProfile advanced` if you want all **82** tools (including `gui_*` fallback).
- The script creates `.venv`, installs AgenticNet (`pip install -e ".[gui]"`), copies `netforge_bridge.pts`, configures your MCP client using the exact `.venv` Python path (no `PATH` changes required), and runs `agenticnet doctor`.

### Manual Alternative

```powershell
pip install ".[gui]"
agenticnet setup --client claude
agenticnet doctor
```

---

## 3. Connect Packet Tracer (One-Time Script Module Setup)

AgenticNet communicates directly with Packet Tracer through a clean, local-only script module (`com.netforge.bridge`, filename `netforge_bridge.pts`) rather than brittle macros. `setup` copies the module and mirrors it into `%LOCALAPPDATA%\netforge\netforge_bridge.pts`; register it once inside Packet Tracer:

1. Open **Cisco Packet Tracer**.
2. Go to **Extensions -> Scripting -> Configure PT Script Modules...**
3. Click **Add**, select `%LOCALAPPDATA%\netforge\netforge_bridge.pts`.
4. Check **On Startup**, click **Save**, and accept when Packet Tracer prompts for script privileges (only asked once).
5. Close and reopen Packet Tracer from the Start Menu.

> **Note:** AgenticNet never modifies `PT.conf` or Packet Tracer's installation folder. AgenticNet stores its SQLite DB under `%LOCALAPPDATA%\agenticnet` and mirrors `bridge_session.json` dynamically to `%LOCALAPPDATA%\netforge\bridge_session.json` so `netforge_bridge.pts` discovers it cleanly.

---

## 4. Verify Live Connection

With **Packet Tracer open** and your MCP client running (or `agenticnet serve --transport stdio` running in another terminal), run:

```powershell
agenticnet doctor
```

Check `"script_bridge"`:
- `"connected": true` and `"state": "connected"` -> Ready to build and verify live labs.
- `"state": "bridge_listening_pt_idle"` -> The server is running, but Packet Tracer hasn't loaded `netforge_bridge.pts` yet. Recheck **On Startup** in **Configure PT Script Modules...** and restart Packet Tracer.
- `"state": "offline"` -> Start your MCP client or run `agenticnet serve` so a bridge session is active.

---

## 5. Notes on Desktop GUI Fallback

- All topology creation, cabling, IOS CLI configuration, PC IP setup, `.pkt`/`.pka` file open/save, verification, and `.pka` activity grading use the **HTTP Script Bridge** (`script_backend`) with no mouse hijacking.
- Only Physical-tab / modal fallback actions (`gui_*`, available in `AGENTICNET_TOOL_PROFILE=advanced` plus `gui_attach_ip_phone_power`) require an unlocked interactive Windows desktop session.
