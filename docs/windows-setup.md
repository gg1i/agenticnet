# Windows Setup Guide (Cisco Packet Tracer 8.2.2)

Windows 10/11 is required for live Cisco Packet Tracer desktop automation. Offline planning, IPAM, IOS validation/generation, and MCP server tests work without Packet Tracer on any OS.

---

## 1. Prerequisites

- **Python 3.11 or 3.12** (`python --version`)
- **Cisco Packet Tracer 8.2.2+** installed locally (default path checked: `C:\Program Files\Cisco Packet Tracer 8.2.2\bin\PacketTracer.exe`; override with `NETFORGE_PT_PATH` if installed elsewhere)

---

## 2. Install NetForge MCP

```powershell
git clone https://github.com/gg1i/netforge-mcp.git
cd netforge-mcp
pip install .
```

Verify installation:

```powershell
netforge-mcp version
netforge-mcp doctor
```

If you also want optional Windows screen-capture / GUI fallback helpers (`pillow`, `opencv-python`, `psutil`, `pywin32`), install the `gui` extra:

```powershell
pip install ".[gui]"
```

---

## 3. Connect Packet Tracer (One-Time Script Module Setup)

NetForge communicates directly with Packet Tracer through a clean, local-only script module (`com.netforge.bridge`) rather than brittle macros. Register it once:

1. Copy the bundled module into `%LOCALAPPDATA%\netforge\netforge_bridge.pts`:
   ```powershell
   netforge-mcp install-module
   ```
2. Open **Cisco Packet Tracer**.
3. Go to **Extensions -> Scripting -> Configure PT Script Modules...**
4. Click **Add**, select `%LOCALAPPDATA%\netforge\netforge_bridge.pts`.
5. Check **On Startup**, click **Save**, and accept when Packet Tracer prompts for script privileges (only asked once).
6. Close and reopen Packet Tracer from the Start Menu.

> **Note:** NetForge never modifies `PT.conf` or Packet Tracer's installation folder. `%LOCALAPPDATA%\netforge\bridge_session.json` is created dynamically when the MCP server runs.

---

## 4. Add NetForge to Your MCP Client

Copy [`examples/claude_desktop_config.json`](../examples/claude_desktop_config.json) (Claude Desktop) or [`examples/mcp_config.json`](../examples/mcp_config.json) (Cursor, VS Code Copilot, Windsurf, Google Antigravity, etc.) into your client's MCP config:

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

If `netforge-mcp` is inside a virtual environment not on `PATH`, set `"command"` to that virtualenv's `python.exe` and `"args": ["-m", "netforge", "serve", "--transport", "stdio"]`.

---

## 5. Verify Live Connection

With **Packet Tracer open** and your MCP client running (or `netforge-mcp serve --transport stdio` running in another terminal), run:

```powershell
netforge-mcp doctor
```

Check `"script_bridge"`:
- `"connected": true` and `"state": "connected"` -> Ready to build and verify live labs.
- `"state": "bridge_listening_pt_idle"` -> The server is running, but Packet Tracer hasn't loaded `netforge_bridge.pts` yet. Recheck **On Startup** in **Configure PT Script Modules...** and restart Packet Tracer.
- `"state": "offline"` -> Start your MCP client or run `netforge-mcp serve` so a bridge session is active.

---

## 6. Notes on Desktop GUI Fallback

- All topology creation, cabling, IOS CLI configuration, PC IP setup, `.pkt`/`.pka` file open/save, verification, and `.pka` activity grading use the **HTTP Script Bridge** (`script_backend`) with no mouse hijacking.
- Only Physical-tab / modal fallback actions (`gui_*`, available in `NETFORGE_TOOL_PROFILE=advanced` plus `gui_attach_ip_phone_power`) require an unlocked interactive Windows desktop session.
