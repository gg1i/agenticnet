# Linux & macOS Compatibility Roadmap

## Supported Cross-Platform Today (Windows, Linux, macOS)
- All core engines (`core`, `security`, `devices`, `topology`, `ipam`, `ios`, `diagnostics`, `storage`, `mcp`) use pure cross-platform Python (`mcp`, `pydantic`, `networkx`, `pyyaml`, `sqlite3`).
- Offline topology planning, VLSM/CIDR IPAM, Cisco IOS command generation & validation, SQLite project persistence, and the MCP server (`stdio` and Streamable HTTP) run natively on **Windows, Linux, and macOS**.

## Live Cisco Packet Tracer Control
- **Windows (Supported)**: Native `127.0.0.1` Script Bridge (`com.netforge.bridge`) + Win32 GUI/DPI fallback adapter (`WindowsGuiBackend`) tested with Cisco Packet Tracer `8.2.2`.
- **Linux (Planned)**: Native Script Bridge works identically once Packet Tracer's scripting bridge connects to localhost; X11/XWayland window automation adapter planned behind `GuiBackend`.
- **macOS (Planned)**: Native Script Bridge compatibility + macOS Accessibility (`AXUIElement`) / window bounds adapter behind `GuiBackend`.
