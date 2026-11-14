# Linux & macOS Compatibility Roadmap

## Phase 1 (Supported Cross-Platform Today)
- All core engines (`core`, `security`, `devices`, `topology`, `ipam`, `ios`, `storage`, `mcp`) use pure cross-platform Python (`mcp`, `pydantic`, `networkx`, `pyyaml`, `sqlite3`).
- Offline planning, VLSM, topology validation, IOS command generation, SQLite project persistence, and MCP stdio/HTTP serving work identically on **Windows, Linux, and macOS**.

## Phases 2–3 (GUI & Window Automation)
- **Windows (Primary)**: Native Win32 (`pywin32` / `ctypes`), DPI scaling awareness, Pillow/OpenCV visual calibration.
- **Linux (X11 / XWayland)**: `wmctrl`/`xdotool` window management + `mss`/Pillow capture adapter behind `GuiBackend`. Wayland native input restrictions will be documented explicitly.
- **macOS**: Accessibility (`AXUIElement`) + AppleScript/Quartz window bounds adapter behind `GuiBackend` (requires macOS Screen Recording & Accessibility permissions).
