# Packet Tracer Compatibility & Capabilities Guide

**Tested Simulator:** Cisco Packet Tracer `8.2.2` (Windows 10/11)  
**Cross-Platform Core:** Windows, Linux, and macOS (offline topology, IPAM, IOS validation, SQLite storage, MCP server)

---

## 1. Operational Modes & Backends

AgenticNet separates local network modeling from live simulator execution so every tool response clearly reports both its execution backend (`execution_backend`) and state truth level (`planned`, `executed`, `verified`):

| Capability | Primary Path (`script_backend`) | Fallback / Offline Path | Notes for Users |
|---|---|---|---|
| **Add / Remove / Move Devices** | `LogicalWorkspace.addDevice` / `removeDevice` / `moveToLocation` | Offline `TopologyEngine` | Automatically inserts `HWIC-2T` serial cards on `2911`/`1941`/`2811` routers and auto-powers Cisco `7960` IP phones when added via the bridge. |
| **Create / Remove Cables** | `LogicalWorkspace.createLink` / `deleteLink` | Offline auto MDI/MDI-X planner | Supports Ethernet straight/cross, Fiber, Serial DCE/DTE, Phone, Console, and Auto cabling. |
| **IOS CLI Execution & Read-Back** | Direct `TerminalLine` execution + paging handling | `WindowsGuiConsoleTransport` / offline IOS validation | Waits cleanly for router/switch boot prompts, auto-elevates User Exec (`>`) to Privileged Exec (`#`), and paginates long outputs. |
| **Host IP / Gateway Setup** | Direct `HostPort` IPC + PC `ipconfig` fallback | Offline IPAM planning | Supports IPv4 static addressing, subnet mask, default gateway, DNS, and DHCP renewal on `PC-PT` / `Laptop-PT` / `Server-PT`. |
| **File Lifecycle (`.pkt` / `.pka`)** | `AppWindow.fileOpen` & `fileSaveAsNoPrompt` | Safe sibling copy-on-write (`*_agenticnet.pkt`) | Original `.pkt`/`.pka` files are preserved by default unless `overwrite=True` is explicitly requested. |
| **Live Verification (`verify_lab`)** | Parallel live CLI queries (`show` + `ping`) | Bounded retry loop | Verifies interfaces, routes, VLANs/trunks, DHCP bindings, Cisco CME phones, and real ICMP ping success with raw CLI evidence. |
| **`.pka` Activity Grading (`grade_lab`)** | Read-only `ActivityFile` completion & item tree | Automatic fallback to `verify_lab` | Never bypasses instructor locks; cleanly reports `"unavailable"` when an activity locks assessment reads and verifies via CLI instead. |
| **Physical-Tab Fallback (`gui_*`)** | Windows desktop Win32 adapter (`GuiBackend`) | Explicit error when desktop is locked | Required only for raw desktop clicks or Physical-tab drag fallback (`gui_attach_ip_phone_power` mouse-drag fallback is *experimental: not yet validated by the 5-attempt live protocol*; Script Bridge `7960` power succeeds without mouse input). |

---

## 2. Known Cisco Packet Tracer `8.2.2` Quirks Handled Automatically

- **Router Cold Boot Delay (`~10s`):** Fresh `2911` and similar ISR routers decompress IOS images (`###...`) before showing `initial configuration dialog`. AgenticNet's bridge waits for the live CLI prompt rather than sending commands blindly.
- **`terminal length 0` Non-Fatal on PT Routers:** Packet Tracer `2911` IOS rejects `terminal length 0` (`status=2`). AgenticNet handles `--More--` pagination automatically and marks that specific check non-fatal.
- **No Unnecessary Screenshots:** Whenever CLI/IPC read-back answers a question (`show ip interface brief`, `show running-config`, `show ip route`), AgenticNet uses structured text rather than taking screenshots.

---

## 3. Troubleshooting Live Connections

Run `agenticnet doctor` at any time to check environment health (home directory usernames and bridge tokens are automatically redacted from output):

- **`"script_bridge.state": "connected"`**: Packet Tracer and the MCP server are paired and ready.
- **`"script_bridge.state": "bridge_listening_pt_idle"`**: Open Packet Tracer, check `Extensions -> Scripting -> Configure PT Script Modules...`, ensure `netforge_bridge.pts` is enabled **On Startup**, and restart Packet Tracer.
- **`"packet_tracer_detected": false`**: Install Cisco Packet Tracer `8.2.2+` or set `AGENTICNET_PT_PATH` (legacy `NETFORGE_PT_PATH` also supported) to your `PacketTracer.exe` path.
