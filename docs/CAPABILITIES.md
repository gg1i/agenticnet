# Packet Tracer Compatibility & Capabilities Guide

**Tested Simulator:** Cisco Packet Tracer `8.2.2` (Windows 10/11)  
**Cross-Platform Core:** Windows, Linux, and macOS (offline topology, IPAM, IOS validation, SQLite storage, MCP server)

---

## 1. Operational Modes & Backends

AgenticNet separates local network modeling from live simulator execution so every tool response clearly reports both its execution backend (`execution_backend`) and state truth level (`planned`, `executed`, `verified`):

| Capability | Primary Path (`script_backend`) | Fallback / Offline Path | Notes for Users |
|---|---|---|---|
| **Add / Remove / Move Devices** | `LogicalWorkspace.addDevice` / `removeDevice` / `moveToLocation` | Offline `TopologyEngine` | Automatically inserts `HWIC-2T` serial cards on `2911`/`1941`/`2811` routers, `AC-POWER-SUPPLY` on `3650-24PS` L3 switches, and auto-powers Cisco `7960` IP phones when added via `netforge_bridge.js`. Re-export `netforge_bridge.pts` via Packet Tracer's Script Module Builder if upgrading an older `.pts` archive; `BackendRouter` falls back cleanly to offline state if an older `.pts` lacks a new opcode. |
| **Create / Remove Cables** | `LogicalWorkspace.createLink` / `deleteLink` | Offline auto MDI/MDI-X planner | Supports Ethernet straight/cross, Fiber, Serial DCE/DTE (with automatic endpoint swap for `serial_dte`), Phone, Console, Coaxial, Octal, IoT Custom, USB, and Auto cabling. |
| **IOS & ASA CLI Execution** | Direct `TerminalLine` execution + paging handling (`--More--` & `<--- More --->`) | `WindowsGuiConsoleTransport` / offline IOS validation | Waits cleanly for cold-boot prompts, handles IOS & ASA (`enable` blank `Password:`, `[confirm]`, RSA modulus, `?` help, submodes), supports `capture_before_after=True` config diffs, and gates destructive CLI commands (`reload`, `write erase`, `erase`, `delete`, `format`) behind `confirm=True`. |
| **Host IP / Gateway / DNS Setup** | Direct `HostPort` IPC + PC `ipconfig` fallback | Offline IPAM planning | Supports IPv4 static addressing, subnet mask, default gateway, `dns_server`, and DHCP renewal on `PC-PT` / `Laptop-PT` / `Server-PT` / wireless hosts. |
| **File Lifecycle (`.pkt` / `.pka`)** | `AppWindow.fileOpen` & `fileSaveAsNoPrompt` + live topology/IPAM hydration | Safe sibling copy-on-write (`*_agenticnet.pkt`) | `lab_open` automatically hydrates `TopologyEngine`, `IPAMEngine`, and IOS hostname aliases from the live workspace; overwriting a pre-existing non-working-copy `.pkt`/`.pka` file requires `overwrite=True` and `confirm=True`. |
| **Live Verification (`verify_lab`)** | Parallel live CLI queries (`show` + `ping`) | Bounded retry loop | Verifies interfaces, routes, VLANs/trunks, DHCP bindings, Cisco CME phones, and real ICMP ping success with raw CLI evidence. |
| **`.pka` Activity Grading (`grade_lab`)** | Read-only `ActivityFile` completion & item tree | Automatic fallback to `verify_lab` | Never bypasses instructor locks; cleanly reports `"unavailable"` when an activity locks assessment reads and verifies via CLI instead. |
| **Physical-Tab Fallback (`gui_*`)** | Windows desktop Win32 adapter (`GuiBackend`) | Explicit error when desktop is locked | Required only for raw desktop clicks or Physical-tab drag fallback (`gui_attach_ip_phone_power` mouse-drag fallback is `status="experimental"`; Script Bridge `7960` power succeeds without mouse input). |

---

## 2. Known Cisco Packet Tracer `8.2.2` Quirks Handled Automatically

- **Router Cold Boot Delay (`~10s`):** Fresh `2911` and similar ISR routers decompress IOS images (`###...`) before showing `initial configuration dialog`. AgenticNet's bridge waits for the live CLI prompt rather than sending commands blindly.
- **`terminal length 0` Non-Fatal on PT Routers & ASA Paging:** Packet Tracer `2911` IOS rejects `terminal length 0` (`status=2`), while ASA (`5505`/`5506-X`) uses `terminal pager 0`, `<--- More --->`, and a blank `Password:` prompt after `enable`. AgenticNet handles both automatically.
- **`3650-24PS` Modular Power Supply:** Packet Tracer `3650-24PS` L3 switches spawn unpowered without `AC-POWER-SUPPLY`; `netforge_bridge.js` auto-attaches the power supply on creation, and built-in quirk guides are exposed via `agenticnet://guides/{topic}` (`master`, `l2-l3`, `hosts`, `asa`, `wireless`, `iot`, `voip`).
- **No Unnecessary Screenshots:** Whenever CLI/IPC read-back answers a question (`show ip interface brief`, `show running-config`, `show ip route`), AgenticNet uses structured text rather than taking screenshots.

---

## 3. Troubleshooting Live Connections

Run `agenticnet doctor` at any time to check environment health (home directory usernames and bridge tokens are automatically redacted from output):

- **`"script_bridge.state": "connected"`**: Packet Tracer and the MCP server are paired and ready.
- **`"script_bridge.state": "bridge_listening_pt_idle"`**: Open Packet Tracer, check `Extensions -> Scripting -> Configure PT Script Modules...`, ensure `netforge_bridge.pts` is enabled **On Startup**, and restart Packet Tracer.
- **`"packet_tracer_detected": false`**: Install Cisco Packet Tracer `8.2.2+` or set `AGENTICNET_PT_PATH` (legacy `NETFORGE_PT_PATH` also supported) to your `PacketTracer.exe` path.
