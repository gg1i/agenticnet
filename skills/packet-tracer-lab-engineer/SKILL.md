---
name: packet-tracer-lab-engineer
description: >-
  Operational runbook for Cisco Packet Tracer 8.2.2+ automation via AgenticNet's
  Script Bridge, copy-on-write file lifecycle, 30-model catalog quirks, built-in
  reference guides, and closed-loop .pkt/.pka verification.
---

# Packet Tracer Lab Engineer

Execute and verify live Cisco Packet Tracer `8.2.2+` labs safely through AgenticNet's Script Bridge (`com.netforge.bridge`, shipped as `netforge_bridge.pts`).

## 1. Live Connection & File Lifecycle

1. **Check Bridge Connectivity First:**
   - Run `list_devices` or `lab_open`; if unavailable, instruct the user to run `agenticnet doctor` and verify `Extensions -> Scripting -> Configure PT Script Modules...` has `netforge_bridge.pts` checked **On Startup** in Packet Tracer.
   - If `lab_start` reports `waiting_for_login` (Skills for All / Guest wall) or `waiting_for_user_launch`, stop and let the user sign in or open PT visibly—never spam GUI clicks or spawn a second PT instance.
2. **Preserve Original Files (Copy-on-Write):**
   - Use `lab_open(..., copy_on_write=True)` or `lab_start` so edits save to `*_agenticnet.pkt` / working copy.
   - Only overwrite an original `.pkt`/`.pka` if explicitly authorized (`overwrite_original=True, confirm_overwrite_original=True`).
3. **Closed-Loop Lab Solving (`solve_lab` / `start_lab`):**
   - Open lab (`lab_open` / `lab_start`) -> capture baseline (`lab_snapshot`) -> enumerate every task ID into `task_ids` -> author declarative requirements via `verify_requirements_schema` -> build/configure -> iterate `lab_status(requirements=..., task_ids=...)` -> inspect `lab_diff` -> persist via `lab_save`.

## 2. Verified PT 8.2.2 Device Catalog (30 Models) & Quirks

Always call `device_capabilities(model=...)` and read `agenticnet://guides/{topic}` (`master`, `l2-l3`, `hosts`, `asa`, `wireless`, `iot`, `voip`) before selecting interfaces. Key verified platform facts:

| Model(s) | Interfaces & Naming | Critical PT 8.2.2 Quirks |
|---|---|---|
| `2911`, `1941`, `2811` | `2911`: `Gi0/0..2`; `1941`: `Gi0/0..1`; `2811`: `Fa0/0..1`; all `Se0/0/0..1` | Cold boot takes ~10s (`###...`) + `[yes/no]` dialog (`handleCliExec` handles this). Bridge `add_device` auto-inserts up to two `HWIC-2T` serial cards. |
| `4321`, `ISR4331` | `4321`: `Gi0/0/0..1`; `ISR4331`: `Gi0/0/0..2`, `Se0/1/0..1` (3-tuple) | Uses 3-tuple naming (`GigabitEthernet0/0/0`) and `NIM-2T` serial bays; crypto/ZBFW features may require `securityk9` license activation. |
| `Router-PT` | `Fa0/0`, `Fa1/0`, `Se2/0`, `Se3/0` | Slot-based numbering (`Serial2/0`, `Serial3/0`). |
| `2960-24TT` | `Fa0/1..24`, `Gi0/1..2` | **L2 only**: rejects `ip routing` and **rejects `switchport trunk encapsulation dot1q`**. |
| `Switch-PT` | `Fa0/1..4` | Minimal L2 switch; only 4 FastEthernet ports by default. |
| `3560-24PS` | `Fa0/1..24`, `Gi0/1..2` | **Requires `switchport trunk encapsulation dot1q` BEFORE `switchport mode trunk`**. Needs `ip routing` for L3 SVIs/routing; `no switchport` for routed ports; **no NAT/PAT in PT**. |
| `3650-24PS` | `Gi1/0/1..24`, `Gi1/1/1..4` (3-tuple) | **Requires `AC-POWER-SUPPLY` module before CLI boots** (`netforge_bridge.js` auto-attaches it on `device_add`; use Physical tab if opened manually without PSU). |
| `5505`, `5506-X` | `5505`: `Eth0/0..7` + `Vlan<id>`; `5506-X`: `Gi1/1..8` + `Management1/1` | `5505` uses switchports + VLAN SVIs (`nameif`/`security-level`); `5506-X` uses routed ports directly. Blank `Password:` on `enable`, `terminal pager 0`, no dynamic routing in PT. |
| `PC-PT`, `Laptop-PT`, `Server-PT`, `Printer-PT`, `Smartphone-PT`, `TabletPC-PT` | `FastEthernet0` (`Laptop-PT`/`Smartphone-PT`/`TabletPC-PT` also `Wireless0`) | **No Cisco IOS CLI.** Configure via `host_configure` (`dhcp=True` or static IP/mask/gateway/DNS); `Laptop-PT` wireless requires Physical-tab module swap. |
| `7960` (IP Phone) | `Switch`, `PC` ports | Needs power adapter if connected to non-PoE switch (`device_add` auto-powers via bridge; otherwise call `gui_attach_ip_phone_power`). Registers via SCCP / DHCP Option 150. |
| `Home-VOIP-PT`, `Analog-Phone-PT` | `Home-VOIP-PT`: `Fa0`, `Phone`; `Analog-Phone-PT`: `Phone` | Connect via RJ-11 `phone` cable (`Home-VOIP-PT:Phone` <-> `Analog-Phone-PT:Phone`). |
| `WRT300N`, `AccessPoint-PT`, `HomeGateway-PT` | `WRT300N`/`HomeGateway`: `Internet`, `Eth1..4`, `Wireless`; `AP-PT`: `Port0`, `Port1` | Configured via Config/Web GUI rather than IOS CLI (`AccessPoint-PT` is L2 bridge-only; `HomeGateway-PT` hosts IoT SSID). |
| `WLC-2504`, `WLC-3504`, `WLC-PT`, `LAP-PT`, `3702i`, `Cloud-PT` | `WLC`: `Gi1..4/5` + `management`; `LAP-PT`/`3702i`: `Gi0`, `Dot11Radio0`; `Cloud-PT`: `Eth6`, `Se0..3` | `LAP-PT`/`3702i` connect via `straight_through` to switchports and need PoE/power brick + CAPWAP WLC discovery (Option 43 / DNS); `WLC`/`Cloud-PT` use Web/Config GUI. |

## 3. Script Bridge Constraints & GUI Fallback Escalation

- `terminal length 0` returns `status=2` on PT `2911` routers; AgenticNet marks it non-fatal and auto-advances `--More--` prompts.
- Prefer `console_execute(..., batch_configs={...})` for multi-device CLI provisioning rather than single-command round-trips.
- Avoid `gui_screenshot` or raw GUI clicks when `console_execute`, `list_devices`, `verify_lab`, or `interface_status(live=True)` provide exact text evidence.
- **When the Script Bridge Cannot Automate an Action:** Escalate to the Windows GUI tools (available when `AGENTICNET_TOOL_PROFILE=advanced` is enabled and the Windows desktop is unlocked)—specifically for `3650-24PS` PSU installation, `Laptop-PT` Ethernet-to-wireless module swaps, `Server-PT` GUI Services (DHCP/DNS/HTTP), `WRT300N`/`AccessPoint-PT` GUI config, `Simulation` toolbar clicks, and Physical-tab dragging (`gui_calibrate` -> `gui_state_inspect` -> `gui_batch` / `gui_click` / `gui_keypress`, using `gui_screenshot` / `click_template` only when visual verification or locating unanchored controls is required). `gui_batch` supports `click`, `click_dialog` (supports `nx`/`ny` or `offset_x`/`offset_y`), `click_template`, `drag`, `drag_dialog` (supports `from_nx`/`from_ny`/`to_nx`/`to_ny` or pixel offsets), `wait_dialog`, `close_dialog`, `keypress`, `paste_lines`, `sleep`, and `screenshot`.
- `grade_lab` is fail-closed: if `.pka` Assessment mode or password protection hides grading, report `unavailable` and rely on `verify_lab`.
