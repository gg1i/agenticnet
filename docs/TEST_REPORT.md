# NetForge MCP Test & Live Verification Report

This report records the verified live Cisco Packet Tracer (`8.2.2.0400`) runs alongside offline automated tests (`pytest`) for NetForge MCP, strictly separating **`verified live`** evidence from **`offline only`** and **`pending / blocked`** tracks.

---

## 1. Live Packet Tracer `8.2.2.0400` Verification Summary

Machine-readable evidence artifact: [`docs/evidence/phase5_live_verification.json`](evidence/phase5_live_verification.json) (`timestamp_utc`: `2026-11-15T22:02:11.041324+00:00`).

### 1.1 Lab Lifecycle Persistence (`lab_save` -> Close PT -> Fresh PT -> `lab_open` -> `lab_status`) — **VERIFIED LIVE**

Executed against a fresh 2-router lab (`Router0` <-> `Router1`) built from a blank canvas in Cisco Packet Tracer `8.2.2.0400`:

| Stage | Tool / Action | Observed Live Result |
|---|---|---|
| 1. Baseline check | `lab_status` | `overall_passed=false`, `failing_count=6` (`r1_host`, `r2_host`, `r1_ip`, `r2_ip`, `r1_up`, `r2_up`) |
| 2. Configuration | `console_execute` + `write memory` | Configured `R1-LIVE` (`10.10.10.1/30`), `R2-LIVE` (`10.10.10.2/30`), `no shutdown` on `GigabitEthernet0/0`, saved NVRAM |
| 3. Pre-save verify | `lab_status` | `overall_passed=true`, `state_level="verified"`, `summary`: `total=6, passed=6, failed=0, errors=0` |
| 4. Save `.pkt` | `lab_save` | `success=true`, `execution_backend="script_backend"`, `data.ok=true`, `overwrite=true`, saved `%LOCALAPPDATA%\netforge\phase5_solved_roundtrip.pkt` (`39,548` bytes) |
| 5. Cold PT restart | Close `PacketTracer.exe`, launch fresh PT | `relaunch_bridge_ping_ok=true` |
| 6. Reopen `.pkt` | `lab_open` | `success=true`, `execution_backend="script_backend"` |
| 7. Post-reopen verify | `lab_status` + `lab_snapshot` | `post_reopen_status`: `overall_passed=true`, `state_level="verified"`, `6/6` passed (`what_is_left_is_empty=true`, `grader_fallback_note="Activity completion status is unavailable."`); `LabVerifier._read_cli` auto-elevated reopened User Exec prompts (`R1-LIVE>` -> `enable`); `lab_snapshot` reported `3` devices, `1` link (`Router0:GigabitEthernet0/0` <-> `Router1:GigabitEthernet0/0`), `port_up=true`, `protocol_up=true` |

### 1.2 External Stock `.pkt` Discovery (`list_devices` & `lab_snapshot`) — **VERIFIED LIVE**

Opened an external Packet Tracer sample file not constructed by NetForge (`<PT_DIR>\saves\01 Networking\DHCP\dhcp_reservation.pkt`) via `lab_open` (`success=true`, `execution_backend="script_backend"`, `state_level="executed"`):

- **`list_devices`**: `device_count=10`
  - `Wireless Router0` (`Linksys-WRT300N`, `hostname="Wireless Router0"`, `type="wireless_router"`, `type_code=11`, `port_count=9`)
  - `PC0`–`PC5` (`PC-PT`, `hostname="PC0"`–`"PC5"`, `type="pc"`, `type_code=8`, `port_count=2`)
  - `Switch0`, `Switch1` (`2960-24TT`, `hostname="Switch0"`/`"Switch1"`, `type="switch"`, `type_code=1`, `port_count=27`)
  - `Power Distribution Device0` (`Power Distribution Device`, `type="other"`, `type_code=45`, `port_count=0`)
- **`lab_snapshot`**:
  - `device_count=10`, `link_count=4`, `active_interface_count=23`
  - Links resolved via `Cable::getOtherPort`:
    - `Switch1:FastEthernet0/1` <-> `PC5:FastEthernet0`
    - `Switch1:FastEthernet0/2` <-> `PC4:FastEthernet0`
    - `PC2:FastEthernet0` <-> `Switch0:FastEthernet0/1`
    - `PC3:FastEthernet0` <-> `Switch0:FastEthernet0/2`
  - Interface state included `Wireless Router0:Vlan1` (`192.168.0.1 / 255.255.255.0`, `port_up=true`, `protocol_up=true`) and `PC2`–`PC5` `FastEthernet0` interfaces (`169.254.*` with resolved remote switch ports).

### 1.3 Prior Live Capabilities & Known Live Limitations

See [`docs/CAPABILITIES.md`](CAPABILITIES.md) for earlier live checks (`sokoban.pka`, `mqttdemo.pka` via `grade_lab` / `open_file`, and `7960` Physical-tab geometry).

- **`gui_attach_ip_phone_power`**: **Experimental / Blocked in isolated agent desktop (`0/5` live `SendInput` attempts)**. Fails closed when `GetForegroundWindow() == 0`; run `scripts/verify_7960_power_reliability.py` directly on an interactive unlocked `WinSta0\Default` Windows session.
- **Phase 5 AI-Agent End-to-End Benchmark (`01_static_routing`, `02_vlan_dhcp`, `03_small_voice`)**: **Pending live run** (only offline mock harness checks exist today; never reported as live benchmark scores).

---

## 2. Offline Automated Verification Summary (`offline only`)

All unit and MCP protocol integration tests run offline without live Packet Tracer (`MockBackend` / mocked `ScriptBackend` / FastMCP stdio server):

| Check | Scope | Mode | Expected / Verified Contract |
|---|---|---|---|
| `python -m pytest -q` | Full unit + integration suite | `offline only` | Verifies MCP tool registration (`79` `advanced` / `22` default `solve_lab`), `solve_lab` prompt & resource alignment, fail-closed `list_devices` / `lab_snapshot`, `LabVerifier` polling wait (`45.0s` default on live `HttpScriptBridgeBackend`, `0.0s` default on offline mocks) + failure-with-evidence, `PacedDeviceCliQueue` pacing & bounded retries (including User Exec `>` auto-`enable`), and doc/README manifest count sync (`docs/manifest.json`) |
| `python -m ruff check .` | Package & test lint | `offline only` | Zero lint errors across `netforge/`, `scripts/`, and `tests/` |
| `python -m netforge version` & `manifest` | CLI smoke checks | `offline only` | Clean CLI startup and deterministic manifest serialization |
