# Stranger Test Checklist (Pre-Phase 7 Release Gate)

Run this end-to-end verification on a **second Windows user profile, separate PC, or clean VM** before public release (Phase 7) to prove zero host-specific paths, secrets, or manual dev setup are assumed.

## Prerequisites
- Clean user account or VM with Python **3.11+** and Cisco Packet Tracer **8.2.2** installed.
- Unlocked interactive desktop session (required during one-time PT Script Module registration and any GUI fallback steps).

## Verification Steps
1. **Install NetForge cleanly:**
   ```bash
   pip install -e .
   netforge version
   ```
   Confirm `netforge install-module --help` and `netforge doctor` run cleanly with zero missing assets or hardcoded dev paths.

2. **Install the bundled Script Module (`.pts`):**
   ```bash
   netforge install-module
   ```
   Confirm `%LOCALAPPDATA%\netforge\netforge_bridge.pts` is written (`> 0` bytes) and registration steps print clearly.

3. **Register once inside Cisco Packet Tracer:**
   - Open Cisco Packet Tracer `8.2.2`.
   - Go to **Extensions -> Scripting -> Configure PT Script Modules...**
   - Click **Add**, select `%LOCALAPPDATA%\netforge\netforge_bridge.pts`, enable **On Startup**, and accept the requested privileges.
   - Restart Packet Tracer once cleanly (confirm zero version-warning popups block startup).

4. **Start the MCP server & confirm bridge connection:**
   ```bash
   netforge serve --transport stdio
   ```
   While both `netforge serve` and Packet Tracer are running, check in another terminal:
   ```bash
   netforge doctor
   ```
   Confirm `script_bridge.reachable` is `true`, `script_bridge.connected` is `true`, and `script_bridge.state` is `"connected"` (and no secret token appears in `doctor` output).

5. **Confirm live RPC `ping`:**
   Call any live MCP smoke check (or `HttpScriptBridgeBackend.ping()`) and verify:
   - `ok: true`, `backend: "script_http"`
   - `response.pong: true`
   - `response.dynamic_session_discovery: true`
   - `response.has_hardcoded_session_file: false`

## Pass Criteria
- All 5 steps succeed on a clean account/machine without editing any files, re-exporting `.pts` manually, or running inside the original author's workspace.
