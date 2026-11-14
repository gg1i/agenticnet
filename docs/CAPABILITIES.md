# Packet Tracer 8.2.2 Live Capabilities & Probe Log (`CAPABILITIES.md`)

**Target Binary:** Cisco Packet Tracer `8.2.2.0400` (Windows x64)  
**Test Display Environment:** `1920x1080`, `120 DPI` (125% Windows scaling)  
**Last Verified Live:** Phase 1a Probe Runs (`probe_start_test.py` -> PT `8.2.2.0400`)

This document records empirical facts directly observed by executing live probes against Cisco Packet Tracer `8.2.2` on Windows, including **failures, race conditions, modal dialogs, and untested boundaries**. Unverified capabilities are explicitly marked `UNTESTED`.

---

## 1. Script Module Packaging, Privileges & Lifecycle

| Capability / Behavior | Status | Live Evidence & Notes |
|---|---|---|
| Binary `.pts` export format | **VERIFIED LIVE** | Exported `.pts` files (`5073`–`6306` bytes) are encrypted/encoded binary (`\x1d\x93\x88d...`, non-ZIP). Built clean-room inside PT via `Scripting Interface` (`Import Script Files` -> `Import Interface Files` -> `Export Script Module`). |
| Persistent Script Module registration | **VERIFIED LIVE** | Exporting a new `.pts` opens modal `"New script modules must be added as persistent script modules before starting. Do you want to add it now?"` (`Yes`) followed by confirmation `"Script module added as a persistent script module."` (`OK`). Selecting **On Startup** + all 10 security privileges (`Application`, `Activity`, `File`, `Ui`, `Ipc`, `GetNetwork`, `ChangeNetwork`, `Simulation`, `Preferences`, `Misc`) succeeded (`On`). |
| Persisting across `fileOpen()` | **VERIFIED LIVE** | Persistent PT Script Module remained `(Running)` across `ipc.appWindow().fileOpen(".../mqttdemo.pka")`. |
| Version warning modal (`8.2.2.0400`) | **FAILURE / GOTCHA RECORDED** | Starting / creating a WebView with default unnamed module metadata triggered modal `"Some scripts in this file were saved in an earlier version of Cisco Packet Tracer... com.yourcompany.newptscriptmodule0"` (`OK`). Blocks Qt UI event loop until dismissed. |
| Start/Stop toggle crash hazard | **FAILURE / GOTCHA RECORDED** | `groupBox_8.btnStart` / `ScriptEngine.btnStart` is a **Start/Stop toggle**. Invoking it multiple times while `Start` is initializing immediately invokes `cleanUp()` (`wv.close()`) during Chromium/QWebEngine initialization and crashes Packet Tracer cleanly exiting with no crash dialog. Invoking `btnStart` once works cleanly. |
| Windows UIA COM deadlocks on Scripting UI | **FAILURE / GOTCHA RECORDED** | On PT's Qt5 `Scripting Interface`, UIA `ScrollIntoView()`, `ValuePattern.SetValue`, `InvokePattern.Invoke()` on modal-spawning buttons, and `TogglePattern.Toggle()` on `.chkMisc` deadlock COM calls. Win32 `PostMessageW` (`WM_MOUSEWHEEL` + `ChildWindowFromPointEx`) + modal dialog automation works reliably. |
| QtScript timer APIs | **VERIFIED LIVE** | `setTimeout`, `setInterval`, `clearTimeout`, `clearInterval`, `Date.now()`, and `JSON` work inside PT's Qt Script Engine. |

---

## 2. Bridge Transport Probe (`WebView` Localhost HTTP vs File Mailbox)

| Transport Channel | Status | Live Evidence & Notes |
|---|---|---|
| **Headless `WebView` + `127.0.0.1` HTTP (`QWebEngine` + `$se()`)** | **VERIFIED LIVE** | `webViewManager.createWebView(...)` + `wv.addAllowedExternalFilter("http://127.0.0.1*")` **without calling `wv.show()`** loaded `this-sm:probe.html` headless (`[WEBVIEW_HEADLESS_OK]`). QWebEngine issued CORS `OPTIONS /probe` (`204`) and `POST /probe` (`200 OK`) to `http://127.0.0.1:<port>/probe` with header `X-NetForge-Token` (`Origin: pt-sm://com.yourcompany.newptscriptmodule0/probe.html`) and invoked `$se("onHttpProbeResult", ...)` inside the Script Engine in `<0.8s`. No visible browser window needed. |
| `ipc.systemFileManager()` file mailbox | **VERIFIED LIVE** | `fileExists()`, `getFileContents()`, and `writePlainTextToFile()` cleanly read Python-written JSON (`mailbox_in.json`) and wrote structured JSON/logs (`mailbox_out.json`, `probe_trace.log`). Viable backup channel if QWebEngine is blocked on a host. |
| Localhost bidirectional Python `HttpScriptBridge` long-poll command loop | **OFFLINE MOCKED ONLY** | Handshake/auth `OPTIONS`+`POST` and `$se()` callback verified live (`http_probe_result.json`); continuous `/v1/commands/next` long-poll + `/v1/commands/result` RPC loop tested via offline mocked HTTP client in `tests/unit/test_script_backend.py` (scheduled for live full-runtime test in Phase 2). |
| Native binary PTMP / `ExApp` (ports `38000`+) | **UNTESTED** | Excluded per ADR-001 to avoid `.pta` registration and undocumented binary framing. |
| `dprint()` visibility | **PARTIALLY VERIFIED** | `dprint()` writes to `Debug - <ModuleName>` dialog; opening `btnDebug` makes text readable, though `systemFileManager` trace logs or HTTP results are far more reliable for automation. |

---

## 3. Core Scripting Spike (`LogicalWorkspace`, `Network`, `TerminalLine`)

Live execution of the Phase 1a core spike (`probe_confirm_template.js`) produced:

| Primitive | Status | Live Evidence & PT `8.2.2` Details |
|---|---|---|
| `addDevice(deviceType, model, x, y)` | **VERIFIED LIVE** | `lw.addDevice(0, "2911", 150, 150)` returned `"Router0"`; `lw.addDevice(1, "2960-24TT", 350, 150)` returned `"Switch0"`. (`DeviceType` enum documented in `class_logical_workspace.html`: `0=eRouter`, `1=eSwitch`, `8=ePc`, `9=eServer`, `12=eIpPhone`, `16=eMultiLayerSwitch`, etc.) |
| `createLink(dev1, port1, dev2, port2, connType)` | **VERIFIED LIVE** | `lw.createLink("Router0", "GigabitEthernet0/0", "Switch0", "FastEthernet0/1", 8100)` returned `true`. (`CONNECT_TYPES` enum documented in `class_logical_workspace.html`: `8100=ETHERNET_STRAIGHT`, `8101=ETHERNET_CROSS`, `8103=FIBER`, `8104=PHONE`, `8106=SERIAL`, `8107=AUTO`, `8108=CONSOLE`, etc.) |
| `TerminalLine` IOS CLI execution & raw output readback | **VERIFIED LIVE** | `ipc.network().getDevice("Router0").getCommandLine()` with `outputWritten` + `commandEnded` events captured full IOS output (`2884` chars), navigated `Would you like to enter the initial configuration dialog? [yes/no]: no` -> `RETURN` -> `enable` -> `show ip interface brief`, reached `Router#` (`finalMode: "enable"`), and returned the full interface table verbatim. |
| IOS Boot Delay Failure (`2911`) | **FAILURE / GOTCHA RECORDED** | Initial probe with fixed `3000ms` wait sent `"no"` while `2911` was still decompressing IOS (`###########################`), capturing zero prompt/interface output. Event-driven polling on `outputWritten` / `getPrompt()` measured actual `2911` boot time at `bootElapsedMs: 10505` (~10.5s) before `[yes/no]:`. |
| `terminal length 0` on PT `2911` IOS | **FAILURE / QUIRK RECORDED** | `term.enterCommand("terminal length 0")` triggered `% Invalid input detected at '^' marker.` and emitted `commandEnded(..., status=2)` on PT `2911` (`Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M5`), whereas valid commands (`no`, `enable`, `show ip interface brief`) emitted `status=0`. Bridge CLI wrappers should NOT assume `terminal length 0` succeeds on all PT IOS images. |
| `running-config` (`show running-config`), PC/Server IP config, Ping | **UNTESTED LIVE** | Documented in PT `8.2.2` `IpcAPI` (`HostPort.setIpSubnetMask`, `TerminalLine`, etc.); scheduled for live runtime verification in Phase 2/3. |

---

## 4. `.pka` Grader Oracle Probe (`ActivityFile` & `TreeNode`)

Target tested live: `C:/Program Files/Cisco Packet Tracer 8.2.2/saves/04 IoT/MQTT/mqttdemo.pka`

| Check | Status | Live Evidence & Notes |
|---|---|---|
| Open `.pka` & detect activity state | **VERIFIED LIVE** | `ipc.appWindow().fileOpen(pkaPath)` + `ipc.appWindow().getActiveFile()` returned `isActivityFile() == true` and `savedFilename` matching the `.pka`. Persistent PT Script Module stayed running. |
| Read activity percentage & score counts | **VERIFIED LIVE** | On unmodified `mqttdemo.pka`: `percentageComplete: 12.5`, `percentageCompleteScore: 12.5`, `itemsCount: 8`, `correctItemsCount: 1`, `scoreCount: 8`, `correctScoreCount: 1`, `completedFeedback`, `incompleteFeedback` all readable directly without UI clicks or Check Results modal interaction. |
| Read individual comparator tree items (unmet vs met) | **VERIFIED LIVE** | `af.getAssessedComparatorTree()` (`TreeNode`) returned `treeRootName: "Network"`, `leafCount: 8`, `checkLeafCount: 1`. Recursive traversal via `getChildCount()` / `getChildNodeAt(i)` extracted all `8` leaf items with `path` (e.g. `Network > MQTT Broker > Custom Device Properties > MQTT_BROKER_AUTHORIZED_USERS`), `name`, expected `value`, `checkLeafCount` (`0` = unmet, `1` = met), `totalLeafPoints`/`checkLeafPoints`, and `incorrectFeedback`. |
| `AssessmentModel` global availability | **VERIFIED LIVE** | `typeof AssessmentModel !== "undefined"` evaluated to `true`. |
| Strict Assessment-mode / password-locked `.pka` | **UNTESTED** | PT `8.2.2` ships only `mqttdemo.pka` and `sokoban.pka`. Behavior when an instructor `.pka` sets Assessment Lock / Activity Wizard password restrictions on scripting IPC will be probed empirically in Phase 4. |

---

## 5. Scripting vs GUI-Only Operational Boundary (Verified Basis for Phase 2 Router)

- **ScriptBackend Target Scope (Proven Foundation):** Device creation (`addDevice`), link creation (`createLink`), IOS CLI execution + raw output + status code (`TerminalLine`), `.pka` completion & comparator tree reading (`ActivityFile` / `TreeNode`). Further `Device`/`HostPort`/`Simulation` methods remain to be live-tested in Phases 2–3.
- **GuiBackend Required Scope:** Physical tab racks/cables/power bricks, modal file/save/preferences dialogs, module slot drag/drops requiring GUI interaction (unless IPC `addModule` verified later), Check Results screenshot auditing if `.pka` locks IPC, and initial bootstrap/recovery of Packet Tracer or the companion `.pts` Script Module.

## Phase 2 step (a): production bridge, live end-to-end (PT 8.2.2.0400, Windows)

Verified live (exported `netforge_bridge.pts`, module id `com.netforge.bridge`, real `HttpScriptBridgeServer`/`HttpScriptBridgeBackend`):

- `ping` over long-poll HTTP: ok (0.01 s), backend `script_http`.
- `add_device` 2911 -> `Router0`; 2960-24TT -> `Switch0`: ok.
- `create_link` Router0 Gi0/0 <-> Switch0 Fa0/1: ok.
- `execute_cli` on a booting 2911: `timed_out=false`; `terminal length 0` returned status 2 and was reported as `non_fatal`; `--More--` paging advanced 5 pages through `show running-config`; IOS `ping 10.77.77.1` -> `Success rate is 100 percent (5/5)`.
- Stop -> Start: bridge reconnected and `ping` succeeded afterwards.

Findings (including failures):

- WebView `fetch`/XHR to `http://127.0.0.1` works. Origin sent by PT is the opaque `pt-sm:` (no `//`); the server previously rejected it with 403 ("Failed to fetch"). Fixed in `is_allowed_bridge_origin`. Preflight `OPTIONS` is sent for the token header and must return CORS headers. `<img>` loads to 127.0.0.1 failed (`IMG_ERR`); not used.
- Queuing all CLI commands at once breaks after `--More--` (pager swallowed the first char of `ping`). Commands are now sent one at a time.
- The "Some scripts in this file were saved in an earlier version ... 8.2.2.0400" dialog appeared only when manually editing/starting a `.pts` via the script module editor (`New PT Script Module`); starting an unsaved editor module directly instead prompts `"New script modules must be exported and added as persistent script modules before starting."` and opens `Export Script Module`.
- **Persistence & Zero-Popup Reopen (verified live in `task-3750`):** After registering `%LOCALAPPDATA%\netforge\netforge_bridge.pts` once via `Extensions -> Scripting -> Configure PT Script Modules -> Add`, cleanly closing and reopening Packet Tracer 8.2.2 auto-started the module and connected to `HttpScriptBridgeBackend` with **no manual clicks** and **zero startup/version popups** (`EXTRA_WINDOWS_ON_REOPEN = []`, `ping` succeeded).
- **One-time Manual Setup (no GUI auto-click dependency):** Build/place `netforge_bridge.pts` in `%LOCALAPPDATA%\netforge\`, open PT 8.2.2 once, go to `Extensions -> Scripting -> Configure PT Script Modules -> Add`, and select `netforge_bridge.pts`. On all subsequent PT launches, `HttpScriptBridgeBackend` connects cleanly without depending on `GuiBackend` auto-clicking OK.
- **Device-to-Device Ping Across Link (verified live in `task-3780`):** Added `Router0` (`2911`) and `Router1` (`2911`), linked `Router0 GigabitEthernet0/0 <-> Router1 GigabitEthernet0/0` (`conn_type: 8101`), configured `10.77.88.1/24` and `10.77.88.2/24` (`no shutdown`) via `execute_cli`, and verified bidirectional ping (`10.77.88.1 -> 10.77.88.2` and `10.77.88.2 -> 10.77.88.1`, both `100% (5/5)`). Note: `addDevice` with `2960-24TT` returned an empty name right after fresh PT startup in two runs after succeeding earlier in `e2e_run2`; `2911` succeeded consistently.
- Leftover probe module `com.yourcompany.newptscriptmodule0` is not registered in PT 8.2.2 (checked in Configure PT Script Modules).

---

## 6. Path-Independent `.pts` & Unlocked Desktop Requirement for GUI Fallback

| Capability / Behavior | Status | Live Evidence & Notes |
|---|---|---|
| Dynamic user-folder discovery inside `.pts` | **VERIFIED LIVE** | Updated `netforge_bridge.js` to resolve `bridge_session.json` via `ipc.appWindow().getTempFileLocation()` and `ipc.appWindow().getUserFolder()` with `SESSION_FILE = "__NETFORGE_SESSION_FILE__"` intact. Binary scan of exported `netforge_bridge.pts` (`9,203` bytes) confirmed `0` username/path hits, and restarting PT `8.2.2` auto-connected with `ping` returning `dynamic_session_discovery: true, has_hardcoded_session_file: false`. |
| Unlocked interactive desktop required for foreground GUI fallback | **VERIFIED LIVE (FAILURE RECORDED)** | When the Windows desktop is locked or the display session is asleep/disconnected, `PIL.ImageGrab.grab` raises `OSError: screen grab failed`, and `SetCursorPos`/`SendInput` returns `0` (blocking foreground `gui_click`, `gui_keypress`, and `ImageGrab` screen captures). Meanwhile, `PrintWindow` (`_capture_window_printwindow` when `focus_first=False`) and `background=True` `PostMessageW` still operate on visible top-level windows/dialogs, and `ScriptBackend` (`127.0.0.1` HTTP bridge) requires no screen grab or pointer input after one-time `.pts` registration. |
