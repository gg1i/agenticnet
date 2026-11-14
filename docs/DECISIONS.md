# NetForge MCP — Architectural Decision Records (Phase 0)

This document records the core architectural decisions before Phase 1 implementation begins. Every external project attribution, license obligation, security boundary, and live-probing trigger is captured here.

---

## ADR-001: Scripting Channel Architecture (Reuse/Interoperate vs. Clean-Room Bridge)

### Context
NetForge currently drives Packet Tracer `8.2.2` strictly through OS-level Win32 input/clipboard scraping (`WindowsGuiBackend` + `WindowsGuiConsoleTransport`), making basic operations (`device_add`, `connection_create`, `configure_*`, `console_execute`) slow, resolution-dependent, and focus-sensitive. To prove our positioning reliably while keeping Physical-tab and dialog GUI automation as a targeted fallback, NetForge needs a direct scripting channel inside Packet Tracer.

Packet Tracer `8.2.2`'s local `IpcAPI` documentation (`help/default/IpcAPI/`) exposes Qt Script Engine objects (`AppWindow`, `LogicalWorkspace`, `Network`, `Device`, `TerminalLine`, `Simulation`, `ActivityFile`, `SystemFileManager`, `WebView`, `IpcManager`), while native ExApp IPC uses binary PTMP over TCP (`38000`/`39000~`). However, exact `8.2.2` runtime privilege prompts and localhost transport restrictions have **not yet been probed live**.

### Existing Public Bridges Reviewed (Licenses & Credits Verified)
1. **`Mats2208/MCP-Packet-Tracer`** (Author: Mateo Andres Soto Gareca / `@Mats2208`, **MIT License**):
   - Architecture: Python MCP server (`uvx`-installable) paired with a companion `.pts` Script Module (`MCPControlCenter.pts`) installed into Packet Tracer's `extensions/` folder. The script module polls an authenticated `127.0.0.1` HTTP bridge (with a local file-mailbox fallback) and runs dynamic JavaScript via `new Function()`.
   - License analysis: Permissive **MIT License**. Allows study, adaptation, interoperability, or code reuse provided upstream copyright and MIT permission notices are preserved in `LICENSE` / `NOTICE` and derivative files.
2. **`kiskander/pt-mcp-server`** (**BSD-2-Clause "Simplified" License**):
   - Architecture: Connects directly over Packet Tracer's native PTMP TCP IPC protocol (ExApp model) for topology/CLI/PC/Simulation operations; intentionally blocks `.pka` assessment scores/answers.
   - License analysis: **BSD-2-Clause**. Requires retaining copyright/disclaimer notices in source/binary redistributions (no patent clause) and relies on undocumented binary PTMP wire framing or C++/Java ExApp tooling.

### Options Compared

| Criterion | Option A: Directly Reuse / Interoperate with `MCPControlCenter.pts` (`Mats2208`, MIT) | Option B: Native Binary PTMP ExApp IPC (`kiskander` pattern, BSD-2-Clause) | Option C (Recommended): Clean-Room MIT Typed-Opcode `.pts` Module + `127.0.0.1` Token Bridge |
|---|---|---|---|
| **Implementation Effort** | Low upfront (reuse existing `.pts` release binary or fork JS protocol), medium long-term coupling if upstream `.pts` changes. | High (reverse-engineering/maintaining binary PTMP framing or C++/`.pta` ExApp packaging across platforms & PT versions). | Low–Medium (small self-contained HTTP/file bridge + minimal JS dispatcher inside our own `.pts` extension). |
| **Security Surface** | Medium–High if `pt_send_raw` (`new Function()` arbitrary JS execution) remains reachable over localhost HTTP (browser CORS `text/plain` risk without strict origin/header/token checks). | Medium (native TCP port `39000~`, requires `.pta` registration + ExApp auth handshake; `.pka` assessment mode may lock external IPC). | **Best:** Strict allowlisted **typed opcodes** (`add_device`, `add_link`, `cli_exec`, `get_state`, `read_assessment`, etc.) validated by Pydantic on both sides, `127.0.0.1` only, per-session CSPRNG token; **no unconstrained `eval()` by default**. |
| **`.pka` Grader Control** | Upstream focuses on topology/exam generation rather than solving + reading `ActivityFile` comparator trees. | Upstream explicitly forbids reading `.pka` answers/scores; uncertain whether PT locks ExApp access during `.pka` activities. | Direct ownership of `read_assessment` probe against `ActivityFile` / fallback strategy in Phase 4. |
| **Maintenance & Licensing** | Must track upstream `MCPControlCenter.pts` binary releases or fork & retain copyright notices. | BSD-2-Clause notice obligations + brittle binary protocol maintenance. | Single MIT codebase (`netforge-mcp`), full control over script protocol, clean credits in docs/attribution. |
| **Phase 1 Risk** | PT `8.2.2` module security prompts (`shouldPromptExternalNetworkAccess`) still apply on load. | PTMP wire compatibility / ExApp registration friction on end-user machines. | PT `8.2.2` might restrict `WebView` `fetch` -> `http://127.0.0.1` or require clicking "Allow" on Script Module privileges once. |

### Decision
Adopt **Option C (Clean-Room Typed-Opcode `.pts` Companion Module + Authenticated `127.0.0.1` Python Bridge)** as the recommended primary `ScriptBackend`, with a **two-transport Phase 1 probe** inside Packet Tracer `8.2.2`:
1. **Primary transport candidate:** Localhost HTTP JSON API (`127.0.0.1:<ephemeral_port>`) guarded by an ephemeral CSPRNG `X-NetForge-Token` header and `Content-Type: application/json` enforcement (rejecting `text/plain` simple CORS requests).
2. **Built-in backup transport inside Option C:** Local filesystem atomic JSON queue (`SystemFileManager` / user runtime directory with `0600`/owner-only directory ACLs) if PT `8.2.2` blocks `WebView` HTTP callbacks or triggers unacceptable repetitive security popups.
3. **Escalation trigger (Option B fallback):** Only if live Phase 1 probing proves **both** HTTP and file-mailbox `.pts` Script Module channels fail or break `.pka` execution on `8.2.2`, revisit native PTMP ExApp IPC (stopping first to report the blocked probe).

### Proper Attribution
NetForge's clean-room Phase 1 `.pts` bridge will explicitly acknowledge:
- **`Mats2208/MCP-Packet-Tracer` (MIT License, Mateo Andres Soto Gareca)** for pioneering the companion `.pts` Script Module + `127.0.0.1` authenticated HTTP / file-mailbox architectural pattern for Packet Tracer MCP servers.
- **`kiskander/pt-mcp-server` (BSD-2-Clause License)** as prior-art reference for IPC object coverage (modular slot installation and simulation frame read-back).
If any verbatim snippet from `Mats2208/MCP-Packet-Tracer` is ever reused in future phases, its upstream MIT copyright and permission notice will be included verbatim in `LICENSE` / `NOTICE` and the corresponding source file(s).

---

## ADR-002: Hybrid Backend Router, Provenance & Honest Truth Levels

### Context
NetForge currently isolates `GuiBackend`, `ConsoleBackend`, and `SimulationBackend` behind separate calls, while 55 domain tools only update local SQLite/NetworkX state. Meanwhile, `DiagnosticsEngine` falsely reports `StateLevel.VERIFIED` using static model rules alone.

### Decision
1. **Unified `BackendRouter` (`netforge/adapters/router.py`, Phase 2):**
   - Route scripting-capable operations (`device_add/remove/move`, `connection_create/remove`, `configure_*` live push, `console_*`, structured `interface/route/dhcp/ephone/ping` reads, `simulation_mode/start/stop`, `grade_lab`) to `ScriptBackend` by default when attached.
   - Route GUI-only operations (Physical-tab module/power-brick placement, non-scriptable dialogs such as `Home VoIP0` `Server Address` if IPC lacks setters, modal dismissals, explicit `gui_*` calls) and scripted-unsupported fallbacks strictly per-operation to `GuiBackend`.
   - Maintain a capability matrix in `docs/CAPABILITIES.md` populated strictly from live PT `8.2.2` probes so the router never guesses which calls succeed via scripting.
2. **Mandatory Backend Provenance:** Extend `OperationResult` (`netforge/core/models.py`) with an `execution_backend` field (`"offline_model" | "script_backend" | "gui_backend" | "hybrid"`) so callers always know whether a step touched PT via Script Engine, Win32 GUI, or only local planning state.
3. **Strict `StateLevel` Integrity:** Only live simulator read-back or PT assessment read-back may return `StateLevel.VERIFIED`. Fix `DiagnosticsEngine` in Phase 2/3 so offline topology rule evaluation returns `StateLevel.PLANNED`.
4. **No Screenshots When CLI Exists:** `verify_lab` and diagnostic tools must read structured IOS/PC text output and forbid `gui_screenshot` whenever CLI/script read-back covers the check.

---

## ADR-003: Security Boundaries for Localhost Bridge & GUI Automation

### Context
Exposing a local HTTP bridge and OS-level Win32 input/process control requires strict guardrails before NetForge can be distributed publicly via `uvx` and MCP registries (`SECURITY.md` update in Phase 7).

### Decision
1. **Loopback-Only + Ephemeral Auth Token:** The script bridge binds exclusively to `127.0.0.1` (`localhost` IPv4 loopback, never `0.0.0.0`), requires a per-run CSPRNG token passed via runtime environment / private `0600` runtime handshake file (never hardcoded or committed to VCS), and rejects cross-origin/simple-CORS requests (`Origin` header check + `application/json` content-type check).
2. **Typed Opcodes Over Arbitrary Code Execution:** Default bridge dispatch uses strictly typed, Pydantic-validated operations rather than evaluating arbitrary JavaScript strings sent by an LLM.
3. **Preserved Rate Limiting & GUI `dry_run` Mode:** Retain `EmergencyStopController` (`300 actions/min` cap, `(0, 0)` corner fail-safe, `Esc` abort), fix `gui_*` / `SimulationEngine` so `dry_run=True` propagates consistently across every GUI path with zero Win32 side effects, and fix silent `gui_batch` key fallbacks (`x`/`y` vs `offset_x`/`offset_y`, `target_dialog` on `screenshot`) to fail loudly with `ValidationError`.
4. **Zero Third-Party Proprietary / Course Assets:** Never bundle Packet Tracer binaries, Cisco IOS images, encrypted Cisco extensions, or copyrighted/course-owned lab files (`*.pkt`, university PDFs/labs) in the published package or repository. Phase 7 ships clean, self-authored sample labs only.

---

## ADR-004: Verification & Grader Oracle Strategy

### Context
Solving real `.pka` activities requires trusting Packet Tracer's own grading logic where possible while remaining deterministic on ungraded `.pkt` topologies.

### Decision
1. **Primary Grader Oracle (`grade_lab`, Phase 4):** Probe `ActivityFile` (`isActivityFile`, `getPercentageComplete`, `getPercentageCompleteScore`, `getAssessmentItemsCount`, `getCorrectAssessmentItemsCount`, `getAssessedComparatorTree`, `getIncompleteFeedback`) inside live PT `8.2.2` `.pka` activities, and empirically document reliability and lockouts in `docs/CAPABILITIES.md`.
2. **Automatic Fallback (`verify_lab`, Phase 3):** When operating on a `.pkt` file, when `ActivityFile.isActivityFile()` is `false`, or if PT restricts assessment reads, fall back automatically to `verify_lab(requirements)` backed by raw CLI output (`show ip interface brief`, `show ip route`, `show ip dhcp binding`, `show ephone`, `show telephony-service`, `ping`) as verifiable evidence.
3. **Bounded Repair Loop (`solve_lab`, Phase 5):** Enforce an explicit `max_iterations` cap, track diffs between iterations, stop immediately at 100% pass or repeated stalled state, and return structured unmet requirements on failure rather than infinite retry loops.

---

## ADR-005: Cross-Platform Degradation & Strict `netforge doctor` Capability Gate

### Context
Hardcoded `1920x991 @ 120 DPI` anchors (`netforge/gui/calibration.py`) cause silent mis-clicks on different displays, and GUI automation cannot run cleanly on Linux Wayland/headless environments without explicit platform adapters.

### Decision (Enforced in Phase 6)
1. **Strict Environment Preflight:** Upgrade `netforge doctor` (`netforge/cli.py`) to inspect OS platform/display server, Packet Tracer installation & version, display resolution, and per-monitor DPI scaling.
2. **Fail Closed on Unsupported GUI Setups:** When a tool requires `GuiBackend` fallback on an unsupported OS, mismatched uncalibrated resolution/DPI, or minimized/occluded window, **refuse GUI execution cleanly with an actionable remediation message** instead of guessing coordinates and mis-clicking.
3. **Detection / Per-Machine Calibration:** Replace static screen assumptions with OpenCV template/UI detection plus per-machine calibration profiles stored outside the repository under user state data directories.

---

## ADR-006: Packaging, Hygiene & Dependency Choices

### Decision
1. **Official MCP SDK (`mcp>=2.0.0`, tested on `2.3.0`):** Keep `MCPServer` (`mcp.server.mcpserver`) as the single server framework, verifying SDK API docs before changing tool schemas, lifespans, or Streamable HTTP options.
2. **Console Script & `uvx` Readiness (Phase 7):** Expose `netforge-mcp` console entrypoint via `pyproject.toml` compatible with `uvx netforge-mcp`, fix all `39` pre-existing `ruff` lint errors so CI enforces clean `ruff` + `pytest`, initialize proper version control (small atomic commits per phase thereafter), remove workspace root screenshot clutter and course-owned files from package manifests, and align registry metadata against current official MCP Registry specifications before publishing.
3. **IOS Baseline Cleanups Deferred to Phase 2:** Keep Phase 0 strictly code-free; track fixing the VoIP validation lab switch config (missing `no ip domain-lookup`) and removing switch `"no"` injection in `load_ios_command_sequence` as explicit Phase 2 repair items alongside router migration.
