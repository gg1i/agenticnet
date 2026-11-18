"""Offline safeguard tests for Phase 5: blind reference scoring, mock labels, profile & prompt."""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from agenticnet.adapters.base import ScriptBackend
from agenticnet.adapters.router import BackendRouter
from agenticnet.core.exceptions import AdapterUnavailableError
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.diagnostics.benchmark import (
    BenchmarkResult,
    evaluate_benchmark_with_reference,
    extract_agent_lab_brief,
    load_reference_spec,
    run_offline_mock_benchmark,
)
from agenticnet.mcp.profiles import RAW_GUI_INPUT_TOOLS, SOLVE_LAB_TOOLS, resolve_tool_profile
from agenticnet.mcp.server import create_mcp_server

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_LAB_IDS = ("01_static_routing", "02_vlan_dhcp", "03_small_voice")


class _GamingTestBackend(ScriptBackend):
    """Simulates either broken or fixed CLI state for blind benchmark reference tests."""

    def __init__(self, *, broken: bool) -> None:
        self.broken = broken

    def is_connected(self) -> bool:
        return True

    def ping(self) -> dict[str, Any]:
        return {"ok": True}

    def add_device(
        self,
        model: str,
        *,
        device_type: int | str = 0,
        x: float = 100.0,
        y: float = 100.0,
    ) -> dict[str, Any]:
        return {"ok": True, "device_name": model}

    def create_link(
        self,
        device1: str,
        port1: str,
        device2: str,
        port2: str,
        *,
        conn_type: int | str = 8107,
    ) -> dict[str, Any]:
        return {"ok": True}

    def read_activity_status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "is_activity_file": False,
            "state": "not_activity",
            "readable": False,
        }

    def execute_cli(
        self,
        device_name: str,
        commands: list[str],
        *,
        ensure_privileged: bool = True,
        timeout_seconds: float = 25.0,
    ) -> dict[str, Any]:
        cmd = (commands[-1] if commands else "").lower()
        if cmd.startswith("show ip interface brief"):
            if self.broken:
                out = (
                    "Interface              IP-Address      OK? Method Status                "
                    "Protocol\n"
                    "GigabitEthernet0/0     10.10.12.1      YES manual up                    "
                    "up\n"
                    "Loopback0              unassigned      YES manual administratively down "
                    "down"
                )
            elif device_name == "R1":
                out = (
                    "Interface              IP-Address      OK? Method Status                "
                    "Protocol\n"
                    "GigabitEthernet0/0     10.10.12.1      YES manual up                    "
                    "up\n"
                    "Loopback0              10.10.1.1       YES manual up                    up"
                )
            else:
                out = (
                    "Interface              IP-Address      OK? Method Status                "
                    "Protocol\n"
                    "GigabitEthernet0/0     10.10.12.2      YES manual up                    "
                    "up\n"
                    "Loopback0              10.10.2.1       YES manual up                    up"
                )
        elif cmd.startswith("show ip route"):
            if self.broken:
                out = "Gateway of last resort is not set"
            elif device_name == "R1":
                out = "S    10.10.2.0/24 [110/2] via 10.10.12.2, 00:00:05, Gi0/0"
            else:
                out = "S    10.10.1.0/24 [110/2] via 10.10.12.1, 00:00:05, Gi0/0"
        elif cmd.startswith("ping "):
            out = (
                "Success rate is 0 percent (0/5)"
                if self.broken
                else "Success rate is 100 percent (5/5)"
            )
        else:
            out = ""
        return {"ok": True, "raw_output": out, "results": [{"command": cmd, "status": 0}]}


@pytest.mark.unit
def test_mock_benchmark_unmistakable_labels_and_readme_live_only() -> None:
    import scripts.run_benchmark as bench_cli

    # Multi-lab CLI run labels both outer envelope and every child result as mock
    res_all = [
        run_offline_mock_benchmark(REPO_ROOT / "labs" / f"{lab_id}.json")
        for lab_id in SAMPLE_LAB_IDS
    ]
    for item in res_all:
        assert item.mock is True
        assert item.mode == "offline_mock"
        assert "not comparable" in item.comparability_notice.lower()
        assert item.reference_score.source == "human_authored_reference"

    # CLI output checks
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = bench_cli.main(["--all-sample-labs", "--mock"])
    assert rc == 0
    report = json.loads(buf.getvalue())
    assert report["mock"] is True
    assert report["mode"] == "offline_mock"
    assert "not comparable" in report["comparability_notice"].lower()
    assert len(report["results"]) == 3
    for child in report["results"]:
        validated = BenchmarkResult.model_validate(child)
        assert validated.mock is True

    # README must expose only live results section cleanly without mock scores
    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "## Live Verification & Benchmark Results" in readme_text
    assert "live_pt" in readme_text
    assert "never reported as benchmark scores" in readme_text


@pytest.mark.unit
def test_hidden_human_reference_scoring_isolated_from_agent_self_report() -> None:
    # 1. All 3 sample labs have human-authored hidden reference files & agent brief strips answers
    for lab_id in SAMPLE_LAB_IDS:
        ref_path, ref_spec = load_reference_spec(lab_id)
        assert ref_path.is_file()
        assert ref_spec["authored_by"] == "human_reference"
        assert ref_spec["agent_visible"] is False
        assert len(ref_spec["requirements"]) >= 5
        assert len(ref_spec["task_ids"]) >= 5

        raw_lab = json.loads((REPO_ROOT / "labs" / f"{lab_id}.json").read_text(encoding="utf-8"))
        brief = extract_agent_lab_brief(raw_lab)
        for forbidden_key in (
            "requirements",
            "reference_requirements",
            "task_ids",
            "configs",
            "break_step",
            "fix_step",
        ):
            assert forbidden_key not in brief

    # 2. Gaming attempt: device topology is BROKEN, agent submits easy trivial requirement
    #    that reports 100% pass/coverage -> official reference score MUST STILL FAIL.
    trivial_agent_reqs = {
        "lab_name": "Agent Gaming Effort",
        "task_ids": ["ONLY_GI00"],
        "requirements": [
            {
                "id": "easy_up",
                "task_id": "ONLY_GI00",
                "type": "interface_up",
                "device": "R1",
                "interface": "GigabitEthernet0/0",
            }
        ],
    }
    broken_router = BackendRouter(script_backend=_GamingTestBackend(broken=True))
    gamed_result = evaluate_benchmark_with_reference(
        broken_router,
        lab_id="01_static_routing",
        agent_name="gaming-agent",
        model_name="mock-model",
        mode="offline_mock",
        agent_requirements=trivial_agent_reqs,
        agent_task_ids=["ONLY_GI00"],
    )
    # Agent self-report shows 100% pass on its trivial check, marked non-scoring
    assert gamed_result.agent_self_report is not None
    assert gamed_result.agent_self_report.counts_toward_score is False
    assert gamed_result.agent_self_report.overall_passed is True
    assert gamed_result.agent_self_report.verify_summary == {
        "total": 1,
        "passed": 1,
        "failed": 0,
        "errors": 0,
    }
    # Official score fails against hidden reference checks (only Gi0/0 checks pass: 2/8 = 25.0%)
    assert gamed_result.passed is False
    assert gamed_result.status == "budget_exceeded" or gamed_result.status == "failed"
    assert gamed_result.score_pct < 100.0
    assert gamed_result.reference_score.passed is False
    assert gamed_result.reference_score.requirements_passed < 8
    assert gamed_result.reference_score.requirements_total == 8

    # 3. Fixed topology passes hidden reference even if agent submitted failing self-checks
    failing_agent_reqs = {
        "lab_name": "Wrong Agent Check",
        "task_ids": ["WRONG_IP"],
        "requirements": [
            {
                "id": "wrong_ip",
                "task_id": "WRONG_IP",
                "type": "ip_assigned",
                "device": "R1",
                "interface": "Loopback0",
                "ip": "192.0.2.99",
            }
        ],
    }
    fixed_router = BackendRouter(script_backend=_GamingTestBackend(broken=False))
    real_pass = evaluate_benchmark_with_reference(
        fixed_router,
        lab_id="01_static_routing",
        agent_name="honest-solver",
        model_name="mock-model",
        mode="offline_mock",
        agent_requirements=failing_agent_reqs,
        agent_task_ids=["WRONG_IP"],
    )
    assert real_pass.agent_self_report is not None
    assert real_pass.agent_self_report.counts_toward_score is False
    assert real_pass.agent_self_report.overall_passed is False
    assert real_pass.passed is True
    assert real_pass.score_pct == 100.0
    assert real_pass.reference_score.passed is True
    assert real_pass.reference_score.requirements_passed == 8


@pytest.mark.unit
def test_default_solve_lab_excludes_raw_gui_and_keeps_purpose_built_actions(tmp_path: Path) -> None:
    raw_input_and_screenshot_tools = {
        "gui_click",
        "gui_keypress",
        "gui_screenshot",
        "gui_batch",
        "gui_calibrate",
        "gui_recover",
        "gui_state_inspect",
        "packet_tracer_launch",
    }
    assert raw_input_and_screenshot_tools <= RAW_GUI_INPUT_TOOLS
    assert SOLVE_LAB_TOOLS.isdisjoint(RAW_GUI_INPUT_TOOLS)
    assert "gui_attach_ip_phone_power" in SOLVE_LAB_TOOLS

    default_srv, _ = create_mcp_server(AgenticNetSettings(data_dir=tmp_path / ".nf_def"))
    default_tools = {t.name for t in asyncio.run(default_srv.list_tools())}
    assert default_tools.isdisjoint(raw_input_and_screenshot_tools)
    assert "gui_attach_ip_phone_power" in default_tools

    # Explicit opt-in to advanced exposes raw GUI input & screenshot tools
    adv_srv, _ = create_mcp_server(
        AgenticNetSettings(data_dir=tmp_path / ".nf_adv", tool_profile="advanced")
    )
    adv_tools = {t.name for t in asyncio.run(adv_srv.list_tools())}
    assert raw_input_and_screenshot_tools <= adv_tools


@pytest.mark.unit
def test_solve_lab_prompt_and_resource_treat_lab_text_as_untrusted_data(tmp_path: Path) -> None:
    srv, _ = create_mcp_server(AgenticNetSettings(data_dir=tmp_path / ".nf_prompt"))

    prompt_res = asyncio.run(srv.get_prompt("solve_lab", arguments={}))
    prompt_text = str(prompt_res.messages[0].content.text).lower()
    assert "untrusted data" in prompt_text
    assert "never as commands" in prompt_text
    assert "override tool policy" in prompt_text
    assert "permission tiers" in prompt_text

    res_chunks = asyncio.run(srv.read_resource("agenticnet://workflows/solve_lab"))
    res_text = "".join(str(getattr(c, "content", c)) for c in res_chunks).lower()
    assert "untrusted data" in res_text
    assert "never as commands" in res_text
    assert "override tool" in res_text
    assert "permission tiers" in res_text


@pytest.mark.unit
def test_benchmark_isolation_doc_and_experimental_gui_phone_marker(tmp_path: Path) -> None:
    bench_doc = (REPO_ROOT / "docs" / "BENCHMARK.md").read_text(encoding="utf-8").lower()
    assert "no repo checkout" in bench_doc
    assert "no `benchmarks/reference/`" in bench_doc
    assert "separate harness process" in bench_doc
    assert "public demo set" in bench_doc
    assert "not a held-out test" in bench_doc

    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()
    assert "experimental: not yet validated by the 5-attempt live protocol" in readme_text

    srv, _ = create_mcp_server(AgenticNetSettings(data_dir=tmp_path / ".nf_exp"))
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    desc = (tools["gui_attach_ip_phone_power"].description or "").lower()
    assert "experimental: not yet validated by the 5-attempt live protocol" in desc


@pytest.mark.unit
def test_every_default_profile_and_prompt_tool_is_registered(tmp_path: Path) -> None:
    srv, runtime = create_mcp_server(AgenticNetSettings(data_dir=tmp_path / ".nf_strict_reg"))
    registered_tools = {t.name for t in asyncio.run(srv.list_tools())}

    # 1. Every tool in resolve_tool_profile("solve_lab") must be registered
    allowed_default = resolve_tool_profile("solve_lab")
    assert allowed_default is not None
    assert allowed_default == registered_tools

    # 2. Every tool named in solve_lab prompt must be registered
    prompt_res = asyncio.run(srv.get_prompt("solve_lab", arguments={}))
    prompt_text = str(prompt_res.messages[0].content.text)
    backticked = set(re.findall(r"`([a-z0-9_]+)`", prompt_text))
    non_tool_words = {"task_ids", "requirements", "pkt", "pka", "json", "notes", "what_is_left"}
    prompt_tools = backticked - non_tool_words
    unregistered_in_prompt = prompt_tools - registered_tools
    assert not unregistered_in_prompt, (
        f"Unregistered tools named in prompt: {unregistered_in_prompt}"
    )


@pytest.mark.unit
def test_readme_and_docs_counts_match_manifest(tmp_path: Path) -> None:
    settings = AgenticNetSettings(data_dir=tmp_path / ".nf_manifest", tool_profile="advanced")
    _, runtime = create_mcp_server(settings=settings)
    manifest = runtime.build_manifest()

    on_disk_manifest = json.loads(
        (REPO_ROOT / "docs" / "manifest.json").read_text(encoding="utf-8")
    )
    assert on_disk_manifest == manifest

    total_tools = int(manifest["tool_count"])
    solve_lab_count = len(SOLVE_LAB_TOOLS)
    resource_count = len(manifest["resources"])
    prompt_count = len(manifest["prompts"])
    model_count = len(manifest["supported_device_models"])

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert f"{total_tools} MCP tools ({solve_lab_count} in default `solve_lab` profile)" in readme
    assert f"{resource_count} resources, {prompt_count} prompts" in readme
    assert f"verified device profiles across **{model_count} models**" in readme
    assert f"{total_tools} tools ({solve_lab_count} default)" in readme
    assert f"({model_count} models)" in readme
    assert "17 models" not in readme
    for stale in ("69 MCP tools", "69 tools", "6 resources", "4 prompts"):
        assert stale not in readme

    mcp_tools_doc = (REPO_ROOT / "docs" / "mcp-tools.md").read_text(encoding="utf-8")
    assert f"**{total_tools} specialized MCP tools**" in mcp_tools_doc
    assert f"`{solve_lab_count}` enabled in default `solve_lab` profile" in mcp_tools_doc
    assert f"**{resource_count} read-only resources**" in mcp_tools_doc
    assert f"**{prompt_count} guided AI agent prompts**" in mcp_tools_doc
    assert f"## 2. Resources ({resource_count})" in mcp_tools_doc
    assert f"## 3. Workflow Prompts ({prompt_count})" in mcp_tools_doc
    assert f"all {total_tools} tools" in mcp_tools_doc
    assert f"{model_count} supported device models" in mcp_tools_doc
    for stale in (
        "69 specialized MCP tools",
        "69 Tools",
        "6 read-only resources",
        "4 guided AI agent prompts",
    ):
        assert stale not in mcp_tools_doc

    arch_doc = (REPO_ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "<!-- BEGIN MANIFEST COUNTS -->" in arch_doc
    assert f"`{total_tools}` registered tools" in arch_doc
    assert f"`{solve_lab_count}` default (`solve_lab` profile)" in arch_doc
    expected_arch_counts = (
        f"`{resource_count}` resources, `{prompt_count}` prompts, `{model_count}` device models"
    )
    assert expected_arch_counts in arch_doc
    assert f"({model_count} models)" in arch_doc
    assert "17 models" not in arch_doc


@pytest.mark.unit
def test_non_interactive_session_refuses_launch_and_graceful_close_first(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agenticnet.adapters.discovery as disc
    from agenticnet.adapters.script_bridge import HttpScriptBridgeBackend, HttpScriptBridgeServer
    from agenticnet.diagnostics.benchmark import run_live_pt_benchmark
    from agenticnet.gui.windows_backend import WindowsGuiBackend

    # 1. Explicit env refusal
    monkeypatch.delenv("AGENTICNET_ALLOW_NON_INTERACTIVE_LAUNCH", raising=False)
    monkeypatch.setenv("AGENTICNET_NON_INTERACTIVE", "1")
    assert disc.is_interactive_desktop() is False
    with pytest.raises(AdapterUnavailableError) as env_exc:
        disc.require_interactive_desktop_for_launch("test_env")
    assert env_exc.value.error_code == "NON_INTERACTIVE_SESSION"

    # 2. Windows isolated desktop (e.g. WinSta0\exebox-*) refusal
    monkeypatch.delenv("AGENTICNET_NON_INTERACTIVE", raising=False)
    monkeypatch.setattr(disc.platform, "system", lambda: "Windows")

    class _FakeKernel32:
        def GetCurrentProcessId(self) -> int:
            return 100

        def ProcessIdToSessionId(self, _pid: int, sess_ptr: Any) -> int:
            import ctypes

            val = ctypes.cast(sess_ptr, ctypes.POINTER(ctypes.wintypes.DWORD))
            val[0] = 2
            return 1

        def WTSGetActiveConsoleSessionId(self) -> int:
            return 2

    class _FakeWindll:
        kernel32 = _FakeKernel32()

    monkeypatch.setattr(disc.ctypes, "windll", _FakeWindll(), raising=False)
    monkeypatch.setattr(disc, "_query_windows_desktop_name", lambda: "exebox-TEST")
    info = disc.get_desktop_session_info()
    assert info["interactive"] is False
    assert info["desktop_name"] == "exebox-TEST"

    # Ensure subprocess.Popen is never called when launchers refuse
    popen_calls: list[Any] = []
    monkeypatch.setattr(
        "agenticnet.adapters.script_bridge.subprocess.Popen",
        lambda *a, **kw: popen_calls.append((a, kw)),
    )
    monkeypatch.setattr(
        "agenticnet.gui.windows_backend.subprocess.Popen",
        lambda *a, **kw: popen_calls.append((a, kw)),
    )

    # 3. WindowsGuiBackend.launch_application refuses
    gui = WindowsGuiBackend(AgenticNetSettings(data_dir=tmp_path / ".nf_gui"))
    monkeypatch.setattr(gui, "_require_windows", lambda: None)
    with pytest.raises(AdapterUnavailableError) as gui_exc:
        gui.launch_application(wait_seconds=1.0)
    assert gui_exc.value.error_code == "NON_INTERACTIVE_SESSION"

    # 4. MCP tool packet_tracer_launch refuses with NON_INTERACTIVE_SESSION
    srv, _ = create_mcp_server(
        AgenticNetSettings(data_dir=tmp_path / ".nf_mcp", tool_profile="advanced"),
        gui_backend=gui,
    )
    mcp_out = asyncio.run(srv.call_tool("packet_tracer_launch", {}))
    assert mcp_out.structured_content is not None
    payload = dict(mcp_out.structured_content)
    assert payload["success"] is False
    assert payload["errors"][0]["error_code"] == "NON_INTERACTIVE_SESSION"

    # 5. HttpScriptBridgeBackend.ensure_connected refuses before spawning PT
    srv_bridge = HttpScriptBridgeServer(session_file=tmp_path / "bridge_session.json")
    bridge = HttpScriptBridgeBackend(srv_bridge, auto_launch_pt=True)
    srv_bridge.start()
    try:
        monkeypatch.setattr(
            "agenticnet.adapters.script_bridge.detect_packet_tracer_binary",
            lambda _p=None: "C:\\Program Files\\Cisco Packet Tracer 8.2.2\\bin\\PacketTracer.exe",
        )
        with pytest.raises(AdapterUnavailableError) as br_exc:
            bridge.ensure_connected(timeout_seconds=1.0)
        assert br_exc.value.error_code == "NON_INTERACTIVE_SESSION"
    finally:
        srv_bridge.stop()

    # 6. run_live_pt_benchmark refuses before killing or launching PT
    with pytest.raises(AdapterUnavailableError) as bench_exc:
        run_live_pt_benchmark(REPO_ROOT / "labs" / "01_static_routing.json")
    assert bench_exc.value.error_code == "NON_INTERACTIVE_SESSION"
    assert popen_calls == []

    # 7. gracefully_close_packet_tracer uses graceful close ONLY (never forced kills)
    events: list[str] = []
    wm_calls: list[set[int]] = []
    monkeypatch.setattr(
        disc, "_post_wm_close_to_pids", lambda pids: wm_calls.append(set(pids)) or [999]
    )
    monkeypatch.setattr(disc.time, "sleep", lambda _s: None)

    def _fake_run(cmd: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
        events.append(" ".join(cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    import itertools

    ticks = itertools.count(0.0, 0.25)
    monkeypatch.setattr(disc, "list_packet_tracer_pids", lambda: [1234])
    monkeypatch.setattr(disc.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(disc.subprocess, "run", _fake_run)
    close_res = disc.gracefully_close_packet_tracer([1234], timeout_seconds=0.3)
    assert wm_calls == [{1234}]
    assert events == ["taskkill /PID 1234"]
    assert all("/F" not in ev for ev in events)
    assert close_res["close_mode"] == "graceful_only"
    assert close_res["forced_kill_used"] is False
    assert close_res["forced_closed_pids"] == []
    assert close_res["remaining_pids"] == [1234]


def _extract_top_level_js_function_bodies(js_source: str) -> dict[str, str]:
    """Extract `{...}` body of each top-level `function name(...) { ... }` in QtScript."""
    bodies: dict[str, str] = {}
    i = 0
    n = len(js_source)
    depth = 0
    in_single = False
    in_double = False
    in_line_comment = False
    in_block_comment = False

    def _advance_char(idx: int) -> int:
        nonlocal depth, in_single, in_double, in_line_comment, in_block_comment
        ch = js_source[idx]
        nxt = js_source[idx + 1] if idx + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            return idx + 1
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                return idx + 2
            return idx + 1
        if in_single:
            if ch == "\\":
                return idx + 2
            if ch == "'":
                in_single = False
            return idx + 1
        if in_double:
            if ch == "\\":
                return idx + 2
            if ch == '"':
                in_double = False
            return idx + 1
        if ch == "/" and nxt == "/":
            in_line_comment = True
            return idx + 2
        if ch == "/" and nxt == "*":
            in_block_comment = True
            return idx + 2
        if ch == "'":
            in_single = True
            return idx + 1
        if ch == '"':
            in_double = True
            return idx + 1
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        return idx + 1

    fn_re = re.compile(r"function\s+([A-Za-z0-9_$]+)\s*\([^)]*\)\s*\{")
    while i < n:
        if (
            depth == 0
            and not (in_single or in_double or in_line_comment or in_block_comment)
            and (i == 0 or js_source[i - 1] == "\n")
        ):
            m = fn_re.match(js_source, i)
            if m:
                fn_name = m.group(1)
                brace_open = m.end() - 1
                depth = 1
                j = brace_open + 1
                while j < n and depth > 0:
                    j = _advance_char(j)
                bodies[fn_name] = js_source[brace_open + 1 : j - 1]
                i = j
                continue
        i = _advance_char(i)
    assert depth == 0, f"Unbalanced braces in JS (final depth={depth})"
    return bodies


@pytest.mark.unit
def test_netforge_bridge_js_failsafe_invariants_and_heartbeat(tmp_path: Path) -> None:
    from agenticnet.adapters.script_bridge import HttpScriptBridgeServer

    js_path = REPO_ROOT / "agenticnet" / "adapters" / "assets" / "netforge_bridge.js"
    html_path = REPO_ROOT / "agenticnet" / "adapters" / "assets" / "bridge.html"
    js_text = js_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")

    # ES5 / QtScript compatibility and brace balance
    assert "=> " not in js_text
    assert re.search(r"^\s*(?:let|const)\s+", js_text, re.MULTILINE) is None

    # Every top-level function body must be wrapped in a top-level try { ... } catch (...)
    fn_bodies = _extract_top_level_js_function_bodies(js_text)
    assert len(fn_bodies) >= 18
    assert "main" in fn_bodies and "cleanUp" in fn_bodies
    assert "pollSessionDescriptor" in fn_bodies and "netforgeOnCommand" in fn_bodies
    for fn_name, body in fn_bodies.items():
        stripped = body.strip()
        assert stripped.startswith("try {"), (
            f"Top-level function {fn_name} in netforge_bridge.js must open with `try {{`"
        )
        # Verify balanced outer `try { ... } catch (...) { ... }` wraps the entire function body
        sub_depth = 0
        catch_idx = None
        k = 0
        while k < len(stripped):
            ch = stripped[k]
            if ch == "{":
                sub_depth += 1
            elif ch == "}":
                sub_depth -= 1
                if sub_depth == 0:
                    catch_idx = k
                    break
            k += 1
        assert catch_idx is not None, f"Could not close outer try block in {fn_name}"
        tail_after_try = stripped[catch_idx + 1 :].lstrip()
        assert re.match(r"^catch\s*\([^)]+\)\s*\{.*\}\s*$", tail_after_try, re.S), (
            f"Top-level function {fn_name} has code outside top-level try/catch: {tail_after_try!r}"
        )

    # Required constants & lazy fail-safe behavior
    assert 'var MODULE_ID = "com.netforge.bridge";' in js_text
    assert "var IDLE_POLL_INTERVAL_MS = 5000;" in js_text
    assert "var SESSION_FRESH_TTL_MS = 60000;" in js_text
    assert "var MAX_FAILED_POLLS = 3;" in js_text
    assert "setInterval(pollSessionDescriptor, IDLE_POLL_INTERVAL_MS)" in js_text
    for sym in (
        "isSessionDescriptorFresh",
        "blacklistSession",
        "destroyWebView",
        "netforgeOnPollFailure",
        "netforgeOnPollSuccess",
    ):
        assert sym in js_text

    # bridge.html must report poll failures and halt at >= 3
    assert "MAX_FAILED_POLLS = 3" in html_text
    assert "netforgeOnPollFailure" in html_text
    assert "netforgeOnPollSuccess" in html_text

    # HttpScriptBridgeServer writes fresh session_id, server_pid, created_at, heartbeat_at, ttl_ms
    session_file = tmp_path / "bridge_session.json"
    srv = HttpScriptBridgeServer(session_file=session_file, heartbeat_interval_seconds=0.2)
    srv.start()
    try:
        desc1 = json.loads(session_file.read_text(encoding="utf-8"))
        assert desc1["module_id"] == "com.netforge.bridge"
        assert desc1["session_id"].startswith("sess_")
        assert isinstance(desc1["server_pid"], int) and desc1["server_pid"] > 0
        assert isinstance(desc1["created_at"], int) and desc1["created_at"] > 0
        assert isinstance(desc1["heartbeat_at"], int)
        assert desc1["heartbeat_at"] >= desc1["created_at"]
        assert desc1["ttl_ms"] == 60000
    finally:
        srv.stop()
    assert not session_file.exists()


@pytest.mark.unit
def test_repo_and_git_history_free_of_course_and_forbidden_terms() -> None:
    forbidden_patterns = [
        re.compile(r"\btp\d+\b", re.I | re.ASCII),
        re.compile("vlsm" + "_rip", re.I),
        re.compile(
            "("
            + "|".join(
                [
                    "sa" + "mid",
                    "one" + "drive",
                    "en" + "sttic",
                    r"\b2" + r"cs\b",
                    "compte" + r"\s*" + "rendu",
                    "saming" + "n",
                    "t" + "p" + "2" + "ngn",
                    "bouh" + "eraoua",
                    "c:/users" + "/",
                    r"c:\\users" + r"\\",
                ]
            )
            + ")",
            re.I,
        ),
    ]
    binary_suffixes = {
        ".webp",
        ".mp4",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".pts",
        ".pkt",
        ".pka",
    }

    tracked = subprocess.check_output(
        ["git", "ls-files"], cwd=REPO_ROOT, text=True
    ).splitlines()
    for rel_path in tracked:
        fp = REPO_ROOT / rel_path
        if not fp.is_file() or fp.suffix.lower() in binary_suffixes:
            continue
        raw = fp.read_bytes()
        if b"\x00" in raw[:8192]:
            continue
        text = raw.decode("utf-8", errors="ignore")
        for pat in forbidden_patterns:
            m = pat.search(text)
            assert m is None, f"Forbidden term {m.group(0)!r} found in tracked file {rel_path}"

    commits = subprocess.check_output(
        ["git", "rev-list", "--all"], cwd=REPO_ROOT, text=True
    ).splitlines()
    for sha in commits:
        raw = subprocess.check_output(["git", "show", sha], cwd=REPO_ROOT)
        text = raw.decode("utf-8", errors="ignore")
        for pat in forbidden_patterns:
            m = pat.search(text)
            assert m is None, f"Forbidden term {m.group(0)!r} found in commit {sha[:7]}"

