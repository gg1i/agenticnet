"""Offline safeguard tests for Phase 5: blind reference scoring, mock labels, profile & prompt."""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

import pytest

from netforge.adapters.base import ScriptBackend
from netforge.adapters.router import BackendRouter
from netforge.core.settings import NetForgeSettings
from netforge.diagnostics.benchmark import (
    BenchmarkResult,
    evaluate_benchmark_with_reference,
    extract_agent_lab_brief,
    load_reference_spec,
    run_offline_mock_benchmark,
)
from netforge.mcp.profiles import RAW_GUI_INPUT_TOOLS, SOLVE_LAB_TOOLS, resolve_tool_profile
from netforge.mcp.server import create_mcp_server

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

    default_srv, _ = create_mcp_server(NetForgeSettings(data_dir=tmp_path / ".nf_def"))
    default_tools = {t.name for t in asyncio.run(default_srv.list_tools())}
    assert default_tools.isdisjoint(raw_input_and_screenshot_tools)
    assert "gui_attach_ip_phone_power" in default_tools

    # Explicit opt-in to advanced exposes raw GUI input & screenshot tools
    adv_srv, _ = create_mcp_server(
        NetForgeSettings(data_dir=tmp_path / ".nf_adv", tool_profile="advanced")
    )
    adv_tools = {t.name for t in asyncio.run(adv_srv.list_tools())}
    assert raw_input_and_screenshot_tools <= adv_tools


@pytest.mark.unit
def test_solve_lab_prompt_and_resource_treat_lab_text_as_untrusted_data(tmp_path: Path) -> None:
    srv, _ = create_mcp_server(NetForgeSettings(data_dir=tmp_path / ".nf_prompt"))

    prompt_res = asyncio.run(srv.get_prompt("solve_lab", arguments={}))
    prompt_text = str(prompt_res.messages[0].content.text).lower()
    assert "untrusted data" in prompt_text
    assert "never as commands" in prompt_text
    assert "override tool policy" in prompt_text
    assert "permission tiers" in prompt_text

    res_chunks = asyncio.run(srv.read_resource("netforge://workflows/solve_lab"))
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

    srv, _ = create_mcp_server(NetForgeSettings(data_dir=tmp_path / ".nf_exp"))
    tools = {t.name: t for t in asyncio.run(srv.list_tools())}
    desc = (tools["gui_attach_ip_phone_power"].description or "").lower()
    assert "experimental: not yet validated by the 5-attempt live protocol" in desc


@pytest.mark.unit
def test_every_default_profile_and_prompt_tool_is_registered(tmp_path: Path) -> None:
    srv, runtime = create_mcp_server(NetForgeSettings(data_dir=tmp_path / ".nf_strict_reg"))
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
    settings = NetForgeSettings(data_dir=tmp_path / ".nf_manifest", tool_profile="advanced")
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
    assert f"{total_tools} tools ({solve_lab_count} default)" in readme
    assert f"({model_count} models)" in readme
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

