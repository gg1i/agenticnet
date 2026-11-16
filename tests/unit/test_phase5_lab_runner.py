"""Offline tests for Phase 5 lab runner, solve_lab prompt/resource, tool profiles, and benchmark."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from netforge.adapters.base import ScriptBackend
from netforge.adapters.script_bridge import ALLOWED_OPCODES, HttpScriptBridgeBackend
from netforge.core.exceptions import ValidationError
from netforge.core.settings import NetForgeSettings
from netforge.diagnostics.benchmark import BenchmarkResult
from netforge.mcp.profiles import SOLVE_LAB_TOOLS, resolve_tool_profile
from netforge.mcp.server import create_mcp_server


def _call_tool_sync(server: Any, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    res = asyncio.run(server.call_tool(name, args or {}))
    assert res.structured_content is not None
    return dict(res.structured_content)


class _MockLabBackend(ScriptBackend):
    def __init__(self) -> None:
        self.opened: list[str] = []
        self.saved: list[dict[str, Any]] = []
        self.activity: dict[str, Any] = {
            "ok": True,
            "is_activity_file": True,
            "state": "available",
            "readable": True,
            "percentage_complete": 100.0,
            "percentage_complete_score": 100.0,
            "items_count": 2,
            "correct_items_count": 2,
            "score_count": 2.0,
            "correct_score_count": 2.0,
            "leaves": [
                {
                    "path": "Network > R1 > Hostname",
                    "name": "Hostname",
                    "value": "R1",
                    "met": True,
                    "leafCount": 1,
                    "checkLeafCount": 1,
                    "totalLeafPoints": 1.0,
                    "checkLeafPoints": 1.0,
                    "incorrectFeedback": "",
                }
            ],
        }
        self.cli_outputs: dict[str, str] = {
            "show ip interface brief": (
                "Interface              IP-Address      OK? Method Status                Protocol\n"
                "GigabitEthernet0/0     10.0.0.1        YES manual up                    up\n"
            ),
            "ping 10.0.0.2": "Success rate is 100 percent (5/5)",
        }

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
        return dict(self.activity)

    def execute_cli(
        self,
        device_name: str,
        commands: list[str],
        *,
        ensure_privileged: bool = True,
        timeout_seconds: float = 25.0,
    ) -> dict[str, Any]:
        cmd = commands[-1] if commands else ""
        txt = self.cli_outputs.get(cmd, "")
        return {"ok": True, "raw_output": txt, "results": [{"command": cmd, "status": 0}]}

    def open_file(self, path: str, *, timeout_seconds: float = 30.0) -> dict[str, Any]:
        self.opened.append(path)
        return {
            "ok": True,
            "path": path,
            "saved_filename": path,
            "is_activity_file": path.lower().endswith(".pka"),
        }

    def save_file(
        self,
        path: str | None = None,
        *,
        overwrite: bool = True,
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        self.saved.append({"path": path, "overwrite": overwrite})
        return {
            "ok": True,
            "saved": True,
            "path": path or "active.pka",
            "method": "fileSaveAsNoPrompt" if path else "fileSave",
        }

    def list_devices(self, *, timeout_seconds: float = 30.0) -> dict[str, Any]:
        return {
            "ok": True,
            "device_count": 2,
            "link_count": 1,
            "devices": [
                {
                    "name": "Router0",
                    "model": "2911",
                    "type_code": 0,
                    "type": "router",
                    "hostname": "HQ_RTR",
                    "port_count": 3,
                    "ports": [
                        {
                            "name": "GigabitEthernet0/0",
                            "ip_address": "10.0.0.1",
                            "subnet_mask": "255.255.255.0",
                            "port_up": True,
                            "protocol_up": True,
                            "mac_address": "0060.2F06.8501",
                            "has_link": True,
                            "remote_port_name": "FastEthernet0/1",
                            "remote_device_name": "Switch0",
                        }
                    ],
                },
                {
                    "name": "Switch0",
                    "model": "2960-24TT",
                    "type_code": 1,
                    "type": "switch",
                    "hostname": "SW1",
                    "port_count": 24,
                    "ports": [
                        {
                            "name": "FastEthernet0/1",
                            "ip_address": "",
                            "subnet_mask": "",
                            "port_up": True,
                            "protocol_up": True,
                            "mac_address": "0060.7067.C401",
                            "has_link": True,
                            "remote_port_name": "GigabitEthernet0/0",
                            "remote_device_name": "Router0",
                        }
                    ],
                },
            ],
            "links": [
                {
                    "device1": "Router0",
                    "port1": "GigabitEthernet0/0",
                    "device2": "Switch0",
                    "port2": "FastEthernet0/1",
                }
            ],
        }


@pytest.mark.unit
def test_lab_open_and_lab_save_live_mocked_and_fail_closed(tmp_path: Path) -> None:
    backend = _MockLabBackend()
    settings = NetForgeSettings(data_dir=tmp_path / ".nf", permission_profile="standard")
    srv_live, _ = create_mcp_server(settings=settings, script_backend=backend)

    # Dry-run checks require zero live bridge
    srv_off, _ = create_mcp_server(settings=settings)
    dry_open = _call_tool_sync(srv_off, "lab_open", {"path": "demo.pka", "dry_run": True})
    assert dry_open["success"] is True
    assert dry_open["execution_backend"] == "offline_model"
    assert dry_open["state_level"] == "planned"

    dry_save = _call_tool_sync(
        srv_off, "lab_save", {"path": "out.pkt", "overwrite": True, "dry_run": True}
    )
    assert dry_save["success"] is True
    assert dry_save["data"]["method"] == "fileSaveAsNoPrompt"

    # Disconnected non-dry calls fail closed
    fail_open = _call_tool_sync(srv_off, "lab_open", {"path": "demo.pka"})
    fail_save = _call_tool_sync(srv_off, "lab_save", {})
    assert fail_open["success"] is False
    assert fail_save["success"] is False

    # Live mocked calls route to script_backend
    live_open = _call_tool_sync(srv_live, "lab_open", {"path": "C:/labs/demo.pka"})
    assert live_open["success"] is True
    assert live_open["execution_backend"] == "script_backend"
    assert live_open["state_level"] == "executed"
    assert backend.opened == ["C:/labs/demo.pka"]

    live_save_inplace = _call_tool_sync(srv_live, "lab_save", {})
    assert live_save_inplace["success"] is True
    assert live_save_inplace["execution_backend"] == "script_backend"
    assert backend.saved[-1] == {"path": None, "overwrite": True}

    live_save_as = _call_tool_sync(
        srv_live, "lab_save", {"path": "C:/labs/solved.pka", "overwrite": True}
    )
    assert live_save_as["success"] is True
    assert backend.saved[-1] == {"path": "C:/labs/solved.pka", "overwrite": True}

    # Blank path validation fails closed
    bad_open = _call_tool_sync(srv_live, "lab_open", {"path": "   "})
    bad_save = _call_tool_sync(srv_live, "lab_save", {"path": "   "})
    assert bad_open["success"] is False
    assert bad_save["success"] is False


@pytest.mark.unit
def test_http_script_bridge_save_file_opcode() -> None:
    assert "save_file" in ALLOWED_OPCODES
    mock_srv = MagicMock()
    mock_srv.is_connected.return_value = True
    mock_srv.enqueue_command.return_value = {"saved": True, "path": "out.pka"}
    bridge = HttpScriptBridgeBackend(mock_srv)
    out = bridge.save_file("out.pka", overwrite=False, timeout_seconds=10.0)
    mock_srv.enqueue_command.assert_called_once_with(
        "save_file",
        {"overwrite": False, "path": "out.pka"},
        timeout_seconds=10.0,
    )
    assert out["ok"] is True
    assert "save_file" in bridge.backend_status().capabilities


@pytest.mark.unit
def test_lab_status_what_is_left_and_fail_closed_grading(tmp_path: Path) -> None:
    backend = _MockLabBackend()
    settings = NetForgeSettings(data_dir=tmp_path / ".nf", permission_profile="standard")
    server, _ = create_mcp_server(settings=settings, script_backend=backend)

    reqs = {
        "lab_name": "Unit Status Check",
        "requirements": [
            {
                "id": "r1_ip",
                "task_id": "T1_IP",
                "type": "ip_assigned",
                "device": "R1",
                "interface": "GigabitEthernet0/0",
                "ip": "10.0.0.1",
            },
            {
                "id": "r1_ping",
                "task_id": "T2_PING",
                "type": "reachable",
                "from": "R1",
                "to": "10.0.0.2",
            },
        ],
    }

    # 1. Partial grader + uncovered task + failing reachability => overall_passed False
    backend.cli_outputs["ping 10.0.0.2"] = "Success rate is 0 percent (0/5)"
    backend.activity["percentage_complete"] = 50.0
    backend.activity["correct_items_count"] = 1
    backend.activity["leaves"].append(
        {
            "path": "Network > R1 > Ping",
            "name": "Reachability",
            "value": "ok",
            "met": False,
            "leafCount": 1,
            "checkLeafCount": 0,
            "totalLeafPoints": 1.0,
            "checkLeafPoints": 0.0,
            "incorrectFeedback": "Target not reachable",
        }
    )
    incomplete = _call_tool_sync(
        server,
        "lab_status",
        {"requirements": reqs, "task_ids": ["T1_IP", "T2_PING", "T3_SAVE"]},
    )
    assert incomplete["success"] is True
    d1 = incomplete["data"]
    assert d1["overall_passed"] is False
    assert len(d1["what_is_left"]["failing_requirements"]) == 1
    assert len(d1["what_is_left"]["unmet_grader_items"]) == 1
    assert d1["what_is_left"]["uncovered_tasks"] == ["T3_SAVE"]
    assert d1["what_is_left"]["is_empty"] is False
    assert any("ping" in ev.lower() for ev in d1["raw_evidence"])

    # 2. All requirements pass & 100% task coverage, grader 100% => overall_passed True
    backend.cli_outputs["ping 10.0.0.2"] = "Success rate is 100 percent (5/5)"
    backend.activity["percentage_complete"] = 100.0
    backend.activity["correct_items_count"] = 2
    backend.activity["leaves"] = [backend.activity["leaves"][0]]
    complete = _call_tool_sync(
        server,
        "lab_status",
        {"requirements": reqs, "task_ids": ["T1_IP", "T2_PING"]},
    )
    d2 = complete["data"]
    assert d2["overall_passed"] is True
    assert d2["state_level"] == "verified"
    assert d2["what_is_left"]["is_empty"] is True

    # 3. Assessment-locked .pka fails closed on grader without blocking verify_lab pass
    backend.activity = {
        "ok": True,
        "is_activity_file": True,
        "locked": True,
        "assessment_mode": True,
        "state": "unavailable",
        "readable": False,
        "reason": "Assessment mode lock enabled.",
    }
    locked_status = _call_tool_sync(
        server,
        "lab_status",
        {"requirements": reqs, "task_ids": ["T1_IP", "T2_PING"]},
    )
    d3 = locked_status["data"]
    assert d3["overall_passed"] is True
    assert d3["grade"]["state"] == "unavailable"
    assert d3["grade"]["fallback"] == "verify_lab"
    assert "Assessment" in d3["what_is_left"]["grader_unavailable_reason"]


@pytest.mark.unit
def test_solve_lab_prompt_and_resource(tmp_path: Path) -> None:
    settings = NetForgeSettings(data_dir=tmp_path / ".nf")
    server, runtime = create_mcp_server(settings=settings)
    assert "solve_lab" in runtime.registry.prompt_names
    assert "netforge://workflows/solve_lab" in runtime.registry.resource_uris

    prompt_res = asyncio.run(
        server.get_prompt(
            "solve_lab",
            arguments={
                "lab_goal": "Configure OSPF lab",
                "max_iterations": 6,
                "time_budget_minutes": 10,
            },
        )
    )
    text = str(prompt_res.messages[0].content.text)
    for required in (
        "lab_open",
        "task_ids",
        "lab_status",
        "what_is_left",
        "lab_save",
        "max_iterations=6",
        "time_budget_minutes=10",
        "NEVER bypass",
    ):
        assert required in text

    resources = asyncio.run(server.read_resource("netforge://workflows/solve_lab"))
    res_text = "".join(str(getattr(c, "content", c)) for c in resources)
    assert "lab_status" in res_text and "lab_save" in res_text


@pytest.mark.unit
def test_tool_profiles_solve_lab_default_vs_advanced(tmp_path: Path) -> None:
    default_settings = NetForgeSettings(data_dir=tmp_path / ".nf1")
    assert default_settings.tool_profile == "solve_lab"
    srv_default, rt_default = create_mcp_server(default_settings)
    default_names = {t.name for t in asyncio.run(srv_default.list_tools())}
    assert default_names == SOLVE_LAB_TOOLS
    assert len(default_names) == 25
    assert rt_default.build_manifest()["tool_profile"] == "solve_lab"
    assert "configure_ospf" not in default_names

    adv_settings = NetForgeSettings(data_dir=tmp_path / ".nf2", tool_profile="advanced")
    srv_adv, rt_adv = create_mcp_server(adv_settings)
    adv_names = {t.name for t in asyncio.run(srv_adv.list_tools())}
    assert len(adv_names) == 82
    assert default_names < adv_names
    assert rt_adv.build_manifest()["tool_profile"] == "advanced"

    with pytest.raises(ValidationError):
        resolve_tool_profile("nonexistent_profile")


@pytest.mark.unit
def test_benchmark_runner_mock_and_fail_closed_live(tmp_path: Path) -> None:
    import scripts.run_benchmark as bench_cli

    out_file = tmp_path / "bench_out.json"
    rc = bench_cli.main(["--all-sample-labs", "--mock", "--output", str(out_file)])
    assert rc == 0
    report = json.loads(out_file.read_text(encoding="utf-8"))
    assert report["total"] == 3
    assert report["passed"] == 3
    for item in report["results"]:
        validated = BenchmarkResult.model_validate(item)
        assert validated.passed is True
        assert validated.status == "passed"
        assert validated.mode == "offline_mock"
        assert validated.iterations == 2
        assert validated.evidence.task_coverage is not None
        assert validated.evidence.task_coverage["all_tasks_covered"] is True

    # Budget limit test (--max-iterations 1 leaves lab broken -> budget_exceeded)
    budget_file = tmp_path / "bench_budget.json"
    rc_budget = bench_cli.main(
        ["--mock", "--max-iterations", "1", "--output", str(budget_file)]
    )
    assert rc_budget == 1
    single = BenchmarkResult.model_validate_json(budget_file.read_text(encoding="utf-8"))
    assert single.passed is False
    assert single.status == "budget_exceeded"
    assert single.iterations == 1

    # Live mode refuses when run in offline skeleton
    assert bench_cli.main(["--live"]) == 2


@pytest.mark.unit
def test_list_devices_and_lab_snapshot_mocked_and_fail_closed(tmp_path: Path) -> None:
    backend = _MockLabBackend()
    settings = NetForgeSettings(data_dir=tmp_path / ".nf", permission_profile="standard")
    srv_live, _ = create_mcp_server(settings=settings, script_backend=backend)

    # 1. list_devices live via mock backend
    ld_res = _call_tool_sync(srv_live, "list_devices", {})
    assert ld_res["success"] is True
    assert ld_res["execution_backend"] == "script_backend"
    devs = ld_res["data"]["devices"]
    assert len(devs) == 2
    rtr = next(d for d in devs if d["name"] == "Router0")
    assert rtr["model"] == "2911"
    assert rtr["hostname"] == "HQ_RTR"
    assert rtr["type"] == "router"

    # 2. lab_snapshot live via mock backend
    snap_res = _call_tool_sync(srv_live, "lab_snapshot", {})
    assert snap_res["success"] is True
    assert snap_res["data"]["device_count"] == 2
    assert snap_res["data"]["link_count"] == 1
    assert len(snap_res["data"]["active_interfaces"]) == 2
    iface0 = snap_res["data"]["active_interfaces"][0]
    assert iface0["device"] == "Router0"
    assert iface0["ip_address"] == "10.0.0.1"
    assert iface0["subnet_mask"] == "255.255.255.0"
    assert iface0["remote_device"] == "Switch0"

    # 3. Fail-closed when no script backend connected
    srv_off, _ = create_mcp_server(settings=settings)
    fail_ld = _call_tool_sync(srv_off, "list_devices", {})
    assert fail_ld["success"] is False
    assert "no live ScriptBackend" in str(fail_ld.get("error") or fail_ld.get("errors") or fail_ld)


@pytest.mark.unit
def test_verifier_polling_wait_passes_eventually_and_fails_with_evidence(tmp_path: Path) -> None:
    from netforge.adapters.router import BackendRouter
    from netforge.diagnostics.verifier import LabVerifier

    class _ConvergenceBackend(_MockLabBackend):
        def __init__(self) -> None:
            super().__init__()
            self.call_counts: dict[str, int] = {}

        def execute_cli(
            self, device_name: str, commands: list[str], **kwargs: Any
        ) -> dict[str, Any]:
            cmd = commands[-1]
            self.call_counts[cmd] = self.call_counts.get(cmd, 0) + 1
            count = self.call_counts[cmd]
            if cmd == "show ip interface brief":
                # Fails on attempts 1 and 2, passes on attempt 3
                if count < 3:
                    out = (
                        "GigabitEthernet0/0     10.0.0.1        "
                        "YES manual up                    down\n"
                    )
                else:
                    out = (
                        "GigabitEthernet0/0     10.0.0.1        "
                        "YES manual up                    up\n"
                    )
                return {
                    "ok": True,
                    "raw_output": out,
                    "results": [{"command": cmd, "status": 0}],
                }
            if cmd == "ping 10.99.99.99":
                return {
                    "ok": True,
                    "raw_output": "Success rate is 0 percent (0/5)",
                    "results": [{"command": cmd, "status": 0}],
                }
            return super().execute_cli(device_name, commands, **kwargs)

    backend = _ConvergenceBackend()
    router = BackendRouter(script_backend=backend)
    verifier = LabVerifier(router, cli_pacing_seconds=0.01, max_cli_retries=1)

    # 1. Requirement that converges after polling
    reqs = [
        {
            "id": "r1_int",
            "task_id": "T1",
            "type": "interface_up",
            "device": "R1",
            "interface": "GigabitEthernet0/0",
        }
    ]
    rep = verifier.verify(reqs, poll_wait_seconds=5.0, poll_interval_seconds=0.05)
    assert rep["passed"] is True
    assert rep["results"][0]["status"] == "pass"
    assert backend.call_counts["show ip interface brief"] >= 3

    # 2. Requirement that never converges: polling times out and reports real failure with evidence
    fail_reqs = [
        {
            "id": "r1_ping",
            "task_id": "T2",
            "type": "reachable",
            "source": "R1",
            "target": "10.99.99.99",
        }
    ]
    rep_fail = verifier.verify(fail_reqs, poll_wait_seconds=0.15, poll_interval_seconds=0.05)
    assert rep_fail["passed"] is False
    assert rep_fail["results"][0]["status"] == "fail"
    assert "0 percent" in rep_fail["results"][0]["evidence"]
    assert rep_fail["results"][0]["reason"]


@pytest.mark.unit
def test_verifier_paced_cli_queue_and_bounded_retries(tmp_path: Path) -> None:
    from netforge.adapters.router import BackendRouter
    from netforge.core.exceptions import NetForgeError
    from netforge.diagnostics.verifier import LabVerifier, PacedDeviceCliQueue

    # 1. Test pacing queue timing
    queue = PacedDeviceCliQueue(pacing_seconds=0.05, max_retries=2)
    t0 = time.monotonic()
    queue.pace("R1")
    queue.pace("R1")
    t1 = time.monotonic()
    assert (t1 - t0) >= 0.04

    # 2. Bounded retries on transient error
    class _FlakyBackend(_MockLabBackend):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def execute_cli(
            self, device_name: str, commands: list[str], **kwargs: Any
        ) -> dict[str, Any]:
            self.calls += 1
            if self.calls < 3:
                raise NetForgeError("Transient bridge timeout")
            return {
                "ok": True,
                "raw_output": (
                    "GigabitEthernet0/0     10.0.0.1        "
                    "YES manual up                    up\n"
                ),
                "results": [{"command": commands[0], "status": 0}],
            }

    flaky = _FlakyBackend()
    router = BackendRouter(script_backend=flaky)
    verifier = LabVerifier(router, cli_pacing_seconds=0.01, max_cli_retries=3)
    outcome = verifier._read_cli("R1", "show ip interface brief", timeout_seconds=10.0)
    assert outcome.error is None
    assert "10.0.0.1" in outcome.raw_evidence
    assert flaky.calls == 3

    # 3. Auto-elevates from User Exec ('>') to Privileged Exec ('enable') when read fails
    class _UserExecBackend(_MockLabBackend):
        def __init__(self) -> None:
            super().__init__()
            self.sent_cmds: list[str] = []
            self.mode = "user"

        def execute_cli(
            self, device_name: str, commands: list[str], **kwargs: Any
        ) -> dict[str, Any]:
            cmd = commands[0]
            self.sent_cmds.append(cmd)
            if cmd == "enable":
                self.mode = "priv"
                return {"ok": True, "prompt": "R1#", "raw_output": "", "command_statuses": []}
            if cmd == "show running-config" and self.mode == "user":
                return {
                    "ok": True,
                    "prompt": "R1>",
                    "raw_output": "% Invalid input detected at '^' marker.\nR1>",
                    "command_statuses": [{"command": cmd, "status": 2}],
                }
            return {
                "ok": True,
                "prompt": "R1#",
                "raw_output": "hostname R1-LIVE\nend\nR1#",
                "command_statuses": [{"command": cmd, "status": 0}],
            }

    ux_backend = _UserExecBackend()
    ux_verifier = LabVerifier(
        BackendRouter(script_backend=ux_backend),
        cli_pacing_seconds=0.01,
        max_cli_retries=1,
    )
    ux_outcome = ux_verifier._read_cli("R1", "show running-config", timeout_seconds=10.0)
    assert ux_outcome.error is None
    assert "hostname R1-LIVE" in ux_outcome.raw_evidence
    assert ux_backend.sent_cmds == ["show running-config", "enable", "show running-config"]


@pytest.mark.unit
def test_attach_ip_phone_power_script_first_and_gui_fallback(tmp_path: Path) -> None:
    from netforge.core.exceptions import AdapterUnavailableError
    from netforge.gui.adapter import NullGuiBackend

    assert "attach_ip_phone_power" in ALLOWED_OPCODES
    bridge_meta = HttpScriptBridgeBackend()
    assert "attach_ip_phone_power" in bridge_meta.backend_status().capabilities

    class _PhonePowerBackend(_MockLabBackend):
        def __init__(self) -> None:
            super().__init__()
            self.powered_calls: list[str] = []

        def attach_ip_phone_power(
            self, device_name: str, *, timeout_seconds: float = 25.0
        ) -> dict[str, Any]:
            self.powered_calls.append(device_name)
            return {
                "ok": True,
                "backend": "script_http",
                "device_name": device_name,
                "powered": True,
                "module_added": True,
                "method_used": "rootModule.addModuleAt(IP_PHONE_POWER_ADAPTER,0)",
            }

    settings = NetForgeSettings(data_dir=tmp_path / ".nf", tool_profile="solve_lab")
    backend = _PhonePowerBackend()
    gui_mock = NullGuiBackend(settings)
    gui_mock.attach_ip_phone_power = MagicMock(  # type: ignore[attr-defined]
        side_effect=AssertionError("GUI fallback must not be called when ScriptBackend works")
    )
    server, runtime = create_mcp_server(settings, gui_backend=gui_mock, script_backend=backend)
    runtime.router.device_aliases["IP_PHONE1"] = "IP Phone0"

    res = _call_tool_sync(server, "gui_attach_ip_phone_power", {"device_name": "IP_PHONE1"})
    assert res["success"] is True
    assert res["execution_backend"] == "script_backend"
    assert res["state_level"] == "verified"
    assert res["data"]["powered"] is True
    assert backend.powered_calls == ["IP Phone0"]

    # When ScriptBackend cannot attach power, falls back cleanly to GuiBackend
    class _UnconnectedPhoneBackend(_MockLabBackend):
        def is_connected(self) -> bool:
            return False

        def attach_ip_phone_power(
            self, device_name: str, *, timeout_seconds: float = 25.0
        ) -> dict[str, Any]:
            raise AdapterUnavailableError("disconnected")

    gui_fallback = NullGuiBackend(settings)
    fallback_spy = MagicMock(
        return_value={
            "state_level": "executed",
            "device_name": "IP_PHONE1",
            "pt_device_title": "IP_PHONE1",
            "hwnd": 1,
            "dpi": 96,
            "socket_roi_diff_ratio": 0.25,
        }
    )
    gui_fallback.attach_ip_phone_power = fallback_spy  # type: ignore[attr-defined]
    server2, _ = create_mcp_server(
        settings, gui_backend=gui_fallback, script_backend=_UnconnectedPhoneBackend()
    )
    res2 = _call_tool_sync(server2, "gui_attach_ip_phone_power", {"device_name": "IP_PHONE1"})
    assert res2["success"] is True
    assert res2["execution_backend"] == "gui_backend"
    assert fallback_spy.called


@pytest.mark.unit
def test_zero_touch_auto_launch_and_auto_create_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netforge.adapters.router import BackendRouter
    from netforge.core.exceptions import ProjectNotOpenError
    from netforge.storage.project_manager import ProjectManager

    # 1. Settings defaults and env overrides
    default_s = NetForgeSettings(data_dir=tmp_path / ".nf1")
    assert default_s.auto_launch_packet_tracer is True
    assert default_s.auto_create_project is True

    monkeypatch.setenv("NETFORGE_AUTO_LAUNCH_PT", "0")
    monkeypatch.setenv("NETFORGE_AUTO_CREATE_PROJECT", "false")
    env_s = NetForgeSettings.from_env()
    assert env_s.auto_launch_packet_tracer is False
    assert env_s.auto_create_project is False

    # 2. ProjectManager auto-creates default workspace and re-opens it automatically
    pm = ProjectManager(default_s)
    meta, _, _, _ = pm.require_active()
    assert meta.project_id == "default-workspace"
    pm.close_project()
    meta2, _, _, _ = pm.require_active()
    assert meta2.project_id == "default-workspace"

    pm_manual = ProjectManager(
        NetForgeSettings(data_dir=tmp_path / ".nf2", auto_create_project=False)
    )
    with pytest.raises(ProjectNotOpenError):
        pm_manual.require_active()

    # 3. BackendRouter.ensure_live_script() auto-connects and lab_open attaches discovery
    class _AutoConnectingBackend(_MockLabBackend):
        def __init__(self) -> None:
            super().__init__()
            self._connected = False
            self.ensure_calls = 0

        def is_connected(self) -> bool:
            return self._connected

        def ensure_connected(self, *, timeout_seconds: float = 40.0) -> bool:
            self.ensure_calls += 1
            self._connected = True
            return True

        def list_devices(self, *, timeout_seconds: float = 30.0) -> dict[str, Any]:
            return {
                "ok": True,
                "device_count": 1,
                "link_count": 0,
                "devices": [
                    {
                        "name": "Router0",
                        "model": "2911",
                        "type": "router",
                        "hostname": "R1",
                        "ports": [],
                    }
                ],
                "links": [],
            }

    auto_b = _AutoConnectingBackend()
    router = BackendRouter(script_backend=auto_b)
    backend_used, add_data, _, _ = router.add_device("R1", "2911")
    assert backend_used == "script_backend"
    assert auto_b.ensure_calls == 1
    assert add_data["device_name"] == "2911"

    srv, _ = create_mcp_server(
        NetForgeSettings(data_dir=tmp_path / ".nf3", tool_profile="solve_lab"),
        script_backend=auto_b,
    )
    opened = _call_tool_sync(srv, "lab_open", {"path": "sample.pkt"})
    assert opened["success"] is True
    assert opened["data"]["discovered_devices"]["device_count"] == 1


@pytest.mark.unit
def test_one_command_lab_start_copy_on_write_diff_watch_and_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netforge.adapters.base import GuiBackend
    from netforge.mcp.profiles import RAW_GUI_INPUT_TOOLS

    class _FakeGui(GuiBackend):
        def __init__(self, *, running: bool = False, login_wall: bool = False) -> None:
            self.running = running
            self.login_wall = login_wall
            self.launch_calls: list[dict[str, Any]] = []
            self.click_calls: int = 0

        def detect_application(self) -> dict[str, Any]:
            dialogs = (
                [{"title": "Skills for All Login", "dialog_type": "login_wall"}]
                if self.login_wall
                else []
            )
            return {
                "detected_binary": True,
                "executable_path": "PacketTracer.exe",
                "running": self.running,
                "dialogs": dialogs,
            }

        def launch_application(
            self,
            executable_path: str | None = None,
            *,
            project_file: str | None = None,
            wait_seconds: float = 15.0,
            background: bool | None = None,
        ) -> dict[str, Any]:
            self.launch_calls.append(
                {"wait_seconds": wait_seconds, "background": background, "project": project_file}
            )
            self.running = True
            return {
                "already_running": False,
                "launched": True,
                "detection": self.detect_application(),
            }

        def capture_screenshot(self, output_path: str | None = None, **_: Any) -> dict[str, Any]:
            return {}

        def calibrate(self, *, profile_id: str = "default") -> dict[str, Any]:
            return {}

        def click(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            self.click_calls += 1
            return {}

        def inspect_state(self) -> dict[str, Any]:
            return {}

        def keypress(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {}

        def recover(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            return {}

    # 1. Default profile keeps raw GUI input tools out and includes start_lab prompt
    srv_def, _ = create_mcp_server(NetForgeSettings(data_dir=tmp_path / ".nf_def"))
    prompt_res = asyncio.run(srv_def.get_prompt("start_lab", arguments={"lab_input": "demo"}))
    assert "lab_start" in prompt_res.messages[0].content.text
    assert SOLVE_LAB_TOOLS.isdisjoint(RAW_GUI_INPUT_TOOLS)
    assert {"lab_start", "lab_diff"} <= SOLVE_LAB_TOOLS

    # 2. Idea / .md plan-then-build mode: waits for approval without touching PT; <= 3 questions
    gui_idle = _FakeGui(running=False)
    srv_plan, _ = create_mcp_server(
        NetForgeSettings(data_dir=tmp_path / ".nf_plan"),
        gui_backend=gui_idle,
    )
    vague = _call_tool_sync(srv_plan, "lab_start", {"input_target": "build a small network"})
    assert vague["success"] is True
    assert vague["data"]["state"] == "awaiting_plan_approval"
    assert vague["data"]["touched_packet_tracer"] is False
    assert gui_idle.launch_calls == []
    assert 1 <= len(vague["data"]["clarifying_questions"]) <= 3
    assert len(vague["data"]["plan"]["devices"]) >= 2

    md_file = tmp_path / "campus_spec.md"
    md_file.write_text(
        "# OSPF Dual Router Lab\n"
        "Build 2 routers R1 and R2 over 10.10.0.0/16 with OSPF and VLAN 10.\n",
        encoding="utf-8",
    )
    md_plan = _call_tool_sync(srv_plan, "lab_start", {"input_target": str(md_file)})
    assert md_plan["success"] is True
    assert md_plan["data"]["state"] == "awaiting_plan_approval"
    assert md_plan["data"]["input"]["kind"] == "document"
    assert md_plan["data"]["clarifying_questions"] == []
    assert any(d["name"] == "R2" for d in md_plan["data"]["plan"]["devices"])

    # 3. Non-interactive session refuses hidden PT launch cleanly
    monkeypatch.setenv("NETFORGE_NON_INTERACTIVE", "1")
    non_int = _call_tool_sync(
        srv_plan, "lab_start", {"input_target": str(md_file), "auto_approve": True}
    )
    assert non_int["success"] is False
    assert non_int["errors"][0]["error_code"] == "NON_INTERACTIVE_SESSION"
    assert gui_idle.launch_calls == []

    # 4. Login wall pauses cleanly and never clicks
    monkeypatch.delenv("NETFORGE_NON_INTERACTIVE", raising=False)
    gui_login = _FakeGui(running=True, login_wall=True)
    srv_login, _ = create_mcp_server(
        NetForgeSettings(data_dir=tmp_path / ".nf_login"),
        gui_backend=gui_login,
    )
    login_out = _call_tool_sync(
        srv_login, "lab_start", {"input_target": str(md_file), "auto_approve": True}
    )
    assert login_out["success"] is False
    assert login_out["errors"][0]["error_code"] == "LOGIN_WALL"
    assert gui_login.click_calls == 0

    # 5. Bridge timeout returns clear error when interactive PT launches without bridge
    import netforge.diagnostics.lab_runner as lr

    monkeypatch.setattr(lr, "require_interactive_desktop_for_launch", lambda *_a: None)
    gui_launch = _FakeGui(running=False)
    srv_timeout, _ = create_mcp_server(
        NetForgeSettings(data_dir=tmp_path / ".nf_to"),
        gui_backend=gui_launch,
    )
    to_out = _call_tool_sync(
        srv_timeout,
        "lab_start",
        {"input_target": str(md_file), "auto_approve": True, "wait_seconds": 0.05},
    )
    assert to_out["success"] is False
    assert to_out["errors"][0]["error_code"] == "BRIDGE_TIMEOUT"
    assert len(gui_launch.launch_calls) == 1
    assert gui_launch.launch_calls[0]["background"] is False

    # 6. Live .pkt copy-on-write, single-instance reuse, watch mode, lab_diff, backup
    orig_pkt = tmp_path / "campus.pkt"
    orig_pkt.write_bytes(b"ORIGINAL_PKT_DATA")

    class _DynamicDiffBackend(_MockLabBackend):
        def __init__(self) -> None:
            super().__init__()
            self.added_r2 = False
            self.linked_r2 = False

        def add_device(
            self, model: str, *, device_type: int | str = 0, x: float = 100.0, y: float = 100.0
        ) -> dict[str, Any]:
            self.added_r2 = True
            return {"ok": True, "device_name": "R2"}

        def create_link(
            self,
            device1: str,
            port1: str,
            device2: str,
            port2: str,
            *,
            conn_type: int | str = 8107,
        ) -> dict[str, Any]:
            self.linked_r2 = True
            return {"ok": True}

        def execute_cli(
            self,
            device_name: str,
            commands: list[str],
            *,
            ensure_privileged: bool = True,
            timeout_seconds: float = 25.0,
        ) -> dict[str, Any]:
            cmd = commands[-1] if commands else ""
            if cmd.strip() in {"", "enable"}:
                return {"ok": True, "raw_output": f"{device_name}#", "prompt": f"{device_name}#"}
            if "configure terminal" in cmd:
                return {
                    "ok": True,
                    "raw_output": f"{device_name}(config)#",
                    "prompt": f"{device_name}(config)#",
                }
            return {
                "ok": True,
                "raw_output": f"{device_name}(config)#",
                "prompt": f"{device_name}(config)#",
            }

        def list_devices(self, *, timeout_seconds: float = 30.0) -> dict[str, Any]:
            base = super().list_devices(timeout_seconds=timeout_seconds)
            if self.added_r2:
                base["devices"].append(
                    {
                        "name": "R2",
                        "model": "2911",
                        "type_code": 0,
                        "type": "router",
                        "hostname": "R2_BRANCH",
                        "port_count": 3,
                        "ports": [
                            {
                                "name": "GigabitEthernet0/0",
                                "ip_address": "10.0.12.2",
                                "subnet_mask": "255.255.255.252",
                                "port_up": True,
                                "protocol_up": True,
                                "mac_address": "0060.2F06.9901",
                                "has_link": self.linked_r2,
                                "remote_port_name": "FastEthernet0/2" if self.linked_r2 else "",
                                "remote_device_name": "Switch0" if self.linked_r2 else "",
                            }
                        ],
                    }
                )
            if self.linked_r2:
                base["links"].append(
                    {
                        "device1": "Switch0",
                        "port1": "FastEthernet0/2",
                        "device2": "R2",
                        "port2": "GigabitEthernet0/0",
                    }
                )
            base["device_count"] = len(base["devices"])
            base["link_count"] = len(base["links"])
            return base

    live_b = _DynamicDiffBackend()
    gui_reused = _FakeGui(running=True)
    sleep_calls: list[float] = []
    srv_live, rt_live = create_mcp_server(
        NetForgeSettings(data_dir=tmp_path / ".nf_live"),
        gui_backend=gui_reused,
        script_backend=live_b,
    )
    rt_live.router._sleep = lambda sec: sleep_calls.append(sec)

    started = _call_tool_sync(
        srv_live,
        "lab_start",
        {"input_target": str(orig_pkt), "watch_pace_seconds": 0.25},
    )
    assert started["success"] is True
    assert started["data"]["state"] == "ready"
    assert started["data"]["pt_status"] == "reused_running_instance"
    assert gui_reused.launch_calls == []
    assert started["data"]["original_path"] == str(orig_pkt)
    assert started["data"]["working_copy_path"] == str(tmp_path / "campus_netforge.pkt")
    assert started["data"]["initial_snapshot"]["device_count"] == 2
    assert live_b.opened == [str(orig_pkt)]
    assert live_b.saved[0]["path"] == str(tmp_path / "campus_netforge.pkt")
    assert orig_pkt.read_bytes() == b"ORIGINAL_PKT_DATA"

    # Register pre-existing Switch0 in local TopologyEngine before linking a new R2
    _, topo_live, _, _ = rt_live.manager.require_active()
    topo_live.add_device("Switch0", "2960-24TT")

    # Modify step-by-step under watch mode
    add_out = _call_tool_sync(srv_live, "device_add", {"name": "R2", "model": "2911"})
    assert "narration" in add_out["data"]["live_backend"]
    link_out = _call_tool_sync(
        srv_live,
        "connection_create",
        {
            "source_device": "Switch0",
            "source_interface": "FastEthernet0/2",
            "target_device": "R2",
            "target_interface": "GigabitEthernet0/0",
        },
    )
    assert link_out["success"] is True
    cli_out = _call_tool_sync(
        srv_live,
        "console_execute",
        {"device_name": "R2", "commands": ["configure terminal", "hostname R2_BRANCH"]},
    )
    assert cli_out["success"] is True
    assert "narration" in cli_out["data"]
    assert len(sleep_calls) >= 3

    # lab_diff shows device added, link added, interface & CLI config changes
    diff_out = _call_tool_sync(srv_live, "lab_diff", {})
    assert diff_out["success"] is True
    assert diff_out["data"]["has_changes"] is True
    assert diff_out["data"]["devices_added"][0]["name"] == "R2"
    assert len(diff_out["data"]["links_added"]) == 1
    assert "R2" in diff_out["data"]["config_changes"]
    assert "Devices added: R2" in diff_out["data"]["readable_summary"]

    # lab_save defaults to copy-on-write working file and protects original
    saved_cow = _call_tool_sync(srv_live, "lab_save", {})
    assert saved_cow["success"] is True
    assert live_b.saved[-1]["path"] == str(tmp_path / "campus_netforge.pkt")
    assert "lab_diff" in saved_cow["data"]

    refused_orig = _call_tool_sync(srv_live, "lab_save", {"path": str(orig_pkt)})
    assert refused_orig["success"] is False

    approved_orig = _call_tool_sync(
        srv_live,
        "lab_save",
        {
            "path": str(orig_pkt),
            "overwrite_original": True,
            "confirm_overwrite_original": True,
        },
    )
    assert approved_orig["success"] is True
    backup_p = Path(approved_orig["data"]["backup_path"])
    assert backup_p.is_file()
    assert backup_p.read_bytes() == b"ORIGINAL_PKT_DATA"

    # 7. Mirror session file works for custom NETFORGE_DATA_DIR and cleans up on stop()
    from netforge.adapters.script_bridge import HttpScriptBridgeServer

    mirror_file = tmp_path / "mirror" / "bridge_session.json"
    srv_mirrored = HttpScriptBridgeServer(
        session_file=tmp_path / "custom" / "bridge_session.json",
        mirror_session_files=[mirror_file],
    )
    srv_mirrored.start()
    try:
        assert mirror_file.is_file()
        assert json.loads(mirror_file.read_text(encoding="utf-8"))["url"] == srv_mirrored.base_url
    finally:
        srv_mirrored.stop()
    assert not mirror_file.exists()

    # 8. working_copy_path on approved document input flows through lab_start
    doc_ready = _call_tool_sync(
        srv_live,
        "lab_start",
        {
            "input_target": str(md_file),
            "auto_approve": True,
            "working_copy_path": str(tmp_path / "md_out.pkt"),
        },
    )
    assert doc_ready["success"] is True
    assert doc_ready["data"]["working_copy_path"] == str(tmp_path / "md_out.pkt")

