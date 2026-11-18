"""Unit tests for the Device Console Engine, prompt detector, and state machine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agenticnet.console.engine import DeviceConsoleEngine
from agenticnet.console.models import CLIPromptMode
from agenticnet.console.state_machine import ConsoleStateMachine, PromptDetector
from agenticnet.console.transport import SimulatedConsoleTransport
from agenticnet.core.enums import StateLevel
from agenticnet.core.exceptions import IOSConfigError


@pytest.mark.unit
def test_prompt_detector_and_mode_transitions() -> None:
    setup = PromptDetector.parse(
        "Would you like to enter the initial configuration dialog? [yes/no]:"
    )
    assert setup.mode == CLIPromptMode.INITIAL_SETUP_DIALOG
    assert ConsoleStateMachine.recovery_inputs(setup) == ["no"]

    more = PromptDetector.parse("interface FastEthernet0/1\n --More-- ")
    assert more.mode == CLIPromptMode.PAGING_MORE
    assert more.has_paging

    subif = PromptDetector.parse("R1(config-subif)#")
    assert subif.mode == CLIPromptMode.SUBINTERFACE_CONFIG
    assert subif.hostname == "R1"

    cmds = ConsoleStateMachine.transition_commands(
        CLIPromptMode.USER_EXEC, CLIPromptMode.GLOBAL_CONFIG
    )
    assert cmds == ["enable", "configure terminal"]


@pytest.mark.unit
def test_console_engine_recovery_execution_and_error_detection() -> None:
    transport = SimulatedConsoleTransport(
        initial_prompt="Would you like to enter the initial configuration dialog? [yes/no]:"
    )
    transport.seed_device(
        "R1",
        initial_output="Would you like to enter the initial configuration dialog? [yes/no]:",
        mode="setup_dialog",
    )
    engine = DeviceConsoleEngine(transport=transport)

    opened = engine.open_console("R1", model="2911")
    assert opened["session"]["is_open"] is True
    assert opened["session"]["recoveries_performed"] >= 2
    assert opened["session"]["current_mode"] == CLIPromptMode.USER_EXEC.value

    res = engine.execute_commands(
        "R1",
        ["hostname EDGE-R1", "interface GigabitEthernet0/0", "ip address 10.0.0.1 255.255.255.252"],
        model="2911",
        target_mode="global_config",
        verification_commands=["show running-config"],
    )
    assert res["all_commands_succeeded"] is True
    assert res["state_level"] == StateLevel.VERIFIED.value
    assert res["session"]["hostname"] == "EDGE-R1"
    assert "show running-config" in res["verification_output"]

    failed = engine.execute_commands(
        "R1",
        ["bad command"],
        model="2911",
        target_mode="global_config",
    )
    assert failed["all_commands_succeeded"] is False
    assert "bad command" in failed["failed_commands"]


@pytest.mark.unit
def test_console_engine_guards_non_cli_models_and_redacts_secrets() -> None:
    transport = SimulatedConsoleTransport()
    engine = DeviceConsoleEngine(transport=transport)

    with pytest.raises(IOSConfigError):
        engine.open_console("AP1", model="AccessPoint-PT")

    res = engine.execute_commands(
        "R2",
        ["username netadmin secret MySuperSecret99!"],
        model="2911",
        target_mode="global_config",
    )
    assert res["all_commands_succeeded"] is True
    transcript_cmds = [t["command"] for t in res["transcripts"]]
    assert all("MySuperSecret99!" not in c for c in transcript_cmds)


@pytest.mark.unit
def test_subconfig_modes_asa_paging_and_password_detection() -> None:
    from agenticnet.console.state_machine import strip_paging_and_control

    cases = [
        ("R1(config-isakmp)#", CLIPromptMode.CRYPTO_ISAKMP_CONFIG),
        ("R1(config-crypto-map)#", CLIPromptMode.CRYPTO_MAP_CONFIG),
        ("R1(config-sec-zone)#", CLIPromptMode.ZONE_CONFIG),
        ("R1(config-sec-zone-pair)#", CLIPromptMode.ZONE_PAIR_CONFIG),
        ("R1(config-pmap)#", CLIPromptMode.POLICY_MAP_CONFIG),
        ("R1(config-cmap)#", CLIPromptMode.CLASS_MAP_CONFIG),
        ("R1(config-telephony)#", CLIPromptMode.TELEPHONY_CONFIG),
        ("R1(config-ephone)#", CLIPromptMode.EPHONE_CONFIG),
        ("R1(config-ephone-dn)#", CLIPromptMode.EPHONE_DN_CONFIG),
        ("SW1(config-if-range)#", CLIPromptMode.INTERFACE_RANGE_CONFIG),
        ("R1(config-custom-xyz)#", CLIPromptMode.CONFIG_SUBMODE),
    ]
    for raw_prompt, expected_mode in cases:
        parsed = PromptDetector.parse(raw_prompt)
        assert parsed.mode == expected_mode
        assert parsed.mode != CLIPromptMode.GLOBAL_CONFIG
        assert ConsoleStateMachine.transition_commands(
            parsed.mode, CLIPromptMode.GLOBAL_CONFIG
        ) == ["exit"]
        assert ConsoleStateMachine.transition_commands(
            parsed.mode, CLIPromptMode.PRIVILEGED_EXEC
        ) == ["end"]

    asa_more = PromptDetector.parse("access-list OUT_IN extended permit ip any any\n<--- More --->")
    assert asa_more.mode == CLIPromptMode.PAGING_MORE
    assert asa_more.has_paging is True
    assert "<--- More --->" not in strip_paging_and_control("line1\n<--- More --->  line2")

    pw = PromptDetector.parse("ciscoasa> enable\nPassword: ")
    assert pw.mode == CLIPromptMode.PASSWORD_PROMPT
    assert pw.in_password_prompt is True

    modulus = PromptDetector.parse("How many bits in the modulus [512]: ")
    assert modulus.mode == CLIPromptMode.CONFIRM_PROMPT
    assert modulus.in_confirm_prompt is True


@pytest.mark.unit
def test_asa_profile_interactive_prompts_and_context_help() -> None:
    from agenticnet.console.models import ConsoleInteractionKind
    from agenticnet.console.profiles import get_console_profile

    asa_prof = get_console_profile("5505")
    assert asa_prof.interaction_kind == ConsoleInteractionKind.ASA_CLI
    assert asa_prof.supports_paging_disable is True
    assert asa_prof.paging_disable_command == "terminal pager 0"

    transport = SimulatedConsoleTransport()
    engine = DeviceConsoleEngine(transport=transport)
    opened = engine.open_console("FW1", model="5505")
    assert opened["session"]["current_mode"] == CLIPromptMode.USER_EXEC.value

    # ASA enable -> blank Password: -> show running-config (<--- More ---> drained cleanly)
    asa_res = engine.execute_commands(
        "FW1",
        ["show running-config"],
        model="5505",
        target_mode="privileged_exec",
    )
    assert asa_res["all_commands_succeeded"] is True
    assert "hostname ciscoasa" in asa_res["transcripts"][-1]["raw_output"]

    # Interactive RSA modulus, [confirm], and ? context-help on router
    rtr_res = engine.execute_commands(
        "R1",
        ["crypto key generate rsa", "end", "clear counters", "show ?"],
        model="2911",
        target_mode="global_config",
    )
    assert rtr_res["all_commands_succeeded"] is True
    assert any("1024 bit RSA keys" in t["raw_output"] for t in rtr_res["transcripts"])
    assert "context help" in rtr_res["transcripts"][-1]["raw_output"]


@pytest.mark.unit
def test_batch_transcript_outputs_and_stop_on_error() -> None:
    from agenticnet.console.models import DeviceConsoleProfile
    from agenticnet.console.transport import ConsoleTransport

    class _BatchMockTransport(ConsoleTransport):
        transport_name = "script_bridge"

        def __init__(self, payload: dict[str, Any]) -> None:
            self.payload = payload
            self.seen_stop_on_error: list[bool] = []

        def is_available(self) -> bool:
            return True

        def can_batch(self) -> bool:
            return True

        def open_device(self, device_name: str, profile: DeviceConsoleProfile) -> str:
            return "R1>"

        def send_line(self, device_name: str, line: str, *, timeout_s: float = 5.0) -> str:
            return "R1#"

        def read_buffer(self, device_name: str) -> str:
            return "R1#"

        def send_batch(
            self,
            device_name: str,
            lines: list[str],
            *,
            stop_on_error: bool = True,
            timeout_s: float = 25.0,
        ) -> dict[str, Any]:
            _ = (device_name, lines, timeout_s)
            self.seen_stop_on_error.append(stop_on_error)
            return dict(self.payload)

    # 1. Single show command preceded by prep `enable` -> transcripts[0].raw_output is NEVER empty
    t_show = _BatchMockTransport(
        {
            "ok": True,
            "raw_output": "R1#show ip interface brief\nGi0/0 10.0.0.1 YES manual up up\nR1#",
            "prompt": "R1#",
            "command_statuses": [
                {"command": "enable", "status": 0},
                {"command": "show ip interface brief", "status": 0},
            ],
            "command_outputs": ["", "Gi0/0 10.0.0.1 YES manual up up\nR1#"],
        }
    )
    eng_show = DeviceConsoleEngine(transport=t_show)
    rep_show = eng_show.execute_commands(
        "R1", ["show ip interface brief"], target_mode="privileged_exec"
    )
    assert rep_show["all_commands_succeeded"] is True
    assert "Gi0/0 10.0.0.1" in rep_show["transcripts"][0]["raw_output"]
    assert "Gi0/0 10.0.0.1" in rep_show["transcripts"][-1]["raw_output"]

    # 2. stop_on_error=True marks subsequent commands skipped/failed and halts mode advance
    t_err = _BatchMockTransport(
        {
            "ok": True,
            "raw_output": "% Invalid input detected at '^' marker.\nR1(config)#",
            "prompt": "R1(config)#",
            "command_statuses": [
                {"command": "enable", "status": 0},
                {"command": "configure terminal", "status": 0},
                {"command": "bogus command", "status": 2},
            ],
            "stopped_on_error": True,
        }
    )
    eng_err = DeviceConsoleEngine(transport=t_err)
    rep_err = eng_err.execute_commands(
        "R1",
        ["bogus command", "interface GigabitEthernet0/0"],
        target_mode="global_config",
        stop_on_error=True,
    )
    assert t_err.seen_stop_on_error == [True]
    assert rep_err["all_commands_succeeded"] is False
    assert "bogus command" in rep_err["failed_commands"]
    skipped = rep_err["transcripts"][-1]
    assert skipped["command"] == "interface GigabitEthernet0/0"
    assert skipped["succeeded"] is False
    assert skipped["diagnostics"][0]["code"] == "SKIPPED_AFTER_ERROR"


@pytest.mark.unit
def test_console_execute_destructive_gate_and_before_after_diff(tmp_path: Path) -> None:
    import asyncio

    from agenticnet.core.settings import AgenticNetSettings
    from agenticnet.mcp.server import create_mcp_server

    transport = SimulatedConsoleTransport(initial_prompt="R1>")
    settings = AgenticNetSettings(data_dir=tmp_path / "data", tool_profile="advanced")
    server, runtime = create_mcp_server(settings, console_transport=transport)

    async def _exercise() -> None:
        await server.call_tool("project_create", {"name": "ConsoleGateTest"})

        # Destructive command without confirm=True -> approval_required
        blocked_raw = await server.call_tool(
            "console_execute",
            {"device_name": "R1", "commands": ["write erase"]},
        )
        blocked = dict(blocked_raw.structured_content or {})
        assert blocked["success"] is False
        assert blocked["status"] == "approval_required"

        # Dry-run destructive command allowed without confirm (planned only)
        dry_raw = await server.call_tool(
            "console_execute",
            {"device_name": "R1", "commands": ["reload"], "dry_run": True},
        )
        dry = dict(dry_raw.structured_content or {})
        assert dry["success"] is True
        assert dry["state_level"] == "planned"

        # Authorized with confirm=True -> executes
        ok_raw = await server.call_tool(
            "console_execute",
            {
                "device_name": "R1",
                "commands": ["write erase"],
                "target_mode": "privileged_exec",
                "confirm": True,
            },
        )
        ok_res = dict(ok_raw.structured_content or {})
        assert ok_res["success"] is True

        # capture_before_after=True + secret scrubbing in audit log
        diff_raw = await server.call_tool(
            "console_execute",
            {
                "device_name": "R1",
                "commands": ["hostname CORE-R1", "enable secret HiddenAuditPass99"],
                "target_mode": "global_config",
                "verification_commands": ["show running-config"],
                "capture_before_after": True,
            },
        )
        diff_res = dict(diff_raw.structured_content or {})
        assert diff_res["success"] is True
        assert diff_res["state_level"] == "verified"
        assert diff_res["data"]["changed"] is True
        assert "+hostname CORE-R1" in diff_res["data"]["before_after_diff"]["show running-config"]

        logs = runtime.manager.store.list_execution_logs(limit=10)
        serialized_logs = str(logs)
        assert "HiddenAuditPass99" not in serialized_logs

    asyncio.run(_exercise())
