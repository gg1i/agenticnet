"""Unit tests for the Device Console Engine, prompt detector, and state machine."""

from __future__ import annotations

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
