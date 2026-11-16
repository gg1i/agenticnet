"""Unit tests for core runtime models, permissions, secret redaction, and input validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from agenticnet.core.enums import OperationStatus, PermissionTier, StateLevel
from agenticnet.core.exceptions import ApprovalRequiredError, PermissionDeniedError, ValidationError
from agenticnet.core.models import OperationResult
from agenticnet.security.permissions import PermissionGuard, PermissionPolicy
from agenticnet.security.redaction import redact_cli_text, redact_secrets
from agenticnet.security.validation import (
    safe_resolve_path,
    validate_device_name,
    validate_project_id,
)


@pytest.mark.unit
def test_operation_result_state_separation() -> None:
    res = OperationResult.ok(
        "topology_create",
        "Created planned topology",
        state_level=StateLevel.PLANNED,
        evidence=["Graph validated"],
    )
    assert res.success is True
    assert res.status == OperationStatus.SUCCEEDED
    assert res.state_level == StateLevel.PLANNED
    assert res.operation_id.startswith("op_")

    fail = OperationResult.fail(
        "device_remove",
        "Confirmation required",
        error_code="APPROVAL_REQUIRED",
        status=OperationStatus.APPROVAL_REQUIRED,
    )
    assert fail.success is False
    assert fail.errors[0].error_code == "APPROVAL_REQUIRED"


@pytest.mark.unit
def test_permission_guard_profiles_and_destructive_gate() -> None:
    ro_guard = PermissionGuard(PermissionPolicy.from_profile("read-only"))
    ro_guard.check("project_status", PermissionTier.READ_ONLY)
    with pytest.raises(PermissionDeniedError):
        ro_guard.check("device_add", PermissionTier.PLANNING)

    std_guard = PermissionGuard(PermissionPolicy.from_profile("standard"))
    with pytest.raises(ApprovalRequiredError):
        std_guard.check("device_remove", PermissionTier.DESTRUCTIVE, confirmed=False)
    std_guard.check("device_remove", PermissionTier.DESTRUCTIVE, confirmed=True)


@pytest.mark.unit
def test_secret_redaction_cli_and_dicts() -> None:
    raw_params = {
        "device_name": "R1",
        "username": "netadmin",
        "secret": "SuperSecret123!",
        "enable_secret": "EnablePass99",
        "nested": [{"password": "hidden"}],
    }
    redacted = redact_secrets(raw_params)
    assert redacted["secret"] == "[REDACTED]"
    assert redacted["enable_secret"] == "[REDACTED]"
    assert redacted["nested"][0]["password"] == "[REDACTED]"
    assert redacted["device_name"] == "R1"

    cli_text = redact_cli_text(
        "username admin privilege 15 secret TopSecretPass\nenable secret Class123\n"
    )
    assert "TopSecretPass" not in cli_text
    assert "Class123" not in cli_text
    assert "[REDACTED]" in cli_text


@pytest.mark.unit
def test_redact_cli_text_covers_typed_secrets_snmp_lines_and_aaa() -> None:
    sample = "\n".join(
        [
            "enable secret 0 ClearEnable0",
            "enable secret 5 $1$salt$Hash5Value",
            "enable secret 7 0822455D0A16",
            "enable secret 8 $8$salt$Hash8Value",
            "enable secret 9 $9$salt$Hash9Value",
            "enable password 7 02050D480809",
            "enable password PlainEnablePass",
            "username admin privilege 15 secret 5 $1$usr$UserHash5",
            "username netops algorithm-type scrypt secret $9$usr$ScryptHash",
            "username tech password 7 121A0C0411",
            "username guest password PlainGuestPass",
            "snmp-server community SecretCommRO RO",
            "snmp-server community SecretCommRW RW 10",
            "key-string 7 094F471A1A",
            "key-string ClearKeyString",
            "line con 0",
            " password 7 0307521805",
            "line vty 0 4",
            " password VtySecretPass",
            "tacacs-server key 7 1511021F07",
            "tacacs-server host 10.0.0.50 key TacacsHostSecret",
            "radius-server key RadiusGlobalSecret",
            "radius-server host 10.0.0.51 auth-port 1812 key 7 04580215",
            "tacacs server ISE1",
            " key 0 TacacsSubmodeSecret",
            "radius server RAD1",
            " key RadiusSubmodeSecret",
        ]
    )
    redacted = redact_cli_text(sample)

    leaked = [
        "ClearEnable0",
        "$1$salt$Hash5Value",
        "0822455D0A16",
        "$8$salt$Hash8Value",
        "$9$salt$Hash9Value",
        "02050D480809",
        "PlainEnablePass",
        "$1$usr$UserHash5",
        "$9$usr$ScryptHash",
        "121A0C0411",
        "PlainGuestPass",
        "SecretCommRO",
        "SecretCommRW",
        "094F471A1A",
        "ClearKeyString",
        "0307521805",
        "VtySecretPass",
        "1511021F07",
        "TacacsHostSecret",
        "RadiusGlobalSecret",
        "04580215",
        "TacacsSubmodeSecret",
        "RadiusSubmodeSecret",
    ]
    for secret in leaked:
        assert secret not in redacted, f"Secret leaked after redaction: {secret}"

    # Verify type digits and keywords remain intact while hashes are masked
    assert "enable secret 5 [REDACTED]" in redacted
    assert "enable secret 9 [REDACTED]" in redacted
    assert "enable password 7 [REDACTED]" in redacted
    assert "username admin privilege 15 secret 5 [REDACTED]" in redacted
    assert "snmp-server community [REDACTED] RO" in redacted
    assert "key-string 7 [REDACTED]" in redacted
    assert " password 7 [REDACTED]" in redacted
    assert "tacacs-server key 7 [REDACTED]" in redacted
    assert " key 0 [REDACTED]" in redacted


@pytest.mark.unit
def test_configuration_backup_redacts_all_sensitive_ios_secrets(tmp_path: Path) -> None:
    import asyncio
    from typing import Any

    from agenticnet.adapters.base import ScriptBackend
    from agenticnet.core.settings import AgenticNetSettings
    from agenticnet.mcp.server import create_mcp_server

    raw_running_config = "\n".join(
        [
            "hostname CoreR1",
            "enable secret 5 $1$abcd$SecretHash5",
            "enable password 7 070C285F4D",
            "username ops privilege 15 secret 9 $9$xyz$SecretHash9",
            "snmp-server community SuperPrivRW RW",
            "key chain OSPF_KEYS",
            " key 1",
            "  key-string MyOspfKey99",
            "line vty 0 4",
            " password 7 060506324F",
            "tacacs-server host 192.168.10.5 key TacacsKey88",
            "radius-server key RadiusKey77",
            "CoreR1#",
        ]
    )

    class _SecretConfigBackend(ScriptBackend):
        def is_connected(self) -> bool:
            return True

        def ping(self) -> dict[str, Any]:
            return {"ok": True}

        def add_device(
            self, model: str, *, device_type: int | str = 0, x: float = 0, y: float = 0
        ) -> dict[str, Any]:
            return {"ok": True, "device_name": "CoreR1"}

        def create_link(
            self, d1: str, p1: str, d2: str, p2: str, *, conn_type: int | str = 8107
        ) -> dict[str, Any]:
            return {"ok": True}

        def execute_cli(
            self,
            device_name: str,
            commands: list[str],
            *,
            wait_for_prompt: bool = True,
            timeout_seconds: float | None = None,
        ) -> dict[str, Any]:
            return {"ok": True, "raw_output": raw_running_config, "prompt": "CoreR1#"}

    settings = AgenticNetSettings(data_dir=tmp_path / "data")
    server, _ = create_mcp_server(settings, script_backend=_SecretConfigBackend())

    async def _run() -> dict[str, Any]:
        await server.call_tool("project_create", {"name": "RedactionBackupTest"})
        await server.call_tool("device_add", {"name": "CoreR1", "model": "2911"})
        res = await server.call_tool("configuration_backup", {"device_name": "CoreR1"})
        assert res.structured_content is not None
        return dict(res.structured_content)

    out = asyncio.run(_run())
    assert out["success"] is True
    cfg = out["data"]["config_text"]
    for secret in (
        "$1$abcd$SecretHash5",
        "070C285F4D",
        "$9$xyz$SecretHash9",
        "SuperPrivRW",
        "MyOspfKey99",
        "060506324F",
        "TacacsKey88",
        "RadiusKey77",
    ):
        assert secret not in cfg
    assert "enable secret 5 [REDACTED]" in cfg


@pytest.mark.unit
def test_input_validation_and_safe_paths(tmp_path: Path) -> None:
    assert validate_device_name("SW-CORE-01") == "SW-CORE-01"
    with pytest.raises(ValidationError):
        validate_device_name("1BadName")
    with pytest.raises(ValidationError):
        validate_device_name("bad name with spaces")

    assert validate_project_id("Campus_Lab-01") == "campus_lab-01"
    with pytest.raises(ValidationError):
        validate_project_id("a")

    with pytest.raises(ValidationError):
        safe_resolve_path("bad\x00path")

    outside = tmp_path.parent / "escape.json"
    with pytest.raises(ValidationError):
        safe_resolve_path(outside, base_dir=tmp_path, allow_outside_base=False)


@pytest.mark.unit
def test_load_ios_command_sequence_never_sends_no_to_switches(tmp_path: Path) -> None:
    from agenticnet.ios.validators import load_ios_command_sequence

    sw_file = tmp_path / "switch_access.ios"
    sw_file.write_text("!\nenable\nconfigure terminal\nhostname SW_ACCESS\n", encoding="utf-8")

    # Even if caller omits device_type or passes router/2960, switches never get "no"
    for dtype in ("switch", "2960-24TT", "router"):
        cmds = load_ios_command_sequence(sw_file, device_type=dtype)
        assert "no" not in [c.lower() for c in cmds]
        assert "no ip domain-lookup" in cmds

    generic_file = tmp_path / "sw_core.ios"
    generic_file.write_text("hostname SW_CORE\n", encoding="utf-8")
    assert "no" not in [
        c.lower() for c in load_ios_command_sequence(generic_file, device_type="switch")
    ]

    r_file = tmp_path / "r_core.ios"
    r_file.write_text("hostname R1\n", encoding="utf-8")
    r_cmds = load_ios_command_sequence(r_file, device_type="router")
    assert r_cmds[0] == "no"
    assert "no ip domain-lookup" in r_cmds

