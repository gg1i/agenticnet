"""Data models for the Device Console Engine and CLI interaction state machine."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from agenticnet.core.enums import StateLevel
from agenticnet.ios.models import CLIDiagnostic


def _utc_now() -> datetime:
    return datetime.now(UTC)


class CLIPromptMode(StrEnum):
    """Recognized Cisco IOS, ASA, and Packet Tracer host prompt states."""

    UNKNOWN = "unknown"
    PRESS_RETURN = "press_return"
    INITIAL_SETUP_DIALOG = "initial_setup_dialog"
    PASSWORD_PROMPT = "password_prompt"
    CONFIRM_PROMPT = "confirm_prompt"
    USER_EXEC = "user_exec"
    PRIVILEGED_EXEC = "privileged_exec"
    GLOBAL_CONFIG = "global_config"
    CONFIG_SUBMODE = "config_submode"
    INTERFACE_CONFIG = "interface_config"
    INTERFACE_RANGE_CONFIG = "interface_range_config"
    SUBINTERFACE_CONFIG = "subinterface_config"
    ROUTER_CONFIG = "router_config"
    DHCP_CONFIG = "dhcp_config"
    LINE_CONFIG = "line_config"
    VLAN_CONFIG = "vlan_config"
    ACL_CONFIG = "acl_config"
    CRYPTO_ISAKMP_CONFIG = "crypto_isakmp_config"
    CRYPTO_MAP_CONFIG = "crypto_map_config"
    ZONE_CONFIG = "zone_config"
    ZONE_PAIR_CONFIG = "zone_pair_config"
    POLICY_MAP_CONFIG = "policy_map_config"
    CLASS_MAP_CONFIG = "class_map_config"
    TELEPHONY_CONFIG = "telephony_config"
    EPHONE_CONFIG = "ephone_config"
    EPHONE_DN_CONFIG = "ephone_dn_config"
    PAGING_MORE = "paging_more"
    PC_PROMPT = "pc_prompt"


class ConsoleInteractionKind(StrEnum):
    """How a device exposes interactive command execution in Packet Tracer."""

    IOS_CLI = "ios_cli"
    ASA_CLI = "asa_cli"
    PT_DESKTOP_CMD = "pt_desktop_cmd"
    GUI_ONLY = "gui_only"


class DeviceConsoleProfile(BaseModel):
    """Device-specific terminal timing, capability, and recovery configuration."""

    model: str
    interaction_kind: ConsoleInteractionKind
    supports_ios_cli: bool
    supports_paging_disable: bool = False
    paging_disable_command: str = "terminal length 0"
    line_delay_ms: int = 80
    command_timeout_seconds: float = 5.0
    max_recovery_attempts: int = 4
    notes: str = ""


class ParsedPrompt(BaseModel):
    """Result of inspecting the trailing lines of terminal output."""

    mode: CLIPromptMode
    hostname: str | None = None
    raw_prompt: str = ""
    has_paging: bool = False
    in_setup_dialog: bool = False
    in_password_prompt: bool = False
    in_confirm_prompt: bool = False


class ConsoleSessionState(BaseModel):
    """Live tracked state for an interactive device console session."""

    device_name: str
    model: str
    is_open: bool = False
    transport_name: str = "unattached"
    current_mode: CLIPromptMode = CLIPromptMode.UNKNOWN
    hostname: str | None = None
    last_prompt: str = ""
    last_output_tail: str = ""
    errors_detected: int = 0
    recoveries_performed: int = 0
    updated_at: datetime = Field(default_factory=_utc_now)


class CommandTranscript(BaseModel):
    """Single executed CLI command with before/after modes and parsed diagnostics."""

    command: str
    mode_before: CLIPromptMode
    mode_after: CLIPromptMode
    raw_output: str = ""
    diagnostics: list[CLIDiagnostic] = Field(default_factory=list)
    succeeded: bool = True
    elapsed_ms: float = 0.0


class ConsoleExecutionReport(BaseModel):
    """Aggregated outcome of running commands on a device console."""

    device_name: str
    state_level: StateLevel
    session: ConsoleSessionState
    transcripts: list[CommandTranscript] = Field(default_factory=list)
    all_commands_succeeded: bool = True
    failed_commands: list[str] = Field(default_factory=list)
    verification_output: dict[str, str] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
