"""Cisco IOS prompt recognition, paging cleanup, and recoverable mode state machine."""

from __future__ import annotations

import re

from agenticnet.console.models import CLIPromptMode, ParsedPrompt
from agenticnet.core.exceptions import IOSConfigError

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_MORE_RE = re.compile(r"(?:--More--|<---\s*More\s*--->)\s*$", re.IGNORECASE)
_PRESS_RETURN_RE = re.compile(r"Press RETURN to get started!?$", re.IGNORECASE)
_PASSWORD_PROMPT_RE = re.compile(r"^Password:\s*$", re.IGNORECASE)
_CONFIRM_PROMPT_RE = re.compile(
    r"(?:\[confirm\]\s*$|"
    r"How many bits in the modulus\s*\[[0-9]+\]:\s*$|"
    r"Destination filename\s*\[[^\]]*\][\?:]\s*$)",
    re.IGNORECASE,
)
_SETUP_DIALOG_RE = re.compile(
    r"(?:initial configuration dialog\?\s*\[yes/no\]:|"
    r"terminate autoinstall\?\s*\[yes\]:|"
    r"continue with configuration dialog\?\s*\[yes/no\]:|"
    r"enable anonymous error reporting\?\s*\[yes/no\]:)",
    re.IGNORECASE,
)
_PC_PROMPT_RE = re.compile(r"^([A-Za-z]:\\[^>]*>|Packet Tracer PC Command Line[^\n]*)$")
_IOS_PROMPT_RE = re.compile(
    r"^([A-Za-z0-9_.\-]{1,63})"
    r"(?:\((config(?:-[A-Za-z0-9_./-]+)?|dhcp-config)\))?"
    r"([>#])\s*$"
)


def strip_paging_and_control(text: str) -> str:
    """Remove ANSI escape sequences, backspace overstrikes, and `--More--`/`<--- More --->`."""
    cleaned = _ANSI_ESCAPE_RE.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    cleaned = re.sub(r"(?:--More--|<---\s*More\s*--->)\s*", "", cleaned, flags=re.IGNORECASE)
    # Collapse backspace erase sequences emitted after --More--
    while "\x08" in cleaned:
        updated = re.sub(r".?\x08", "", cleaned, count=1)
        if updated == cleaned:
            cleaned = cleaned.replace("\x08", "")
            break
        cleaned = updated
    return cleaned


class PromptDetector:
    """Identify the active IOS, ASA, or Packet Tracer prompt mode from terminal buffer tail."""

    @staticmethod
    def parse(terminal_output: str) -> ParsedPrompt:
        """Inspect trailing lines of captured terminal output to determine mode and hostname."""
        raw = _ANSI_ESCAPE_RE.sub("", terminal_output or "").replace("\r\n", "\n")
        lines = [line.rstrip() for line in raw.split("\n") if line.strip()]
        if not lines:
            return ParsedPrompt(mode=CLIPromptMode.UNKNOWN)

        last = lines[-1].strip()
        if _MORE_RE.search(last):
            return ParsedPrompt(mode=CLIPromptMode.PAGING_MORE, raw_prompt=last, has_paging=True)
        if _PRESS_RETURN_RE.search(last):
            return ParsedPrompt(mode=CLIPromptMode.PRESS_RETURN, raw_prompt=last)
        if _SETUP_DIALOG_RE.search(last):
            return ParsedPrompt(
                mode=CLIPromptMode.INITIAL_SETUP_DIALOG,
                raw_prompt=last,
                in_setup_dialog=True,
            )
        if _PASSWORD_PROMPT_RE.search(last):
            return ParsedPrompt(
                mode=CLIPromptMode.PASSWORD_PROMPT,
                raw_prompt=last,
                in_password_prompt=True,
            )
        if _CONFIRM_PROMPT_RE.search(last):
            return ParsedPrompt(
                mode=CLIPromptMode.CONFIRM_PROMPT,
                raw_prompt=last,
                in_confirm_prompt=True,
            )
        if _PC_PROMPT_RE.match(last):
            return ParsedPrompt(mode=CLIPromptMode.PC_PROMPT, raw_prompt=last)

        match = _IOS_PROMPT_RE.match(last)
        if not match:
            return ParsedPrompt(mode=CLIPromptMode.UNKNOWN, raw_prompt=last)

        hostname, raw_ctx, symbol = match.groups()
        ctx = raw_ctx.lower() if raw_ctx is not None else None
        if ctx is None:
            mode = CLIPromptMode.PRIVILEGED_EXEC if symbol == "#" else CLIPromptMode.USER_EXEC
        elif ctx == "config":
            mode = CLIPromptMode.GLOBAL_CONFIG
        elif ctx == "config-if":
            mode = CLIPromptMode.INTERFACE_CONFIG
        elif ctx == "config-if-range":
            mode = CLIPromptMode.INTERFACE_RANGE_CONFIG
        elif ctx == "config-subif":
            mode = CLIPromptMode.SUBINTERFACE_CONFIG
        elif ctx == "config-router":
            mode = CLIPromptMode.ROUTER_CONFIG
        elif ctx in {"dhcp-config", "config-dhcp"}:
            mode = CLIPromptMode.DHCP_CONFIG
        elif ctx == "config-line":
            mode = CLIPromptMode.LINE_CONFIG
        elif ctx == "config-vlan":
            mode = CLIPromptMode.VLAN_CONFIG
        elif ctx in {"config-std-nacl", "config-ext-nacl", "config-nacl"}:
            mode = CLIPromptMode.ACL_CONFIG
        elif ctx == "config-isakmp":
            mode = CLIPromptMode.CRYPTO_ISAKMP_CONFIG
        elif ctx == "config-crypto-map":
            mode = CLIPromptMode.CRYPTO_MAP_CONFIG
        elif ctx in {"config-sec-zone", "config-zone"}:
            mode = CLIPromptMode.ZONE_CONFIG
        elif ctx in {"config-sec-zone-pair", "config-zone-pair"}:
            mode = CLIPromptMode.ZONE_PAIR_CONFIG
        elif ctx in {"config-pmap", "config-pmap-c"}:
            mode = CLIPromptMode.POLICY_MAP_CONFIG
        elif ctx == "config-cmap":
            mode = CLIPromptMode.CLASS_MAP_CONFIG
        elif ctx == "config-telephony":
            mode = CLIPromptMode.TELEPHONY_CONFIG
        elif ctx == "config-ephone":
            mode = CLIPromptMode.EPHONE_CONFIG
        elif ctx == "config-ephone-dn":
            mode = CLIPromptMode.EPHONE_DN_CONFIG
        else:
            mode = CLIPromptMode.CONFIG_SUBMODE

        return ParsedPrompt(mode=mode, hostname=hostname, raw_prompt=last)


_SUBCONFIG_MODES = {
    CLIPromptMode.CONFIG_SUBMODE,
    CLIPromptMode.INTERFACE_CONFIG,
    CLIPromptMode.INTERFACE_RANGE_CONFIG,
    CLIPromptMode.SUBINTERFACE_CONFIG,
    CLIPromptMode.ROUTER_CONFIG,
    CLIPromptMode.DHCP_CONFIG,
    CLIPromptMode.LINE_CONFIG,
    CLIPromptMode.VLAN_CONFIG,
    CLIPromptMode.ACL_CONFIG,
    CLIPromptMode.CRYPTO_ISAKMP_CONFIG,
    CLIPromptMode.CRYPTO_MAP_CONFIG,
    CLIPromptMode.ZONE_CONFIG,
    CLIPromptMode.ZONE_PAIR_CONFIG,
    CLIPromptMode.POLICY_MAP_CONFIG,
    CLIPromptMode.CLASS_MAP_CONFIG,
    CLIPromptMode.TELEPHONY_CONFIG,
    CLIPromptMode.EPHONE_CONFIG,
    CLIPromptMode.EPHONE_DN_CONFIG,
}


class ConsoleStateMachine:
    """Plans safe mode transitions and prompt recovery commands for Cisco IOS/ASA consoles."""

    @staticmethod
    def recovery_inputs(parsed: ParsedPrompt) -> list[str]:
        """Return immediate line inputs to unstick an unexpected initial/paging/submode prompt."""
        if parsed.mode == CLIPromptMode.INITIAL_SETUP_DIALOG:
            return ["no"]
        if parsed.mode == CLIPromptMode.PRESS_RETURN:
            return [""]
        if parsed.mode == CLIPromptMode.PASSWORD_PROMPT:
            return [""]
        if parsed.mode == CLIPromptMode.CONFIRM_PROMPT:
            return [""]
        if parsed.mode == CLIPromptMode.PAGING_MORE:
            return [" "]
        if parsed.mode in _SUBCONFIG_MODES:
            return ["end"]
        if parsed.mode == CLIPromptMode.UNKNOWN:
            return [""]
        return []

    @staticmethod
    def transition_commands(
        current_mode: CLIPromptMode,
        target_mode: CLIPromptMode,
        *,
        enable_password: str | None = None,
    ) -> list[str]:
        """Compute exact IOS commands needed to transition `current_mode` -> `target_mode`."""
        if current_mode == target_mode:
            return []

        if target_mode == CLIPromptMode.USER_EXEC:
            if current_mode in _SUBCONFIG_MODES or current_mode == CLIPromptMode.GLOBAL_CONFIG:
                return ["end", "disable"]
            if current_mode == CLIPromptMode.PRIVILEGED_EXEC:
                return ["disable"]
            return []

        if target_mode == CLIPromptMode.PRIVILEGED_EXEC:
            if current_mode == CLIPromptMode.USER_EXEC:
                cmds = ["enable"]
                if enable_password:
                    cmds.append(enable_password)
                return cmds
            if current_mode in _SUBCONFIG_MODES or current_mode == CLIPromptMode.GLOBAL_CONFIG:
                return ["end"]
            return []

        if target_mode == CLIPromptMode.GLOBAL_CONFIG:
            if current_mode == CLIPromptMode.USER_EXEC:
                cmds = ["enable"]
                if enable_password:
                    cmds.append(enable_password)
                cmds.append("configure terminal")
                return cmds
            if current_mode == CLIPromptMode.PRIVILEGED_EXEC:
                return ["configure terminal"]
            if current_mode in _SUBCONFIG_MODES:
                return ["exit"]
            return ["configure terminal"]

        raise IOSConfigError(
            f"Direct transition to submode {target_mode.value!r} requires explicit context command."
        )
