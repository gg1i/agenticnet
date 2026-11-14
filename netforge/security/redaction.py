"""Secret and credential redaction utilities for logs and audit trails."""

from __future__ import annotations

import getpass
import platform
import re
from pathlib import Path
from typing import Any

SENSITIVE_KEY_TOKENS: tuple[str, ...] = (
    "password",
    "secret",
    "passphrase",
    "psk",
    "key",
    "token",
    "credential",
    "auth_string",
    "community",
)

_TYPE_PREFIX = r"(?:[05789]\s+(?=\S))?"
_OPT_TYPE_07 = r"(?:[07]\s+(?=\S))?"

_CLI_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(rf"(?i)\b(enable\s+secret\s+{_TYPE_PREFIX})(\S+)"), r"\1[REDACTED]"),
    (re.compile(rf"(?i)\b(enable\s+password\s+{_TYPE_PREFIX})(\S+)"), r"\1[REDACTED]"),
    (
        re.compile(
            r"(?i)\b(username\s+\S+(?:\s+privilege\s+\d+)?"
            rf"(?:\s+algorithm-type\s+\S+)?\s+(?:secret|password)\s+{_TYPE_PREFIX})(\S+)"
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"(?i)\b(snmp-server\s+community\s+)(\S+)"), r"\1[REDACTED]"),
    (re.compile(rf"(?i)\b(key-string\s+{_OPT_TYPE_07})(\S+)"), r"\1[REDACTED]"),
    (
        re.compile(rf"(?i)\b((?:tacacs|radius)-server\b[^\r\n]*?\bkey\s+{_OPT_TYPE_07})(\S+)"),
        r"\1[REDACTED]",
    ),
    (re.compile(rf"(?im)^(\s*key\s+{_OPT_TYPE_07})(\S+)"), r"\1[REDACTED]"),
    (re.compile(rf"(?i)\b(password\s+{_TYPE_PREFIX})(\S+)"), r"\1[REDACTED]"),
)


def is_sensitive_key(key: str) -> bool:
    """Return True if a parameter or dictionary key likely holds sensitive credentials."""
    lowered = key.lower()
    return any(token in lowered for token in SENSITIVE_KEY_TOKENS)


def redact_cli_text(text: str) -> str:
    """Mask inline Cisco IOS secrets/passwords from rendered CLI or captured logs."""
    masked = text
    for pattern, replacement in _CLI_SECRET_PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked


def redact_secrets(value: Any, *, key_hint: str | None = None) -> Any:
    """Recursively redact sensitive fields in dicts, lists, and CLI command strings."""
    if key_hint is not None and is_sensitive_key(key_hint):
        if value is None or value == "":
            return value
        return "[REDACTED]"

    if isinstance(value, dict):
        return {str(k): redact_secrets(v, key_hint=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        return redact_cli_text(value)
    return value


def redact_path_home(path: str | Path | None) -> str | None:
    """Redact user home directory prefixes and OS username path segments."""
    if path is None:
        return None
    raw = str(path)
    if not raw:
        return raw

    home = str(Path.home())
    home_variants = (home, home.replace("\\", "/"))
    is_win = platform.system() == "Windows"
    redacted = raw
    for prefix in home_variants:
        if not prefix:
            continue
        matched = (
            redacted.lower().startswith(prefix.lower())
            if is_win
            else redacted.startswith(prefix)
        )
        if matched and (len(redacted) == len(prefix) or redacted[len(prefix)] in ("\\", "/")):
            redacted = "~" + redacted[len(prefix) :]
            break

    username = Path.home().name or getpass.getuser()
    if len(username) >= 2:
        flags = re.IGNORECASE if is_win else 0
        user_re = re.compile(rf"(?<=[\\/]){re.escape(username)}(?=[\\/]|$)", flags)
        redacted = user_re.sub("<USER>", redacted)
    return redacted
