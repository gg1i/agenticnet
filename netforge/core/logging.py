"""Stderr-safe structured logging for MCP stdio and CLI runtimes."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class JsonStderrFormatter(logging.Formatter):
    """Formats log records as single-line JSON for clean audit trails."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "netforge_extra", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", *, json_format: bool = False) -> logging.Logger:
    """Configure NetForge root logger strictly targeting `sys.stderr`.

    Stdio MCP servers MUST never write non-JSON-RPC log lines to `sys.stdout`.
    """
    logger = logging.getLogger("netforge")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    # Replace existing stream handlers to avoid duplicate output across tests/reloads.
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    if json_format:
        handler.setFormatter(JsonStderrFormatter())
    else:
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    return logger
