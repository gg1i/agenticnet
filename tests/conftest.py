"""Shared pytest fixtures for AgenticNet offline tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agenticnet.core.settings import AgenticNetSettings
from agenticnet.mcp.server import create_mcp_server


@pytest.fixture
def isolated_settings(tmp_path: Path) -> AgenticNetSettings:
    """Provide isolated AgenticNetSettings pointing at a temporary directory."""
    return AgenticNetSettings(
        data_dir=tmp_path / ".netforge",
        db_filename="test_netforge.sqlite",
        log_level="WARNING",
        permission_profile="standard",
        tool_profile="advanced",
        require_destructive_confirmation=True,
    )


@pytest.fixture
def mcp_bundle(isolated_settings: AgenticNetSettings):
    """Create a fresh (MCPServer, AgenticNetRuntime) pair with isolated SQLite DB."""
    return create_mcp_server(isolated_settings)
