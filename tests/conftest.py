"""Shared pytest fixtures for NetForge MCP offline tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from netforge.core.settings import NetForgeSettings
from netforge.mcp.server import create_mcp_server


@pytest.fixture
def isolated_settings(tmp_path: Path) -> NetForgeSettings:
    """Provide isolated NetForgeSettings pointing at a temporary directory."""
    return NetForgeSettings(
        data_dir=tmp_path / ".netforge",
        db_filename="test_netforge.sqlite",
        log_level="WARNING",
        permission_profile="standard",
        require_destructive_confirmation=True,
    )


@pytest.fixture
def mcp_bundle(isolated_settings: NetForgeSettings):
    """Create a fresh (MCPServer, NetForgeRuntime) pair with isolated SQLite DB."""
    return create_mcp_server(isolated_settings)
