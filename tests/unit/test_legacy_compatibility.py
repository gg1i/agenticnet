"""Backward-compatibility tests preserving legacy `netforge` imports, env vars, and PT bridge."""

from __future__ import annotations

import importlib.resources as importlib_resources
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

from agenticnet.adapters.discovery import get_desktop_session_info
from agenticnet.adapters.script_bridge import HttpScriptBridgeServer, probe_bridge_health
from agenticnet.core.exceptions import AgenticNetError
from agenticnet.core.settings import AgenticNetSettings, canonical_pt_bridge_data_dir
from agenticnet.diagnostics.lab_runner import derive_working_copy_path
from agenticnet.mcp.registry import AgenticNetRuntime


@pytest.mark.unit
def test_legacy_netforge_import_shims_and_aliases() -> None:
    from netforge.core import NetForgeError, NetForgeSettings
    from netforge.mcp import NetForgeRuntime, create_mcp_server

    import agenticnet
    import netforge

    assert netforge.__version__ == agenticnet.__version__
    assert netforge.__schema_version__ == agenticnet.__schema_version__
    assert NetForgeError is AgenticNetError
    assert NetForgeSettings is AgenticNetSettings
    assert NetForgeRuntime is AgenticNetRuntime
    assert callable(create_mcp_server)

    # Resource loading must stay intact across both `agenticnet` and `netforge` namespaces.
    assert (
        importlib_resources.files("netforge.adapters.assets")
        .joinpath("netforge_bridge.pts")
        .is_file()
    )
    assert (
        importlib_resources.files("agenticnet.adapters.assets")
        .joinpath("netforge_bridge.pts")
        .is_file()
    )


@pytest.mark.unit
def test_legacy_env_vars_fallback_and_agenticnet_precedence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for prefix in ("AGENTICNET_", "NETFORGE_"):
        for suffix in (
            "DATA_DIR",
            "TOOL_PROFILE",
            "PERMISSION_PROFILE",
            "REQUIRE_CONFIRM",
            "PT_PATH",
            "NON_INTERACTIVE",
        ):
            monkeypatch.delenv(prefix + suffix, raising=False)

    legacy_dir = tmp_path / "legacy_nf"
    monkeypatch.setenv("NETFORGE_DATA_DIR", str(legacy_dir))
    monkeypatch.setenv("NETFORGE_TOOL_PROFILE", "advanced")
    monkeypatch.setenv("NETFORGE_PERMISSION_PROFILE", "planning")
    monkeypatch.setenv("NETFORGE_REQUIRE_CONFIRM", "false")
    monkeypatch.setenv("NETFORGE_PT_PATH", "C:/PT/PacketTracer.exe")
    monkeypatch.setenv("NETFORGE_NON_INTERACTIVE", "1")

    settings = AgenticNetSettings.from_env()
    assert settings.data_dir == legacy_dir.resolve()
    assert settings.tool_profile == "advanced"
    assert settings.permission_profile == "planning"
    assert settings.require_destructive_confirmation is False
    assert settings.packet_tracer_path == "C:/PT/PacketTracer.exe"
    assert get_desktop_session_info()["interactive"] is False

    # Explicit AGENTICNET_* overrides legacy NETFORGE_* values.
    primary_dir = tmp_path / "primary_an"
    monkeypatch.setenv("AGENTICNET_DATA_DIR", str(primary_dir))
    monkeypatch.setenv("AGENTICNET_TOOL_PROFILE", "solve_lab")
    settings_override = AgenticNetSettings.from_env()
    assert settings_override.data_dir == primary_dir.resolve()
    assert settings_override.tool_profile == "solve_lab"


@pytest.mark.unit
def test_canonical_pt_bridge_dir_and_dual_token_headers(tmp_path: Path) -> None:
    assert canonical_pt_bridge_data_dir().name == "netforge"

    session_file = tmp_path / "data" / "bridge_session.json"
    server = HttpScriptBridgeServer(session_file=session_file)
    server.start()
    desc = json.loads(session_file.read_text(encoding="utf-8"))
    try:
        for header_name in ("X-AgenticNet-Token", "X-NetForge-Token"):
            req = urllib.request.Request(
                f"{desc['url'].rstrip('/')}/v1/health",
                headers={
                    header_name: str(desc["token"]),
                    "Origin": "pt-sm://com.netforge.bridge/bridge.html",
                },
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                assert resp.status == 200
                body = json.loads(resp.read().decode("utf-8"))
                assert body["ok"] is True

        probe = probe_bridge_health(session_file)
        assert probe["reachable"] is True
    finally:
        server.stop()


@pytest.mark.unit
def test_working_copy_preserves_legacy_netforge_and_new_agenticnet_suffixes() -> None:
    assert derive_working_copy_path("campus.pkt") == "campus_agenticnet.pkt"
    assert derive_working_copy_path("campus_agenticnet.pkt") == "campus_agenticnet.pkt"
    assert derive_working_copy_path("campus_netforge.pkt") == "campus_netforge.pkt"


@pytest.mark.unit
def test_cli_python_module_parity() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    an_res = subprocess.run(
        [sys.executable, "-m", "agenticnet", "version"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    nf_res = subprocess.run(
        [sys.executable, "-m", "netforge", "version"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    an_json = json.loads(an_res.stdout)
    nf_json = json.loads(nf_res.stdout)
    assert an_json == nf_json
    assert an_json["name"] == "agenticnet"
