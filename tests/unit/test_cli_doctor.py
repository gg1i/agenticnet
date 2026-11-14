"""Unit tests for `netforge doctor` honesty, live probes, and home/user path redaction."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from netforge import cli
from netforge.adapters.script_bridge import HttpScriptBridgeServer
from netforge.core.settings import NetForgeSettings
from netforge.security.redaction import redact_path_home


@pytest.mark.unit
def test_redact_path_home_masks_home_and_username() -> None:
    home = Path.home()
    username = home.name
    inside_home = home / ".netforge" / "bridge_session.json"
    redacted_home = redact_path_home(inside_home)
    assert redacted_home is not None
    assert redacted_home.startswith("~")
    if len(username) >= 2:
        assert username.lower() not in redacted_home.lower()

    system_path = Path(r"C:\Program Files\Cisco Packet Tracer 8.2.2\bin\PacketTracer.exe")
    redacted_system = redact_path_home(system_path)
    assert redacted_system == str(system_path)
    assert redact_path_home(None) is None


@pytest.mark.unit
def test_doctor_reports_real_probes_without_hardcoded_phase_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_dir = Path.home() / ".netforge_test_doctor"
    fake_pt = Path.home() / "apps" / "PacketTracer.exe"
    settings = NetForgeSettings(data_dir=data_dir, packet_tracer_path=str(fake_pt))

    monkeypatch.setattr(cli, "_detect_packet_tracer_binary", lambda _p: str(fake_pt))
    monkeypatch.setattr(cli, "_is_packet_tracer_running", lambda: True)
    monkeypatch.setattr(cli, "_is_dir_writable", lambda _d: True)
    monkeypatch.setattr(
        cli,
        "probe_bridge_health",
        lambda _p: {
            "session_descriptor_present": False,
            "reachable": False,
            "connected": False,
            "state": "offline",
            "error": None,
        },
    )

    report = cli.build_doctor_report(settings)
    assert "phase_status" not in report
    assert report["roadmap_stage"] == "phase_2_backend_router"
    assert report["packet_tracer_running"] is True
    assert report["packet_tracer_detected"] is True
    assert report["data_dir_writable"] is True

    home_str = str(Path.home())
    username = Path.home().name
    dumped = json.dumps(report)
    assert home_str.lower() not in dumped.lower()
    if len(username) >= 2:
        assert username.lower() not in dumped.lower()

    monkeypatch.setattr(cli.NetForgeSettings, "from_env", classmethod(lambda cls: settings))
    rc = cli.main(["doctor"])
    assert rc == 0
    stdout_text = capsys.readouterr().out
    assert "All Phases 1" not in stdout_text
    assert json.loads(stdout_text)["script_bridge"]["state"] == "offline"


@pytest.mark.unit
def test_doctor_probes_live_bridge_health_without_exposing_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_file = tmp_path / "bridge_session.json"
    server = HttpScriptBridgeServer(session_file=session_file)
    server.start()
    try:
        desc = json.loads(session_file.read_text(encoding="utf-8"))
        settings = NetForgeSettings(data_dir=tmp_path)
        monkeypatch.setattr(cli, "_detect_packet_tracer_binary", lambda _p: None)
        monkeypatch.setattr(cli, "_is_packet_tracer_running", lambda: False)

        # Bridge server listening, no PT polling yet
        report_idle = cli.build_doctor_report(settings)
        assert report_idle["script_bridge"]["reachable"] is True
        assert report_idle["script_bridge"]["connected"] is False
        assert report_idle["script_bridge"]["state"] == "bridge_listening_pt_idle"
        assert desc["token"] not in json.dumps(report_idle)

        # Simulate one PT script-module poll -> heartbeat marks connected
        req = urllib.request.Request(
            f"{desc['url']}/v1/commands/next?wait_ms=0",
            headers={
                "X-NetForge-Token": desc["token"],
                "Origin": "pt-sm://com.netforge.bridge/bridge.html",
            },
        )
        with urllib.request.urlopen(req, timeout=2.0):
            pass

        report_connected = cli.build_doctor_report(settings)
        assert report_connected["script_bridge"]["connected"] is True
        assert report_connected["script_bridge"]["state"] == "connected"
        assert desc["token"] not in json.dumps(report_connected)
    finally:
        server.stop()


@pytest.mark.unit
def test_default_data_dir_uses_localappdata_outside_repo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netforge.core import settings as settings_mod

    monkeypatch.delenv("NETFORGE_DATA_DIR", raising=False)
    monkeypatch.setattr(settings_mod.os, "name", "nt")
    fake_local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(fake_local))

    resolved = settings_mod.default_data_dir()
    assert resolved == (fake_local / "netforge").resolve()
    assert not resolved.is_relative_to(Path.cwd())
    assert resolved.name == "netforge"


@pytest.mark.unit
def test_install_module_copies_pts_and_prints_registration_steps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dest = tmp_path / "netforge_data"
    monkeypatch.setenv("NETFORGE_DATA_DIR", str(dest))

    exit_code = cli.main(["install-module", "--dest-dir", str(dest)])
    assert exit_code == 0

    out = capsys.readouterr().out
    pts_path = dest / "netforge_bridge.pts"
    assert pts_path.is_file()
    assert pts_path.stat().st_size > 0
    assert (dest / "bridge_src" / "netforge_bridge.js").is_file()
    assert (dest / "bridge_src" / "bridge.html").is_file()
    assert "One-time Packet Tracer registration steps:" in out
    assert "Configure PT Script Modules" in out
    assert "On Startup" in out
    assert str(pts_path.resolve()) in out

    # Re-running with --source equal to --dest-dir/netforge_bridge.pts must succeed cleanly
    exit_code_json = cli.main(
        ["install-module", "--dest-dir", str(dest), "--source", str(pts_path), "--json"]
    )
    assert exit_code_json == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["installed"] is True
    assert payload["bytes_written"] == pts_path.stat().st_size
    assert len(payload["steps"]) == 5

