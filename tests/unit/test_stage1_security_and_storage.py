"""Stage 1A unit tests for security hardening, CLI guards, SQLite safety, and auto-persistence."""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import pytest

from agenticnet import cli
from agenticnet.adapters.base import GuiBackend, ScriptBackend
from agenticnet.adapters.discovery import (
    detect_packet_tracer_binary,
    validate_lab_file_path,
    validate_packet_tracer_binary_path,
)
from agenticnet.adapters.script_bridge import HttpScriptBridgeBackend, HttpScriptBridgeServer
from agenticnet.core.enums import OperationStatus, PermissionTier
from agenticnet.core.exceptions import (
    ProjectAlreadyExistsError,
    ValidationError,
)
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.gui.safety import AutomationStopError
from agenticnet.mcp.server import create_mcp_server
from agenticnet.security.permissions import PermissionPolicy
from agenticnet.security.validation import (
    safe_output_path,
    validate_cli_safe_text,
    validate_ping_target,
)
from agenticnet.storage import ProjectBundle, ProjectManager, SQLiteStore, migrate_project_payload
from agenticnet.storage.models import ProjectMetadata


class _FakeGuiBackend(GuiBackend):
    """Deterministic fake GUI backend for testing MCP GUI tool wrappers."""

    def __init__(self) -> None:
        self.last_screenshot_output: str | None = None
        self.launched: bool = False

    def detect_application(self) -> dict[str, Any]:
        return {"detected_binary": None, "running": False}

    def launch_application(
        self,
        executable_path: str | None = None,
        *,
        project_file: str | None = None,
        wait_seconds: float = 15.0,
    ) -> dict[str, Any]:
        self.launched = True
        return {"already_running": False, "pid": 1234, "executable_path": executable_path}

    def capture_screenshot(self, *, output_path: str | None = None) -> dict[str, Any]:
        self.last_screenshot_output = output_path
        return {"screenshot_path": output_path or "memory://capture.png"}

    def calibrate(self, *, profile_id: str = "default") -> dict[str, Any]:
        return {
            "profile_path": "memory://cal.json",
            "profile": {"client_width": 1280, "client_height": 720, "dpi": 96},
        }

    def click(
        self,
        *,
        x: int | None = None,
        y: int | None = None,
        nx: float | None = None,
        ny: float | None = None,
        anchor_name: str | None = None,
        button: str = "left",
        clicks: int = 1,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return {"screen_x": x or 0, "screen_y": y or 0, "resolution_source": "direct"}

    def keypress(
        self,
        keys: str,
        *,
        text: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return {"keys": keys, "text_length": len(text or "")}

    def inspect_state(self) -> dict[str, Any]:
        return {"report": {"running": False, "dialogs": [], "calibration_loaded": False}}

    def recover(self, *, strategy: str = "dismiss_dialog", confirm: bool = False) -> dict[str, Any]:
        return {"strategy": strategy}

    def execute_batch(
        self,
        actions: list[dict[str, Any]],
        *,
        background: bool | None = None,
        restore_focus: bool = True,
        stop_on_error: bool = True,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return {
            "completed_steps": len(actions),
            "total_steps": len(actions),
            "failed_steps": 0,
            "elapsed_ms": 1,
            "background": bool(background),
        }


class _ConnectedScriptBackend(ScriptBackend):
    """Minimal connected script backend stub."""

    def is_connected(self) -> bool:
        return True

    def ping(self) -> dict[str, Any]:
        return {"ok": True}

    def add_device(
        self, model: str, *, device_type: int | str = 0, x: float = 0.0, y: float = 0.0
    ) -> dict[str, Any]:
        return {"ok": True, "device_name": "R1"}

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
        return {"ok": True, "raw_output": "R1#", "prompt": "R1#"}


@pytest.mark.unit
def test_permission_profile_sync_and_fail_closed_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p1 = PermissionPolicy.from_profile("read_only")
    p2 = PermissionPolicy.from_profile("read-only")
    assert p1.profile_name == "read-only"
    assert p1.allowed_tiers == {PermissionTier.READ_ONLY}
    p1.allowed_tiers.add(PermissionTier.PLANNING)
    assert p2.allowed_tiers == {PermissionTier.READ_ONLY}

    ro_hyphen = AgenticNetSettings(data_dir=tmp_path, permission_profile="read-only")
    assert ro_hyphen.permission_profile == "read-only"
    assert ro_hyphen.allowed_tiers == {PermissionTier.READ_ONLY}

    ro_under = AgenticNetSettings(data_dir=tmp_path, permission_profile="read_only")
    assert ro_under.permission_profile == "read-only"
    assert ro_under.allowed_tiers == {PermissionTier.READ_ONLY}

    full_alias = AgenticNetSettings(data_dir=tmp_path, permission_profile="full")
    assert full_alias.permission_profile == "standard"
    assert PermissionTier.DESTRUCTIVE in full_alias.allowed_tiers

    explicit = AgenticNetSettings(
        data_dir=tmp_path,
        permission_profile="read-only",
        allowed_tiers={PermissionTier.READ_ONLY, PermissionTier.PLANNING},
    )
    assert explicit.allowed_tiers == {PermissionTier.READ_ONLY, PermissionTier.PLANNING}

    monkeypatch.setenv("AGENTICNET_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AGENTICNET_PERMISSION_PROFILE", "bogus_profile")
    with pytest.raises(ValidationError):
        AgenticNetSettings.from_env()

    monkeypatch.setenv("AGENTICNET_PERMISSION_PROFILE", "read_only")
    env_ro = AgenticNetSettings.from_env()
    assert env_ro.permission_profile == "read-only"
    assert env_ro.allowed_tiers == {PermissionTier.READ_ONLY}

    monkeypatch.setenv("AGENTICNET_TOOL_PROFILE", "unknown_mode")
    with pytest.raises(ValidationError):
        AgenticNetSettings.from_env()


@pytest.mark.unit
def test_discovery_binary_and_lab_path_validation(tmp_path: Path) -> None:
    win_pt = r"C:\Program Files\Cisco Packet Tracer 8.2.2\bin\PacketTracer.exe"
    validated_win = validate_packet_tracer_binary_path(win_pt)
    assert PureWindowsPath(str(validated_win)).name == "PacketTracer.exe"
    assert validate_packet_tracer_binary_path("/opt/pt/bin/PacketTracer7").name == "PacketTracer7"

    for bad_bin in ("cmd.exe", r"C:\Windows\System32\cmd.exe", "/bin/sh", "bad\x00PacketTracer"):
        with pytest.raises(ValidationError):
            validate_packet_tracer_binary_path(bad_bin)

    with pytest.raises(ValidationError):
        detect_packet_tracer_binary("cmd.exe")

    lab_pkt = tmp_path / "campus_lab.pkt"
    resolved_pkt = validate_lab_file_path(lab_pkt, must_exist=False)
    assert resolved_pkt == lab_pkt.resolve()
    with pytest.raises(ValidationError):
        validate_lab_file_path(lab_pkt, must_exist=True)
    lab_pkt.write_bytes(b"PKT")
    assert validate_lab_file_path(lab_pkt, must_exist=True) == lab_pkt.resolve()

    for bad_lab in (tmp_path / "evil.exe", tmp_path / "script.bat", "bad\x00.pkt"):
        with pytest.raises(ValidationError):
            validate_lab_file_path(bad_lab)

    fake_gui = _FakeGuiBackend()
    settings = AgenticNetSettings(data_dir=tmp_path / "data", tool_profile="advanced")
    server, _ = create_mcp_server(settings, gui_backend=fake_gui)

    async def _attempt_bad_launches() -> tuple[dict[str, Any], dict[str, Any]]:
        r1 = await server.call_tool("packet_tracer_launch", {"executable_path": "cmd.exe"})
        r2 = await server.call_tool("packet_tracer_launch", {"project_file": "payload.bat"})
        assert r1.structured_content is not None and r2.structured_content is not None
        return dict(r1.structured_content), dict(r2.structured_content)

    out1, out2 = asyncio.run(_attempt_bad_launches())
    assert out1["success"] is False
    assert out1["errors"][0]["error_code"] == "VALIDATION_ERROR"
    assert out2["success"] is False
    assert out2["errors"][0]["error_code"] == "VALIDATION_ERROR"
    assert fake_gui.launched is False


@pytest.mark.unit
def test_validate_packet_tracer_binary_path_posix_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakePosixPath(PurePosixPath):
        def expanduser(self) -> _FakePosixPath:
            return self

    monkeypatch.setattr("agenticnet.adapters.discovery.Path", _FakePosixPath)

    win_pt = r"C:\Program Files\Cisco Packet Tracer 8.2.2\bin\PacketTracer.exe"
    validated = validate_packet_tracer_binary_path(win_pt)
    assert isinstance(validated, _FakePosixPath)
    assert PureWindowsPath(str(validated)).name == "PacketTracer.exe"
    assert validate_packet_tracer_binary_path("/opt/pt/bin/PacketTracer7").name == "PacketTracer7"

    for bad_bin in (
        r"C:\Windows\System32\cmd.exe",
        r"C:\Program Files\PacketTracer.exe\cmd.exe",
        "/bin/sh",
    ):
        with pytest.raises(ValidationError):
            validate_packet_tracer_binary_path(bad_bin)


@pytest.mark.unit
def test_cli_safe_text_and_ping_target_validation() -> None:
    assert validate_cli_safe_text("Core Uplink Gi0/1", field_name="description") == (
        "Core Uplink Gi0/1"
    )
    for injected in ("Uplink\nusername backdoor secret pwn", "Desc\rreload", "Null\x00byte"):
        with pytest.raises(ValidationError):
            validate_cli_safe_text(injected, field_name="description")

    assert validate_ping_target("10.10.20.1") == "10.10.20.1"
    assert validate_ping_target("2001:db8::1") == "2001:db8::1"
    assert validate_ping_target("core-r1.lab.internal") == "core-r1.lab.internal"

    for bad_target in ("", "10.0.0.1\nconf t", "10.0.0.1 repeat 999999", "10.0.0.1;reload"):
        with pytest.raises(ValidationError):
            validate_ping_target(bad_target)


@pytest.mark.unit
def test_read_only_profile_and_confined_output_paths(tmp_path: Path) -> None:
    data_dir = tmp_path / "agent_data"
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    with pytest.raises(ValidationError):
        safe_output_path(
            outside_dir / "escape.json",
            default_base_dir=data_dir,
            allow_outside_base=False,
        )

    # Seed a project in standard mode first
    std_settings = AgenticNetSettings(
        data_dir=data_dir,
        permission_profile="standard",
        tool_profile="advanced",
    )
    fake_gui = _FakeGuiBackend()
    std_server, std_runtime = create_mcp_server(std_settings, gui_backend=fake_gui)

    manifest_tools = {t["name"]: t for t in std_runtime.build_manifest()["tools"]}
    assert manifest_tools["gui_attach_ip_phone_power"]["status"] == "experimental"

    async def _run_standard() -> dict[str, Any]:
        await std_server.call_tool(
            "project_create", {"name": "ConfinedLab", "project_id": "confined-lab"}
        )
        esc_export = await std_server.call_tool(
            "project_export", {"output_path": str(outside_dir / "escape.json")}
        )
        trav_export = await std_server.call_tool(
            "project_export", {"output_path": "../../escape.json"}
        )
        ok_export = await std_server.call_tool(
            "project_export", {"output_path": "clean_bundle.json"}
        )
        esc_shot = await std_server.call_tool(
            "gui_screenshot", {"output_path": str(outside_dir / "escape.png")}
        )
        ok_shot = await std_server.call_tool("gui_screenshot", {"output_path": "clean_shot.png"})
        return {
            "esc_export": dict(esc_export.structured_content or {}),
            "trav_export": dict(trav_export.structured_content or {}),
            "ok_export": dict(ok_export.structured_content or {}),
            "esc_shot": dict(esc_shot.structured_content or {}),
            "ok_shot": dict(ok_shot.structured_content or {}),
        }

    std_res = asyncio.run(_run_standard())
    assert std_res["esc_export"]["success"] is False
    assert std_res["esc_export"]["errors"][0]["error_code"] == "VALIDATION_ERROR"
    assert std_res["trav_export"]["success"] is False
    assert std_res["ok_export"]["success"] is True
    assert (data_dir / "exports" / "clean_bundle.json").is_file()
    assert std_res["esc_shot"]["success"] is False
    assert std_res["ok_shot"]["success"] is True
    expected_shot = str((data_dir / "screenshots" / "clean_shot.png").resolve())
    assert fake_gui.last_screenshot_output == expected_shot

    # Now verify read-only profile blocks mutating project_open and file-writing exports/screenshots
    ro_settings = AgenticNetSettings(
        data_dir=data_dir,
        permission_profile="read-only",
        tool_profile="advanced",
    )
    ro_server, ro_runtime = create_mcp_server(ro_settings, gui_backend=fake_gui)
    ro_runtime.manager.open_project("confined-lab")

    async def _run_readonly() -> dict[str, Any]:
        open_res = await ro_server.call_tool("project_open", {"project_id": "confined-lab"})
        exp_write = await ro_server.call_tool("project_export", {"output_path": "blocked.json"})
        exp_mem = await ro_server.call_tool("project_export", {})
        shot_write = await ro_server.call_tool("gui_screenshot", {"output_path": "blocked.png"})
        shot_mem = await ro_server.call_tool("gui_screenshot", {})
        return {
            "open_res": dict(open_res.structured_content or {}),
            "exp_write": dict(exp_write.structured_content or {}),
            "exp_mem": dict(exp_mem.structured_content or {}),
            "shot_write": dict(shot_write.structured_content or {}),
            "shot_mem": dict(shot_mem.structured_content or {}),
        }

    ro_res = asyncio.run(_run_readonly())
    assert ro_res["open_res"]["status"] == OperationStatus.BLOCKED.value
    assert ro_res["exp_write"]["status"] == OperationStatus.BLOCKED.value
    assert ro_res["exp_mem"]["success"] is True
    assert ro_res["shot_write"]["status"] == OperationStatus.BLOCKED.value
    assert ro_res["shot_mem"]["success"] is True


@pytest.mark.unit
def test_project_status_reports_live_backend_truth(tmp_path: Path) -> None:
    settings = AgenticNetSettings(data_dir=tmp_path / "status_data", tool_profile="advanced")
    offline_server, _ = create_mcp_server(settings, gui_backend=_FakeGuiBackend())
    live_server, _ = create_mcp_server(
        settings,
        gui_backend=_FakeGuiBackend(),
        script_backend=_ConnectedScriptBackend(),
    )

    async def _check() -> tuple[dict[str, Any], dict[str, Any]]:
        r_off = await offline_server.call_tool("project_status", {})
        r_live = await live_server.call_tool("project_status", {})
        return dict(r_off.structured_content or {}), dict(r_live.structured_content or {})

    off_out, live_out = asyncio.run(_check())
    assert off_out["data"]["packet_tracer_backend"] == "offline_planning"
    assert live_out["data"]["packet_tracer_backend"] == "script_backend"


@pytest.mark.unit
def test_cli_serve_remote_bind_guard_shared_safety_and_doctor_canonical_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_dir = tmp_path / "primary_data"
    canon_dir = tmp_path / "canonical_data"
    monkeypatch.setenv("AGENTICNET_DATA_DIR", str(data_dir))
    monkeypatch.delenv("AGENTICNET_ALLOW_UNAUTHENTICATED_REMOTE", raising=False)
    monkeypatch.delenv("NETFORGE_ALLOW_UNAUTHENTICATED_REMOTE", raising=False)
    monkeypatch.setattr(cli, "canonical_pt_bridge_data_dir", lambda: canon_dir)

    # 1. Refuses non-loopback streamable-http / sse without explicit opt-in
    rc_blocked = cli.main(["serve", "--transport", "streamable-http", "--host", "0.0.0.0"])
    assert rc_blocked == 2
    err_text = capsys.readouterr().err
    assert "--allow-unauthenticated-remote" in err_text

    # 2. Proceeds when --allow-unauthenticated-remote is set and shares EmergencyStopController
    captured: dict[str, Any] = {}
    orig_create = cli.create_mcp_server

    def _spy_create_mcp_server(
        settings: AgenticNetSettings | None = None,
        **kwargs: Any,
    ) -> tuple[Any, Any]:
        srv, rt = orig_create(settings, **kwargs)
        monkeypatch.setattr(srv, "run", lambda **_kw: None)
        captured["runtime"] = rt
        captured["bridge"] = kwargs.get("script_backend")
        return srv, rt

    monkeypatch.setattr(cli, "create_mcp_server", _spy_create_mcp_server)
    rc_allowed = cli.main(
        [
            "serve",
            "--transport",
            "streamable-http",
            "--host",
            "0.0.0.0",
            "--profile",
            "read_only",
            "--allow-unauthenticated-remote",
        ]
    )
    assert rc_allowed == 0
    rt = captured["runtime"]
    bridge = captured["bridge"]
    assert rt.guard.policy.profile_name == "read-only"
    assert rt.safety is bridge.safety
    if hasattr(rt.gui, "safety"):
        assert rt.gui.safety is rt.safety

    # Arming emergency stop on runtime.safety immediately blocks HttpScriptBridgeBackend actions
    rt.safety.request_stop("unit test emergency stop")
    with pytest.raises(AutomationStopError):
        bridge.ping()

    # 3. Doctor probes canonical session file when primary data_dir has no session file
    canon_dir.mkdir(parents=True, exist_ok=True)
    canon_session = canon_dir / "bridge_session.json"
    bridge_srv = HttpScriptBridgeServer(session_file=canon_session)
    bridge_srv.start()
    try:
        monkeypatch.setattr(cli, "_detect_packet_tracer_binary", lambda _p: None)
        monkeypatch.setattr(cli, "_is_packet_tracer_running", lambda: False)
        report = cli.build_doctor_report(AgenticNetSettings(data_dir=data_dir))
        assert report["roadmap_stage"] == "stage_1_packet_tracer_excellence"
        sb = report["script_bridge"]
        assert isinstance(sb, dict)
        assert sb["session_descriptor_present"] is True
        assert sb["reachable"] is True
    finally:
        bridge_srv.stop()


@pytest.mark.unit
def test_sqlite_connection_closing_atomic_create_and_workspace_preferences(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "store_test.sqlite3"
    store = SQLiteStore(db_path)

    meta = ProjectMetadata(project_id="atomic-lab", name="Atomic Lab")
    assert meta.target_mode == "packet_tracer"
    bundle = ProjectBundle(metadata=meta)
    store.save_bundle(bundle, create_only=True)

    with pytest.raises(ProjectAlreadyExistsError):
        store.save_bundle(bundle, create_only=True)

    # Concurrent atomic create_only race test across 8 threads
    race_results: list[str] = []
    race_lock = threading.Lock()

    def _worker() -> None:
        race_bundle = ProjectBundle(
            metadata=ProjectMetadata(project_id="race-project", name="Race Project")
        )
        try:
            store.save_bundle(race_bundle, create_only=True)
            with race_lock:
                race_results.append("created")
        except ProjectAlreadyExistsError:
            with race_lock:
                race_results.append("exists")

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert race_results.count("created") == 1
    assert race_results.count("exists") == 7

    # Workspace preferences + secret scrubbing
    store.set_preference("default_router_model", "2911")
    store.set_preference("credentials", {"enable_secret": "TopSecretPref123", "user": "admin"})
    assert store.get_preference("default_router_model") == "2911"
    assert store.get_preference("missing_key", default="fallback") == "fallback"
    prefs = store.list_preferences()
    assert prefs["credentials"]["value"]["enable_secret"] == "[REDACTED]"
    assert b"TopSecretPref123" not in db_path.read_bytes()

    # Migration populates target_mode="packet_tracer" for legacy payloads
    migrated = migrate_project_payload(
        {
            "schema_version": "1.0.0",
            "metadata": {"project_id": "legacy-lab", "name": "Legacy Lab"},
        }
    )
    assert migrated["metadata"]["target_mode"] == "packet_tracer"

    # Verify zero leaked SQLite file handles on Windows: unlinking db_path succeeds immediately
    loaded = store.load_bundle("atomic-lab")
    assert loaded.metadata.target_mode == "packet_tracer"
    assert len(store.list_projects()) == 2
    store.delete_project("atomic-lab")
    store.delete_project("race-project")
    db_path.unlink()
    assert not db_path.exists()


@pytest.mark.unit
def test_mcp_auto_persistence_and_audit_log_enrichment(tmp_path: Path) -> None:
    settings = AgenticNetSettings(data_dir=tmp_path / "autopersist", tool_profile="advanced")
    fake_gui = _FakeGuiBackend()
    bridge = HttpScriptBridgeBackend(HttpScriptBridgeServer(session_file=None))
    server, runtime = create_mcp_server(settings, gui_backend=fake_gui, script_backend=bridge)
    assert runtime.safety is bridge.safety

    async def _mutate_without_explicit_save() -> None:
        r_create = await server.call_tool(
            "project_create", {"name": "AutoPersistLab", "project_id": "autopersist-lab"}
        )
        assert (r_create.structured_content or {})["success"] is True

        r_dev = await server.call_tool("device_add", {"name": "R1", "model": "2911"})
        assert (r_dev.structured_content or {})["success"] is True

        r_key = await server.call_tool(
            "gui_keypress",
            {"keys": "enter", "text": "enable secret MyAuditSecret777", "dry_run": True},
        )
        assert (r_key.structured_content or {})["success"] is True

        r_batch = await server.call_tool(
            "gui_batch",
            {"actions": [{"op": "click", "x": 10, "y": 20}], "dry_run": True},
        )
        assert (r_batch.structured_content or {})["success"] is True

    asyncio.run(_mutate_without_explicit_save())

    # Without calling project_save, a fresh ProjectManager must load R1 from SQLite!
    fresh_mgr = ProjectManager(settings)
    reopened = fresh_mgr.open_project("autopersist-lab")
    assert "R1" in reopened.topology.devices
    assert reopened.metadata.target_mode == "packet_tracer"

    logs = fresh_mgr.store.list_execution_logs(project_id="autopersist-lab", limit=20)
    by_tool = {entry["tool_name"]: entry for entry in logs}
    assert "gui_keypress" in by_tool
    keypress_params = json.dumps(by_tool["gui_keypress"]["params"])
    assert "MyAuditSecret777" not in keypress_params
    assert "[REDACTED]" in keypress_params
    assert by_tool["gui_batch"]["params"]["action_ops"] == ["click"]
