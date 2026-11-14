"""Offline unit tests for Phase 4 (`grade_lab`, `verify_lab(task_ids=...)`, GUI power adapter)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from netforge.adapters.router import BackendRouter
from netforge.core.settings import NetForgeSettings
from netforge.mcp.server import create_mcp_server


class _FakeGradeScriptBackend:
    def __init__(self, activity_payload: dict[str, Any] | Exception) -> None:
        self._payload = activity_payload
        self.cli_calls: list[tuple[str, list[str]]] = []

    def is_connected(self) -> bool:
        return True

    def ping(self) -> dict[str, Any]:
        return {"ok": True, "bridge": "fake"}

    def read_activity_status(self) -> dict[str, Any]:
        if isinstance(self._payload, Exception):
            raise self._payload
        return dict(self._payload)

    def execute_cli(
        self,
        device_name: str,
        commands: list[str],
        *,
        timeout_seconds: float = 15.0,
    ) -> dict[str, Any]:
        _ = timeout_seconds
        self.cli_calls.append((device_name, list(commands)))
        cmd = commands[-1] if commands else ""
        if cmd == "show ip interface brief":
            raw = (
                "Interface              IP-Address      OK? Method Status                Protocol\n"
                "GigabitEthernet0/0     10.0.0.1        YES manual up                    up\n"
            )
        elif cmd == "show ip route":
            raw = "S    192.168.20.0/24 [1/0] via 10.0.0.2\n"
        else:
            raw = ""
        return {
            "ok": True,
            "backend": "script_http",
            "device_name": device_name,
            "commands": list(commands),
            "raw_output": raw,
            "timed_out": False,
        }


def _call_tool_sync(server: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    import asyncio

    res = asyncio.run(server.call_tool(name, arguments))
    assert res.structured_content is not None
    return dict(res.structured_content)


def test_grade_lab_available_score_and_unmet_leaves(tmp_path: Path) -> None:
    fake = _FakeGradeScriptBackend(
        {
            "ok": True,
            "is_activity_file": True,
            "state": "available",
            "readable": True,
            "percentage_complete": 66.7,
            "percentage_complete_score": 66.7,
            "items_count": 3,
            "correct_items_count": 2,
            "score_count": 30,
            "correct_score_count": 20,
            "leaves": [
                {
                    "path": "R1 > Interfaces > GigabitEthernet0/0 > IP Address",
                    "name": "IP Address",
                    "value": "10.0.0.1",
                    "leafCount": 1,
                    "checkLeafCount": 1,
                    "totalLeafPoints": 10,
                    "checkLeafPoints": 10,
                    "incorrectFeedback": "",
                },
                {
                    "path": "R1 > Interfaces > GigabitEthernet0/1 > Status",
                    "name": "Status",
                    "value": "up",
                    "leafCount": 1,
                    "checkLeafCount": 1,
                    "totalLeafPoints": 10,
                    "checkLeafPoints": 10,
                    "incorrectFeedback": "",
                },
                {
                    "path": "R1 > Static Routes > 192.168.20.0/24",
                    "name": "192.168.20.0/24",
                    "value": "via 10.0.0.2",
                    "leafCount": 1,
                    "checkLeafCount": 0,
                    "totalLeafPoints": 10,
                    "checkLeafPoints": 0,
                    "incorrectFeedback": "Missing static route to 192.168.20.0/24",
                },
            ],
        }
    )
    settings = NetForgeSettings(data_dir=tmp_path / ".nf", permission_profile="full")
    server, _ = create_mcp_server(settings=settings, script_backend=fake)
    out = _call_tool_sync(server, "grade_lab", {})
    assert out["success"] is True
    assert out["execution_backend"] == "script_backend"
    assert out["state_level"] == "verified"
    data = out["data"]
    assert data["state"] == "available"
    assert data["readable"] is True
    assert data["percentage_complete"] == 66.7
    assert data["correct_items_count"] == 2
    assert data["items_count"] == 3
    assert len(data["met_items"]) == 2
    assert len(data["unmet_items"]) == 1
    assert data["unmet_items"][0]["name"] == "192.168.20.0/24"
    assert "Missing static route" in data["unmet_items"][0]["incorrect_feedback"]
    assert data["passed"] is False


def test_grade_lab_fail_closed_when_locked_or_assessment_mode(tmp_path: Path) -> None:
    for flags in (
        {"locked": True, "percentage_complete": 100.0},
        {"password_locked": True, "percentage_complete": 50.0},
        {"assessment_mode": True, "percentage_complete": 100.0},
        {"state": "unavailable", "readable": False, "percentage_complete": None},
    ):
        fake = _FakeGradeScriptBackend(
            {
                "ok": True,
                "is_activity_file": True,
                "state": "available",
                "readable": True,
                **flags,
            }
        )
        router = BackendRouter(script_backend=fake)
        status = router.read_activity_status()
        assert status["state"] == "unavailable"
        assert status["score"] is None
        settings = NetForgeSettings(data_dir=tmp_path / ".nf", permission_profile="full")
        server, _ = create_mcp_server(settings=settings, script_backend=fake)
        out = _call_tool_sync(server, "grade_lab", {})
        data = out["data"]
        assert data["state"] == "unavailable"
        assert data["readable"] is False
        assert data["percentage_complete"] is None
        assert data["fallback"] == "verify_lab"
        assert data["unmet_items"] == []


def test_grade_lab_non_activity_and_offline_fallback(tmp_path: Path) -> None:
    fake_pkt = _FakeGradeScriptBackend(
        {
            "ok": True,
            "is_activity_file": False,
            "state": "not_activity",
            "readable": False,
        }
    )
    settings = NetForgeSettings(data_dir=tmp_path / ".nf", permission_profile="full")
    srv_live, _ = create_mcp_server(settings=settings, script_backend=fake_pkt)
    out_pkt = _call_tool_sync(srv_live, "grade_lab", {})
    assert out_pkt["data"]["state"] == "unavailable"
    assert out_pkt["data"]["raw_state"] == "not_activity"
    assert out_pkt["data"]["fallback"] == "verify_lab"

    srv_off, _ = create_mcp_server(settings=settings)
    out_off = _call_tool_sync(srv_off, "grade_lab", {})
    assert out_off["execution_backend"] == "offline_model"
    assert out_off["state_level"] == "planned"
    assert out_off["data"]["state"] == "unavailable"
    assert out_off["data"]["fallback"] == "verify_lab"


def test_verify_lab_task_ids_coverage_reporting(tmp_path: Path) -> None:
    fake = _FakeGradeScriptBackend({"is_activity_file": False, "state": "not_activity"})
    settings = NetForgeSettings(data_dir=tmp_path / ".nf", permission_profile="full")
    server, _ = create_mcp_server(settings=settings, script_backend=fake)

    out = _call_tool_sync(
        server,
        "verify_lab",
        {
            "requirements": {
                "lab_name": "Task Coverage Check",
                "requirements": [
                    {
                        "id": "r1_g0",
                        "task_id": "T1_L3_IP",
                        "type": "ip_assigned",
                        "device": "R1",
                        "interface": "GigabitEthernet0/0",
                        "ip": "10.0.0.1",
                    },
                    {
                        "id": "r1_route",
                        "task_id": "T2_STATIC",
                        "type": "route_exists",
                        "device": "R1",
                        "network": "192.168.20.0/24",
                    },
                ],
            },
            "task_ids": ["T1_L3_IP", "T2_STATIC", "T3_DHCP", "T4_NAT"],
            "include_activity_grade": False,
        },
    )
    assert out["success"] is True
    data = out["data"]
    assert data["passed"] is True
    cov = data["task_coverage"]
    assert cov is not None
    assert cov["covered_tasks"] == ["T1_L3_IP", "T2_STATIC"]
    assert cov["uncovered_tasks"] == ["T3_DHCP", "T4_NAT"]
    assert cov["all_tasks_covered"] is False
    assert cov["coverage_ratio"] == 0.5
    assert any("Uncovered task IDs" in w for w in out["warnings"])


class _FakePowerGuiBackend:
    def __init__(self, *, fail_locked: bool = False, missing_window: bool = False) -> None:
        self.fail_locked = fail_locked
        self.missing_window = missing_window
        self.calls: list[dict[str, Any]] = []

    def attach_ip_phone_power(self, **kwargs: Any) -> dict[str, Any]:
        from netforge.core.exceptions import AdapterUnavailableError

        self.calls.append(dict(kwargs))
        if self.missing_window:
            raise AdapterUnavailableError("No visible Cisco Packet Tracer main window detected.")
        if not kwargs.get("dry_run") and self.fail_locked:
            raise AdapterUnavailableError("Windows interactive desktop is locked.")
        dry = bool(kwargs.get("dry_run"))
        return {
            "dry_run": dry,
            "device_name": kwargs.get("device_name", "IP_PHONE1"),
            "pt_device_title": kwargs.get("pt_device_title", "IP Phone0"),
            "hwnd": 12345,
            "dpi": 120,
            "scale_factor": 1.25,
            "canvas_xy": [kwargs.get("canvas_x"), kwargs.get("canvas_y")],
            "socket_roi_diff_ratio": None if dry else 0.14,
            "state_level": "planned" if dry else "executed",
        }


def test_gui_attach_ip_phone_power_dry_run_and_provenance(tmp_path: Path) -> None:
    fake_gui = _FakePowerGuiBackend()
    settings = NetForgeSettings(data_dir=tmp_path / ".nf", permission_profile="full")
    server, _ = create_mcp_server(settings=settings, gui_backend=fake_gui)
    _call_tool_sync(server, "project_create", {"name": "PhoneDryRun"})
    _call_tool_sync(
        server,
        "device_add",
        {"name": "IP_PHONE1", "model": "7960", "x": 420.0, "y": 210.0},
    )

    dry = _call_tool_sync(
        server,
        "gui_attach_ip_phone_power",
        {"device_name": "IP_PHONE1", "dry_run": True},
    )
    assert dry["success"] is True
    assert dry["execution_backend"] == "gui_backend"
    assert dry["state_level"] == "planned"
    assert fake_gui.calls[-1]["canvas_x"] == 420.0
    assert fake_gui.calls[-1]["canvas_y"] == 210.0

    live = _call_tool_sync(
        server,
        "gui_attach_ip_phone_power",
        {"device_name": "IP_PHONE1", "dry_run": False},
    )
    assert live["success"] is True
    assert live["execution_backend"] == "gui_backend"
    assert live["state_level"] == "executed"
    assert live["data"]["socket_roi_diff_ratio"] == 0.14


def test_gui_attach_ip_phone_power_fails_closed_on_missing_hwnd_or_locked_desktop(
    tmp_path: Path,
) -> None:
    settings = NetForgeSettings(data_dir=tmp_path / ".nf", permission_profile="full")
    srv_no_win, _ = create_mcp_server(
        settings=settings, gui_backend=_FakePowerGuiBackend(missing_window=True)
    )
    res1 = _call_tool_sync(
        srv_no_win,
        "gui_attach_ip_phone_power",
        {"device_name": "IP_PHONE1", "dry_run": True},
    )
    assert res1["success"] is False
    assert "main window" in str(res1["summary"]).lower() or res1["errors"]

    srv_locked, _ = create_mcp_server(
        settings=settings, gui_backend=_FakePowerGuiBackend(fail_locked=True)
    )
    res2 = _call_tool_sync(
        srv_locked,
        "gui_attach_ip_phone_power",
        {"device_name": "IP_PHONE1", "dry_run": False},
    )
    assert res2["success"] is False
    assert res2["errors"]


def test_script_bridge_open_file_opcode() -> None:
    from unittest.mock import MagicMock

    from netforge.adapters.script_bridge import HttpScriptBridgeBackend

    mock_server = MagicMock()
    mock_server.is_connected.return_value = True
    mock_server.enqueue_command.return_value = {
        "path": "sample.pka",
        "saved_filename": "sample.pka",
        "is_activity_file": True,
    }
    backend = HttpScriptBridgeBackend(mock_server)
    out = backend.open_file("sample.pka", timeout_seconds=12.0)
    mock_server.enqueue_command.assert_called_once_with(
        "open_file",
        {"path": "sample.pka"},
        timeout_seconds=12.0,
    )
    assert out["ok"] is True
    assert out["backend"] == "script_http"
    assert out["is_activity_file"] is True
    assert "open_file" in backend.backend_status().capabilities
