"""Unit tests for BackendRouter, provenance tags, tool migration, and fail-closed grader."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from agenticnet.adapters.base import ScriptBackend
from agenticnet.adapters.router import BackendRouter
from agenticnet.console.models import DeviceConsoleProfile
from agenticnet.console.transport import ConsoleTransport
from agenticnet.core.exceptions import AdapterUnavailableError
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.mcp.server import create_mcp_server


class _FakeScriptBackend(ScriptBackend):
    """Deterministic in-memory mock ScriptBackend (zero Packet Tracer required)."""

    def __init__(self, *, connected: bool = True) -> None:
        self.connected = connected
        self.added_devices: list[dict[str, Any]] = []
        self.created_links: list[dict[str, Any]] = []
        self.cli_calls: list[dict[str, Any]] = []
        self.activity_payload: dict[str, Any] = {"state": "unavailable", "readable": False}
        self.activity_exc: Exception | None = None
        self._counter = 0

    def is_connected(self) -> bool:
        return self.connected

    def ping(self) -> dict[str, Any]:
        return {"ok": self.connected, "backend": "script_http"}

    def add_device(
        self,
        model: str,
        *,
        device_type: int | str = 0,
        x: float = 100.0,
        y: float = 100.0,
    ) -> dict[str, Any]:
        if not self.connected:
            raise AdapterUnavailableError("Script bridge disconnected.")
        assigned = f"Router{self._counter}" if int(device_type) == 0 else f"Switch{self._counter}"
        self._counter += 1
        rec = {
            "ok": True,
            "backend": "script_http",
            "device_name": assigned,
            "model": model,
            "device_type": device_type,
            "x": x,
            "y": y,
        }
        self.added_devices.append(rec)
        return rec

    def create_link(
        self,
        device1: str,
        port1: str,
        device2: str,
        port2: str,
        *,
        conn_type: int | str = 8107,
    ) -> dict[str, Any]:
        if not self.connected:
            raise AdapterUnavailableError("Script bridge disconnected.")
        rec = {
            "ok": True,
            "backend": "script_http",
            "device1": device1,
            "port1": port1,
            "device2": device2,
            "port2": port2,
            "conn_type": conn_type,
        }
        self.created_links.append(rec)
        return rec

    def execute_cli(
        self,
        device_name: str,
        commands: list[str],
        *,
        wait_for_prompt: bool = True,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        if not self.connected:
            raise AdapterUnavailableError("Script bridge disconnected.")
        self.cli_calls.append({"device_name": device_name, "commands": list(commands)})
        joined = " ; ".join(commands).lower()
        if "show running-config" in joined:
            out = (
                "Building configuration...\n"
                "hostname R1\n"
                "enable secret SuperSecret99\n"
                "interface GigabitEthernet0/0\n"
                " ip address 10.0.0.1 255.255.255.0\n"
                "R1#"
            )
        elif "show interfaces" in joined:
            out = "GigabitEthernet0/0 is up, line protocol is up\nR1#"
        elif "ping " in joined:
            out = (
                "Sending 5, 100-byte ICMP Echos to 10.0.0.2, timeout is 2 seconds:\n"
                "!!!!!\n"
                "Success rate is 100 percent (5/5), round-trip min/avg/max = 0/0/1 ms\n"
                "R1#"
            )
        else:
            out = "R1#"
        return {
            "ok": True,
            "backend": "script_http",
            "device_name": device_name,
            "commands": list(commands),
            "raw_output": out,
            "prompt": "R1#",
            "mode": "privileged_exec",
            "timed_out": False,
        }

    def read_activity_status(self) -> dict[str, Any]:
        if self.activity_exc is not None:
            raise self.activity_exc
        return dict(self.activity_payload)


class _FakeGuiFallbackConsole(ConsoleTransport):
    """Simulated Windows GUI console fallback for router fallback tests."""

    transport_name = "windows_gui"

    def __init__(self) -> None:
        self.sent_lines: list[tuple[str, str]] = []

    def is_available(self) -> bool:
        return True

    def open_device(self, device_name: str, profile: DeviceConsoleProfile) -> str:
        return "Router#"

    def send_line(self, device_name: str, line: str, *, timeout_s: float = 5.0) -> str:
        self.sent_lines.append((device_name, line))
        if line.startswith("ping "):
            return (
                "Success rate is 100 percent (5/5), round-trip min/avg/max = 1/1/2 ms\n"
                "Router#"
            )
        if "show running-config" in line:
            return "hostname Router\nRouter#"
        return "Router#"

    def read_buffer(self, device_name: str) -> str:
        return "Router#"


def _decode(call_result: Any) -> dict[str, Any]:
    assert call_result.structured_content is not None
    return dict(call_result.structured_content)


@pytest.mark.unit
def test_migrated_live_tools_route_to_script_backend_with_provenance(tmp_path: Path) -> None:
    fake_script = _FakeScriptBackend(connected=True)
    settings = AgenticNetSettings(data_dir=tmp_path / "data", tool_profile="advanced")
    server, _ = create_mcp_server(settings, script_backend=fake_script)

    async def _exercise() -> None:
        proj = _decode(await server.call_tool("project_create", {"name": "LiveRouterTest"}))
        assert proj["execution_backend"] == "offline_model"  # unmigrated planning tool

        d1 = _decode(
            await server.call_tool(
                "device_add", {"name": "R1", "model": "2911", "x": 120.0, "y": 140.0}
            )
        )
        assert d1["success"] is True
        assert d1["execution_backend"] == "script_backend"
        assert d1["state_level"] == "executed"
        assert d1["data"]["live_backend"]["device_name"] == "Router0"

        d2 = _decode(
            await server.call_tool(
                "device_add", {"name": "SW1", "model": "2960-24TT", "x": 320.0, "y": 140.0}
            )
        )
        assert d2["execution_backend"] == "script_backend"
        assert d2["data"]["live_backend"]["device_name"] == "Switch1"

        link = _decode(
            await server.call_tool(
                "connection_create",
                {
                    "source_device": "R1",
                    "source_interface": "Gi0/0",
                    "target_device": "SW1",
                    "target_interface": "Fa0/1",
                },
            )
        )
        assert link["success"] is True
        assert link["execution_backend"] == "script_backend"
        assert fake_script.created_links[-1]["device1"] == "Router0"
        assert fake_script.created_links[-1]["device2"] == "Switch1"

        opened = _decode(await server.call_tool("console_open", {"device_name": "R1"}))
        assert opened["execution_backend"] == "script_backend"

        executed = _decode(
            await server.call_tool(
                "console_execute",
                {"device_name": "R1", "commands": ["show ip interface brief"]},
            )
        )
        assert executed["success"] is True
        assert executed["execution_backend"] == "script_backend"
        assert any(call["device_name"] == "Router0" for call in fake_script.cli_calls)

        captured = _decode(await server.call_tool("console_capture", {"device_name": "R1"}))
        assert captured["execution_backend"] == "script_backend"

        inspected = _decode(await server.call_tool("console_inspect", {"device_name": "R1"}))
        assert inspected["execution_backend"] == "script_backend"

        backup = _decode(await server.call_tool("configuration_backup", {"device_name": "R1"}))
        assert backup["success"] is True
        assert backup["execution_backend"] == "script_backend"
        assert backup["state_level"] == "verified"
        assert "SuperSecret99" not in backup["data"]["config_text"]

        iface = _decode(
            await server.call_tool(
                "interface_status",
                {"device_name": "R1", "interface_name": "Gi0/0", "live": True},
            )
        )
        assert iface["execution_backend"] == "script_backend"
        assert iface["state_level"] == "verified"
        assert "up, line protocol is up" in iface["data"]["live_show_output"]

        ping = _decode(
            await server.call_tool(
                "connectivity_test",
                {"source_device": "R1", "destination_ip": "10.0.0.2"},
            )
        )
        assert ping["success"] is True
        assert ping["execution_backend"] == "script_backend"
        assert ping["data"]["reachable"] is True
        assert ping["state_level"] == "verified"

    asyncio.run(_exercise())


@pytest.mark.unit
def test_dry_run_never_dispatches_to_live_backends(tmp_path: Path) -> None:
    fake_script = _FakeScriptBackend(connected=True)
    settings = AgenticNetSettings(data_dir=tmp_path / "data", tool_profile="advanced")
    server, _ = create_mcp_server(settings, script_backend=fake_script)

    async def _exercise() -> None:
        await server.call_tool("project_create", {"name": "DryRunRouterTest"})
        d1 = _decode(
            await server.call_tool(
                "device_add", {"name": "R1", "model": "2911", "dry_run": True}
            )
        )
        d2 = _decode(
            await server.call_tool(
                "device_add", {"name": "R2", "model": "2911", "dry_run": True}
            )
        )
        link = _decode(
            await server.call_tool(
                "connection_create",
                {
                    "source_device": "R1",
                    "source_interface": "Gi0/0",
                    "target_device": "R2",
                    "target_interface": "Gi0/0",
                    "dry_run": True,
                },
            )
        )
        cli = _decode(
            await server.call_tool(
                "console_execute",
                {"device_name": "R1", "commands": ["show version"], "dry_run": True},
            )
        )
        assert d1["execution_backend"] == "offline_model"
        assert d2["execution_backend"] == "offline_model"
        assert link["execution_backend"] == "offline_model"
        assert cli["execution_backend"] == "offline_model"
        assert fake_script.added_devices == []
        assert fake_script.created_links == []
        assert fake_script.cli_calls == []

    asyncio.run(_exercise())


@pytest.mark.unit
def test_router_falls_back_to_gui_then_offline_honestly(tmp_path: Path) -> None:
    disconnected_script = _FakeScriptBackend(connected=False)
    gui_fallback = _FakeGuiFallbackConsole()
    settings = AgenticNetSettings(data_dir=tmp_path / "data")
    server, _ = create_mcp_server(
        settings,
        script_backend=disconnected_script,
        console_transport=gui_fallback,
    )

    async def _exercise() -> None:
        await server.call_tool("project_create", {"name": "FallbackTest"})
        d1 = _decode(await server.call_tool("device_add", {"name": "R1", "model": "2911"}))
        assert d1["execution_backend"] == "offline_model"
        assert d1["state_level"] == "planned"

        cli = _decode(
            await server.call_tool(
                "console_execute", {"device_name": "R1", "commands": ["show version"]}
            )
        )
        assert cli["execution_backend"] == "gui_backend"
        assert gui_fallback.sent_lines

        ping = _decode(
            await server.call_tool(
                "connectivity_test",
                {"source_device": "R1", "destination_ip": "10.0.0.2"},
            )
        )
        assert ping["execution_backend"] == "gui_backend"
        assert ping["data"]["reachable"] is True

    asyncio.run(_exercise())


@pytest.mark.unit
def test_grader_fail_closed_never_bypasses_locked_or_unreadable_activities() -> None:
    # 1. Offline/disconnected returns unavailable + cli_verification fallback
    offline_router = BackendRouter(script_backend=None)
    off = offline_router.read_activity_status()
    assert off["state"] == "unavailable"
    assert off["readable"] is False
    assert off["score"] is None
    assert off["fallback"] == "cli_verification"

    # 2. Password-locked / Assessment-mode activity fails closed (never bypassed)
    fake_script = _FakeScriptBackend(connected=True)
    router = BackendRouter(script_backend=fake_script)
    for locked_payload in (
        {"password_locked": True, "score": 85},
        {"assessment_mode": True, "score": 90},
        {"locked": True, "readable": True, "score": 100},
    ):
        fake_script.activity_payload = locked_payload
        res = router.read_activity_status()
        assert res["state"] == "unavailable"
        assert res["readable"] is False
        assert res["locked"] is True
        assert res["score"] is None
        assert res["fallback"] == "cli_verification"

    # 3. Runtime exception from PT ActivityFile probe fails closed
    fake_script.activity_exc = RuntimeError("ActivityFile locked")
    err_res = router.read_activity_status()
    assert err_res["state"] == "unavailable"
    assert err_res["readable"] is False
    assert err_res["score"] is None
    assert err_res["fallback"] == "cli_verification"


@pytest.mark.unit
def test_add_device_empty_name_retries_with_backoff_then_recovers(tmp_path: Path) -> None:
    sleeps: list[float] = []

    class _WarmingScriptBackend(_FakeScriptBackend):
        def __init__(self) -> None:
            super().__init__(connected=True)
            self.calls = 0

        def add_device(
            self,
            model: str,
            *,
            device_type: int | str = 0,
            x: float = 100.0,
            y: float = 100.0,
        ) -> dict[str, Any]:
            self.calls += 1
            if self.calls < 3:
                return {"ok": True, "backend": "script_http", "device_name": "", "model": model}
            return {
                "ok": True,
                "backend": "script_http",
                "device_name": "Switch0",
                "model": model,
            }

    script = _WarmingScriptBackend()
    settings = AgenticNetSettings(data_dir=tmp_path / "data")
    server, runtime = create_mcp_server(settings, script_backend=script)
    runtime.router.add_device_retry_delays = (0.1, 0.2, 0.4)
    runtime.router._sleep = sleeps.append

    async def _exercise() -> None:
        await server.call_tool("project_create", {"name": "WarmupRetryTest"})
        res = _decode(
            await server.call_tool("device_add", {"name": "SW1", "model": "2960-24TT"})
        )
        assert res["success"] is True
        assert res["execution_backend"] == "script_backend"
        assert res["data"]["live_backend"]["device_name"] == "Switch0"
        assert res["data"]["live_backend"]["attempts"] == 3
        assert sleeps == [0.1, 0.2]
        assert runtime.router.device_aliases == {"SW1": "Switch0"}

    asyncio.run(_exercise())


@pytest.mark.unit
def test_add_device_persistent_empty_name_fails_and_never_stores_empty_alias(
    tmp_path: Path,
) -> None:
    sleeps: list[float] = []

    class _AlwaysEmptyScriptBackend(_FakeScriptBackend):
        def add_device(
            self,
            model: str,
            *,
            device_type: int | str = 0,
            x: float = 100.0,
            y: float = 100.0,
        ) -> dict[str, Any]:
            return {"ok": True, "backend": "script_http", "device_name": "", "model": model}

    script = _AlwaysEmptyScriptBackend(connected=True)
    settings = AgenticNetSettings(data_dir=tmp_path / "data")
    server, runtime = create_mcp_server(settings, script_backend=script)
    runtime.router.add_device_retry_delays = (0.1, 0.2)
    runtime.router._sleep = sleeps.append

    async def _exercise() -> None:
        await server.call_tool("project_create", {"name": "EmptyFailTest"})
        res = _decode(
            await server.call_tool("device_add", {"name": "SW1", "model": "2960-24TT"})
        )
        assert res["success"] is False
        assert res["execution_backend"] == "script_backend"
        assert res["errors"][0]["error_code"] == "PT_EMPTY_DEVICE_NAME"
        assert sleeps == [0.1, 0.2]
        assert runtime.router.device_aliases == {}
        assert "" not in runtime.router.device_aliases.values()
        _, topo, _, _ = runtime.manager.require_active()
        assert "SW1" not in topo.model.devices

    asyncio.run(_exercise())


@pytest.mark.unit
def test_router_stage1_provenance_redaction_and_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agenticnet.adapters.router as router_mod
    from agenticnet.adapters.base import GuiBackend
    from agenticnet.adapters.router import transport_to_execution_backend
    from agenticnet.gui.adapter import NullGuiBackend

    assert transport_to_execution_backend("script_bridge") == "script_backend"
    assert transport_to_execution_backend("windows_gui") == "gui_backend"
    assert transport_to_execution_backend("windows_pt_gui_clipboard") == "gui_backend"
    assert transport_to_execution_backend("test_ios_harness") == "offline_model"

    settings = AgenticNetSettings(data_dir=tmp_path / "data")
    null_gui = NullGuiBackend(settings)
    assert null_gui.is_available() is False
    assert BackendRouter(gui_backend=null_gui).has_live_gui() is False

    class _LiveGuiStub(GuiBackend):
        def __init__(self) -> None:
            self.power_calls: list[dict[str, Any]] = []

        def detect_application(self) -> dict[str, Any]:
            return {"running": True, "window": {"hwnd": 101}}

        def capture_screenshot(self, output_path: str | None = None) -> dict[str, Any]:
            return {"screenshot_path": output_path or "stub.png"}

        def attach_ip_phone_power(self, **kwargs: Any) -> dict[str, Any]:
            self.power_calls.append(dict(kwargs))
            return {"ok": True, "powered": True, **kwargs}

    live_gui = _LiveGuiStub()
    assert live_gui.is_available() is True

    # Disconnected ScriptBackend + live GuiBackend -> attach_ip_phone_power uses GUI fallback
    offline_script = _FakeScriptBackend(connected=False)
    hybrid_router = BackendRouter(script_backend=offline_script, gui_backend=live_gui)
    assert hybrid_router.has_live_gui() is True
    backend_tag, pwr_data, _, _ = hybrid_router.attach_ip_phone_power(
        "IP_PHONE1", canvas_x=320.0, canvas_y=180.0
    )
    assert backend_tag == "gui_backend"
    assert pwr_data["powered"] is True
    assert live_gui.power_calls[-1]["device_name"] == "IP_PHONE1"

    # Offline fallback for remove_device, move_device, delete_link
    assert hybrid_router.remove_device("R1")[0] == "offline_model"
    assert hybrid_router.move_device("R1", 50.0, 60.0)[0] == "offline_model"
    assert hybrid_router.delete_link("R1", "Gi0/0")[0] == "offline_model"

    # Live ScriptBackend redaction, model mapping, serial_dte swap, and wait_for_connection
    class _FullScriptBackend(_FakeScriptBackend):
        def __init__(self) -> None:
            super().__init__(connected=False)
            self.wait_called = False
            self.removed: list[str] = []
            self.moved: list[tuple[str, float, float]] = []
            self.deleted_links: list[tuple[str, str]] = []

        def wait_for_connection(self, *, timeout_seconds: float = 15.0) -> bool:
            _ = timeout_seconds
            self.wait_called = True
            self.connected = True
            return True

        def remove_device(
            self, device_name: str, *, timeout_seconds: float | None = None
        ) -> dict[str, Any]:
            _ = timeout_seconds
            self.removed.append(device_name)
            return {"ok": True, "removed": True, "device_name": device_name}

        def move_device(
            self,
            device_name: str,
            x: float,
            y: float,
            *,
            timeout_seconds: float | None = None,
        ) -> dict[str, Any]:
            _ = timeout_seconds
            self.moved.append((device_name, x, y))
            return {"ok": True, "moved": True, "device_name": device_name, "x": x, "y": y}

        def delete_link(
            self,
            device_name: str,
            port_name: str,
            *,
            timeout_seconds: float | None = None,
        ) -> dict[str, Any]:
            _ = timeout_seconds
            self.deleted_links.append((device_name, port_name))
            return {"ok": True, "deleted": True, "device_name": device_name, "port_name": port_name}

    monkeypatch.setattr(router_mod, "is_packet_tracer_running", lambda: True)
    full_script = _FullScriptBackend()
    live_router = BackendRouter(script_backend=full_script)
    assert live_router.ensure_live_script() is True
    assert full_script.wait_called is True

    live_router.add_device("SW3650", "3650-24PS")
    live_router.add_device("FW2", "5506-X")
    live_router.add_device("HGW1", "HomeGateway-PT")
    live_router.add_device("PH1", "SMARTPHONE-PT")
    live_router.add_device("TAB1", "TabletPC-PT")
    assert [d["device_type"] for d in full_script.added_devices] == [17, 27, 29, 21, 19]

    live_router.create_link("SW3650", "Serial0/0/0", "FW2", "Serial0/0/1", cable_type="serial_dte")
    assert full_script.created_links[-1]["device1"] == live_router.resolve_pt_device_name("FW2")

    live_router.console_transport.send_line("SW3650", "enable secret TopSecretPass123")
    live_router.console_transport.send_batch(
        "SW3650", ["username admin secret AnotherSecret456"]
    )
    logged = " ".join(
        line for lines in live_router.executed_cli_log.values() for line in lines
    )
    assert "TopSecretPass123" not in logged
    assert "AnotherSecret456" not in logged

    sw_pt = live_router.resolve_pt_device_name("SW3650")
    assert live_router.move_device("SW3650", 410.0, 220.0)[0] == "script_backend"
    assert full_script.moved == [(sw_pt, 410.0, 220.0)]
    assert live_router.delete_link("SW3650", "Gi1/0/1")[0] == "script_backend"
    assert full_script.deleted_links == [(sw_pt, "Gi1/0/1")]
    assert live_router.remove_device("SW3650")[0] == "script_backend"
    assert full_script.removed == [sw_pt]
    assert "SW3650" not in live_router.device_aliases

