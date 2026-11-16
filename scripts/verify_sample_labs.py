"""Live break-then-fix acceptance runner for NetForge Phase 3 sample labs."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

from netforge.adapters.discovery import (
    gracefully_close_packet_tracer,
    require_interactive_desktop_for_launch,
)
from netforge.adapters.script_bridge import HttpScriptBridgeBackend, HttpScriptBridgeServer
from netforge.core.settings import NetForgeSettings
from netforge.gui.windows_backend import WindowsGuiBackend
from netforge.mcp.server import create_mcp_server

REPO_ROOT = Path(__file__).resolve().parents[1]
LAB_FILES = [
    REPO_ROOT / "labs" / "01_static_routing.json",
    REPO_ROOT / "labs" / "02_vlan_dhcp.json",
    REPO_ROOT / "labs" / "03_small_voice.json",
]


def _kill_packet_tracer() -> None:
    gracefully_close_packet_tracer(timeout_seconds=5.0)
    time.sleep(0.5)


def _decode(call_result: Any) -> dict[str, Any]:
    assert call_result.structured_content is not None
    return dict(call_result.structured_content)


def _wait_for_bridge(bridge: HttpScriptBridgeBackend, timeout_s: float = 45.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if bridge.is_connected():
            ping = bridge.ping()
            if ping.get("ok"):
                return
        time.sleep(0.5)
    raise RuntimeError("Packet Tracer Script Module bridge did not connect within timeout.")


def _run_cli_step(
    bridge: HttpScriptBridgeBackend,
    router_aliases: dict[str, str],
    device: str,
    commands: list[str],
) -> None:
    pt_name = router_aliases.get(device, device)
    res = bridge.execute_cli(pt_name, commands, timeout_seconds=30.0)
    if res.get("timed_out"):
        raise RuntimeError(f"CLI step timed out on {device} ({pt_name}): {commands}")


async def _run_single_lab(lab_path: Path, gui: WindowsGuiBackend) -> dict[str, Any]:
    lab = json.loads(lab_path.read_text(encoding="utf-8"))
    lab_name = lab["lab_name"]
    print(f"\n=== Running {lab_name} ({lab_path.name}) ===", flush=True)

    _kill_packet_tracer()
    settings = NetForgeSettings(permission_profile="full")
    bridge = HttpScriptBridgeBackend(
        HttpScriptBridgeServer(session_file=settings.data_dir / "bridge_session.json"),
        default_timeout_seconds=30.0,
    )
    bridge.start()
    try:
        gui.launch_application(wait_seconds=12.0)
        _wait_for_bridge(bridge, timeout_s=45.0)
        print("  [bridge] connected", flush=True)

        server, runtime = create_mcp_server(settings=settings, script_backend=bridge)

        # Create offline project (starts with an active empty topology)
        proj = _decode(
            await server.call_tool(
                "project_create",
                {"name": lab_name, "project_id": f"{lab_path.stem}_{int(time.time())}"},
            )
        )
        assert proj["success"], proj

        # Add devices via real MCP tool
        for dev in lab["devices"]:
            res = _decode(
                await server.call_tool(
                    "device_add",
                    {
                        "name": dev["name"],
                        "model": dev["model"],
                        "x": float(dev["x"]),
                        "y": float(dev["y"]),
                    },
                )
            )
            assert res["success"] and res["execution_backend"] == "script_backend", res
            pt_mapped = runtime.router.resolve_pt_device_name(dev["name"])
            print(f"  [device_add] {dev['name']} -> {pt_mapped}", flush=True)

        # Wire links via real MCP tool
        for link in lab["links"]:
            res = _decode(
                await server.call_tool(
                    "connection_create",
                    {
                        "source_device": link["device1"],
                        "source_interface": link["port1"],
                        "target_device": link["device2"],
                        "target_interface": link["port2"],
                        "cable_type": link.get("conn_type", "auto"),
                    },
                )
            )
            assert res["success"] and res["execution_backend"] == "script_backend", res
            print(
                f"  [link] {link['device1']}:{link['port1']} <-> "
                f"{link['device2']}:{link['port2']}",
                flush=True,
            )

        # Apply IOS configs directly over ScriptBackend (fast batch execution, skipping end-devices)
        aliases = runtime.router.device_aliases
        for dev_name, cmds in lab["configs"].items():
            print(f"  [config] applying {len(cmds)} lines on {dev_name}...", flush=True)
            _run_cli_step(bridge, aliases, dev_name, cmds)

        pre_settle = float(lab.get("pre_settle_seconds", 0))
        if pre_settle > 0:
            print(f"  [pre-settle] waiting {pre_settle}s...", flush=True)
            await asyncio.sleep(pre_settle)

        for dev_name, cmds in lab.get("post_configs", {}).items():
            print(f"  [post-config] applying {len(cmds)} lines on {dev_name}...", flush=True)
            _run_cli_step(bridge, aliases, dev_name, cmds)

        settle = float(lab.get("settle_seconds", 3))
        if settle > 0:
            print(f"  [settle] waiting {settle}s for protocols/timers...", flush=True)
            await asyncio.sleep(settle)

        # 1. Verify built lab -> PASS
        pass_res = _decode(
            await server.call_tool("verify_lab", {"requirements": lab["requirements"]})
        )
        print(f"  [verify initial] {pass_res['summary']}", flush=True)
        if not pass_res["data"]["passed"]:
            print(json.dumps(pass_res["data"], indent=2), flush=True)
            raise AssertionError(f"Expected initial build of {lab_name} to PASS.")

        # 2. Break -> FAIL
        brk = lab["break_step"]
        _run_cli_step(bridge, aliases, brk["device"], brk["commands"])
        if "secondary" in brk:
            sec = brk["secondary"]
            _run_cli_step(bridge, aliases, sec["device"], sec["commands"])
        await asyncio.sleep(2.0)

        fail_res = _decode(
            await server.call_tool("verify_lab", {"requirements": lab["requirements"]})
        )
        print(f"  [verify broken] {fail_res['summary']}", flush=True)
        if fail_res["data"]["passed"] or fail_res["data"]["summary"]["failed"] == 0:
            print(json.dumps(fail_res["data"], indent=2), flush=True)
            raise AssertionError(f"Expected broken state of {lab_name} to FAIL.")

        failing_ids = [
            r.get("id") for r in fail_res["data"]["results"] if r["status"] == "fail"
        ]
        for exp_id in brk.get("expected_failing_ids", []):
            if exp_id not in failing_ids:
                raise AssertionError(
                    f"{lab_name}: expected requirement '{exp_id}' to fail when broken, "
                    f"actual failing ids: {failing_ids}"
                )

        # 3. Fix -> PASS
        fix = lab["fix_step"]
        _run_cli_step(bridge, aliases, fix["device"], fix["commands"])
        if "secondary" in fix:
            sec = fix["secondary"]
            _run_cli_step(bridge, aliases, sec["device"], sec["commands"])
        fix_settle = float(fix.get("settle_seconds", 3))
        if fix_settle > 0:
            await asyncio.sleep(fix_settle)

        recovered_res = _decode(
            await server.call_tool("verify_lab", {"requirements": lab["requirements"]})
        )
        print(f"  [verify fixed] {recovered_res['summary']}", flush=True)
        if not recovered_res["data"]["passed"]:
            print(json.dumps(recovered_res["data"], indent=2), flush=True)
            raise AssertionError(f"Expected recovered build of {lab_name} to PASS.")

        return {
            "lab": lab_name,
            "initial": pass_res["data"]["summary"],
            "broken": {
                "summary": fail_res["data"]["summary"],
                "failing_ids": failing_ids,
            },
            "recovered": recovered_res["data"]["summary"],
        }
    finally:
        bridge.stop()
        _kill_packet_tracer()


def main() -> int:
    require_interactive_desktop_for_launch("verify_sample_labs")
    selected = sys.argv[1:]
    paths = [p for p in LAB_FILES if not selected or p.name in selected or p.stem in selected]
    if not paths:
        print("No matching lab files specified.")
        return 2

    gui = WindowsGuiBackend(NetForgeSettings())
    reports: list[dict[str, Any]] = []
    for path in paths:
        report = asyncio.run(_run_single_lab(path, gui))
        reports.append(report)

    print("\n=== ALL SAMPLE LAB ACCEPTANCE RESULTS ===")
    print(json.dumps(reports, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
