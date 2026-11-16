"""Integration tests verifying real MCP protocol sessions (in-memory & stdio)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import anyio
import pytest
from mcp import Client, StdioServerParameters


@pytest.mark.integration
def test_mcp_in_memory_protocol_session(mcp_bundle) -> None:
    server, _ = mcp_bundle

    async def _exercise() -> None:
        async with Client(server) as client:
            assert client.server_info is not None
            assert client.server_info.name == "netforge-mcp"

            tools_res = await client.list_tools()
            cap_res = await client.call_tool("device_capabilities", {"model": "2960-24TT"})
            assert not cap_res.is_error
            payload = json.loads(cap_res.content[0].text)
            assert payload["data"]["model"] == "2960-24TT"

            manifest_res = await client.read_resource("netforge://manifest")
            manifest_json = json.loads(manifest_res.contents[0].text)
            assert len(tools_res.tools) == manifest_json["tool_count"]
            assert len(tools_res.tools) == 82

            prompt_res = await client.get_prompt(
                "solve_lab",
                arguments={"lab_goal": "Verify solve_lab prompt"},
            )
            assert len(prompt_res.messages) >= 1

    anyio.run(_exercise)


@pytest.mark.integration
def test_mcp_stdio_subprocess_handshake(tmp_path: Path) -> None:
    """Launch `python -m netforge serve --transport stdio` and verify default curated profile."""
    repo_root = Path(__file__).resolve().parents[2]
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "netforge",
            "serve",
            "--transport",
            "stdio",
            "--data-dir",
            str(tmp_path / ".nf"),
        ],
        cwd=str(repo_root),
    )

    async def _exercise_stdio() -> None:
        async with Client(server_params) as client:
            assert client.server_info is not None
            assert client.server_info.name == "netforge-mcp"
            tools_res = await client.list_tools()
            tool_names = {t.name for t in tools_res.tools}
            assert len(tool_names) == 25
            assert {
                "lab_start",
                "lab_open",
                "lab_save",
                "lab_status",
                "list_devices",
                "lab_snapshot",
                "lab_diff",
                "verify_lab",
                "grade_lab",
                "gui_attach_ip_phone_power",
            } <= tool_names
            assert "gui_click" not in tool_names
            assert "configure_ospf" not in tool_names
            sub_res = await client.call_tool("subnet_calculate", {"cidr": "192.168.50.0/26"})
            assert not sub_res.is_error
            data = json.loads(sub_res.content[0].text)
            assert data["data"]["usable_hosts"] == 62

    anyio.run(_exercise_stdio)
