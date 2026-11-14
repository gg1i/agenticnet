"""Official Python MCP SDK server factory supporting stdio and HTTP transports."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from netforge import __version__
from netforge.adapters.base import GuiBackend, ScriptBackend
from netforge.console.transport import ConsoleTransport
from netforge.core.settings import NetForgeSettings
from netforge.mcp.prompts import register_prompts
from netforge.mcp.registry import NetForgeRuntime
from netforge.mcp.resources import register_resources
from netforge.mcp.tools_cli import register_cli_tools
from netforge.mcp.tools_connections import register_connection_tools
from netforge.mcp.tools_devices import register_device_tools
from netforge.mcp.tools_diagnostics import register_diagnostics_tools
from netforge.mcp.tools_gui import register_gui_tools
from netforge.mcp.tools_ios import register_ios_tools
from netforge.mcp.tools_ipam import register_ipam_tools
from netforge.mcp.tools_project import register_project_tools
from netforge.mcp.tools_simulation import register_simulation_tools
from netforge.mcp.tools_topology import register_topology_tools
from netforge.mcp.tools_verify import register_verify_tools


def create_mcp_server(
    settings: NetForgeSettings | None = None,
    *,
    gui_backend: GuiBackend | None = None,
    console_transport: ConsoleTransport | None = None,
    script_backend: ScriptBackend | None = None,
) -> tuple[MCPServer, NetForgeRuntime]:
    """Instantiate and wire the complete NetForge MCP server, tools, resources, and prompts."""
    resolved_settings = settings or NetForgeSettings.from_env()
    runtime = NetForgeRuntime(
        settings=resolved_settings,
        gui_backend=gui_backend,
        console_transport=console_transport,
        script_backend=script_backend,
    )

    server = MCPServer(
        name="netforge-mcp",
        title="NetForge MCP — Packet Tracer Network Automation",
        description=(
            "Open-source AI-native MCP platform for designing, configuring, validating, "
            "and automating Cisco Packet Tracer network environments."
        ),
        instructions=(
            "Create or open a project first, check device_capabilities before picking models, "
            "plan subnets via vlsm_plan, build via topology_create or device_add, and always "
            "distinguish PLANNED NetForge state from VERIFIED Packet Tracer runtime state."
        ),
        version=__version__,
        log_level=resolved_settings.log_level,  # type: ignore[arg-type]
    )

    register_project_tools(server, runtime)
    register_topology_tools(server, runtime)
    register_device_tools(server, runtime)
    register_connection_tools(server, runtime)
    register_ipam_tools(server, runtime)
    register_ios_tools(server, runtime)
    register_cli_tools(server, runtime)
    register_gui_tools(server, runtime)
    register_simulation_tools(server, runtime)
    register_diagnostics_tools(server, runtime)
    register_verify_tools(server, runtime)
    register_resources(server, runtime)
    register_prompts(server, runtime)

    return server, runtime
