"""Official Python MCP SDK server factory supporting stdio and HTTP transports."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from agenticnet import __version__
from agenticnet.adapters.base import GuiBackend, ScriptBackend
from agenticnet.console.transport import ConsoleTransport
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.mcp.prompts import register_prompts
from agenticnet.mcp.registry import AgenticNetRuntime
from agenticnet.mcp.resources import register_resources
from agenticnet.mcp.tools_cli import register_cli_tools
from agenticnet.mcp.tools_connections import register_connection_tools
from agenticnet.mcp.tools_devices import register_device_tools
from agenticnet.mcp.tools_diagnostics import register_diagnostics_tools
from agenticnet.mcp.tools_gui import register_gui_tools
from agenticnet.mcp.tools_ios import register_ios_tools
from agenticnet.mcp.tools_ipam import register_ipam_tools
from agenticnet.mcp.tools_project import register_project_tools
from agenticnet.mcp.tools_simulation import register_simulation_tools
from agenticnet.mcp.tools_topology import register_topology_tools
from agenticnet.mcp.tools_verify import register_verify_tools


def create_mcp_server(
    settings: AgenticNetSettings | None = None,
    *,
    gui_backend: GuiBackend | None = None,
    console_transport: ConsoleTransport | None = None,
    script_backend: ScriptBackend | None = None,
) -> tuple[MCPServer, AgenticNetRuntime]:
    """Instantiate and wire the complete AgenticNet server, tools, resources, and prompts."""
    resolved_settings = settings or AgenticNetSettings.from_env()
    runtime = AgenticNetRuntime(
        settings=resolved_settings,
        gui_backend=gui_backend,
        console_transport=console_transport,
        script_backend=script_backend,
    )

    if resolved_settings.tool_profile == "solve_lab":
        instructions = (
            "Start with `lab_start`, `lab_open`, or `project_create`, check `device_capabilities` "
            "before picking models, compute subnets via `subnet_calculate`, build via "
            "`device_add`, `connection_create`, and `host_configure`, push CLI via "
            "`console_execute`, verify via `verify_requirements_schema` + `verify_lab` / "
            "`lab_status` / `grade_lab`, and save via `lab_save` / `project_save`. Always "
            "distinguish PLANNED AgenticNet state from VERIFIED Packet Tracer runtime state."
        )
    else:
        instructions = (
            "Create or open a project first (`project_create` / `project_open` or `lab_open`), "
            "check `device_capabilities` before picking models, plan subnets via `vlsm_plan` or "
            "`subnet_calculate`, build via `topology_create` or `device_add`, configure via "
            "`configure_*` / `console_execute`, verify via `verify_lab` / `lab_status`, and save "
            "via `project_save` / `lab_save`. Always distinguish PLANNED AgenticNet state from "
            "VERIFIED Packet Tracer runtime state."
        )

    server = MCPServer(
        name="agenticnet",
        title="AgenticNet — Agentic Networking Platform",
        description=(
            "An open-source agentic networking platform focusing on Cisco Packet Tracer "
            "automation, configuration, validation, and diagnostics."
        ),
        instructions=instructions,
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
