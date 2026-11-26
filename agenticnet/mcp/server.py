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
            "FAST WORKFLOW (target 3-5 tool calls total; avoid repetitive discovery): "
            "(1) For existing `.pkt`/`.pka` files, call `lab_open` (or `lab_start`). For new "
            "labs, build all devices, links, and optional host IP/DHCP settings in ONE batch "
            "via `topology_create` (with apply_live=True) or `lab_start` (with auto_approve=True, "
            "devices, links, configs) instead of one-by-one `device_add` / `connection_create`. "
            "Standard PT models (`2911` Gi0/0..2, `2811` Fa0/0..1, `2960-24TT` Fa0/1..24+"
            "Gi0/1..2 L2-only, `3560-24PS` Fa0/1..24+Gi0/1..2 L3 dot1q-before-trunk, `PC-PT` Fa0, "
            "`Server-PT` Fa0, `7960` Switch/PC auto-powered) do not need repeated "
            "`device_capabilities` or `list_devices` lookups—call `device_capabilities` only for "
            "unfamiliar models. (2) Push IOS CLI across all routers/switches concurrently in ONE "
            "call via `console_execute` (batch_configs={device: cmds}, "
            "target_mode='global_config'); configure hosts inline in `topology_create` or via "
            "`host_configure`. (3) Verify in ONE pass via `verify_lab` / `lab_status` / "
            "`grade_lab` (plus `connectivity_test` checks=[...] for ping matrices; call "
            "`verify_requirements_schema` at most once if needed). (4) Persist via `lab_save` / "
            "`project_save`. Always distinguish PLANNED AgenticNet state from VERIFIED Packet "
            "Tracer runtime state."
        )
    else:
        instructions = (
            "FAST WORKFLOW: Create or open a project (`project_create` / `project_open` or "
            "`lab_open` / `lab_start`), compute subnets (`vlsm_plan` or `subnet_calculate`) if "
            "needed, deploy devices, links, and inline host settings in ONE batch via "
            "`topology_create` (apply_live=True) or `lab_start` (auto_approve=True, devices, "
            "links, configs), push multi-device IOS CLI concurrently via `console_execute` "
            "(batch_configs={device: cmds}, target_mode='global_config') or `configure_*`, "
            "verify in one pass via `verify_lab` / `lab_status` (and `connectivity_test` "
            "checks=[...]), and save via `lab_save` / `project_save`. Skip redundant "
            "`device_capabilities` / `list_devices` polling for standard models. Always "
            "distinguish PLANNED AgenticNet state from VERIFIED Packet Tracer runtime state."
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
