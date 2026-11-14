"""Reusable MCP workflow prompts enabling multi-agent planning and troubleshooting."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from netforge.mcp.registry import NetForgeRuntime


def register_prompts(server: MCPServer, runtime: NetForgeRuntime) -> None:
    """Register guided NetForge prompts for AI agents."""

    prompt_names = [
        "plan_network_architecture",
        "design_campus_vlan_network",
        "review_network_configurations",
        "troubleshoot_network_workflow",
    ]
    runtime.registry.prompt_names.extend(prompt_names)

    @server.prompt(
        name="plan_network_architecture",
        description=(
            "Guide an AI agent through NetForge's "
            "PLAN -> DESIGN -> VALIDATE -> BUILD -> CONFIGURE -> VERIFY workflow."
        ),
    )
    def plan_network_architecture(requirement: str) -> str:
        return (
            "You are operating NetForge MCP to engineer a Cisco Packet Tracer network.\n"
            f"User requirement: {requirement}\n\n"
            "Follow this strict engineering workflow:\n"
            "1. INSPECT CAPABILITIES: Call `device_capabilities` before choosing models.\n"
            "2. PROJECT SETUP: Create or open a project with `project_create` / `project_open`.\n"
            "3. IPAM & VLSM: Plan non-overlapping subnets via `vlsm_plan` "
            "(with `register_pools=True`).\n"
            "4. TOPOLOGY: Build devices and links with `topology_create` (auto MDI/MDI-X)\n"
            "   and check integrity using `topology_validate` and `topology_analyze`.\n"
            "5. CONFIGURATION: Generate validated IOS sequences with `configure_*` tools.\n"
            "6. STATE HYGIENE: Distinguish PLANNED designs from EXECUTED/VERIFIED PT state.\n"
            "   Never claim live PT verification without actual evidence.\n"
            "7. PERSIST & REPORT: Save via `project_save`, generate addressing table via "
            "`ipam_report`, and render a Mermaid diagram via `topology_visualize`."
        )

    @server.prompt(
        name="design_campus_vlan_network",
        description=(
            "Structured workflow for multi-building campus networks "
            "with VLANs, trunks, OSPF, DHCP, and NAT."
        ),
    )
    def design_campus_vlan_network(buildings: int = 3, hosts_per_vlan: int = 30) -> str:
        return (
            f"Design a campus network for {buildings} building(s) "
            f"(~{hosts_per_vlan} hosts/VLAN):\n"
            "1. Call `device_capabilities` to pick verified models (`2911` edge routers,\n"
            "   `3560-24PS` L3 switches, `2960-24TT` access switches, `PC-PT`/`Server-PT`).\n"
            "2. Run `vlsm_plan` on an RFC1918 supernet (e.g. `10.10.0.0/16`) for VLANs "
            "and `/30` transit links.\n"
            "3. Build the topology via `topology_create` and check loops via `topology_analyze`.\n"
            "4. Configure VLANs (`configure_vlan`), trunks (`configure_trunk`), STP "
            "(`configure_stp`),\n"
            "   SVIs (`configure_interface`), OSPF (`configure_ospf`), DHCP (`configure_dhcp`),\n"
            "   and NAT/PAT (`configure_nat`).\n"
            "5. Validate IPs via `address_validate` and save with `project_save`."
        )

    @server.prompt(
        name="review_network_configurations",
        description="Audit IPAM plans, topology validation warnings, and config snapshots.",
    )
    def review_network_configurations() -> str:
        return (
            "Perform a design and configuration audit on the active NetForge project:\n"
            "1. Call `project_status` for Planned vs. Executed vs. Verified counts.\n"
            "2. Call `topology_validate` & `topology_analyze` for SPOFs or STP loops.\n"
            "3. Call `address_validate` & `ipam_report` for IP conflicts or GW mismatches.\n"
            "4. Inspect devices (`device_inspect`) and diff snapshots (`configuration_compare`)."
        )

    @server.prompt(
        name="troubleshoot_network_workflow",
        description=(
            "Evidence-first troubleshooting workflow separating "
            "root cause analysis from repair approval."
        ),
    )
    def troubleshoot_network_workflow(symptom: str) -> str:
        return (
            f"Investigate the reported network issue: {symptom}\n"
            "Follow strict evidence-based troubleshooting:\n"
            "1. Gather topology (`topology_inspect`), IPAM (`address_validate`), "
            "and device state (`device_inspect`).\n"
            "2. Validate suspect IOS configuration lines using `command_validate`.\n"
            "3. Rank probable root causes with supporting evidence (never guess blindly).\n"
            "4. Propose corrective changes and wait for approval before destructive edits.\n"
            "5. Snapshot configs (`configuration_backup`), apply approved fixes, verify, "
            "and save (`project_save`)."
        )
