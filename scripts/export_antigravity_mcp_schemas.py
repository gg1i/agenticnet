"""Export NetForge MCP tool schemas into Antigravity's lazy tool loader."""
import json
from pathlib import Path

manifest_path = Path("docs/manifest.json")
if not manifest_path.exists():
    print("Manifest not found.")
    raise SystemExit(1)

with open(manifest_path, encoding="utf-8") as f:
    manifest = json.load(f)

mcp_dir = Path.home() / ".gemini" / "antigravity" / "mcp" / "netforge"
mcp_dir.mkdir(parents=True, exist_ok=True)

for tool in manifest.get("tools", []):
    tool_name = tool["name"]
    tool_file = mcp_dir / f"{tool_name}.json"
    tool_payload = {
        "name": tool_name,
        "description": tool["description"],
        "parameters": tool.get("input_schema", {"type": "object", "properties": {}})
    }
    tool_file.write_text(json.dumps(tool_payload, indent=2), encoding="utf-8")

instructions_content = """# NetForge MCP Instructions

NetForge MCP is an autonomous network automation platform for Cisco Packet Tracer.

## Workflow:
1. **PLAN & MODEL**:
   - `project_create`: Start a new project context.
   - `topology_create` / `device_add`: Define network devices (2811, 2960, 7960, ATA).
   - `connection_create`: Wire links between interfaces.
   - `topology_validate`: Run graph validation.
2. **IPAM & ADDRESSING**:
   - `subnet_calculate` / `vlsm_plan`: Plan subnets.
   - `address_allocate`: Assign IPs and default gateways to interfaces.
3. **CISCO IOS CONFIGURATION**:
   - `configure_interface`: Set IP addresses, duplex, speed.
   - `configure_vlan` / `configure_trunk`: Set access/voice/trunk VLANs.
   - `configure_routing` / `configure_ospf`: Static or dynamic routing.
   - `configure_dhcp`: Configure DHCP pools with Option 150 for IP phones.
4. **PACKET TRACER GUI AUTOMATION**:
   - `packet_tracer_launch`: Start Packet Tracer.
   - `packet_tracer_detect`: Check application state.
   - `gui_calibrate`: Calibrate screen anchors.
   - `gui_click` / `gui_keypress`: Interact with UI palette and canvas.
   - `gui_screenshot`: Verify physical placement visually.
5. **CONSOLE & CLI INTERACTION**:
   - `console_open`: Open device CLI window.
   - `console_execute`: Stream commands into CLI terminal.
   - `console_capture`: Read and verify CLI output.
6. **DIAGNOSTICS & SELF-REPAIR**:
   - `network_diagnose`: Analyze connectivity issues and VLAN mismatches.
   - `network_repair_propose`: Propose fixes.
"""

(mcp_dir / "instructions.md").write_text(instructions_content, encoding="utf-8")
print(f"Exported {len(manifest.get('tools', []))} tool schemas to {mcp_dir}")
