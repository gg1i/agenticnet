"""Generate NetForge MCP `docs/manifest.json` and sync tool/resource/prompt counts in docs."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from netforge.core.settings import NetForgeSettings  # noqa: E402
from netforge.mcp.profiles import SOLVE_LAB_TOOLS  # noqa: E402
from netforge.mcp.server import create_mcp_server  # noqa: E402

RESOURCE_DESCRIPTIONS: dict[str, str] = {
    "netforge://manifest": (
        "Machine-readable manifest of all {tool_count} tools, tiers, transports, "
        "and {model_count} supported device models."
    ),
    "netforge://workflows/solve_lab": (
        "Canonical closed-loop `solve_lab` workflow contract "
        "({solve_lab_count} default profile tools)."
    ),
    "netforge://project/current": (
        "Active project summary and Planned vs. Executed vs. Verified state counts."
    ),
    "netforge://project/topology": "Current normalized topology JSON export.",
    "netforge://project/ipam": "IPAM pools, allocations, and utilization JSON report.",
    "netforge://devices/catalog": (
        "Verified Packet Tracer device profiles, physical interfaces, and capabilities."
    ),
    "netforge://logs/recent": "Recent redacted SQLite execution audit logs.",
}

PROMPT_DESCRIPTIONS: dict[str, str] = {
    "solve_lab": (
        "Guided closed-loop lab solver (`lab_open` -> `verify_lab` / `grade_lab` / "
        "`lab_status` -> fix -> `lab_save`)."
    ),
    "plan_network_architecture": (
        "Step-by-step PLAN -> DESIGN -> VALIDATE -> BUILD -> CONFIGURE -> VERIFY guide."
    ),
    "design_campus_vlan_network": (
        "Guided multi-building campus network design with VLANs, OSPF, DHCP, and NAT."
    ),
    "review_network_configurations": (
        "Comprehensive audit workflow checking IPAM, topology loops, and configuration diffs."
    ),
    "troubleshoot_network_workflow": (
        "Evidence-based troubleshooting dividing root-cause isolation from approved self-repair."
    ),
}


def _render_mcp_tools_doc(manifest: dict[str, Any], solve_lab_count: int) -> str:
    tools: list[dict[str, Any]] = manifest["tools"]
    resources: list[str] = manifest["resources"]
    prompts: list[str] = manifest["prompts"]
    models: list[dict[str, Any]] = manifest["supported_device_models"]

    tool_count = int(manifest["tool_count"])
    resource_count = len(resources)
    prompt_count = len(prompts)
    model_count = len(models)
    categories: dict[str, int] = manifest["categories"]
    cat_count = len(categories)

    by_cat: dict[str, list[dict[str, Any]]] = {}
    for entry in tools:
        by_cat.setdefault(str(entry["category"]), []).append(entry)

    lines: list[str] = [
        "# NetForge MCP Tool & Capability Ecosystem",
        "",
        f"NetForge MCP (`v{manifest['version']}`, schema `{manifest['schema_version']}`) exposes "
        f"**{tool_count} specialized MCP tools** (`{solve_lab_count}` enabled in default "
        f"`solve_lab` profile; all `{tool_count}` in `advanced` profile) organized across "
        f"{cat_count} functional categories, **{resource_count} read-only resources**, and "
        f"**{prompt_count} guided AI agent prompts** over `stdio` and HTTP transports.",
        "",
        "<!-- Generated counts and tables below are synced by scripts/generate_manifest.py -->",
        "",
        (
            "Run `python -m netforge manifest` or read `netforge://manifest` "
            "for the live machine-readable JSON schema."
        ),
        "",
        "---",
        "",
        f"## 1. Tool Categories ({tool_count} Tools Total / {solve_lab_count} Default `solve_lab`)",
        "",
        "| Category | Count | Tools | Primary Permission Tier(s) |",
        "|---|---|---|---|",
    ]
    for cat, count in categories.items():
        cat_tools = by_cat.get(cat, [])
        tool_list = ", ".join(f"`{t['name']}`" for t in cat_tools)
        tiers_seen: list[str] = []
        for t in cat_tools:
            tier = str(t["permission_tier"])
            if tier not in tiers_seen:
                tiers_seen.append(tier)
        tiers_str = ", ".join(f"`{tr}`" for tr in tiers_seen)
        lines.append(f"| **{cat}** | {count} | {tool_list} | {tiers_str} |")

    lines.extend(["", "---", "", f"## 2. Resources ({resource_count})", ""])
    for uri in resources:
        desc_tpl = RESOURCE_DESCRIPTIONS.get(uri, "Read-only NetForge resource.")
        desc = desc_tpl.format(
            tool_count=tool_count,
            model_count=model_count,
            solve_lab_count=solve_lab_count,
        )
        lines.append(f"- `{uri}` — {desc}")

    lines.extend(["", "---", "", f"## 3. Workflow Prompts ({prompt_count})", ""])
    for pname in prompts:
        pdesc = PROMPT_DESCRIPTIONS.get(pname, "Guided NetForge workflow prompt.")
        lines.append(f"- `{pname}` — {pdesc}")

    lines.extend(
        [
            "",
            "---",
            "",
            "## 4. State Level Contract (`StateLevel`)",
            "",
            "Every MCP tool returns an `OperationResult` envelope with explicit state separation:",
            "- `planned`: Design intent validated inside NetForge.",
            "- `executed`: Dispatched to Packet Tracer GUI or device console.",
            "- `verified`: Independently confirmed via observed CLI output or simulation trace.",
            "",
        ]
    )
    return "\n".join(lines)


def _sync_readme(readme_path: Path, manifest: dict[str, Any], solve_lab_count: int) -> bool:
    if not readme_path.exists():
        return False
    text = readme_path.read_text(encoding="utf-8")
    tool_count = int(manifest["tool_count"])
    resource_count = len(manifest["resources"])
    prompt_count = len(manifest["prompts"])
    model_count = len(manifest["supported_device_models"])

    updated = re.sub(
        r"\d+ MCP tools(?: \([^)]*\))?, \d+ resources, \d+ prompts",
        (
            f"{tool_count} MCP tools ({solve_lab_count} in default `solve_lab` profile), "
            f"{resource_count} resources, {prompt_count} prompts"
        ),
        text,
    )
    updated = re.sub(
        r"Official Python MCP SDK server, \d+ tools(?: \([^)]*\))?, "
        r"\d+ resources, \d+ prompts, manifest",
        (
            f"Official Python MCP SDK server, {tool_count} tools ({solve_lab_count} default), "
            f"{resource_count} resources, {prompt_count} prompts, manifest"
        ),
        updated,
    )
    updated = re.sub(
        r"(# Verified Packet Tracer device catalog & interface normalization \()\d+( models\))",
        rf"\g<1>{model_count}\g<2>",
        updated,
    )
    if updated != text:
        readme_path.write_text(updated, encoding="utf-8")
        return True
    return False


def _sync_architecture(arch_path: Path, manifest: dict[str, Any], solve_lab_count: int) -> bool:
    if not arch_path.exists():
        return False
    text = arch_path.read_text(encoding="utf-8")
    tool_count = int(manifest["tool_count"])
    resource_count = len(manifest["resources"])
    prompt_count = len(manifest["prompts"])
    model_count = len(manifest["supported_device_models"])

    banner = (
        "<!-- BEGIN MANIFEST COUNTS -->\n"
        f"> **Current Live Registry Counts (`docs/manifest.json`):** "
        f"`{tool_count}` registered tools "
        f"(`advanced` profile) / `{solve_lab_count}` default (`solve_lab` profile), "
        f"`{resource_count}` resources, `{prompt_count}` prompts, "
        f"`{model_count}` device models.\n"
        "<!-- END MANIFEST COUNTS -->"
    )
    if "<!-- BEGIN MANIFEST COUNTS -->" in text:
        updated = re.sub(
            r"<!-- BEGIN MANIFEST COUNTS -->.*?<!-- END MANIFEST COUNTS -->",
            banner,
            text,
            flags=re.DOTALL,
        )
    else:
        updated = text.replace(
            "\n---\n",
            f"\n{banner}\n\n---\n",
            1,
        )
    if updated != text:
        arch_path.write_text(updated, encoding="utf-8")
        return True
    return False


def main() -> int:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else (REPO_ROOT / "docs" / "manifest.json")
    sync_docs = len(sys.argv) == 1
    settings = NetForgeSettings.from_env()
    settings.tool_profile = "advanced"
    _, runtime = create_mcp_server(settings)
    manifest = runtime.build_manifest()
    solve_lab_count = len(SOLVE_LAB_TOOLS)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote NetForge MCP manifest to {output}")

    if sync_docs:
        mcp_tools_path = REPO_ROOT / "docs" / "mcp-tools.md"
        mcp_tools_path.write_text(
            _render_mcp_tools_doc(manifest, solve_lab_count),
            encoding="utf-8",
        )
        print(f"Synced {mcp_tools_path}")
        if _sync_readme(REPO_ROOT / "README.md", manifest, solve_lab_count):
            print("Synced README.md counts")
        if _sync_architecture(REPO_ROOT / "docs" / "ARCHITECTURE.md", manifest, solve_lab_count):
            print("Synced docs/ARCHITECTURE.md counts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
