"""Unit tests validating the portable AgenticNet engineering skill pack under `skills/`."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from agenticnet.core.settings import AgenticNetSettings
from agenticnet.mcp.server import create_mcp_server

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILLS_DIR = REPO_ROOT / "skills"

EXPECTED_SKILLS: tuple[str, ...] = (
    "senior-network-engineer",
    "packet-tracer-lab-engineer",
    "network-architecture",
    "ip-addressing",
    "switching-and-vlans",
    "routing",
    "ios-configuration-review",
    "troubleshooting-and-verification",
    "network-security-basics",
)

# Backticked identifiers matching AgenticNet tool naming conventions
_TOOL_PREFIX_RE = re.compile(
    r"`((?:lab|project|device|host|connection|interface|topology|subnet|vlsm|address|ipam|"
    r"configure|configuration|command|console|gui|simulation|packet|connectivity|verify|"
    r"grade|network|routing|vlan)_[a-z_]+|list_devices)`"
)

# Valid non-tool snake_case identifiers that share tool-like prefixes
_NON_TOOL_IDENTIFIERS: frozenset[str] = frozenset(
    {
        "interface_up",
        "ip_assigned",
        "route_exists",
        "vlan_exists",
        "dhcp_binding",
        "config_contains",
        "telephony_service",
        "ephone_registered",
        "network_address",
        "broadcast_address",
        "usable_hosts",
        "first_usable",
        "last_usable",
        "default_gateway",
        "subnet_mask",
        "ip_address",
        "task_ids",
        "task_coverage",
        "overall_passed",
        "verified_in_pt",
        "offline_topology_check",
    }
)


def _parse_frontmatter(skill_md: Path) -> tuple[dict, str]:
    raw = skill_md.read_text(encoding="utf-8")
    assert raw.startswith("---\n"), f"{skill_md} missing YAML frontmatter opener"
    parts = raw.split("---\n", 2)
    assert len(parts) == 3, f"{skill_md} missing YAML frontmatter terminator"
    meta = yaml.safe_load(parts[1])
    assert isinstance(meta, dict), f"{skill_md} frontmatter must be a mapping"
    return meta, parts[2].strip()


@pytest.mark.unit
def test_skills_pack_structure_and_frontmatter() -> None:
    readme = SKILLS_DIR / "README.md"
    assert readme.is_file()
    readme_text = readme.read_text(encoding="utf-8")

    for slug in EXPECTED_SKILLS:
        skill_dir = SKILLS_DIR / slug
        skill_md = skill_dir / "SKILL.md"
        assert skill_dir.is_dir(), f"Missing skill directory: {skill_dir}"
        assert skill_md.is_file(), f"Missing SKILL.md: {skill_md}"
        assert slug in readme_text, f"skills/README.md must link skill '{slug}'"

        meta, body = _parse_frontmatter(skill_md)
        assert meta.get("name") == slug
        assert isinstance(meta.get("description"), str) and len(meta["description"].strip()) >= 20
        assert len(body) >= 300


@pytest.mark.unit
def test_skills_only_reference_real_mcp_tools() -> None:
    settings = AgenticNetSettings.from_env()
    settings.tool_profile = "advanced"
    _, runtime = create_mcp_server(settings)
    registered_tools = {t.name for t in runtime.registry.tools}

    all_cited: set[str] = set()
    for slug in EXPECTED_SKILLS:
        text = (SKILLS_DIR / slug / "SKILL.md").read_text(encoding="utf-8")
        for match in _TOOL_PREFIX_RE.findall(text):
            if match not in _NON_TOOL_IDENTIFIERS:
                all_cited.add(match)

    unknown = sorted(all_cited - registered_tools)
    assert not unknown, f"Skills reference unknown MCP tool(s): {unknown}"
    assert "lab_status" in all_cited
    assert "verify_lab" in all_cited
    assert "console_execute" in all_cited
