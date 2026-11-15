"""MCP tool-exposure profiles (`solve_lab` curated default vs `advanced` full catalog)."""

from __future__ import annotations

from netforge.core.exceptions import ValidationError

TOOL_PROFILE_NAMES: tuple[str, ...] = ("solve_lab", "advanced")

# Raw coordinate/keystroke/screenshot GUI tools are strictly excluded from `solve_lab`
# and require explicit opt-in via `--tool-profile advanced` / `NETFORGE_TOOL_PROFILE=advanced`.
RAW_GUI_INPUT_TOOLS: frozenset[str] = frozenset(
    {
        "gui_click",
        "gui_keypress",
        "gui_screenshot",
        "gui_batch",
        "gui_calibrate",
        "gui_recover",
        "gui_state_inspect",
        "packet_tracer_launch",
    }
)

# Curated 20-tool default profile for client agents solving labs cleanly:
# keeps purpose-built GUI actions (`gui_attach_ip_phone_power`) and excludes raw GUI input tools.
SOLVE_LAB_TOOLS: frozenset[str] = frozenset(
    {
        "lab_open",
        "lab_save",
        "lab_status",
        "list_devices",
        "lab_snapshot",
        "project_create",
        "project_status",
        "device_capabilities",
        "device_add",
        "device_inspect",
        "connection_create",
        "interface_status",
        "topology_inspect",
        "subnet_calculate",
        "console_execute",
        "console_capture",
        "configuration_backup",
        "connectivity_test",
        "verify_requirements_schema",
        "verify_lab",
        "grade_lab",
        "gui_attach_ip_phone_power",
    }
)

if not SOLVE_LAB_TOOLS.isdisjoint(RAW_GUI_INPUT_TOOLS):
    overlap = sorted(SOLVE_LAB_TOOLS & RAW_GUI_INPUT_TOOLS)
    raise RuntimeError(f"Raw GUI tools must never appear in SOLVE_LAB_TOOLS: {overlap}")


def resolve_tool_profile(profile: str) -> frozenset[str] | None:
    """Return allowed tool names for `profile`, or `None` for explicit `advanced` opt-in."""
    normalized = str(profile or "solve_lab").strip().lower()
    if normalized == "solve_lab":
        return SOLVE_LAB_TOOLS
    if normalized == "advanced":
        return None
    raise ValidationError(
        f"Unsupported tool_profile '{profile}'.",
        details={"supported_profiles": list(TOOL_PROFILE_NAMES)},
        remediation="Choose 'solve_lab' (default curated profile) or 'advanced' (explicit opt-in).",
    )
