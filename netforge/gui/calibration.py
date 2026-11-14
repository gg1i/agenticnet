"""DPI-aware coordinate calibration profiles and relative-to-screen mapping."""

from __future__ import annotations

import json
from pathlib import Path

from netforge.core.exceptions import ValidationError
from netforge.core.settings import NetForgeSettings
from netforge.gui.models import AnchorBox, CalibrationProfile, Rect, WindowInfo
from netforge.security.validation import safe_resolve_path, validate_project_id

# Relative layout anchors for Cisco Packet Tracer 8.x Logical Workspace.
# Marked verified=False until confirmed via window calibration or visual template matching.
DEFAULT_PT_ANCHORS: dict[str, AnchorBox] = {
    "canvas_center": AnchorBox(
        name="canvas_center",
        rx=0.50,
        ry=0.48,
        rw=0.50,
        rh=0.45,
        description="Logical workspace central canvas region.",
        verified=False,
    ),
    "menu_file": AnchorBox(
        name="menu_file",
        rx=0.0083,
        ry=0.0141,
        rw=0.02,
        rh=0.02,
        description="Top menu bar File entry.",
        verified=True,
    ),
    "top_save_icon": AnchorBox(
        name="top_save_icon",
        rx=0.0411,
        ry=0.0464,
        rw=0.015,
        rh=0.025,
        description="Main toolbar Save icon.",
        verified=True,
    ),
    "tool_select": AnchorBox(
        name="tool_select",
        rx=0.0094,
        ry=0.0817,
        rw=0.015,
        rh=0.025,
        description="Common tools bar Select pointer tool (Esc).",
        verified=True,
    ),
    "tool_inspect": AnchorBox(
        name="tool_inspect",
        rx=0.0250,
        ry=0.0817,
        rw=0.015,
        rh=0.025,
        description="Common tools bar Inspect tool (I).",
        verified=True,
    ),
    "tool_delete": AnchorBox(
        name="tool_delete",
        rx=0.0411,
        ry=0.0817,
        rw=0.015,
        rh=0.025,
        description="Common tools bar Delete tool (Del).",
        verified=True,
    ),
    "tool_place_note": AnchorBox(
        name="tool_place_note",
        rx=0.0771,
        ry=0.0817,
        rw=0.015,
        rh=0.025,
        description="Common tools bar Place Note tool (N).",
        verified=True,
    ),
    "pdu_simple": AnchorBox(
        name="pdu_simple",
        rx=0.1615,
        ry=0.0817,
        rw=0.015,
        rh=0.025,
        description="Common tools bar Add Simple PDU envelope icon (P).",
        verified=True,
    ),
    "pdu_complex": AnchorBox(
        name="pdu_complex",
        rx=0.1776,
        ry=0.0817,
        rw=0.015,
        rh=0.025,
        description="Common tools bar Add Complex PDU open-envelope icon (C).",
        verified=True,
    ),
    "workspace_logical": AnchorBox(
        name="workspace_logical",
        rx=0.0255,
        ry=0.1130,
        rw=0.045,
        rh=0.026,
        description="Top workspace switcher Logical tab (Shift+L).",
        verified=True,
    ),
    "workspace_physical": AnchorBox(
        name="workspace_physical",
        rx=0.0766,
        ry=0.1130,
        rw=0.045,
        rh=0.026,
        description="Top workspace switcher Physical tab (Shift+P).",
        verified=True,
    ),
    "power_cycle_devices": AnchorBox(
        name="power_cycle_devices",
        rx=0.0620,
        ry=0.8668,
        rw=0.016,
        rh=0.030,
        description="Simulation bar Power Cycle Devices button (Alt+S).",
        verified=True,
    ),
    "fast_forward_time": AnchorBox(
        name="fast_forward_time",
        rx=0.0792,
        ry=0.8668,
        rw=0.016,
        rh=0.030,
        description="Simulation bar Fast Forward Time button (Alt+D).",
        verified=True,
    ),
    "mode_realtime": AnchorBox(
        name="mode_realtime",
        rx=0.9073,
        ry=0.8668,
        rw=0.055,
        rh=0.030,
        description="Bottom-right Realtime mode toggle pill.",
        verified=True,
    ),
    "mode_simulation": AnchorBox(
        name="mode_simulation",
        rx=0.9688,
        ry=0.8668,
        rw=0.055,
        rh=0.030,
        description="Bottom-right Simulation mode toggle pill.",
        verified=True,
    ),
    "device_category_network_devices": AnchorBox(
        name="device_category_network_devices",
        rx=0.0104,
        ry=0.9142,
        rw=0.018,
        rh=0.036,
        description="Bottom-left Network Devices category icon.",
        verified=True,
    ),
    "device_category_end_devices": AnchorBox(
        name="device_category_end_devices",
        rx=0.0292,
        ry=0.9142,
        rw=0.018,
        rh=0.036,
        description="Bottom-left End Devices category icon.",
        verified=True,
    ),
    "device_category_components": AnchorBox(
        name="device_category_components",
        rx=0.0464,
        ry=0.9142,
        rw=0.018,
        rh=0.036,
        description="Bottom-left Components category icon.",
        verified=True,
    ),
    "device_category_connections": AnchorBox(
        name="device_category_connections",
        rx=0.0641,
        ry=0.9142,
        rw=0.018,
        rh=0.036,
        description="Bottom-left Connections (lightning) category icon.",
        verified=True,
    ),
    "device_category_routers": AnchorBox(
        name="device_category_routers",
        rx=0.0104,
        ry=0.9717,
        rw=0.018,
        rh=0.036,
        description="Bottom-left Network Devices -> Routers subcategory.",
        verified=True,
    ),
    "device_category_switches": AnchorBox(
        name="device_category_switches",
        rx=0.0286,
        ry=0.9717,
        rw=0.018,
        rh=0.036,
        description="Bottom-left Network Devices -> Switches subcategory.",
        verified=True,
    ),
    "device_category_wireless": AnchorBox(
        name="device_category_wireless",
        rx=0.0641,
        ry=0.9717,
        rw=0.018,
        rh=0.036,
        description="Bottom-left Network Devices -> Wireless Devices subcategory.",
        verified=True,
    ),
    "toggle_pdu_panel": AnchorBox(
        name="toggle_pdu_panel",
        rx=0.4620,
        ry=0.9692,
        rw=0.075,
        rh=0.035,
        description="Bottom PDU List Window toggle button.",
        verified=True,
    ),
    "cli_terminal_area": AnchorBox(
        name="cli_terminal_area",
        rx=0.50,
        ry=0.52,
        rw=0.45,
        rh=0.40,
        description="Detached or active device CLI terminal focus area.",
        verified=False,
    ),
}


class CalibrationManager:
    """Manages DPI-aware relative calibration profiles under `settings.data_dir/calibration`."""

    def __init__(self, settings: NetForgeSettings) -> None:
        self.calibration_dir = settings.data_dir / "calibration"
        self.active_profile: CalibrationProfile | None = None

    def _profile_path(self, profile_id: str) -> Path:
        pid = validate_project_id(profile_id if len(profile_id) >= 2 else f"{profile_id}_pt")
        return safe_resolve_path(
            self.calibration_dir / f"{pid}.json",
            base_dir=self.calibration_dir,
            allow_outside_base=False,
        )

    def create_from_window(
        self,
        window: WindowInfo,
        *,
        profile_id: str = "default",
        verified_anchors: list[str] | None = None,
        notes: str = "",
    ) -> CalibrationProfile:
        """Build a CalibrationProfile bound to observed client geometry and DPI."""
        anchors = {k: v.model_copy(deep=True) for k, v in DEFAULT_PT_ANCHORS.items()}
        verified = list(verified_anchors or [])
        for name in verified:
            if name in anchors:
                anchors[name].verified = True

        profile = CalibrationProfile(
            profile_id=profile_id,
            client_width=max(1, window.client_rect.width),
            client_height=max(1, window.client_rect.height),
            dpi=window.dpi,
            scale_factor=window.scale_factor,
            anchors=anchors,
            verified_anchors=verified,
            notes=notes
            or (
                "Window geometry calibrated from live client rect; layout anchors remain "
                "relative estimates until individually template-matched or user-verified."
            ),
        )
        self.save_profile(profile)
        self.active_profile = profile
        return profile

    def save_profile(self, profile: CalibrationProfile) -> Path:
        """Persist calibration profile JSON safely inside the calibration directory."""
        self.calibration_dir.mkdir(parents=True, exist_ok=True)
        path = self._profile_path(profile.profile_id)
        path.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
        self.active_profile = profile
        return path

    def load_profile(self, profile_id: str = "default") -> CalibrationProfile:
        """Load an existing calibration profile JSON from disk, backfilling new default anchors."""
        path = self._profile_path(profile_id)
        if not path.exists():
            raise ValidationError(
                f"Calibration profile '{profile_id}' does not exist.",
                details={"profile_id": profile_id, "path": str(path)},
                remediation="Run gui_calibrate while Cisco Packet Tracer is open.",
            )
        profile = CalibrationProfile.model_validate(json.loads(path.read_text(encoding="utf-8")))
        updated = False
        for name, default_box in DEFAULT_PT_ANCHORS.items():
            existing = profile.anchors.get(name)
            if existing is None or (default_box.verified and not existing.verified):
                profile.anchors[name] = default_box.model_copy(deep=True)
                updated = True
        if updated:
            profile.verified_anchors = sorted(
                {n for n, box in profile.anchors.items() if box.verified}
            )
        self.active_profile = profile
        return profile

    def ensure_or_default(self, profile_id: str = "default") -> CalibrationProfile | None:
        """Return active or stored profile if available without failing."""
        if self.active_profile and self.active_profile.profile_id == profile_id:
            return self.active_profile
        try:
            return self.load_profile(profile_id)
        except ValidationError:
            return None

    def resolve_screen_point(
        self,
        client_rect: Rect,
        *,
        x: int | None = None,
        y: int | None = None,
        nx: float | None = None,
        ny: float | None = None,
        anchor_name: str | None = None,
        profile: CalibrationProfile | None = None,
    ) -> tuple[int, int, str, bool]:
        """Resolve exact screen pixels `(sx, sy)` inside `client_rect`.

        Returns `(screen_x, screen_y, resolution_source, anchor_verified)`.
        """
        prof = profile or self.active_profile
        anchor_verified = False

        if anchor_name:
            anchors = prof.anchors if prof is not None else DEFAULT_PT_ANCHORS
            if anchor_name not in anchors:
                raise ValidationError(
                    f"Unknown UI anchor '{anchor_name}'.",
                    details={"anchor_name": anchor_name, "available": sorted(anchors.keys())},
                )
            box = anchors[anchor_name]
            sx = client_rect.left + int(round(box.rx * client_rect.width))
            sy = client_rect.top + int(round(box.ry * client_rect.height))
            source = f"anchor:{anchor_name}"
            anchor_verified = box.verified
        elif nx is not None and ny is not None:
            if not (0.0 <= nx <= 1.0 and 0.0 <= ny <= 1.0):
                raise ValidationError(
                    f"Normalized coordinates ({nx}, {ny}) must be within [0.0, 1.0].",
                    details={"nx": nx, "ny": ny},
                )
            sx = client_rect.left + int(round(nx * client_rect.width))
            sy = client_rect.top + int(round(ny * client_rect.height))
            source = "normalized"
            anchor_verified = True
        elif x is not None and y is not None:
            sx, sy = int(x), int(y)
            source = "absolute_screen"
            anchor_verified = True
        else:
            raise ValidationError(
                "Must specify (x, y), (nx, ny), or anchor_name to resolve a click target."
            )

        if not client_rect.contains(sx, sy):
            bounds = (
                f"[{client_rect.left}, {client_rect.top}, "
                f"{client_rect.right}, {client_rect.bottom}]"
            )
            raise ValidationError(
                f"Target point ({sx}, {sy}) lies outside Packet Tracer client bounds {bounds}.",
                details={"screen_x": sx, "screen_y": sy, "client_rect": client_rect.model_dump()},
                remediation="Focus/maximize Packet Tracer and re-run gui_calibrate.",
            )
        return sx, sy, source, anchor_verified
