"""Packet Tracer GUI automation subsystem (Phase 2)."""

from netforge.gui.adapter import NullGuiBackend, create_gui_backend
from netforge.gui.calibration import DEFAULT_PT_ANCHORS, CalibrationManager
from netforge.gui.models import (
    AnchorBox,
    CalibrationProfile,
    DialogType,
    GuiDialogInfo,
    GuiStateReport,
    ImageStats,
    Rect,
    VisualAnchorMatch,
    WindowInfo,
)
from netforge.gui.safety import AutomationStopError, EmergencyStopController
from netforge.gui.vision import (
    compute_image_stats,
    detect_ui_regions_from_image,
    image_diff_ratio,
    match_template,
    save_image_png,
)
from netforge.gui.windows_backend import WindowsGuiBackend

__all__ = [
    "AnchorBox",
    "AutomationStopError",
    "CalibrationManager",
    "CalibrationProfile",
    "DEFAULT_PT_ANCHORS",
    "DialogType",
    "EmergencyStopController",
    "GuiDialogInfo",
    "GuiStateReport",
    "ImageStats",
    "NullGuiBackend",
    "Rect",
    "VisualAnchorMatch",
    "WindowInfo",
    "WindowsGuiBackend",
    "compute_image_stats",
    "create_gui_backend",
    "detect_ui_regions_from_image",
    "image_diff_ratio",
    "match_template",
    "save_image_png",
]
