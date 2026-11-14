"""Pydantic data models for desktop GUI detection, calibration, vision, and state."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    return datetime.now(UTC)


class DialogType(StrEnum):
    """Known Packet Tracer modal/child dialog classifications."""

    LOGIN_WALL = "login_wall"
    SAVE_PROMPT = "save_prompt"
    CONFIRM_OVERWRITE = "confirm_overwrite"
    FILE_DIALOG = "file_dialog"
    ERROR_DIALOG = "error_dialog"
    DEVICE_WINDOW = "device_window"
    UNKNOWN = "unknown"


class Rect(BaseModel):
    """Screen-space rectangle in physical pixels."""

    left: int
    top: int
    right: int
    bottom: int

    @property
    def width(self) -> int:
        """Rectangle width in pixels."""
        return max(0, self.right - self.left)

    @property
    def height(self) -> int:
        """Rectangle height in pixels."""
        return max(0, self.bottom - self.top)

    @property
    def center(self) -> tuple[int, int]:
        """Integer pixel center `(x, y)` of the rectangle."""
        return (self.left + self.width // 2, self.top + self.height // 2)

    def contains(self, x: int, y: int) -> bool:
        """Return True if pixel `(x, y)` falls inside the rectangle."""
        return self.left <= x < self.right and self.top <= y < self.bottom


class WindowInfo(BaseModel):
    """Metadata describing the detected Packet Tracer application window."""

    hwnd: int
    pid: int
    process_name: str
    title: str
    class_name: str = ""
    window_rect: Rect
    client_rect: Rect
    dpi: int = 96
    scale_factor: float = 1.0
    is_minimized: bool = False
    is_foreground: bool = False
    active_file_hint: str | None = None
    has_unsaved_changes: bool = False


class GuiDialogInfo(BaseModel):
    """Detected popup dialog or detached device subwindow."""

    hwnd: int
    title: str
    class_name: str = ""
    dialog_type: DialogType = DialogType.UNKNOWN
    buttons: list[str] = Field(default_factory=list)
    rect: Rect | None = None
    detected_at: datetime = Field(default_factory=_utc_now)


class AnchorBox(BaseModel):
    """Normalized UI region inside Packet Tracer's client area (`[0.0, 1.0]`)."""

    name: str
    rx: float = Field(ge=0.0, le=1.0)
    ry: float = Field(ge=0.0, le=1.0)
    rw: float = Field(default=0.02, gt=0.0, le=1.0)
    rh: float = Field(default=0.02, gt=0.0, le=1.0)
    description: str = ""
    verified: bool = False


class CalibrationProfile(BaseModel):
    """DPI- and window-normalized coordinate calibration profile for Packet Tracer."""

    profile_id: str = "default"
    client_width: int = Field(ge=1)
    client_height: int = Field(ge=1)
    dpi: int = Field(default=96, ge=72)
    scale_factor: float = Field(default=1.0, gt=0.0)
    anchors: dict[str, AnchorBox] = Field(default_factory=dict)
    verified_anchors: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)
    notes: str = ""


class VisualAnchorMatch(BaseModel):
    """OpenCV template or structural detection result for a UI element."""

    anchor_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    screen_x: int
    screen_y: int
    norm_x: float = Field(ge=0.0, le=1.0)
    norm_y: float = Field(ge=0.0, le=1.0)
    bbox: Rect
    method: str = "opencv_ccoeff_normed"


class ImageStats(BaseModel):
    """Summary metrics computed from a captured screenshot."""

    width: int
    height: int
    mean_luma: float
    std_luma: float
    sha256_prefix: str
    looks_blank: bool = False


class GuiStateReport(BaseModel):
    """Snapshot of Packet Tracer window, dialogs, calibration, and safety status."""

    detected: bool
    running: bool
    executable_path: str | None = None
    window: WindowInfo | None = None
    dialogs: list[GuiDialogInfo] = Field(default_factory=list)
    calibration_loaded: bool = False
    calibration_profile_id: str | None = None
    abort_armed: bool = False
    warnings: list[str] = Field(default_factory=list)
    observed_at: datetime = Field(default_factory=_utc_now)
