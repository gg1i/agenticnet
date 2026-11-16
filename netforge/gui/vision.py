"""OpenCV and Pillow screenshot analysis, visual diffing, and template matching."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from netforge.core.exceptions import AdapterUnavailableError, ValidationError
from netforge.gui.models import ImageStats, Rect, VisualAnchorMatch

if TYPE_CHECKING:
    from PIL import Image


def _require_vision_deps() -> tuple[Any, Any, Any]:
    try:
        import cv2  # type: ignore[import-untyped]
        import numpy as np  # type: ignore[import-untyped]
        from PIL import Image as pil_image
    except ImportError as exc:
        raise AdapterUnavailableError(
            "GUI vision utilities require Pillow, NumPy, and OpenCV.",
            remediation="Install optional GUI extras: pip install 'netforge-mcp[gui]'.",
        ) from exc
    return cv2, np, pil_image


def save_image_png(image: Image.Image, target_path: Path) -> Path:
    """Persist a Pillow image to PNG, creating parent directories safely."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(target_path, format="PNG")
    return target_path


def _pil_to_bgr(image: Image.Image) -> Any:
    cv2, np, _ = _require_vision_deps()
    rgb = np.asarray(image.convert("RGB"), dtype=np.uint8)
    return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)


def compute_image_stats(image: Image.Image) -> ImageStats:
    """Compute basic brightness, contrast, hash, and blank-screen checks."""
    cv2, np, _ = _require_vision_deps()
    rgb = np.asarray(image.convert("RGB"), dtype=np.uint8)
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    mean_val = float(np.mean(gray))
    std_val = float(np.std(gray))
    digest = hashlib.sha256(rgb.tobytes()).hexdigest()[:16]
    return ImageStats(
        width=image.width,
        height=image.height,
        mean_luma=round(mean_val, 2),
        std_luma=round(std_val, 2),
        sha256_prefix=digest,
        looks_blank=std_val < 2.0,
    )


def image_diff_ratio(
    before: Image.Image,
    after: Image.Image,
    *,
    pixel_delta_threshold: int = 18,
) -> float:
    """Return fraction of pixels `[0.0, 1.0]` that changed significantly between screenshots."""
    cv2, np, _ = _require_vision_deps()
    after_resized = after.resize(before.size) if before.size != after.size else after

    gray_a = cv2.cvtColor(_pil_to_bgr(before), cv2.COLOR_BGR2GRAY)
    gray_b = cv2.cvtColor(_pil_to_bgr(after_resized), cv2.COLOR_BGR2GRAY)
    diff = cv2.absdiff(gray_a, gray_b)
    changed = int(np.count_nonzero(diff >= pixel_delta_threshold))
    total = int(diff.shape[0] * diff.shape[1]) or 1
    return round(changed / total, 5)


def match_template(
    screenshot: Image.Image,
    template: Image.Image | str | Path,
    *,
    anchor_name: str,
    threshold: float = 0.80,
    client_rect: Rect | None = None,
) -> VisualAnchorMatch | None:
    """Locate `template` inside `screenshot` using normalized OpenCV template matching."""
    cv2, _, pil_image = _require_vision_deps()
    if isinstance(template, (str, Path)):
        tpl_path = Path(template)
        if not tpl_path.exists():
            raise ValidationError(
                f"Template image file does not exist: {tpl_path}",
                details={"template_path": str(tpl_path)},
            )
        tpl_img = pil_image.open(tpl_path)
    else:
        tpl_img = template

    if tpl_img.width > screenshot.width or tpl_img.height > screenshot.height:
        return None

    screen_gray = cv2.cvtColor(_pil_to_bgr(screenshot), cv2.COLOR_BGR2GRAY)
    tpl_gray = cv2.cvtColor(_pil_to_bgr(tpl_img), cv2.COLOR_BGR2GRAY)
    result = cv2.matchTemplate(screen_gray, tpl_gray, cv2.TM_CCOEFF_NORMED)
    _, max_val, _, max_loc = cv2.minMaxLoc(result)

    confidence = float(max_val)
    if confidence < threshold:
        return None

    rel_left, rel_top = int(max_loc[0]), int(max_loc[1])
    w, h = tpl_img.width, tpl_img.height
    center_rel_x = rel_left + w // 2
    center_rel_y = rel_top + h // 2

    base_left = client_rect.left if client_rect is not None else 0
    base_top = client_rect.top if client_rect is not None else 0
    base_w = client_rect.width if client_rect is not None else max(1, screenshot.width)
    base_h = client_rect.height if client_rect is not None else max(1, screenshot.height)

    screen_x = base_left + center_rel_x
    screen_y = base_top + center_rel_y
    bbox = Rect(
        left=base_left + rel_left,
        top=base_top + rel_top,
        right=base_left + rel_left + w,
        bottom=base_top + rel_top + h,
    )
    return VisualAnchorMatch(
        anchor_name=anchor_name,
        confidence=round(confidence, 4),
        screen_x=screen_x,
        screen_y=screen_y,
        norm_x=round(min(1.0, max(0.0, center_rel_x / base_w)), 4),
        norm_y=round(min(1.0, max(0.0, center_rel_y / base_h)), 4),
        bbox=bbox,
    )


def detect_ui_regions_from_image(image: Image.Image) -> dict[str, Any]:
    """Analyze a Packet Tracer screenshot to estimate layout strips and dialog overlays."""
    cv2, np, _ = _require_vision_deps()
    gray = cv2.cvtColor(_pil_to_bgr(image), cv2.COLOR_BGR2GRAY)
    h, w = gray.shape
    if h < 100 or w < 100:
        return {
            "width": w,
            "height": h,
            "canvas_estimated_bright": False,
            "center_region_mean_luma": float(np.mean(gray)),
        }

    top_strip = gray[: max(1, int(h * 0.10)), :]
    center_box = gray[int(h * 0.20) : int(h * 0.72), int(w * 0.15) : int(w * 0.85)]
    bottom_strip = gray[int(h * 0.76) :, :]

    center_mean = float(np.mean(center_box))
    center_std = float(np.std(center_box))
    top_mean = float(np.mean(top_strip))
    bottom_mean = float(np.mean(bottom_strip))

    # Empty Packet Tracer logical workspace canvas is predominantly bright neutral white/gray.
    canvas_bright = center_mean > 205.0
    possible_modal_overlay = center_mean < 175.0 and center_std > 28.0

    return {
        "width": w,
        "height": h,
        "top_toolbar_mean_luma": round(top_mean, 2),
        "center_canvas_mean_luma": round(center_mean, 2),
        "center_canvas_std_luma": round(center_std, 2),
        "bottom_palette_mean_luma": round(bottom_mean, 2),
        "canvas_looks_clear": canvas_bright,
        "possible_center_overlay": possible_modal_overlay,
    }
