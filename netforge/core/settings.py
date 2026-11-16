"""Runtime settings loaded safely from environment variables or defaults."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field

from netforge.core.enums import PermissionTier


def canonical_pt_bridge_data_dir() -> Path:
    """Resolve the OS-standard directory where `netforge_bridge.pts` discovers session files."""
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        base_dir = (
            Path(local_app_data).expanduser().resolve()
            if local_app_data
            else (Path.home() / "AppData" / "Local").resolve()
        )
        return (base_dir / "netforge").resolve()
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    base_dir = (
        Path(xdg_data_home).expanduser().resolve()
        if xdg_data_home
        else (Path.home() / ".local" / "share").resolve()
    )
    return (base_dir / "netforge").resolve()


def default_data_dir() -> Path:
    """Resolve platform-appropriate runtime data directory outside synced repos."""
    env_dir = os.environ.get("NETFORGE_DATA_DIR")
    if env_dir:
        return Path(env_dir).expanduser().resolve()
    return canonical_pt_bridge_data_dir()


class NetForgeSettings(BaseModel):
    """Centralized configuration for NetForge MCP server and engines."""

    data_dir: Path = Field(default_factory=default_data_dir)
    db_filename: str = "netforge.sqlite"
    log_level: str = "INFO"
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8765
    permission_profile: str = "standard"
    tool_profile: str = "solve_lab"
    require_destructive_confirmation: bool = True
    allowed_tiers: set[PermissionTier] = Field(
        default_factory=lambda: {
            PermissionTier.READ_ONLY,
            PermissionTier.PLANNING,
            PermissionTier.CONFIGURATION,
            PermissionTier.GUI_CONTROL,
            PermissionTier.DESTRUCTIVE,
        }
    )
    max_devices_per_project: int = 250
    max_links_per_project: int = 1000
    packet_tracer_path: str | None = None
    operation_timeout_seconds: float = 30.0
    gui_background_mode: bool = True
    auto_launch_packet_tracer: bool = True
    auto_create_project: bool = True

    @property
    def db_path(self) -> Path:
        """Full SQLite database file path."""
        return self.data_dir / self.db_filename

    @property
    def backup_dir(self) -> Path:
        """Directory used for automated project backup archives."""
        return self.data_dir / "backups"

    @classmethod
    def from_env(cls) -> NetForgeSettings:
        """Build settings from `NETFORGE_*` environment variables."""
        profile = os.environ.get("NETFORGE_PERMISSION_PROFILE", "standard").strip().lower()
        tier_map: dict[str, set[PermissionTier]] = {
            "read-only": {PermissionTier.READ_ONLY},
            "planning": {PermissionTier.READ_ONLY, PermissionTier.PLANNING},
            "configuration": {
                PermissionTier.READ_ONLY,
                PermissionTier.PLANNING,
                PermissionTier.CONFIGURATION,
            },
            "standard": {
                PermissionTier.READ_ONLY,
                PermissionTier.PLANNING,
                PermissionTier.CONFIGURATION,
                PermissionTier.GUI_CONTROL,
                PermissionTier.DESTRUCTIVE,
            },
        }
        allowed_tiers = tier_map.get(profile, tier_map["standard"])
        tool_profile = os.environ.get("NETFORGE_TOOL_PROFILE", "solve_lab").strip().lower()
        if tool_profile not in {"solve_lab", "advanced"}:
            tool_profile = "solve_lab"
        require_confirm_raw = os.environ.get("NETFORGE_REQUIRE_CONFIRM", "true").strip().lower()
        require_confirm = require_confirm_raw not in {"0", "false", "no"}

        return cls(
            data_dir=default_data_dir(),
            db_filename=os.environ.get("NETFORGE_DB_NAME", "netforge.sqlite"),
            log_level=os.environ.get("NETFORGE_LOG_LEVEL", "INFO").upper(),
            transport=os.environ.get("NETFORGE_TRANSPORT", "stdio").lower(),
            host=os.environ.get("NETFORGE_HOST", "127.0.0.1"),
            port=int(os.environ.get("NETFORGE_PORT", "8765")),
            permission_profile=profile,
            tool_profile=tool_profile,
            require_destructive_confirmation=require_confirm,
            allowed_tiers=allowed_tiers,
            max_devices_per_project=int(os.environ.get("NETFORGE_MAX_DEVICES", "250")),
            max_links_per_project=int(os.environ.get("NETFORGE_MAX_LINKS", "1000")),
            packet_tracer_path=os.environ.get("NETFORGE_PT_PATH"),
            operation_timeout_seconds=float(os.environ.get("NETFORGE_TIMEOUT", "30.0")),
            gui_background_mode=os.environ.get("NETFORGE_GUI_BACKGROUND", "true")
            .strip()
            .lower()
            not in {"0", "false", "no", "off"},
            auto_launch_packet_tracer=os.environ.get("NETFORGE_AUTO_LAUNCH_PT", "true")
            .strip()
            .lower()
            not in {"0", "false", "no", "off"},
            auto_create_project=os.environ.get("NETFORGE_AUTO_CREATE_PROJECT", "true")
            .strip()
            .lower()
            not in {"0", "false", "no", "off"},
        )
