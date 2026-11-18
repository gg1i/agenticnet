"""Runtime settings loaded safely from environment variables or defaults."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

from agenticnet.core.enums import PermissionTier
from agenticnet.core.exceptions import ValidationError


def _is_windows() -> bool:
    return os.name == "nt"


def _platform_data_dir(app_name: str) -> Path:
    if _is_windows():
        local_app_data = os.environ.get("LOCALAPPDATA")
        base_dir = (
            Path(local_app_data).expanduser().resolve()
            if local_app_data
            else (Path.home() / "AppData" / "Local").resolve()
        )
        return (base_dir / app_name).resolve()
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    base_dir = (
        Path(xdg_data_home).expanduser().resolve()
        if xdg_data_home
        else (Path.home() / ".local" / "share").resolve()
    )
    return (base_dir / app_name).resolve()


def _env_first(primary: str, legacy: str, default: str | None = None) -> str | None:
    """Return `AGENTICNET_*` value if set, otherwise fall back to legacy `NETFORGE_*`."""
    if primary in os.environ and os.environ[primary] != "":
        return os.environ[primary]
    if legacy in os.environ and os.environ[legacy] != "":
        return os.environ[legacy]
    return default


def _env_str(primary: str, legacy: str, default: str) -> str:
    value = _env_first(primary, legacy, default)
    return default if value is None else value


def canonical_pt_bridge_data_dir() -> Path:
    """Resolve the OS-standard directory where `netforge_bridge.pts` discovers session files."""
    return _platform_data_dir("netforge")


def default_data_dir() -> Path:
    """Resolve platform-appropriate runtime data directory outside synced repos."""
    env_dir = _env_first("AGENTICNET_DATA_DIR", "NETFORGE_DATA_DIR")
    if env_dir:
        return Path(env_dir).expanduser().resolve()
    return _platform_data_dir("agenticnet")


class AgenticNetSettings(BaseModel):
    """Centralized configuration for AgenticNet server and engines."""

    data_dir: Path = Field(default_factory=default_data_dir)
    db_filename: str = "agenticnet.sqlite"
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

    @model_validator(mode="after")
    def _sync_permission_tiers_from_profile(self) -> AgenticNetSettings:
        """Normalize permission_profile and derive allowed_tiers fail-closed unless set."""
        from agenticnet.security.permissions import PermissionPolicy

        try:
            policy = PermissionPolicy.from_profile(
                self.permission_profile,
                require_destructive_confirmation=self.require_destructive_confirmation,
            )
        except ValueError as exc:
            raise ValidationError(
                str(exc),
                details={"permission_profile": self.permission_profile},
                remediation="Use one of: read-only, planning, configuration, standard.",
            ) from exc

        self.permission_profile = policy.profile_name
        if "allowed_tiers" not in self.model_fields_set:
            self.allowed_tiers = set(policy.allowed_tiers)
        return self

    @property
    def db_path(self) -> Path:
        """Full SQLite database file path."""
        return self.data_dir / self.db_filename

    @property
    def backup_dir(self) -> Path:
        """Directory used for automated project backup archives."""
        return self.data_dir / "backups"

    @classmethod
    def from_env(cls) -> AgenticNetSettings:
        """Build settings from `AGENTICNET_*` (or legacy `NETFORGE_*`) environment variables."""
        from agenticnet.security.permissions import PermissionPolicy

        raw_profile = _env_str(
            "AGENTICNET_PERMISSION_PROFILE", "NETFORGE_PERMISSION_PROFILE", "standard"
        )
        require_confirm_raw = (
            _env_str("AGENTICNET_REQUIRE_CONFIRM", "NETFORGE_REQUIRE_CONFIRM", "true")
            .strip()
            .lower()
        )
        require_confirm = require_confirm_raw not in {"0", "false", "no"}
        try:
            policy = PermissionPolicy.from_profile(
                raw_profile,
                require_destructive_confirmation=require_confirm,
            )
        except ValueError as exc:
            raise ValidationError(
                f"Invalid permission profile {raw_profile!r} from environment.",
                details={"permission_profile": raw_profile},
                remediation=(
                    "Set AGENTICNET_PERMISSION_PROFILE to "
                    "read-only, planning, configuration, or standard."
                ),
            ) from exc

        tool_profile = (
            _env_str("AGENTICNET_TOOL_PROFILE", "NETFORGE_TOOL_PROFILE", "solve_lab")
            .strip()
            .lower()
        )
        if tool_profile not in {"solve_lab", "advanced"}:
            raise ValidationError(
                f"Invalid tool profile {tool_profile!r} from environment.",
                details={"tool_profile": tool_profile},
                remediation="Set AGENTICNET_TOOL_PROFILE to 'solve_lab' or 'advanced'.",
            )

        return cls(
            data_dir=default_data_dir(),
            db_filename=_env_str("AGENTICNET_DB_NAME", "NETFORGE_DB_NAME", "agenticnet.sqlite"),
            log_level=_env_str("AGENTICNET_LOG_LEVEL", "NETFORGE_LOG_LEVEL", "INFO").upper(),
            transport=_env_str("AGENTICNET_TRANSPORT", "NETFORGE_TRANSPORT", "stdio").lower(),
            host=_env_str("AGENTICNET_HOST", "NETFORGE_HOST", "127.0.0.1"),
            port=int(_env_str("AGENTICNET_PORT", "NETFORGE_PORT", "8765")),
            permission_profile=policy.profile_name,
            tool_profile=tool_profile,
            require_destructive_confirmation=require_confirm,
            allowed_tiers=set(policy.allowed_tiers),
            max_devices_per_project=int(
                _env_str("AGENTICNET_MAX_DEVICES", "NETFORGE_MAX_DEVICES", "250")
            ),
            max_links_per_project=int(
                _env_str("AGENTICNET_MAX_LINKS", "NETFORGE_MAX_LINKS", "1000")
            ),
            packet_tracer_path=_env_first("AGENTICNET_PT_PATH", "NETFORGE_PT_PATH"),
            operation_timeout_seconds=float(
                _env_str("AGENTICNET_TIMEOUT", "NETFORGE_TIMEOUT", "30.0")
            ),
            gui_background_mode=_env_str(
                "AGENTICNET_GUI_BACKGROUND", "NETFORGE_GUI_BACKGROUND", "true"
            )
            .strip()
            .lower()
            not in {"0", "false", "no", "off"},
            auto_launch_packet_tracer=_env_str(
                "AGENTICNET_AUTO_LAUNCH_PT", "NETFORGE_AUTO_LAUNCH_PT", "true"
            )
            .strip()
            .lower()
            not in {"0", "false", "no", "off"},
            auto_create_project=_env_str(
                "AGENTICNET_AUTO_CREATE_PROJECT", "NETFORGE_AUTO_CREATE_PROJECT", "true"
            )
            .strip()
            .lower()
            not in {"0", "false", "no", "off"},
        )


# Backward-compatibility alias for pre-rename callers importing NetForgeSettings.
NetForgeSettings = AgenticNetSettings
