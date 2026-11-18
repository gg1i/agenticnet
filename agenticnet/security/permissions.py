"""Tool-level permission enforcement and destructive confirmation gates."""

from __future__ import annotations

from pydantic import BaseModel, Field

from agenticnet.core.enums import PermissionTier
from agenticnet.core.exceptions import ApprovalRequiredError, PermissionDeniedError


class PermissionPolicy(BaseModel):
    """Configurable permission policy controlling what tiers an AI client may invoke."""

    profile_name: str = "standard"
    allowed_tiers: set[PermissionTier] = Field(
        default_factory=lambda: {
            PermissionTier.READ_ONLY,
            PermissionTier.PLANNING,
            PermissionTier.CONFIGURATION,
            PermissionTier.GUI_CONTROL,
            PermissionTier.DESTRUCTIVE,
        }
    )
    require_destructive_confirmation: bool = True
    denied_tools: set[str] = Field(default_factory=set)

    @classmethod
    def from_profile(
        cls,
        profile_name: str,
        *,
        require_destructive_confirmation: bool = True,
    ) -> PermissionPolicy:
        """Instantiate a named permission policy preset."""
        normalized = profile_name.strip().lower().replace("_", "-")
        if normalized == "full":
            normalized = "standard"
        presets: dict[str, set[PermissionTier]] = {
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
        if normalized not in presets:
            raise ValueError(
                f"Unknown permission profile {profile_name!r}. "
                f"Expected one of: {sorted(presets.keys())}"
            )
        return cls(
            profile_name=normalized,
            allowed_tiers=set(presets[normalized]),
            require_destructive_confirmation=require_destructive_confirmation,
        )


class PermissionGuard:
    """Enforces tool-tier permissions and explicit confirmation for destructive actions."""

    def __init__(self, policy: PermissionPolicy | None = None) -> None:
        self.policy = policy or PermissionPolicy()

    def check(
        self,
        tool_name: str,
        tier: PermissionTier,
        *,
        confirmed: bool = False,
        destructive_reason: str | None = None,
    ) -> None:
        """Verify whether `tool_name` may execute under the active policy."""
        if tool_name in self.policy.denied_tools:
            raise PermissionDeniedError(
                f"Tool '{tool_name}' is explicitly blocked by security policy.",
                details={"tool_name": tool_name, "profile": self.policy.profile_name},
                remediation="Update the AgenticNet permission policy if this tool is needed.",
            )

        if tier not in self.policy.allowed_tiers:
            raise PermissionDeniedError(
                f"Tool '{tool_name}' requires '{tier.value}' permission, "
                f"which is disabled under profile '{self.policy.profile_name}'.",
                details={
                    "tool_name": tool_name,
                    "required_tier": tier.value,
                    "allowed_tiers": sorted(t.value for t in self.policy.allowed_tiers),
                },
                remediation=(
                    "Use a higher permission profile "
                    "(e.g. AGENTICNET_PERMISSION_PROFILE=standard) "
                    "or grant the required tier explicitly."
                ),
            )

        if (
            tier == PermissionTier.DESTRUCTIVE
            and self.policy.require_destructive_confirmation
            and not confirmed
        ):
            reason = (
                destructive_reason or f"Destructive operation '{tool_name}' requires confirmation."
            )
            raise ApprovalRequiredError(
                reason,
                details={"tool_name": tool_name, "required_parameter": "confirm=True"},
                remediation="Ask the user for approval and re-invoke with confirm=True.",
            )
