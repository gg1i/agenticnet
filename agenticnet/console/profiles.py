"""Device-specific Packet Tracer console interaction profiles."""

from __future__ import annotations

from agenticnet.console.models import ConsoleInteractionKind, DeviceConsoleProfile
from agenticnet.core.enums import ConfigCapability, DeviceCategory
from agenticnet.devices import DEFAULT_CATALOG, DeviceCatalog


def get_console_profile(
    model: str,
    *,
    catalog: DeviceCatalog | None = None,
) -> DeviceConsoleProfile:
    """Resolve the terminal interaction profile for a verified Packet Tracer device model."""
    cat = catalog or DEFAULT_CATALOG
    dev = cat.get_profile(model)

    if dev.supports(ConfigCapability.IOS_CLI):
        delay = 100 if dev.category == DeviceCategory.L3_SWITCH else 80
        return DeviceConsoleProfile(
            model=dev.model,
            interaction_kind=ConsoleInteractionKind.IOS_CLI,
            supports_ios_cli=True,
            supports_paging_disable=True,
            paging_disable_command="terminal length 0",
            line_delay_ms=delay,
            command_timeout_seconds=6.0,
            max_recovery_attempts=4,
            notes=f"Cisco IOS CLI profile for {dev.display_name}.",
        )

    if dev.category in {DeviceCategory.PC, DeviceCategory.LAPTOP, DeviceCategory.SERVER}:
        return DeviceConsoleProfile(
            model=dev.model,
            interaction_kind=ConsoleInteractionKind.PT_DESKTOP_CMD,
            supports_ios_cli=False,
            supports_paging_disable=False,
            paging_disable_command="",
            line_delay_ms=100,
            command_timeout_seconds=8.0,
            max_recovery_attempts=2,
            notes=(
                f"Packet Tracer Desktop Command Prompt profile for {dev.display_name} "
                "(supports ping/ipconfig/tracert; not Cisco IOS CLI)."
            ),
        )

    return DeviceConsoleProfile(
        model=dev.model,
        interaction_kind=ConsoleInteractionKind.GUI_ONLY,
        supports_ios_cli=False,
        supports_paging_disable=False,
        paging_disable_command="",
        notes=(
            f"{dev.display_name} has no IOS CLI or interactive Command Prompt; "
            "configure via Config/Desktop GUI."
        ),
    )
