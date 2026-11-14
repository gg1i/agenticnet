"""Pre-execution IOS validators and CLI output error parsers."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from netforge.core.enums import ConfigCapability
from netforge.core.exceptions import IOSConfigError
from netforge.devices import DeviceProfile
from netforge.ios.models import CLIDiagnostic

_CLI_ERROR_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(r"%\s*Invalid input detected", re.IGNORECASE),
        "CLI_INVALID_INPUT",
        "Cisco IOS rejected command syntax at the '^' marker.",
    ),
    (
        re.compile(r"%\s*Incomplete command", re.IGNORECASE),
        "CLI_INCOMPLETE_COMMAND",
        "Command is missing required arguments.",
    ),
    (
        re.compile(r"%\s*Ambiguous command", re.IGNORECASE),
        "CLI_AMBIGUOUS_COMMAND",
        "Abbreviated keyword matched multiple IOS commands.",
    ),
    (
        re.compile(r"%\s*.*\boverlaps with\b", re.IGNORECASE),
        "CLI_OVERLAPPING_SUBNET",
        "Configured subnet overlaps with another interface on this device.",
    ),
    (
        re.compile(r"%\s*Bad mask\b", re.IGNORECASE),
        "CLI_BAD_SUBNET_MASK",
        "Subnet mask is non-contiguous or invalid for the specified IP.",
    ),
    (
        re.compile(r"%\s*Unrecognized command", re.IGNORECASE),
        "CLI_UNRECOGNIZED",
        "Command not supported on this device or IOS mode.",
    ),
)


def require_capability(profile: DeviceProfile, capability: ConfigCapability, feature: str) -> None:
    """Assert that a device profile supports a requested IOS capability."""
    if not profile.supports(ConfigCapability.IOS_CLI):
        raise IOSConfigError(
            f"Device model '{profile.model}' does not expose Cisco IOS CLI; "
            f"cannot configure {feature} via IOS commands.",
            details={"model": profile.model, "feature": feature},
            remediation="Use a router or managed switch (e.g. 2911, 2960-24TT, 3560-24PS), "
            "or configure host IP settings via Desktop/Web GUI.",
        )
    if not profile.supports(capability):
        raise IOSConfigError(
            f"Device model '{profile.model}' does not support '{capability.value}' ({feature}).",
            details={
                "model": profile.model,
                "missing_capability": capability.value,
                "restrictions": profile.restrictions,
            },
            remediation="Select a device model that supports this protocol or feature.",
        )


def parse_ipv4_and_mask(address: str, mask: str | None) -> tuple[str, str]:
    """Validate an IPv4 address and dotted-decimal mask (or CIDR input)."""
    try:
        if "/" in address and mask is None:
            iface = ipaddress.IPv4Interface(address.strip())
            return str(iface.ip), str(iface.netmask)
        ip_obj = ipaddress.IPv4Address(address.strip())
        if mask is None:
            raise IOSConfigError(
                f"Missing subnet mask for IPv4 address {address!r}.",
                details={"ip": address},
            )
        # Validate contiguous mask via IPv4Network parsing
        net = ipaddress.IPv4Network(f"0.0.0.0/{mask.strip()}", strict=True)
        return str(ip_obj), str(net.netmask)
    except ValueError as exc:
        raise IOSConfigError(
            f"Invalid IPv4 address/mask ({address!r}, {mask!r}): {exc}",
            details={"ip": address, "mask": mask},
        ) from exc


def to_network_and_wildcard(network_or_cidr: str, wildcard: str | None = None) -> tuple[str, str]:
    """Normalize a CIDR or network+wildcard pair into (network_ip, wildcard_mask)."""
    try:
        if "/" in network_or_cidr and wildcard is None:
            net = ipaddress.IPv4Network(network_or_cidr.strip(), strict=False)
            return str(net.network_address), str(net.hostmask)
        ip_obj = ipaddress.IPv4Address(network_or_cidr.strip())
        if wildcard is None:
            # Explicit wildcard/CIDR required; avoid guessing classful boundaries.
            raise IOSConfigError(
                f"Wildcard mask or CIDR prefix is required for network {network_or_cidr!r}.",
                remediation="Pass CIDR like '192.168.10.0/24' or explicit wildcard '0.0.0.255'.",
            )
        wc_obj = ipaddress.IPv4Address(wildcard.strip())
        # Verify wildcard is valid inverse of a contiguous netmask
        inverted = int(wc_obj) ^ 0xFFFFFFFF
        ipaddress.IPv4Network(f"0.0.0.0/{ipaddress.IPv4Address(inverted)}", strict=True)
        masked_net = ipaddress.IPv4Address(int(ip_obj) & inverted)
        return str(masked_net), str(wc_obj)
    except ValueError as exc:
        raise IOSConfigError(
            f"Invalid network/wildcard ({network_or_cidr!r}, {wildcard!r}): {exc}",
        ) from exc


def parse_cli_output(output: str) -> list[CLIDiagnostic]:
    """Scan raw Cisco IOS console output for syntax, mask, and overlap errors."""
    diagnostics: list[CLIDiagnostic] = []
    lines = output.splitlines()
    last_command = ""
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if "#" in stripped or ">" in stripped:
            # Capture prompt line context
            for sep in ("#", ">"):
                if sep in stripped:
                    last_command = stripped.split(sep, 1)[1].strip() or last_command
        for pattern, code, msg in _CLI_ERROR_PATTERNS:
            if pattern.search(stripped):
                diagnostics.append(
                    CLIDiagnostic(
                        line_number=idx,
                        command=last_command or stripped,
                        severity="error",
                        code=code,
                        message=f"{msg} Raw output: {stripped}",
                    )
                )
    return diagnostics


def validate_raw_commands(profile: DeviceProfile, commands: list[str]) -> list[CLIDiagnostic]:
    """Perform static capability & syntax checks on raw IOS commands before console execution."""
    diagnostics: list[CLIDiagnostic] = []
    if not profile.supports(ConfigCapability.IOS_CLI):
        return [
            CLIDiagnostic(
                line_number=1,
                command=commands[0] if commands else "",
                severity="error",
                code="NO_IOS_CLI",
                message=f"Device model '{profile.model}' does not have an IOS CLI.",
            )
        ]

    for idx, raw_cmd in enumerate(commands, start=1):
        cmd = raw_cmd.strip()
        if not cmd or cmd.startswith("!"):
            continue
        lower = cmd.lower()

        if lower.startswith("ip routing") and not profile.supports(ConfigCapability.STATIC_ROUTING):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNSUPPORTED_IP_ROUTING",
                    message=f"'{profile.model}' is Layer 2 only and does not support 'ip routing'.",
                )
            )

        if lower.startswith("router ospf") and not profile.supports(ConfigCapability.OSPF):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNSUPPORTED_OSPF",
                    message=f"'{profile.model}' does not support OSPF.",
                )
            )

        if lower.startswith("router eigrp") and not profile.supports(ConfigCapability.EIGRP):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNSUPPORTED_EIGRP",
                    message=f"'{profile.model}' does not support EIGRP.",
                )
            )

        if lower.startswith("ip nat ") and not profile.supports(ConfigCapability.NAT_PAT):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNSUPPORTED_NAT",
                    message=f"'{profile.model}' does not support NAT/PAT.",
                )
            )

        if (
            "switchport trunk encapsulation" in lower
            and profile.supports(ConfigCapability.TRUNKING)
            and not profile.supports(ConfigCapability.TRUNK_ENCAP_DOT1Q)
        ):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNNEEDED_TRUNK_ENCAP",
                    message=(
                        f"'{profile.model}' rejects 'switchport trunk encapsulation dot1q'; "
                        "use 'switchport mode trunk' directly."
                    ),
                )
            )

        if lower.startswith("switchport") and not profile.supports(ConfigCapability.VLANS):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNSUPPORTED_SWITCHPORT",
                    message=(
                        f"Router model '{profile.model}' does not support "
                        "Layer 2 switchport commands."
                    ),
                )
            )

        if lower.startswith("show "):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="warning",
                    code="SHOW_IN_CONFIG_SEQUENCE",
                    message=(
                        "Inside global configuration mode, prefix with 'do show ...' or exit first."
                    ),
                )
            )

    return diagnostics


def load_ios_command_sequence(ios_path: Path, *, device_type: str = "router") -> list[str]:
    """Read an `.ios` config file and wrap with safe enable/conf-t entry for the device class."""
    raw_lines = ios_path.read_text(encoding="utf-8").splitlines()
    body = [
        line.strip()
        for line in raw_lines
        if line.strip() and not line.strip().startswith("!")
    ]
    while body and body[0].lower() in {"enable", "en", "configure terminal", "conf t"}:
        body.pop(0)
    # Never send "no" to switches (Catalyst has no setup dialog and triggers DNS lookup).
    hint = f"{device_type} {ios_path.stem}".lower()
    is_switch = any(tok in hint for tok in ("switch", "2960", "3560", "3650"))
    body = [cmd for cmd in body if cmd.lower() != "no ip domain-lookup"]
    if not is_switch and device_type.lower() == "router":
        return ["no", "", "", "enable", "configure terminal", "no ip domain-lookup", *body]
    return ["", "", "enable", "configure terminal", "no ip domain-lookup", *body]
