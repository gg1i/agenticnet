"""Pre-execution IOS validators and CLI output error parsers."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from agenticnet.core.enums import ConfigCapability
from agenticnet.core.exceptions import InterfaceError, IOSConfigError
from agenticnet.devices import DEFAULT_CATALOG, DeviceCatalog, DeviceProfile
from agenticnet.ios.models import CLIDiagnostic

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
    has_cli = profile.supports(ConfigCapability.IOS_CLI) or profile.supports(
        ConfigCapability.ASA_FIREWALL
    )
    if not has_cli:
        return [
            CLIDiagnostic(
                line_number=1,
                command=commands[0] if commands else "",
                severity="error",
                code="NO_IOS_CLI",
                message=f"Device model '{profile.model}' does not have an IOS CLI.",
            )
        ]

    is_asa = profile.supports(ConfigCapability.ASA_FIREWALL) and not profile.supports(
        ConfigCapability.IOS_CLI
    )
    seen_trunk_encap = False
    for idx, raw_cmd in enumerate(commands, start=1):
        if any(ch in raw_cmd for ch in ("\r", "\n", "\x00")):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=raw_cmd.replace("\r", "\\r").replace("\n", "\\n"),
                    severity="error",
                    code="CLI_CONTROL_CHAR_INJECTION",
                    message="Command string contains embedded newline or null characters.",
                )
            )
            continue

        cmd = raw_cmd.strip()
        if not cmd or cmd.startswith("!"):
            continue
        lower = cmd.lower()

        if lower.startswith("interface "):
            seen_trunk_encap = False

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

        if lower.startswith("router bgp") and not profile.supports(ConfigCapability.BGP):
            code = (
                "UNSUPPORTED_ROUTING_PROTOCOL"
                if not profile.supports(ConfigCapability.STATIC_ROUTING)
                else "UNSUPPORTED_BGP"
            )
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code=code,
                    message=f"'{profile.model}' does not support BGP.",
                )
            )
        elif lower.startswith("router rip") and not profile.supports(ConfigCapability.RIP):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNSUPPORTED_ROUTING_PROTOCOL",
                    message=f"'{profile.model}' cannot run RIP dynamic routing.",
                )
            )

        if lower.startswith("standby ") and not profile.supports(ConfigCapability.HSRP):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNSUPPORTED_HSRP",
                    message=f"'{profile.model}' does not support HSRP ('standby').",
                )
            )

        if lower.startswith("ip dhcp snooping") and not profile.supports(
            ConfigCapability.DHCP_SNOOPING
        ):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNSUPPORTED_DHCP_SNOOPING",
                    message=f"'{profile.model}' does not support DHCP Snooping.",
                )
            )

        if lower.startswith("ip arp inspection") and not profile.supports(ConfigCapability.DAI):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNSUPPORTED_DAI",
                    message=f"'{profile.model}' does not support Dynamic ARP Inspection.",
                )
            )

        if lower.startswith("encapsulation dot1q") and not profile.supports(
            ConfigCapability.ROUTER_ON_A_STICK
        ):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNSUPPORTED_SUBINTERFACE_ENCAP",
                    message=(
                        f"'{profile.model}' does not support router subinterface "
                        "'encapsulation dot1q'."
                    ),
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

        if "switchport trunk encapsulation" in lower:
            seen_trunk_encap = True
            if profile.supports(ConfigCapability.TRUNKING) and not profile.supports(
                ConfigCapability.TRUNK_ENCAP_DOT1Q
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

        if (
            lower == "switchport mode trunk"
            and profile.supports(ConfigCapability.TRUNK_ENCAP_DOT1Q)
            and not seen_trunk_encap
        ):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="warning",
                    code="MISSING_TRUNK_ENCAP_DOT1Q",
                    message=(
                        f"'{profile.model}' requires 'switchport trunk encapsulation dot1q' "
                        "before 'switchport mode trunk'."
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
                        f"Model '{profile.model}' does not support Layer 2 switchport commands."
                    ),
                )
            )

        if lower.startswith("ip address "):
            parts = cmd.split()
            if len(parts) >= 4 and parts[2].lower() not in {"dhcp", "negotiated"}:
                try:
                    parse_ipv4_and_mask(parts[2], parts[3])
                except IOSConfigError as exc:
                    diagnostics.append(
                        CLIDiagnostic(
                            line_number=idx,
                            command=cmd,
                            severity="error",
                            code="INVALID_IP_OR_MASK",
                            message=exc.message,
                        )
                    )

        if lower.startswith("show ") and not is_asa:
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


def validate_pre_apply(
    profile_or_model: DeviceProfile | str,
    commands: list[str],
    *,
    device_name: str | None = None,
    ipam: Any | None = None,
    catalog: DeviceCatalog | None = None,
    raise_on_error: bool = False,
) -> dict[str, Any]:
    """Blocking pre-apply / pre-export validator gate for IOS and ASA configurations.

    Checks capability rules, control-character injection, interface validity against the
    device model, same-device IPv4 subnet overlaps, IPAM duplicate-IP conflicts, and
    unsupported Packet Tracer IOS-XE constructs.
    """
    cat = catalog or DEFAULT_CATALOG
    profile = (
        profile_or_model
        if isinstance(profile_or_model, DeviceProfile)
        else cat.get_profile(profile_or_model)
    )
    diagnostics = list(validate_raw_commands(profile, commands))

    current_iface: str | None = None
    seen_subnets: list[tuple[str, ipaddress.IPv4Network, int]] = []

    for idx, raw_cmd in enumerate(commands, start=1):
        if any(ch in raw_cmd for ch in ("\r", "\n", "\x00")):
            continue
        cmd = raw_cmd.strip()
        if not cmd or cmd.startswith("!"):
            continue
        lower = cmd.lower()

        if lower in {"exit", "end"}:
            current_iface = None
            continue

        if lower.startswith("interface ") and not lower.startswith("interface range "):
            raw_if = cmd.split(None, 1)[1].strip()
            try:
                current_iface = cat.normalize_interface_name(profile.model, raw_if)
            except InterfaceError as exc:
                current_iface = raw_if
                diagnostics.append(
                    CLIDiagnostic(
                        line_number=idx,
                        command=cmd,
                        severity="error",
                        code="INVALID_INTERFACE_FOR_MODEL",
                        message=exc.message,
                    )
                )
            continue

        if profile.model in {"4321", "ISR4331"} and lower.startswith(
            ("route-map ", "ip prefix-list ", "ip policy route-map ")
        ):
            diagnostics.append(
                CLIDiagnostic(
                    line_number=idx,
                    command=cmd,
                    severity="error",
                    code="UNSUPPORTED_PT_IOS_XE_COMMAND",
                    message=(
                        f"Packet Tracer IOS-XE on '{profile.model}' does not implement "
                        "route-map, ip prefix-list, or policy-based routing."
                    ),
                )
            )

        if lower.startswith("ip address "):
            parts = cmd.split()
            if len(parts) >= 4 and parts[2].lower() not in {"dhcp", "negotiated"}:
                try:
                    ip_str, mask_str = parse_ipv4_and_mask(parts[2], parts[3])
                    net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
                    iface_label = current_iface or f"line_{idx}"
                    for prev_iface, prev_net, _prev_ln in seen_subnets:
                        if prev_iface != iface_label and prev_net.overlaps(net):
                            diagnostics.append(
                                CLIDiagnostic(
                                    line_number=idx,
                                    command=cmd,
                                    severity="error",
                                    code="OVERLAPPING_INTERFACE_SUBNET",
                                    message=(
                                        f"Subnet {net} on {iface_label} overlaps with {prev_net} "
                                        f"configured on {prev_iface}."
                                    ),
                                )
                            )
                    seen_subnets.append((iface_label, net, idx))

                    if ipam is not None and hasattr(ipam, "state"):
                        for existing in ipam.state.allocations.values():
                            same_owner = (
                                device_name is not None
                                and existing.device_name == device_name
                                and existing.interface_name == (current_iface or "")
                            )
                            if existing.ip_address == ip_str and not same_owner:
                                diagnostics.append(
                                    CLIDiagnostic(
                                        line_number=idx,
                                        command=cmd,
                                        severity="error",
                                        code="IPAM_DUPLICATE_IP",
                                        message=(
                                            f"IP {ip_str} is already allocated in IPAM to "
                                            f"{existing.device_name}:{existing.interface_name}."
                                        ),
                                    )
                                )
                except IOSConfigError:
                    # Already reported by validate_raw_commands as INVALID_IP_OR_MASK
                    pass

    errors = [d for d in diagnostics if d.severity == "error"]
    warnings = [d for d in diagnostics if d.severity == "warning"]
    if raise_on_error and errors:
        raise IOSConfigError(
            f"Pre-apply validation blocked configuration for '{profile.model}': "
            f"{len(errors)} error(s) ({errors[0].code}: {errors[0].message})",
            details={
                "model": profile.model,
                "device_name": device_name,
                "errors": [e.model_dump(mode="json") for e in errors],
            },
            remediation="Fix all validation errors before applying configuration to Packet Tracer.",
        )

    return {
        "valid": len(errors) == 0,
        "blocked": len(errors) > 0,
        "model": profile.model,
        "device_name": device_name,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "diagnostics": diagnostics,
    }


def load_ios_command_sequence(ios_path: Path, *, device_type: str = "router") -> list[str]:
    """Read an `.ios` config file and wrap with safe enable/conf-t entry for the device class."""
    raw_lines = ios_path.read_text(encoding="utf-8").splitlines()
    body = [line.strip() for line in raw_lines if line.strip() and not line.strip().startswith("!")]
    while body and body[0].lower() in {"enable", "en", "configure terminal", "conf t"}:
        body.pop(0)
    # Never send "no" to switches (Catalyst has no setup dialog and triggers DNS lookup).
    hint = f"{device_type} {ios_path.stem}".lower()
    is_switch = any(tok in hint for tok in ("switch", "2960", "3560", "3650"))
    body = [cmd for cmd in body if cmd.lower() != "no ip domain-lookup"]
    if not is_switch and device_type.lower() == "router":
        return ["no", "", "", "enable", "configure terminal", "no ip domain-lookup", *body]
    return ["", "", "enable", "configure terminal", "no ip domain-lookup", *body]
