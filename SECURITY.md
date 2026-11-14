# Security Policy

## Scope and Threat Model

NetForge MCP enables AI assistants to design networks and interact with local Cisco Packet Tracer workspaces. Key security controls built into NetForge include:

- **No arbitrary shell execution**: NetForge exposes domain-specific networking tools only and never provides a raw shell tool to AI agents.
- **Tool-level permission tiers**: `read_only`, `planning`, `configuration`, `gui_control`, `destructive`.
- **Confirmation gates**: Destructive operations require explicit `confirm=True` when confirmation is enabled.
- **Secret redaction**: Passwords, shared secrets, and enable secrets are automatically scrubbed from SQLite execution logs and configuration snapshots.
- **Path validation**: Null bytes and unsafe path traversals are rejected.

## Supported Versions

| Version | Supported |
|---|---|
| `0.1.x` (Alpha) | Yes |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security vulnerabilities (such as path traversal, credential leakage in logs, or unsafe GUI input injection).

Instead, report vulnerabilities privately to the maintainers with:
1. Affected version and module.
2. Reproduction steps or minimal proof of concept.
3. Suggested mitigation if known.

Maintainers will acknowledge reports within 72 hours and coordinate a fix prior to public disclosure.
