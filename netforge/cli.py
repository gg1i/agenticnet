"""Command-line entry point for launching and inspecting NetForge MCP."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from collections.abc import Sequence
from importlib import resources
from pathlib import Path

from netforge import __schema_version__, __version__
from netforge.adapters.discovery import (
    detect_packet_tracer_binary as _detect_packet_tracer_binary,
)
from netforge.adapters.discovery import (
    is_packet_tracer_running as _is_packet_tracer_running,
)
from netforge.adapters.script_bridge import (
    HttpScriptBridgeBackend,
    HttpScriptBridgeServer,
    probe_bridge_health,
    render_script_module_sources,
)
from netforge.core.logging import configure_logging
from netforge.core.settings import NetForgeSettings
from netforge.mcp.server import create_mcp_server
from netforge.security.redaction import redact_path_home


def _is_dir_writable(target: Path) -> bool:
    """Return True if target or its nearest existing ancestor directory is writable."""
    probe = target
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    return probe.exists() and os.access(probe, os.W_OK)


def build_doctor_report(settings: NetForgeSettings) -> dict[str, object]:
    """Run live environment probes with home/user path redaction and honest status."""
    pt_exe = _detect_packet_tracer_binary(settings.packet_tracer_path)
    pt_running = _is_packet_tracer_running()
    session_file = settings.data_dir / "bridge_session.json"
    bridge_probe = probe_bridge_health(session_file)
    data_writable = _is_dir_writable(settings.data_dir)
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "netforge_version": __version__,
        "schema_version": __schema_version__,
        "data_dir": redact_path_home(settings.data_dir),
        "data_dir_writable": data_writable,
        "permission_profile": settings.permission_profile,
        "tool_profile": settings.tool_profile,
        "packet_tracer_detected": pt_exe is not None,
        "packet_tracer_path": redact_path_home(pt_exe),
        "packet_tracer_running": pt_running,
        "script_bridge": {
            "session_file": redact_path_home(session_file),
            **bridge_probe,
        },
        "roadmap_stage": "phase_2_backend_router",
        "capabilities_doc": "docs/CAPABILITIES.md",
    }


def install_script_module(
    settings: NetForgeSettings,
    *,
    dest_dir: Path | None = None,
    source_pts: Path | None = None,
) -> dict[str, object]:
    """Copy `netforge_bridge.pts` into `settings.data_dir` and return registration steps."""
    target_dir = (dest_dir or settings.data_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    dest_pts = target_dir / "netforge_bridge.pts"

    if source_pts is not None:
        src_resolved = source_pts.expanduser().resolve()
        if not src_resolved.is_file():
            raise FileNotFoundError(f"Script module file not found: {src_resolved}")
        raw_bytes = src_resolved.read_bytes()
    else:
        asset = resources.files("netforge.adapters.assets").joinpath("netforge_bridge.pts")
        if not asset.is_file():
            raise FileNotFoundError(
                "Bundled netforge_bridge.pts asset not found in netforge.adapters.assets."
            )
        raw_bytes = asset.read_bytes()

    if source_pts is None or source_pts.expanduser().resolve() != dest_pts:
        dest_pts.write_bytes(raw_bytes)

    custom_session = target_dir / "bridge_session.json" if dest_dir is not None else None
    src_paths = render_script_module_sources(
        target_dir / "bridge_src",
        session_file=custom_session,
    )
    steps = [
        "1. Open Cisco Packet Tracer (8.2.2+).",
        "2. Go to Extensions -> Scripting -> Configure PT Script Modules...",
        f"3. Click Add and select: {dest_pts}",
        "4. Enable 'On Startup' (State: On) and accept the requested script privileges.",
        (
            "5. Restart Packet Tracer once; future `netforge-mcp serve` runs "
            "auto-connect with no popups."
        ),
    ]
    return {
        "installed": True,
        "module_path": str(dest_pts),
        "redacted_module_path": redact_path_home(dest_pts),
        "bridge_src_dir": str(src_paths["js"].parent),
        "bytes_written": len(raw_bytes),
        "steps": steps,
    }


def build_parser() -> argparse.ArgumentParser:
    """Construct the NetForge CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="netforge-mcp",
        description=(
            "NetForge MCP — Open-source AI-native automation platform for Cisco Packet Tracer."
        ),
    )
    sub = parser.add_subparsers(dest="command")

    serve_p = sub.add_parser("serve", help="Run the NetForge MCP server.")
    serve_p.add_argument(
        "--transport",
        choices=["stdio", "streamable-http", "sse"],
        default=None,
        help="MCP transport protocol (default: stdio).",
    )
    serve_p.add_argument("--host", default=None, help="Bind host for HTTP/SSE transports.")
    serve_p.add_argument(
        "--port", type=int, default=None, help="Bind port for HTTP/SSE transports."
    )
    serve_p.add_argument(
        "--data-dir", default=None, help="Directory for SQLite database and backups."
    )
    serve_p.add_argument(
        "--profile",
        choices=["read-only", "planning", "configuration", "standard"],
        default=None,
        help="Permission profile limiting active tool tiers.",
    )
    serve_p.add_argument(
        "--tool-profile",
        choices=["solve_lab", "advanced"],
        default=None,
        help="Tool exposure profile: 'solve_lab' (default curated loop) or 'advanced' (all tools).",
    )
    serve_p.add_argument(
        "--json-logs", action="store_true", help="Emit JSON-formatted logs to stderr."
    )

    manifest_p = sub.add_parser(
        "manifest", help="Print the machine-readable MCP capability manifest."
    )
    manifest_p.add_argument(
        "--output", default=None, help="Optional file path to write manifest JSON."
    )
    manifest_p.add_argument(
        "--tool-profile",
        choices=["solve_lab", "advanced"],
        default=None,
        help="Tool exposure profile to emit in the manifest.",
    )

    sub.add_parser(
        "doctor", help="Check Python environment, dependencies, SQLite path, and Packet Tracer."
    )
    inst_p = sub.add_parser(
        "install-module",
        help="Copy netforge_bridge.pts to the NetForge data directory and print setup steps.",
    )
    inst_p.add_argument(
        "--dest-dir",
        default=None,
        help="Override target directory (default: NetForge data_dir).",
    )
    inst_p.add_argument(
        "--source",
        default=None,
        help="Optional path to a custom netforge_bridge.pts file.",
    )
    inst_p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    sub.add_parser("version", help="Print NetForge MCP version and schema version.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for `netforge-mcp` and `python -m netforge`."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    command = args.command or "serve"

    settings = NetForgeSettings.from_env()

    if command == "version":
        print(
            json.dumps(
                {
                    "name": "netforge-mcp",
                    "version": __version__,
                    "schema_version": __schema_version__,
                },
                indent=2,
            )
        )
        return 0

    if command == "doctor":
        print(json.dumps(build_doctor_report(settings), indent=2))
        return 0

    if command == "install-module":
        dest_arg = Path(args.dest_dir) if getattr(args, "dest_dir", None) else None
        src_arg = Path(args.source) if getattr(args, "source", None) else None
        info = install_script_module(settings, dest_dir=dest_arg, source_pts=src_arg)
        if getattr(args, "json", False):
            print(json.dumps(info, indent=2))
        else:
            print(
                f"Installed netforge_bridge.pts ({info['bytes_written']} bytes) -> "
                f"{info['module_path']}"
            )
            print("One-time Packet Tracer registration steps:")
            for line in info["steps"]:  # type: ignore[attr-defined]
                print(f"  {line}")
        return 0

    if command == "manifest":
        if getattr(args, "tool_profile", None):
            settings.tool_profile = args.tool_profile
        configure_logging(settings.log_level)
        _, runtime = create_mcp_server(settings)
        manifest_json = json.dumps(runtime.build_manifest(), indent=2)
        if args.output:
            Path(args.output).write_text(manifest_json, encoding="utf-8")
        else:
            print(manifest_json)
        return 0

    if command == "serve":
        if getattr(args, "data_dir", None):
            settings.data_dir = Path(args.data_dir).expanduser().resolve()
        if getattr(args, "tool_profile", None):
            settings.tool_profile = args.tool_profile
        if getattr(args, "profile", None):
            from netforge.security.permissions import PermissionPolicy

            policy = PermissionPolicy.from_profile(
                args.profile,
                require_destructive_confirmation=settings.require_destructive_confirmation,
            )
            settings.permission_profile = policy.profile_name
            settings.allowed_tiers = policy.allowed_tiers
        if getattr(args, "transport", None):
            settings.transport = args.transport
        if getattr(args, "host", None):
            settings.host = args.host
        if getattr(args, "port", None):
            settings.port = args.port

        configure_logging(settings.log_level, json_format=bool(getattr(args, "json_logs", False)))
        bridge = HttpScriptBridgeBackend(
            HttpScriptBridgeServer(session_file=settings.data_dir / "bridge_session.json"),
            auto_launch_pt=settings.auto_launch_packet_tracer,
            packet_tracer_path=settings.packet_tracer_path,
        )
        bridge.start()
        try:
            server, _ = create_mcp_server(settings, script_backend=bridge)

            if settings.transport == "stdio":
                server.run(transport="stdio")
            else:
                server.run(
                    transport=settings.transport,  # type: ignore[arg-type]
                    host=settings.host,
                    port=settings.port,
                )
        finally:
            bridge.stop()
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
