"""Command-line entry point for launching and inspecting AgenticNet."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import sys
from collections.abc import Sequence
from importlib import resources
from pathlib import Path
from typing import Any

from agenticnet import __schema_version__, __version__
from agenticnet.adapters.discovery import (
    detect_packet_tracer_binary as _detect_packet_tracer_binary,
)
from agenticnet.adapters.discovery import (
    is_packet_tracer_running as _is_packet_tracer_running,
)
from agenticnet.adapters.script_bridge import (
    HttpScriptBridgeBackend,
    HttpScriptBridgeServer,
    probe_bridge_health,
    render_script_module_sources,
)
from agenticnet.core.logging import configure_logging
from agenticnet.core.settings import AgenticNetSettings, canonical_pt_bridge_data_dir
from agenticnet.mcp.server import create_mcp_server
from agenticnet.security.redaction import redact_path_home


def _is_dir_writable(target: Path) -> bool:
    """Return True if target or its nearest existing ancestor directory is writable."""
    probe = target
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    return probe.exists() and os.access(probe, os.W_OK)


def build_doctor_report(settings: AgenticNetSettings) -> dict[str, object]:
    """Run live environment probes with home/user path redaction and honest status."""
    pt_exe = _detect_packet_tracer_binary(settings.packet_tracer_path)
    pt_running = _is_packet_tracer_running()
    session_file = settings.data_dir / "bridge_session.json"
    bridge_probe = probe_bridge_health(session_file)
    data_writable = _is_dir_writable(settings.data_dir)
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "agenticnet_version": __version__,
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
    settings: AgenticNetSettings,
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
        asset = resources.files("agenticnet.adapters.assets").joinpath("netforge_bridge.pts")
        if not asset.is_file():
            raise FileNotFoundError(
                "Bundled netforge_bridge.pts asset not found in agenticnet.adapters.assets."
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
        (
            "3. One-time re-registration: if an older entry "
            "(such as com.yourcompany.newptscriptmodule0 or a prior netforge_bridge.pts) "
            "is listed, Remove it first; then click Add and select: "
            f"{dest_pts} (canonical module ID: com.netforge.bridge; "
            "when exporting from Script Module Editor -> Info tab, set ID to "
            "`com.netforge.bridge` and import bridge_src/netforge_bridge.js + bridge.html)."
        ),
        "4. Enable 'On Startup' (State: On) and accept the requested script privileges.",
        (
            "5. Restart Packet Tracer once; future `agenticnet serve` runs "
            "auto-connect cleanly without spawning a WebView unless a fresh session exists."
        ),
    ]
    return {
        "installed": True,
        "module_id": "com.netforge.bridge",
        "module_path": str(dest_pts),
        "redacted_module_path": redact_path_home(dest_pts),
        "bridge_src_dir": str(src_paths["js"].parent),
        "bytes_written": len(raw_bytes),
        "steps": steps,
    }


SUPPORTED_MCP_CLIENTS: tuple[str, ...] = ("none", "antigravity", "claude", "cursor", "vscode")


def _probe_gui_dependencies() -> dict[str, bool]:
    """Check which optional GUI fallback dependencies are importable."""
    modules = ["PIL", "cv2", "numpy", "psutil"]
    if platform.system() == "Windows":
        modules.append("win32gui")
    return {mod: importlib.util.find_spec(mod) is not None for mod in modules}


def resolve_mcp_client_config_path(
    client: str,
    *,
    cwd: Path | None = None,
) -> Path | None:
    """Resolve the standard MCP config file path for a supported desktop client."""
    normalized = client.strip().lower()
    home = Path.home()
    if normalized == "none":
        return None
    if normalized == "antigravity":
        return home / ".gemini" / "antigravity" / "mcp_config.json"
    if normalized == "cursor":
        return home / ".cursor" / "mcp.json"
    if normalized == "vscode":
        return (cwd or Path.cwd()).resolve() / ".vscode" / "mcp.json"
    if normalized == "claude":
        sys_name = platform.system()
        if sys_name == "Windows":
            appdata = os.environ.get("APPDATA")
            base = Path(appdata) if appdata else (home / "AppData" / "Roaming")
            return base / "Claude" / "claude_desktop_config.json"
        if sys_name == "Darwin":
            return (
                home
                / "Library"
                / "Application Support"
                / "Claude"
                / "claude_desktop_config.json"
            )
        return home / ".config" / "Claude" / "claude_desktop_config.json"
    raise ValueError(f"Unsupported MCP client '{client}'. Expected one of {SUPPORTED_MCP_CLIENTS}.")


def build_mcp_server_entry(
    settings: AgenticNetSettings,
    *,
    python_executable: str | None = None,
    pt_executable: str | None = None,
    client: str = "none",
    include_data_dir: bool = False,
) -> dict[str, Any]:
    """Build a portable stdio MCP server config block using the active Python interpreter."""
    env: dict[str, str] = {
        "AGENTICNET_TOOL_PROFILE": settings.tool_profile,
        "AGENTICNET_PERMISSION_PROFILE": settings.permission_profile,
        "AGENTICNET_REQUIRE_CONFIRM": str(settings.require_destructive_confirmation).lower(),
    }
    if pt_executable:
        env["AGENTICNET_PT_PATH"] = pt_executable
    if include_data_dir:
        env["AGENTICNET_DATA_DIR"] = str(settings.data_dir)

    entry: dict[str, Any] = {
        "command": python_executable or sys.executable,
        "args": ["-m", "agenticnet", "serve", "--transport", "stdio"],
        "env": env,
    }
    if client.strip().lower() == "vscode":
        return {"type": "stdio", **entry}
    return entry


def write_mcp_client_config(
    config_path: Path,
    server_entry: dict[str, Any],
    *,
    client: str,
    server_name: str = "agenticnet",
) -> dict[str, Any]:
    """Safely merge the AgenticNet server block into an existing or new MCP client config."""
    root_key = "servers" if client.strip().lower() == "vscode" else "mcpServers"
    data: dict[str, Any] = {}
    backup_path: Path | None = None

    if config_path.is_file():
        raw = config_path.read_text(encoding="utf-8").strip()
        if raw:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError(f"Expected JSON object in {config_path}.")
            data = parsed
        backup_path = config_path.with_name(f"{config_path.name}.bak")
        shutil.copy2(config_path, backup_path)

    servers = data.setdefault(root_key, {})
    if not isinstance(servers, dict):
        raise ValueError(f"Expected '{root_key}' to be a JSON object in {config_path}.")
    servers[server_name] = server_entry

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return {
        "config_path": str(config_path),
        "root_key": root_key,
        "backup_path": str(backup_path) if backup_path else None,
    }


def run_guided_setup(
    settings: AgenticNetSettings,
    *,
    client: str = "none",
    custom_data_dir: bool = False,
    dry_run: bool = False,
    cwd: Path | None = None,
) -> dict[str, Any]:
    """Perform one-command AgenticNet setup: bridge module install, probe, and MCP client config."""
    pt_exe = _detect_packet_tracer_binary(settings.packet_tracer_path)
    gui_deps = _probe_gui_dependencies()
    canonical_dir = canonical_pt_bridge_data_dir()
    primary_pts = settings.data_dir / "netforge_bridge.pts"
    canonical_pts = canonical_dir / "netforge_bridge.pts"

    module_info: dict[str, Any] = {
        "installed": False,
        "module_path": str(primary_pts),
        "redacted_module_path": redact_path_home(primary_pts),
        "mirrored_canonical_path": (
            str(canonical_pts) if canonical_dir.resolve() != settings.data_dir.resolve() else None
        ),
        "dry_run": dry_run,
    }
    if not dry_run:
        installed = install_script_module(settings)
        module_info.update(installed)
        if canonical_dir.resolve() != settings.data_dir.resolve():
            canonical_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(primary_pts, canonical_pts)
            module_info["mirrored_canonical_path"] = str(canonical_pts)

    config_path = resolve_mcp_client_config_path(client, cwd=cwd)
    server_entry = build_mcp_server_entry(
        settings,
        pt_executable=pt_exe,
        client=client,
        include_data_dir=custom_data_dir,
    )
    root_key = "servers" if client.strip().lower() == "vscode" else "mcpServers"
    snippet = {root_key: {"agenticnet": server_entry}}

    client_result: dict[str, Any] = {
        "client": client,
        "configured": False,
        "config_path": str(config_path) if config_path else None,
        "redacted_config_path": redact_path_home(config_path),
        "backup_path": None,
        "dry_run": dry_run,
    }
    if config_path is not None and not dry_run:
        written = write_mcp_client_config(config_path, server_entry, client=client)
        client_result.update(
            {
                "configured": True,
                "config_path": written["config_path"],
                "backup_path": written["backup_path"],
            }
        )

    missing_gui = [k for k, ok in gui_deps.items() if not ok]
    return {
        "dry_run": dry_run,
        "python": sys.executable,
        "tool_profile": settings.tool_profile,
        "permission_profile": settings.permission_profile,
        "packet_tracer_detected": pt_exe is not None,
        "packet_tracer_path": redact_path_home(pt_exe),
        "gui_dependencies": gui_deps,
        "gui_ready": len(missing_gui) == 0,
        "missing_gui_dependencies": missing_gui,
        "module": module_info,
        "mcp_client": client_result,
        "mcp_config_snippet": snippet,
    }


def build_parser() -> argparse.ArgumentParser:
    """Construct the AgenticNet CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="agenticnet",
        description=(
            "AgenticNet — An open-source agentic networking platform (Cisco Packet Tracer)."
        ),
    )
    sub = parser.add_subparsers(dest="command")

    serve_p = sub.add_parser("serve", help="Run the AgenticNet server.")
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
        help="Copy netforge_bridge.pts to the AgenticNet data directory and print setup steps.",
    )
    inst_p.add_argument(
        "--dest-dir",
        default=None,
        help="Override target directory (default: AgenticNet data_dir).",
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

    setup_p = sub.add_parser(
        "setup",
        help="One-command setup: install PT script module, detect PT, and configure MCP client.",
    )
    setup_p.add_argument(
        "--client",
        choices=list(SUPPORTED_MCP_CLIENTS),
        default="none",
        help="MCP client config to update automatically (default: none, prints JSON snippet).",
    )
    setup_p.add_argument(
        "--tool-profile",
        choices=["solve_lab", "advanced"],
        default=None,
        help="Tool exposure profile for generated MCP config (default: current/solve_lab).",
    )
    setup_p.add_argument(
        "--profile",
        choices=["read-only", "planning", "configuration", "standard"],
        default=None,
        help="Permission profile for generated MCP config (default: current/standard).",
    )
    setup_p.add_argument(
        "--data-dir",
        default=None,
        help="Optional custom AGENTICNET_DATA_DIR to store SQLite DB and bridge files.",
    )
    setup_p.add_argument(
        "--pt-path",
        default=None,
        help="Optional explicit PacketTracer.exe path.",
    )
    setup_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview detected paths and generated MCP config without writing files.",
    )
    setup_p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    sub.add_parser("version", help="Print AgenticNet version and schema version.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for `agenticnet`, `agenticnet-mcp`, and `python -m agenticnet`."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    command = args.command or "serve"

    settings = AgenticNetSettings.from_env()

    if command == "version":
        print(
            json.dumps(
                {
                    "name": "agenticnet",
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

    if command == "setup":
        custom_data_dir = bool(getattr(args, "data_dir", None))
        if custom_data_dir:
            settings.data_dir = Path(args.data_dir).expanduser().resolve()
        if getattr(args, "tool_profile", None):
            settings.tool_profile = args.tool_profile
        if getattr(args, "profile", None):
            settings.permission_profile = args.profile
        if getattr(args, "pt_path", None):
            settings.packet_tracer_path = args.pt_path

        summary = run_guided_setup(
            settings,
            client=args.client,
            custom_data_dir=custom_data_dir,
            dry_run=bool(getattr(args, "dry_run", False)),
        )
        if getattr(args, "json", False):
            print(json.dumps(summary, indent=2))
            return 0

        mod = summary["module"]
        cli_info = summary["mcp_client"]
        prefix = "[DRY-RUN] " if summary["dry_run"] else ""
        print(f"{prefix}AgenticNet Setup Summary")
        print(f"  Python:         {summary['python']}")
        print(
            "  Packet Tracer:  "
            + (
                f"Detected ({summary['packet_tracer_path']})"
                if summary["packet_tracer_detected"]
                else "Not detected (offline planning works; set AGENTICNET_PT_PATH if installed)"
            )
        )
        print(f"  PT Script Mod:  {mod['module_path']}")
        if mod.get("mirrored_canonical_path"):
            print(f"  PT Mirror Path: {mod['mirrored_canonical_path']}")
        print(
            "  GUI Fallback:   "
            + (
                "Ready"
                if summary["gui_ready"]
                else (
                    "Optional extras missing ("
                    + ", ".join(summary["missing_gui_dependencies"])
                    + ") -> install with: pip install \".[gui]\""
                )
            )
        )
        if cli_info["configured"]:
            print(f"  MCP Client:     Updated {cli_info['client']} at {cli_info['config_path']}")
        elif cli_info["config_path"]:
            print(
                f"  MCP Client:     Would update {cli_info['client']} at {cli_info['config_path']}"
            )
        else:
            print("  MCP Client Config Snippet (paste into your client's MCP JSON):")
            print(json.dumps(summary["mcp_config_snippet"], indent=2))

        if summary["packet_tracer_detected"]:
            pts_select = mod.get("mirrored_canonical_path") or mod["module_path"]
            print("\nNext (one-time inside Packet Tracer 8.2.2+):")
            print("  1. Extensions -> Scripting -> Configure PT Script Modules...")
            print(f"  2. Click Add -> select {pts_select}")
            print("  3. Check 'On Startup', click Save, accept privileges, and restart PT.")
        print("Then run: agenticnet doctor")
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
            from agenticnet.security.permissions import PermissionPolicy

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
        primary_session = settings.data_dir / "bridge_session.json"
        canonical_session = canonical_pt_bridge_data_dir() / "bridge_session.json"
        mirrors = (
            [canonical_session]
            if canonical_session.resolve() != primary_session.resolve()
            else None
        )
        bridge = HttpScriptBridgeBackend(
            HttpScriptBridgeServer(
                session_file=primary_session,
                mirror_session_files=mirrors,
            ),
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
