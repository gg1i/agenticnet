"""Generate the NetForge MCP machine-readable capability manifest JSON."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netforge.core.settings import NetForgeSettings
from netforge.mcp.server import create_mcp_server


def main() -> int:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/manifest.json")
    settings = NetForgeSettings.from_env()
    settings.tool_profile = "advanced"
    _, runtime = create_mcp_server(settings)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(runtime.build_manifest(), indent=2), encoding="utf-8")
    print(f"Wrote NetForge MCP manifest to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
