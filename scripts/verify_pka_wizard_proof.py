"""Ready-to-run Activity Wizard `.pka` grading proof for Lab 01 (`grade_lab` + break/fix).

Usage (once you author a `.pka` from Lab 01 in Packet Tracer's Activity Wizard):
    python scripts/verify_pka_wizard_proof.py path/to/lab01_wizard.pka

Expected flow:
  1. Launch Packet Tracer with the `.pka` open and connect the HTTP bridge.
  2. Apply Lab 01 baseline config via ScriptBackend so score reaches 100%.
  3. Prove broken state yields `percentage_complete < 100` with unmet leaves,
     and repaired state yields `percentage_complete == 100` with 0 unmet leaves.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from netforge.adapters.discovery import (
    gracefully_close_packet_tracer,
    require_interactive_desktop_for_launch,
)
from netforge.adapters.router import BackendRouter
from netforge.adapters.script_bridge import HttpScriptBridgeBackend, HttpScriptBridgeServer
from netforge.core.settings import NetForgeSettings
from netforge.diagnostics.grader import grade_open_activity
from netforge.gui.windows_backend import WindowsGuiBackend

ROOT = Path(__file__).resolve().parents[1]
LAB01_PATH = ROOT / "labs" / "01_static_routing.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify grade_lab break->fix proof on a .pka.")
    parser.add_argument("pka_path", type=Path, help="Path to user-authored Activity Wizard .pka.")
    parser.add_argument("--wait-seconds", type=float, default=15.0)
    args = parser.parse_args()

    pka = args.pka_path.expanduser().resolve()
    if not pka.exists():
        print(f"ERROR: .pka file not found: {pka}", file=sys.stderr)
        return 2

    require_interactive_desktop_for_launch("verify_pka_wizard_proof")
    lab = json.loads(LAB01_PATH.read_text(encoding="utf-8"))
    settings = NetForgeSettings.from_env()
    gui = WindowsGuiBackend(settings=settings)
    bridge = HttpScriptBridgeBackend(
        HttpScriptBridgeServer(session_file=settings.data_dir / "bridge_session.json"),
        default_timeout_seconds=25.0,
    )
    bridge.start()
    launch_res: dict[str, object] = {}
    try:
        launch_res = gui.launch_application(project_file=str(pka), wait_seconds=args.wait_seconds)
        deadline = time.monotonic() + 35.0
        while time.monotonic() < deadline and not (
            bridge.is_connected() and bridge.ping().get("ok")
        ):
            time.sleep(0.3)
        if not bridge.is_connected():
            print("ERROR: Script bridge did not connect.", file=sys.stderr)
            return 3

        router = BackendRouter(script_backend=bridge)
        for dev, cmds in lab["configs"].items():
            bridge.execute_cli(dev, cmds, timeout_seconds=25.0)
        time.sleep(float(lab.get("settle_seconds", 3.0)))

        ok_grade = grade_open_activity(router)
        print("INITIAL_CONFIGURED_GRADE:", json.dumps(ok_grade, indent=2))

        brk = lab["break_step"]
        bridge.execute_cli(brk["device"], brk["commands"], timeout_seconds=25.0)
        time.sleep(1.5)
        broken_grade = grade_open_activity(router)
        print("BROKEN_GRADE:", json.dumps(broken_grade, indent=2))

        fix = lab["fix_step"]
        bridge.execute_cli(fix["device"], fix["commands"], timeout_seconds=25.0)
        time.sleep(float(fix.get("settle_seconds", 3.0)))
        fixed_grade = grade_open_activity(router)
        print("FIXED_GRADE:", json.dumps(fixed_grade, indent=2))

        if broken_grade.get("state") != "available" or fixed_grade.get("state") != "available":
            print("FAIL: Activity grade unavailable (locked/Assessment-mode or unreadable).")
            return 4
        if not (float(broken_grade.get("percentage_complete") or 0.0) < 100.0):
            print("FAIL: Broken network did not drop .pka score below 100%.")
            return 5
        if float(fixed_grade.get("percentage_complete") or 0.0) < 100.0:
            print("FAIL: Repaired network did not reach 100%.")
            return 6
        print("PASS: Activity Wizard .pka break->score<100->fix->100% verified!")
        return 0
    finally:
        bridge.stop()
        if launch_res.get("launched") and isinstance(launch_res.get("pid"), int):
            gracefully_close_packet_tracer([int(launch_res["pid"])], timeout_seconds=5.0)


if __name__ == "__main__":
    raise SystemExit(main())
