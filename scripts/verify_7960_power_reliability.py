"""5-attempt live reliability verification for gui_attach_ip_phone_power on Windows.

Requires an unlocked interactive Windows desktop (`GetForegroundWindow() != 0`)
because Packet Tracer's Qt Physical-tab power-adapter drag requires real cursor
movement via `SendInput`. Each of the 5 attempts starts a clean Packet Tracer
instance with an unpowered Cisco 7960 IP Phone, runs `show ephone` before and
after a single `attach_ip_phone_power` call (no internal retries, no coordinate
tuning between attempts), and reports exact `X/5` `UNREGISTERED -> REGISTERED`.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
import time
from pathlib import Path

from netforge.adapters.script_bridge import HttpScriptBridgeBackend, HttpScriptBridgeServer
from netforge.core.settings import NetForgeSettings
from netforge.gui.windows_backend import WindowsGuiBackend
from netforge.simulation.parsers import parse_show_ephone

ATTEMPTS = 5
CME_COMMANDS = [
    "configure terminal",
    "no ip domain-lookup",
    "interface GigabitEthernet0/0",
    "ip address 10.79.60.1 255.255.255.0",
    "no shutdown",
    "exit",
    "ip dhcp excluded-address 10.79.60.1 10.79.60.10",
    "ip dhcp pool VOICE",
    "network 10.79.60.0 255.255.255.0",
    "default-router 10.79.60.1",
    "option 150 ip 10.79.60.1",
    "exit",
    "telephony-service",
    "max-ephones 5",
    "max-dn 5",
    "ip source-address 10.79.60.1 port 2000",
    "auto assign 1 to 5",
    "auto-reg-ephone",
    "exit",
    "ephone-dn 1",
    "number 1001",
    "end",
]


def _wait_bridge(bridge: HttpScriptBridgeBackend, timeout_s: float = 35.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if bridge.is_connected():
            bridge.ping()
            return
        time.sleep(0.5)
    raise RuntimeError("Packet Tracer script bridge did not connect within timeout.")


def _find_pt_exe() -> Path:
    candidates = [
        Path(r"C:\Program Files\Cisco Packet Tracer 8.2.2\bin\PacketTracer.exe"),
        Path(r"C:\Program Files\Cisco Packet Tracer 8.2.1\bin\PacketTracer.exe"),
    ]
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError("Cisco Packet Tracer binary not found.")


def _run_attempt(attempt: int, settings: NetForgeSettings, pt_exe: Path) -> bool:
    session_file = settings.data_dir / "bridge_session.json"
    server = HttpScriptBridgeServer(session_file=session_file)
    bridge = HttpScriptBridgeBackend(server)
    gui = WindowsGuiBackend(settings)
    bridge.start()
    proc = subprocess.Popen([str(pt_exe)])
    try:
        _wait_bridge(bridge)
        r_res = bridge.add_device("2911", device_type=0, x=220.0, y=180.0)
        s_res = bridge.add_device("2960-24TT", device_type=1, x=360.0, y=180.0)
        p_res = bridge.add_device("7960", device_type=12, x=500.0, y=180.0)
        r_name = r_res["device_name"]
        s_name = s_res["device_name"]
        p_name = p_res["device_name"]

        bridge.create_link(r_name, "GigabitEthernet0/0", s_name, "FastEthernet0/1", conn_type=8100)
        bridge.create_link(s_name, "FastEthernet0/2", p_name, "Switch", conn_type=8100)

        cli_res = bridge.execute_cli(
            r_name,
            CME_COMMANDS,
            ensure_privileged=True,
            timeout_seconds=35.0,
        )
        if not cli_res.get("ok"):
            print(f"[Attempt {attempt}] Router CME setup failed: {cli_res}")
            return False

        # Ensure Switch Fa0/2 is up / spanning-tree portfast for fast DHCP.
        bridge.execute_cli(
            s_name,
            [
                "configure terminal",
                "interface FastEthernet0/2",
                "switchport mode access",
                "spanning-tree portfast",
                "no shutdown",
                "end",
            ],
            ensure_privileged=True,
            timeout_seconds=20.0,
        )

        before_cli = bridge.execute_cli(r_name, ["show ephone"], ensure_privileged=True)
        before_raw = str(before_cli.get("raw_output", ""))
        before_parsed = parse_show_ephone(before_raw)
        before_reg = any(e.registered for e in before_parsed)
        print(f"--- Attempt {attempt}: show ephone BEFORE ({p_name}) ---")
        print(before_raw.strip())
        if before_reg:
            print(f"[Attempt {attempt}] Unexpected: phone already REGISTERED before GUI attach.")
            return False

        drag_out = gui.attach_ip_phone_power(
            device_name=p_name,
            pt_device_title=p_name,
            canvas_x=500.0,
            canvas_y=180.0,
            close_dialog=True,
            restore_focus=True,
            dry_run=False,
        )
        print(f"[Attempt {attempt}] gui_attach_ip_phone_power result: {drag_out}")

        registered = False
        after_raw = ""
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            after_cli = bridge.execute_cli(r_name, ["show ephone"], ensure_privileged=True)
            after_raw = str(after_cli.get("raw_output", ""))
            after_parsed = parse_show_ephone(after_raw)
            if any(e.registered for e in after_parsed):
                registered = True
                break
            time.sleep(2.0)

        print(f"--- Attempt {attempt}: show ephone AFTER ({p_name}) ---")
        print(after_raw.strip())
        status = "REGISTERED" if registered else "UNREGISTERED (FAILED)"
        print(f"[Attempt {attempt}] RESULT: {status}")
        return registered
    finally:
        bridge.stop()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(1.0)


def main() -> int:
    if ctypes.windll.user32.GetForegroundWindow() == 0:
        print(
            "ERROR: GetForegroundWindow() == 0. Desktop is locked, asleep, or isolated "
            "(e.g. WinSta0\\exebox-*). Run from an unlocked interactive Windows session."
        )
        return 2

    settings = NetForgeSettings.from_env()
    pt_exe = _find_pt_exe()
    passed = 0
    for idx in range(1, ATTEMPTS + 1):
        try:
            if _run_attempt(idx, settings, pt_exe):
                passed += 1
        except Exception as exc:
            print(f"[Attempt {idx}] EXCEPTION: {exc}")
    print(f"\nFINAL 7960 POWER RELIABILITY SCORE: {passed}/{ATTEMPTS}")
    return 0 if passed == ATTEMPTS else 1


if __name__ == "__main__":
    sys.exit(main())
