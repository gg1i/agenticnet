"""Unit tests for Phase 3 IOS output parsers, declarative schema, and `verify_lab`."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from agenticnet.adapters.base import ScriptBackend
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.mcp.server import create_mcp_server
from agenticnet.simulation.parsers import (
    canonicalize_interface_name,
    detect_cli_read_error,
    parse_ping_output,
    parse_running_config_sections,
    parse_show_ephone,
    parse_show_ip_dhcp_binding,
    parse_show_ip_int_brief,
    parse_show_ip_route,
    parse_show_telephony_service,
    parse_show_vlan_brief,
)


def _decode(call_result: Any) -> dict[str, Any]:
    assert call_result.structured_content is not None
    return dict(call_result.structured_content)


class _ScriptedCliBackend(ScriptBackend):
    """Fake ScriptBackend serving canned IOS responses per `(device, command)`."""

    def __init__(self, *, connected: bool = True) -> None:
        self.connected = connected
        self.responses: dict[tuple[str, str], dict[str, Any]] = {}
        self.executed: list[tuple[str, list[str]]] = []
        self.activity_payload: dict[str, Any] = {
            "state": "available",
            "readable": True,
            "locked": False,
            "percentage_complete": 100,
        }

    def is_connected(self) -> bool:
        return self.connected

    def ping(self) -> dict[str, Any]:
        return {"ok": self.connected, "backend": "script_http"}

    def add_device(
        self,
        model: str,
        *,
        device_type: int | str = 0,
        x: float = 100.0,
        y: float = 100.0,
    ) -> dict[str, Any]:
        return {"ok": True, "device_name": model}

    def create_link(
        self,
        device1: str,
        port1: str,
        device2: str,
        port2: str,
        *,
        conn_type: int | str = 8107,
    ) -> dict[str, Any]:
        return {"ok": True}

    def execute_cli(
        self,
        device_name: str,
        commands: list[str],
        *,
        wait_for_prompt: bool = True,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        self.executed.append((device_name, list(commands)))
        cmd = commands[-1].strip()
        payload = self.responses.get((device_name, cmd))
        if payload is None:
            raw = f"{device_name}#{cmd}\n% Invalid input detected at '^' marker.\n{device_name}#"
            return {
                "ok": True,
                "device_name": device_name,
                "raw_output": raw,
                "prompt": f"{device_name}#",
                "timed_out": False,
                "command_statuses": [{"command": cmd, "status": 0}],
            }
        return {
            "ok": True,
            "device_name": device_name,
            "prompt": f"{device_name}#",
            "timed_out": False,
            "command_statuses": [{"command": cmd, "status": 0}],
            **payload,
        }

    def read_activity_status(self) -> dict[str, Any]:
        return dict(self.activity_payload)


@pytest.mark.unit
def test_parsers_handle_pt_ios_quirks() -> None:
    assert canonicalize_interface_name("Gi0/0.20") == "gigabitethernet0/0.20"
    assert canonicalize_interface_name("Fa0/12") == "fastethernet0/12"
    assert canonicalize_interface_name("Vl100") == "vlan100"

    int_brief_raw = (
        "R1#show ip interface brief\r\n"
        "Interface              IP-Address      OK? Method Status                Protocol\r\n"
        "GigabitEthernet0/0     10.10.12.1      YES manual up                    up\r\n"
        " --More-- \r\n"
        "GigabitEthernet0/0.20  172.16.20.1     YES manual up                    up\r\n"
        "Vlan1                  unassigned      YES unset  administratively down down\r\n"
        "R1#\r\n"
    )
    ifaces = parse_show_ip_int_brief(int_brief_raw)
    assert len(ifaces) == 3
    assert ifaces[0].interface == "GigabitEthernet0/0"
    assert ifaces[0].is_up_up
    assert ifaces[1].ip_address == "172.16.20.1"
    assert not ifaces[2].is_up_up

    route_raw = (
        "Gateway of last resort is 10.10.12.2 to network 0.0.0.0\n\n"
        "     10.0.0.0/8 is variably subnetted, 2 subnets, 2 masks\n"
        "C       10.10.12.0/30 is directly connected, GigabitEthernet0/0\n"
        "L       10.10.12.1/32 is directly connected, GigabitEthernet0/0\n"
        "     172.16.0.0/24 is subnetted, 1 subnets\n"
        "C       172.16.20.0 is directly connected, GigabitEthernet0/0.20\n"
        "S    192.168.99.0/24 [1/0] via 10.10.12.2\n"
        "S*   0.0.0.0/0 [1/0] via 10.10.12.2, GigabitEthernet0/0\n"
    )
    rt = parse_show_ip_route(route_raw)
    assert "10.10.12.2" in str(rt["gateway_of_last_resort"])
    nets = {r.network: r for r in rt["routes"]}  # type: ignore[index]
    assert "10.10.12.0/30" in nets
    assert "172.16.20.0/24" in nets
    assert nets["192.168.99.0/24"].next_hop == "10.10.12.2"
    assert nets["0.0.0.0/0"].code == "S*"
    assert nets["0.0.0.0/0"].outgoing_interface == "GigabitEthernet0/0"

    vlan_raw = (
        "SW1#show vlan brief\n\n"
        "VLAN Name                             Status    Ports\n"
        "---- -------------------------------- --------- -------------------------------\n"
        "1    default                          active    Fa0/1, Fa0/3\n"
        "                                                Fa0/4, Fa0/5\n"
        "20   WORKSTATIONS                     active    Fa0/2\n"
        "1002 fddi-default                     act/unsup \n"
        "SW1#\n"
    )
    vlans = parse_show_vlan_brief(vlan_raw)
    vmap = {v.vlan_id: v for v in vlans}
    assert vmap[1].ports == ["Fa0/1", "Fa0/3", "Fa0/4", "Fa0/5"]
    assert vmap[20].name == "WORKSTATIONS"
    assert vmap[20].ports == ["Fa0/2"]
    assert vmap[1002].status == "act/unsup"

    dhcp_raw = (
        "IP address       Client-ID/              Lease expiration        Type\n"
        "                 Hardware address\n"
        "172.16.20.11     0001.4255.89A1           --                     Automatic\n"
        "172.16.20.12     0100.5056.ABCD.01        Infinite               Manual\n"
    )
    bindings = parse_show_ip_dhcp_binding(dhcp_raw)
    assert len(bindings) == 2
    assert bindings[0].ip_address == "172.16.20.11"
    assert bindings[0].binding_type == "Automatic"
    assert bindings[1].client_id == "0100.5056.ABCD.01"

    cfg_raw = (
        "Building configuration...\n"
        "!\n"
        "hostname GW\n"
        "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0\n"
        "!\n"
        "ip dhcp pool WORKSTATIONS\n"
        " network 172.16.20.0 255.255.255.0\n"
        " default-router 172.16.20.1\n"
        "!\n"
        "interface GigabitEthernet0/0.20\n"
        " encapsulation dot1Q 20\n"
        " ip address 172.16.20.1 255.255.255.0\n"
        "!\n"
        "telephony-service\n"
        " max-ephones 5\n"
        " max-dn 10\n"
        " ip source-address 10.50.100.1 port 2000\n"
        "!\n"
    )
    all_sec = parse_running_config_sections(cfg_raw)
    assert [s.header for s in all_sec][:2] == ["global", "ip dhcp pool WORKSTATIONS"]
    gi_sec = parse_running_config_sections(cfg_raw, section="interface Gi0/0.20")
    assert len(gi_sec) == 1
    assert "encapsulation dot1Q 20" in gi_sec[0].text

    tel_ok = parse_show_telephony_service(
        "CONFIG (Version=8.6)\n"
        "max-ephones 5\n"
        "max-dn 10\n"
        "ip source-address 10.50.100.1 port 2000\n"
        "auto assign 1 to 5\n"
    )
    assert tel_ok.configured is True
    assert tel_ok.source_address == "10.50.100.1"
    assert tel_ok.source_port == 2000
    assert tel_ok.max_ephones == 5

    tel_off = parse_show_telephony_service("% Telephony-service is not configured")
    assert tel_off.configured is False

    ephones = parse_show_ephone(
        "ephone-1[0] Mac:0001.64A1.2233 TCP socket:[1] activeLine:0 REGISTERED in SCCP ver 17\n"
        "IP:10.50.100.11 * 1024 7960 keepalive 3 max_line 2\n"
        "button 1: dn 1 number 1001 CH1 IDLE\n"
        "ephone-2 Mac:0001.64A1.2244 UNREGISTERED\n"
        "IP:0.0.0.0 0 7960   keepalive 43 max_line 2\n"
        " button 1: dn 2  number 1002 CH1   DOWN\n"
    )
    assert len(ephones) == 2
    assert ephones[0].status == "REGISTERED"
    assert ephones[0].ip_address == "10.50.100.11"
    assert ephones[0].buttons[0].number == "1001"
    assert ephones[1].status == "UNREGISTERED"
    assert ephones[1].device_model == "7960"
    assert ephones[1].buttons[0].number == "1002"

    ping_ok = parse_ping_output(
        "Sending 5, 100-byte ICMP Echos to 10.10.2.1, timeout is 2 seconds:\n"
        "!!!!!\n"
        "Success rate is 100 percent (5/5), round-trip min/avg/max = 0/1/4 ms\n"
    )
    assert ping_ok.reached is True
    assert ping_ok.received == 5

    assert detect_cli_read_error("% Invalid input detected at '^' marker.") is not None
    assert (
        detect_cli_read_error(
            "terminal length 0\n            ^\n% Invalid input detected at '^' marker.\nR1#ok"
        )
        is None
    )
    assert detect_cli_read_error("% Telephony-service is not configured") is None


@pytest.mark.unit
def test_verify_requirements_schema_tool_and_pass_fail_error_semantics(tmp_path: Path) -> None:
    backend = _ScriptedCliBackend(connected=True)
    backend.responses = {
        ("R1", "show ip interface brief"): {
            "raw_output": (
                "R1#show ip interface brief\n"
                "Interface              IP-Address      OK? Method Status                Protocol\n"
                "GigabitEthernet0/0     10.10.12.1      YES manual up                    up\n"
                "R1#\n"
            ),
        },
        ("R1", "show ip route"): {
            "raw_output": (
                "R1#show ip route\n"
                "C    10.10.12.0/30 is directly connected, GigabitEthernet0/0\n"
                "S    10.10.2.0/24 [1/0] via 10.10.12.2\n"
                "R1#\n"
            ),
        },
        ("R1", "ping 10.10.2.1"): {
            "raw_output": (
                "R1#ping 10.10.2.1\n"
                "Sending 5, 100-byte ICMP Echos to 10.10.2.1, timeout is 2 seconds:\n"
                "!!!!!\n"
                "Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/3 ms\n"
            ),
        },
        ("SW1", "show vlan brief"): {
            "raw_output": (
                "SW1#show vlan brief\n"
                "VLAN Name                             Status    Ports\n"
                "---- -------------------------------- --------- -------------------------------\n"
                "20   DATA                             active    Fa0/2\n"
                "SW1#\n"
            ),
        },
        ("R1", "show ip dhcp binding"): {
            "raw_output": (
                "R1#show ip dhcp binding\n"
                "IP address       Client-ID/              Lease expiration        Type\n"
                "172.16.20.11     0001.4255.89A1           --                     Automatic\n"
            ),
        },
        ("R1", "show running-config"): {
            "raw_output": (
                "hostname R1\n"
                "enable secret 5 $1$supersecret$hashvalue\n"
                "!\n"
                "interface GigabitEthernet0/0\n"
                " ip address 10.10.12.1 255.255.255.252\n"
                "!\n"
                "telephony-service\n"
                " ip source-address 10.50.100.1 port 2000\n"
                "!\n"
            ),
        },
        ("R1", "show telephony-service"): {
            "raw_output": "max-ephones 5\nmax-dn 10\nip source-address 10.50.100.1 port 2000\n",
        },
        ("R1", "show ephone"): {
            "raw_output": (
                "ephone-1 Mac:0001.64A1.2233 REGISTERED\n"
                "IP:10.50.100.11 * 1024 7960\n"
                "button 1: dn 1 number 1001 CH1 IDLE\n"
            ),
        },
    }

    settings = AgenticNetSettings(data_dir=tmp_path / ".nf", permission_profile="full")
    server, _ = create_mcp_server(settings=settings, script_backend=backend)

    async def _run() -> None:
        schema_res = _decode(await server.call_tool("verify_requirements_schema", {}))
        assert schema_res["success"] is True
        assert "reachable" in schema_res["data"]["supported_types"]
        assert len(schema_res["data"]["examples"]) >= 3

        reqs = {
            "lab_name": "AllChecks",
            "requirements": [
                {"type": "interface_up", "device": "R1", "interface": "Gi0/0"},
                {"type": "ip_assigned", "device": "R1", "interface": "Gi0/0", "ip": "10.10.12.1"},
                {
                    "type": "route_exists",
                    "device": "R1",
                    "network": "10.10.2.0/24",
                    "next_hop": "10.10.12.2",
                    "protocol_code": "S",
                },
                {"type": "vlan_exists", "device": "SW1", "vlan_id": 20, "ports": ["Fa0/2"]},
                {"type": "dhcp_binding", "device": "R1", "ip": "172.16.20.11"},
                {"type": "reachable", "from": "R1", "to": "10.10.2.1"},
                {
                    "type": "config_contains",
                    "device": "R1",
                    "section": "interface GigabitEthernet0/0",
                    "contains": ["ip address 10.10.12.1 255.255.255.252"],
                },
                {
                    "type": "telephony_service",
                    "device": "R1",
                    "source_address": "10.50.100.1",
                    "source_port": 2000,
                },
                {"type": "ephone_registered", "device": "R1", "ephone_id": 1, "number": "1001"},
            ],
        }
        pass_res = _decode(await server.call_tool("verify_lab", {"requirements": reqs}))
        assert pass_res["data"]["passed"] is True
        assert pass_res["data"]["verified_live"] is True
        assert pass_res["state_level"] == "verified"
        assert pass_res["execution_backend"] == "script_backend"
        assert pass_res["data"]["summary"] == {"total": 9, "passed": 9, "failed": 0, "errors": 0}
        # Verify show ip interface brief was cached across interface_up + ip_assigned
        r1_int_reads = [
            cmds
            for dev, cmds in backend.executed
            if dev == "R1" and "show ip interface brief" in cmds
        ]
        assert len(r1_int_reads) == 1
        # Verify running-config evidence had secrets redacted
        cfg_item = next(r for r in pass_res["data"]["results"] if r["type"] == "config_contains")
        assert "$1$supersecret$hashvalue" not in cfg_item["evidence"]

        # Fail scenario: ping 0/5 fails EVEN IF .pka score says 100% (non-bypass)
        backend.responses[("R1", "ping 10.10.2.1")] = {
            "raw_output": (
                "Sending 5, 100-byte ICMP Echos to 10.10.2.1, timeout is 2 seconds:\n"
                ".....\n"
                "Success rate is 0 percent (0/5)\n"
            ),
        }
        fail_res = _decode(await server.call_tool("verify_lab", {"requirements": reqs}))
        assert fail_res["data"]["passed"] is False
        assert fail_res["data"]["verified_live"] is True
        assert fail_res["data"]["summary"]["failed"] == 1
        assert fail_res["data"]["activity_grade"]["percentage_complete"] == 100
        ping_row = next(r for r in fail_res["data"]["results"] if r["type"] == "reachable")
        assert ping_row["status"] == "fail"
        assert "0 percent (0/5)" in ping_row["evidence"]

        # Error scenario: timed_out read -> status 'error', NEVER 'verified'
        backend.responses[("R1", "show ip route")] = {
            "raw_output": "",
            "timed_out": True,
        }
        err_res = _decode(await server.call_tool("verify_lab", {"requirements": reqs}))
        assert err_res["data"]["passed"] is False
        assert err_res["data"]["verified_live"] is False
        assert err_res["state_level"] != "verified"
        assert err_res["data"]["summary"]["errors"] == 1
        rt_row = next(r for r in err_res["data"]["results"] if r["type"] == "route_exists")
        assert rt_row["status"] == "error"

        # Offline scenario -> all error, state_level='planned'
        backend.connected = False
        off_res = _decode(await server.call_tool("verify_lab", {"requirements": reqs}))
        assert off_res["data"]["passed"] is False
        assert off_res["data"]["verified_live"] is False
        assert off_res["state_level"] == "planned"
        assert off_res["execution_backend"] == "offline_model"
        assert off_res["data"]["summary"]["errors"] == 9

        # Verify fallback from PT unsupported `show telephony-service` -> running-config
        backend.connected = True
        backend.responses[("R1", "show route_reset")] = {}
        backend.responses[("R1", "ping 10.10.2.1")] = {
            "raw_output": (
                "Sending 5, 100-byte ICMP Echos to 10.10.2.1:\n"
                "!!!!!\n"
                "Success rate is 100 percent (5/5)"
            )
        }
        backend.responses[("R1", "show ip route")] = {
            "raw_output": "S    10.10.2.0/24 [1/0] via 10.10.12.2\n"
        }
        backend.responses[("R1", "show telephony-service")] = {
            "raw_output": "show telephony-service\n^\n% Invalid input detected at '^' marker.\nR1#"
        }
        tel_only = _decode(
            await server.call_tool(
                "verify_lab",
                {
                    "requirements": [
                        {
                            "type": "telephony_service",
                            "device": "R1",
                            "source_address": "10.50.100.1",
                            "source_port": 2000,
                        }
                    ]
                },
            )
        )
        assert tel_only["data"]["passed"] is True
        assert "show running-config" in tel_only["data"]["results"][0]["command"]

    asyncio.run(_run())


@pytest.mark.unit
def test_new_verify_requirement_types_and_ping_target_sanitization() -> None:
    from agenticnet.adapters.router import BackendRouter
    from agenticnet.core.exceptions import ValidationError
    from agenticnet.diagnostics.verifier import LabVerifier
    from agenticnet.diagnostics.verify_schema import normalize_requirements_payload

    # Whitespace/newline injection in reachable/traceroute target fails schema validation
    with pytest.raises(ValidationError):
        normalize_requirements_payload(
            [{"type": "reachable", "from": "R1", "to": "10.0.0.1 ; reload"}]
        )
    with pytest.raises(ValidationError):
        normalize_requirements_payload(
            [{"type": "traceroute_hops", "from": "R1", "to": "10.0.0.1\nend"}]
        )

    backend = _ScriptedCliBackend(connected=True)
    backend.responses = {
        ("R1", "traceroute 10.10.20.1"): {
            "raw_output": (
                "Tracing the route to 10.10.20.1\n"
                "  1 10.10.12.2 1 msec 1 msec 1 msec\n"
                "  2 10.10.20.1 2 msec 2 msec 2 msec\n"
            )
        },
        ("SW1", "show interfaces trunk"): {
            "raw_output": (
                "Port        Mode         Encapsulation  Status        Native vlan\n"
                "Gi0/1       on           802.1q         trunking      99\n\n"
                "Port        Vlans allowed on trunk\n"
                "Gi0/1       10,20,99\n"
            )
        },
        ("SW1", "show spanning-tree"): {
            "raw_output": (
                "VLAN0010\n"
                "  Spanning tree enabled protocol rstp\n"
                "  Root ID    Priority    24586\n"
                "             Address     0001.42AA.1111\n"
                "             This bridge is the root\n"
            )
        },
        ("PC1", "ipconfig /all"): {
            "raw_output": (
                "FastEthernet0 Connection:(default port)\n"
                "   IPv4 Address....................: 10.10.10.50\n"
                "   Subnet Mask.....................: 255.255.255.0\n"
                "   Default Gateway.................: 10.10.10.1\n"
                "   DNS Servers.....................: 10.10.99.53\n"
            )
        },
    }
    verifier = LabVerifier(BackendRouter(script_backend=backend))
    rep = verifier.verify(
        [
            {
                "type": "traceroute_hops",
                "from": "R1",
                "to": "10.10.20.1",
                "expected_hops": ["10.10.12.2", "10.10.20.1"],
            },
            {
                "type": "trunk_exists",
                "device": "SW1",
                "interface": "Gi0/1",
                "native_vlan": 99,
                "allowed_vlans": [10, 20],
            },
            {"type": "stp_root", "device": "SW1", "vlan_id": 10, "expect_root": True},
            {
                "type": "host_ipconfig",
                "device": "PC1",
                "ip": "10.10.10.50",
                "default_gateway": "10.10.10.1",
                "dns_server": "10.10.99.53",
            },
        ]
    )
    assert rep["passed"] is True
    assert rep["summary"] == {"total": 4, "passed": 4, "failed": 0, "errors": 0}
