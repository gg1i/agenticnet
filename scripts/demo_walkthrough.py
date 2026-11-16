"""AgenticNet End-to-End Walkthrough Demonstration Script.

Runs the complete network automation workflow:
PLAN -> DESIGN -> VALIDATE -> BUILD -> CONFIGURE -> DIAGNOSE -> VISUALIZE -> SAVE
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add repo root to path for local execution
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agenticnet.core.settings import AgenticNetSettings
from agenticnet.mcp.server import create_mcp_server


def main() -> int:
    print("=" * 70)
    print("AGENTICNET — LIVE AUTOMATION WALKTHROUGH")
    print("=" * 70)

    # Initialize in-memory runtime with isolated settings
    server, runtime = create_mcp_server(AgenticNetSettings.from_env())

    # Step 1: Create or Open a Project
    import time

    demo_pid = f"demo-campus-{int(time.time())}"
    print(f"\n[1] Creating Project: '{demo_pid}'...")
    res = runtime.manager.create_project(
        name="Campus-Network-2026",
        project_id=demo_pid,
        description="Multi-VLAN Campus Network with OSPF routing and NAT",
    )
    print(f"    -> Project ID: {res.metadata.project_id} (schema v{res.schema_version})")

    # Step 2: VLSM Subnet Planning
    print("\n[2] Planning VLSM Subnets from 10.10.0.0/22...")
    _, topo, ipam, _ = runtime.manager.require_active()
    from agenticnet.ipam.engine import plan_vlsm
    from agenticnet.ipam.models import SubnetRequirement

    requirements = [
        SubnetRequirement(name="Students-VLAN10", required_hosts=120, vlan_id=10),
        SubnetRequirement(name="Faculty-VLAN20", required_hosts=60, vlan_id=20),
        SubnetRequirement(name="Admin-VLAN30", required_hosts=25, vlan_id=30),
        SubnetRequirement(name="WAN-Link", required_hosts=2),
    ]
    plan = plan_vlsm("10.10.0.0/22", requirements)
    for alloc in plan.allocations:
        ipam.register_pool(
            alloc.name,
            alloc.allocated_cidr,
            vlan_id=alloc.vlan_id,
            gateway=alloc.gateway,
        )
        print(f"    - {alloc.name:15}: {alloc.allocated_cidr:18} GW: {alloc.gateway}")

    # Step 3: Build Topology
    print("\n[3] Constructing Network Topology (Auto MDI/MDI-X Cabling)...")
    topo.add_device("R1-CORE", "2911", role="Core Gateway")
    topo.add_device("SW-DIST-01", "3560-24PS", role="Distribution L3 Switch")
    topo.add_device("SW-ACC-01", "2960-24TT", role="Access Layer Switch")
    topo.add_device("PC-FACULTY", "PC-PT", role="Faculty Workstation")
    topo.add_device("SRV-WEB", "Server-PT", role="Campus Web Server")

    c1 = topo.connect("R1-CORE", "GigabitEthernet0/0", "SW-DIST-01", "GigabitEthernet0/1")
    c2 = topo.connect("SW-DIST-01", "GigabitEthernet0/2", "SW-ACC-01", "GigabitEthernet0/1")
    c3 = topo.connect("SW-ACC-01", "FastEthernet0/1", "PC-FACULTY", "FastEthernet0")
    c4 = topo.connect("SW-DIST-01", "FastEthernet0/1", "SRV-WEB", "FastEthernet0")

    print(f"    - Added 5 devices: {list(topo.model.devices.keys())}")
    print(f"    - Created Link 1: R1 <-> SW-DIST ({c1.cable_type.value})")
    print(f"    - Created Link 2: SW-DIST <-> SW-ACC ({c2.cable_type.value})")
    print(f"    - Created Link 3: SW-ACC <-> PC-FACULTY ({c3.cable_type.value})")
    print(f"    - Created Link 4: SW-DIST <-> SRV-WEB ({c4.cable_type.value})")

    # Step 4: Generate Validated Cisco IOS Configs
    print("\n[4] Generating Validated Cisco IOS Configuration...")
    from agenticnet.ios.models import OspfConfigSpec, OspfNetworkEntry, VlanSpec

    # Configure VLANs on L3 switch
    vlans = [VlanSpec(vlan_id=10, name="Students"), VlanSpec(vlan_id=20, name="Faculty")]
    vlan_seq = runtime.ios.vlans("SW-DIST-01", "3560-24PS", vlans)
    print("    - SW-DIST-01 VLAN commands:\n      " + "\n      ".join(vlan_seq.commands[:4]))

    # Configure OSPF routing on Core Router
    ospf_spec = OspfConfigSpec(
        device_name="R1-CORE",
        process_id=1,
        router_id="1.1.1.1",
        networks=[
            OspfNetworkEntry(network="10.10.0.0/22", area=0),
        ],
        passive_interfaces=["GigabitEthernet0/1"],
    )
    ospf_seq = runtime.ios.ospf(ospf_spec, "2911")
    print("    - R1-CORE OSPF commands:\n      " + "\n      ".join(ospf_seq.commands))

    # Step 5: Run Network Diagnostics
    print("\n[5] Running Automated Diagnostics...")
    diag_report = runtime.diagnostics.run_diagnostics(topology=topo, ipam=ipam)
    print(f"    - Total findings: {len(diag_report.findings)}")
    print(f"    - Proposed repairs: {len(diag_report.proposed_repairs)}")
    for p in diag_report.proposed_repairs[:2]:
        print(f"      * {p.proposal_id}: {p.summary}")

    # Step 6: Render Mermaid Diagram
    print("\n[6] Rendering Mermaid Diagram Preview:")
    mermaid = topo.to_mermaid()
    for line in mermaid.splitlines()[:10]:
        print(f"    {line}")
    print("    ...")

    # Step 7: Persist Project
    print("\n[7] Persisting Project State...")
    save_info = runtime.manager.save_project(create_backup=True)
    print(f"    - Saved to SQLite DB: {save_info['db_path']}")
    print(f"    - Backup archive: {save_info['backup_path']}")

    print("\n" + "=" * 70)
    print("DEMO COMPLETE: AgenticNet fully operational!")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
