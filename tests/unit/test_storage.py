"""Unit tests for SQLite persistence, schema migration, backups, and secret scrubbing."""

from __future__ import annotations

from pathlib import Path

import pytest

from agenticnet.core.enums import OperationStatus, PermissionTier, StateLevel
from agenticnet.core.exceptions import ProjectNotFoundError, StorageError
from agenticnet.core.models import ExecutionLogEntry
from agenticnet.core.settings import AgenticNetSettings
from agenticnet.ios import IOSGenerator, SshConfigSpec
from agenticnet.storage import ProjectManager, migrate_project_payload


@pytest.mark.unit
def test_project_manager_lifecycle_and_secret_scrubbing(
    isolated_settings: AgenticNetSettings,
) -> None:
    mgr = ProjectManager(isolated_settings)
    mgr.create_project("Campus Demo", project_id="campus-demo", description="Unit test lab")

    _, topo, ipam, _ = mgr.require_active()
    topo.add_device("R1", "2911")
    topo.add_device("SW1", "2960-24TT")
    topo.connect("R1", "Gi0/0", "SW1", "Gi0/1")
    ipam.register_pool("LAN", "192.168.1.0/24", vlan_id=10)
    ipam.allocate_address("R1", "Gi0/0", "192.168.1.1/24")

    # Record SSH sequence containing secret -> SQLite must NOT store plaintext secret!
    seq = IOSGenerator().ssh(
        SshConfigSpec(
            device_name="R1",
            domain_name="lab.local",
            username="netops",
            secret="UltraSecret999",
            enable_secret="EnablePass888",
        ),
        "2911",
    )
    snap_id = mgr.record_generated_sequence(seq)
    mgr.store.append_execution_log(
        ExecutionLogEntry(
            operation_id="op_test01",
            project_id="campus-demo",
            tool_name="configure_ssh",
            permission_tier=PermissionTier.CONFIGURATION,
            status=OperationStatus.SUCCEEDED,
            state_level=StateLevel.PLANNED,
            summary="Generated SSH",
            params_redacted={"secret": "UltraSecret999"},
        )
    )

    save_info = mgr.save_project(create_backup=True, checkpoint_label="after_ssh")
    assert Path(save_info["backup_path"]).exists()

    raw_db_text = isolated_settings.db_path.read_bytes()
    assert b"UltraSecret999" not in raw_db_text
    assert b"EnablePass888" not in raw_db_text

    # Export YAML & close & reopen from SQLite
    exported = mgr.export_project(fmt="yaml")
    mgr.close_project()
    assert not mgr.has_active_project

    reopened = mgr.open_project("campus-demo")
    assert len(reopened.topology.devices) == 2
    assert len(reopened.topology.connections) == 1
    assert any(s.snapshot_id == snap_id for s in reopened.config_snapshots)

    # Import into a fresh project manager
    mgr.store.delete_project("campus-demo")
    with pytest.raises(ProjectNotFoundError):
        mgr.open_project("campus-demo")

    imported = mgr.import_project(content=exported["content"])
    assert imported.metadata.project_id == "campus-demo"
    assert len(imported.topology.devices) == 2


@pytest.mark.unit
def test_example_yaml_import_and_schema_migration(isolated_settings: AgenticNetSettings) -> None:
    example_path = Path(__file__).resolve().parents[2] / "examples" / "university_topology.yaml"
    assert example_path.exists()

    mgr = ProjectManager(isolated_settings)
    bundle = mgr.import_project(file_path=str(example_path))
    assert bundle.metadata.project_id == "university-core-demo"
    assert len(bundle.topology.devices) == 4
    assert len(bundle.topology.connections) == 3

    with pytest.raises(StorageError):
        migrate_project_payload({"schema_version": "2.0.0"})
