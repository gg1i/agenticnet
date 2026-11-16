"""Configuration snapshot storage and unified diff comparison."""

from __future__ import annotations

import difflib

from agenticnet.core.enums import StateLevel
from agenticnet.core.exceptions import ValidationError
from agenticnet.ios.models import ConfigDiffResult, ConfigSnapshot


class ConfigHistory:
    """In-memory and serializable registry of per-device IOS configuration snapshots."""

    def __init__(self, snapshots: list[ConfigSnapshot] | None = None) -> None:
        self._snapshots: list[ConfigSnapshot] = list(snapshots or [])

    def add_snapshot(
        self,
        device_name: str,
        config_text: str,
        *,
        state_level: StateLevel = StateLevel.PLANNED,
        source: str = "manual",
        commands: list[str] | None = None,
        note: str = "",
    ) -> ConfigSnapshot:
        """Record an immutable configuration snapshot for a device."""
        snap = ConfigSnapshot(
            device_name=device_name,
            state_level=state_level,
            source=source,
            config_text=config_text,
            commands=commands or [line for line in config_text.splitlines() if line.strip()],
            note=note,
        )
        self._snapshots.append(snap)
        return snap

    def list_snapshots(self, device_name: str | None = None) -> list[ConfigSnapshot]:
        """Return snapshots ordered oldest to newest, optionally filtered by device."""
        if device_name is None:
            return list(self._snapshots)
        return [s for s in self._snapshots if s.device_name == device_name]

    def get_snapshot(self, snapshot_id: str) -> ConfigSnapshot:
        """Retrieve a snapshot by ID."""
        for snap in self._snapshots:
            if snap.snapshot_id == snapshot_id:
                return snap
        raise ValidationError(
            f"Configuration snapshot '{snapshot_id}' was not found.",
            details={"snapshot_id": snapshot_id},
        )

    def latest_for_device(
        self, device_name: str, *, state_level: StateLevel | None = None
    ) -> ConfigSnapshot | None:
        """Return the latest snapshot for a device, optionally filtered by truth level."""
        matches = [
            s
            for s in self._snapshots
            if s.device_name == device_name
            and (state_level is None or s.state_level == state_level)
        ]
        return matches[-1] if matches else None

    def compare(self, left_snapshot_id: str, right_snapshot_id: str) -> ConfigDiffResult:
        """Compute a structured unified diff between two snapshots."""
        left = self.get_snapshot(left_snapshot_id)
        right = self.get_snapshot(right_snapshot_id)
        left_lines = left.config_text.splitlines()
        right_lines = right.config_text.splitlines()
        diff_lines = list(
            difflib.unified_diff(
                left_lines,
                right_lines,
                fromfile=f"{left.device_name}:{left.snapshot_id} ({left.state_level.value})",
                tofile=f"{right.device_name}:{right.snapshot_id} ({right.state_level.value})",
                lineterm="",
            )
        )
        added = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
        removed = sum(
            1 for line in diff_lines if line.startswith("-") and not line.startswith("---")
        )
        return ConfigDiffResult(
            device_name=right.device_name,
            left_snapshot_id=left.snapshot_id,
            right_snapshot_id=right.snapshot_id,
            identical=(len(diff_lines) == 0),
            added_lines=added,
            removed_lines=removed,
            unified_diff="\n".join(diff_lines),
        )
