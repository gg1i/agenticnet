"""Configuration snapshot storage and unified diff comparison."""

from __future__ import annotations

import difflib
from typing import Any

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
        if "\x00" in config_text:
            raise ValidationError("Configuration text must not contain null bytes.")
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

    def upsert_config(
        self,
        device_name: str,
        config_text: str,
        *,
        note: str = "",
        source: str = "design_store",
        replace_planned: bool = True,
    ) -> ConfigSnapshot:
        """Upsert or replace the stored pre-deploy PLANNED config for `device_name`."""
        if "\x00" in config_text:
            raise ValidationError("Configuration text must not contain null bytes.")
        if replace_planned:
            self._snapshots = [
                s
                for s in self._snapshots
                if not (
                    s.device_name == device_name
                    and s.state_level == StateLevel.PLANNED
                    and s.source == source
                )
            ]
        return self.add_snapshot(
            device_name,
            config_text,
            state_level=StateLevel.PLANNED,
            source=source,
            note=note or f"Stored design configuration for {device_name}",
        )

    def read_config_numbered(
        self,
        device_name: str,
        *,
        start_line: int = 1,
        end_line: int | None = None,
        state_level: StateLevel | None = None,
    ) -> dict[str, Any]:
        """Read the latest stored configuration for `device_name` with 1-based line numbers."""
        if start_line < 1:
            raise ValidationError("start_line must be >= 1.")
        snap = self.latest_for_device(device_name, state_level=state_level)
        if snap is None:
            raise ValidationError(
                f"No stored configuration snapshot found for device '{device_name}'.",
                details={"device_name": device_name},
            )
        raw_lines = snap.config_text.splitlines()
        total = len(raw_lines)
        eff_end = total if end_line is None else min(total, end_line)
        if end_line is not None and end_line < start_line:
            raise ValidationError("end_line must be >= start_line.")
        sliced = [
            {"line": ln_no, "text": raw_lines[ln_no - 1]}
            for ln_no in range(start_line, eff_end + 1)
            if 1 <= ln_no <= total
        ]
        numbered_text = "\n".join(f"{row['line']}: {row['text']}" for row in sliced)
        return {
            "device_name": device_name,
            "snapshot_id": snap.snapshot_id,
            "state_level": snap.state_level.value,
            "total_lines": total,
            "start_line": start_line,
            "end_line": eff_end,
            "lines": sliced,
            "numbered_text": numbered_text,
        }

    def merge_config_lines(
        self,
        device_name: str,
        *,
        start_line: int,
        end_line: int | None = None,
        new_lines: list[str] | str,
        note: str = "",
        source: str = "design_store",
    ) -> ConfigSnapshot:
        """Apply a 1-based line-range splice/replacement to the device's stored config."""
        if start_line < 1:
            raise ValidationError("start_line must be >= 1.")
        snap = self.latest_for_device(device_name)
        existing_lines = snap.config_text.splitlines() if snap else []
        replacement = new_lines.splitlines() if isinstance(new_lines, str) else list(new_lines)
        for ln in replacement:
            if any(ch in ln for ch in ("\r", "\n", "\x00")):
                raise ValidationError(
                    "Each replacement line in merge_config_lines must be a single safe line."
                )

        start_idx = min(start_line - 1, len(existing_lines))
        if end_line is None:
            # Insert before start_line without deleting when end_line is omitted and out-of-range,
            # or replace the single line `start_line` when within range.
            end_idx = start_line if start_line <= len(existing_lines) else start_idx
        else:
            if end_line < start_line - 1:
                raise ValidationError("end_line must be >= start_line - 1.")
            end_idx = min(end_line, len(existing_lines))

        merged = existing_lines[:start_idx] + replacement + existing_lines[end_idx:]
        return self.upsert_config(
            device_name,
            "\n".join(merged),
            note=note or f"Merged lines {start_line}..{end_line or start_line} on {device_name}",
            source=source,
        )

    def delete_config(
        self,
        device_name: str,
        *,
        state_level: StateLevel | None = None,
    ) -> int:
        """Delete stored snapshots for `device_name` (optionally scoped by state_level)."""
        before_count = len(self._snapshots)
        self._snapshots = [
            s
            for s in self._snapshots
            if not (
                s.device_name == device_name
                and (state_level is None or s.state_level == state_level)
            )
        ]
        return before_count - len(self._snapshots)

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

    def compare(
        self,
        left_snapshot_id: str,
        right_snapshot_id: str,
        *,
        allow_cross_device: bool = False,
    ) -> ConfigDiffResult:
        """Compute a structured unified diff between two snapshots."""
        left = self.get_snapshot(left_snapshot_id)
        right = self.get_snapshot(right_snapshot_id)
        if left.device_name != right.device_name and not allow_cross_device:
            raise ValidationError(
                f"Cannot compare snapshots from different devices "
                f"('{left.device_name}' vs '{right.device_name}') unless allow_cross_device=True.",
                details={
                    "left_device": left.device_name,
                    "right_device": right.device_name,
                },
            )
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
