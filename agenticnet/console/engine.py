"""Device Console Engine implementing recoverable CLI execution and verification."""

from __future__ import annotations

import functools
import inspect
import platform
import threading
import time
from collections.abc import Callable
from typing import Any

from agenticnet.adapters.base import ConsoleBackend
from agenticnet.console.models import (
    CLIPromptMode,
    CommandTranscript,
    ConsoleExecutionReport,
    ConsoleInteractionKind,
    ConsoleSessionState,
)
from agenticnet.console.profiles import get_console_profile
from agenticnet.console.state_machine import (
    ConsoleStateMachine,
    PromptDetector,
    strip_paging_and_control,
)
from agenticnet.console.transport import (
    ConsoleTransport,
    UnavailableConsoleTransport,
    WindowsGuiConsoleTransport,
)
from agenticnet.core.enums import DeviceCategory, StateLevel
from agenticnet.core.exceptions import AdapterUnavailableError, IOSConfigError
from agenticnet.devices import DEFAULT_CATALOG, DeviceCatalog
from agenticnet.gui.windows_backend import WindowsGuiBackend
from agenticnet.ios.models import CLIDiagnostic
from agenticnet.ios.validators import parse_cli_output
from agenticnet.security.redaction import redact_cli_text


@functools.lru_cache(maxsize=128)
def _func_accepts_kwarg(func_obj: Any, kwarg: str) -> bool:
    try:
        return kwarg in inspect.signature(func_obj).parameters
    except (TypeError, ValueError):
        return False


def _callable_accepts_kwarg(fn: Any, kwarg: str) -> bool:
    func_obj = getattr(fn, "__func__", fn)
    try:
        return _func_accepts_kwarg(func_obj, kwarg)
    except TypeError:
        try:
            return kwarg in inspect.signature(fn).parameters
        except (TypeError, ValueError):
            return False


def _canon_mode_cmd(cmd: str) -> str:
    low = cmd.strip().lower()
    if low in {"en", "enable"}:
        return "enable"
    if low in {"conf t", "config t", "configure terminal"}:
        return "configure terminal"
    return low


def _dedupe_prep_commands(prep_cmds: list[str], commands: list[str]) -> list[str]:
    """Drop trailing prep commands already explicitly supplied at the start of `commands`."""
    user_cmds = [_canon_mode_cmd(c) for c in commands if c.strip()]
    if not prep_cmds or not user_cmds:
        return list(prep_cmds)
    remaining = [_canon_mode_cmd(c) for c in prep_cmds]
    raw_remaining = list(prep_cmds)
    if len(remaining) >= 2 and remaining[-2:] == ["enable", "configure terminal"]:
        if len(user_cmds) >= 2 and user_cmds[:2] == ["enable", "configure terminal"]:
            return raw_remaining[:-2]
        if user_cmds[0] == "configure terminal":
            return raw_remaining[:-1]
    elif remaining and (
        _canon_mode_cmd(remaining[-1]) == user_cmds[0]
        or (
            remaining == ["configure terminal"]
            and len(user_cmds) >= 2
            and user_cmds[:2] == ["enable", "configure terminal"]
        )
    ):
        return raw_remaining[:-1]
    return raw_remaining


_PRIVILEGED_OR_CONFIG_MODES: frozenset[CLIPromptMode] = frozenset(
    mode
    for mode in CLIPromptMode
    if mode
    not in {
        CLIPromptMode.UNKNOWN,
        CLIPromptMode.USER_EXEC,
        CLIPromptMode.PRESS_RETURN,
        CLIPromptMode.INITIAL_SETUP_DIALOG,
        CLIPromptMode.PASSWORD_PROMPT,
        CLIPromptMode.CONFIRM_PROMPT,
        CLIPromptMode.PAGING_MORE,
        CLIPromptMode.PC_PROMPT,
    }
)


_SHUTDOWN_CMDS: frozenset[str] = frozenset({"no shutdown", "no shut", "shutdown", "shut"})
_EXEC_TAIL_CMDS: frozenset[str] = frozenset(
    {
        "end",
        "write",
        "write memory",
        "wr",
        "wr mem",
        "copy running-config startup-config",
        "copy run start",
    }
)
_TOP_LEVEL_BLOCK_PREFIXES: tuple[str, ...] = (
    "interface ",
    "int ",
    "router ",
    "vlan ",
    "line ",
    "ip dhcp pool ",
    "ip access-list ",
    "access-list ",
    "policy-map ",
    "class-map ",
    "crypto isakmp policy ",
    "crypto map ",
    "zone security ",
    "zone-pair security ",
    "telephony-service",
    "ephone",
)
_SWITCH_CATEGORIES: frozenset[DeviceCategory] = frozenset(
    {DeviceCategory.L2_SWITCH, DeviceCategory.L3_SWITCH}
)
_MICRO_BATCH_SETTLE_SECONDS = 0.06


def _is_switch_model(catalog: DeviceCatalog | None, model: str) -> bool:
    """Return True if `model` classifies as a Layer 2 or Layer 3 switch."""
    cat = catalog or DEFAULT_CATALOG
    try:
        if cat.get_profile(model).category in _SWITCH_CATEGORIES:
            return True
    except (KeyError, ValueError):
        pass
    low = model.lower()
    return any(tok in low for tok in ("2960", "3560", "3650", "switch"))


def _get_batch_sleep_fn(transport: Any) -> Callable[[float], None]:
    """Resolve router's sleep function when available so tests avoid real wall waits."""
    router = getattr(transport, "router", None)
    sleep_fn = getattr(router, "_sleep", None)
    return sleep_fn if callable(sleep_fn) else time.sleep


def _partition_ios_micro_batches(
    cleaned_lines: list[tuple[str, bool]],
    initial_mode: CLIPromptMode,
    *,
    is_switch: bool,
    max_chunk_cmds: int | None = None,
) -> list[tuple[list[tuple[str, bool]], bool]]:
    """Split large or switch `no shutdown`-heavy IOS batches at safe boundaries for PT."""
    if len(cleaned_lines) <= 1:
        return [(list(cleaned_lines), False)] if cleaned_lines else []

    # Switches on Packet Tracer drop characters across back-to-back port-bounce stanzas
    # unless split into small settling chunks; routers tolerate much larger single batches.
    chunk_limit = max_chunk_cmds if max_chunk_cmds is not None else (12 if is_switch else 48)
    chunks: list[tuple[list[tuple[str, bool]], bool]] = []
    chunk: list[tuple[str, bool]] = []
    chunk_has_user_cmd = False
    chunk_saw_shutdown = False
    pred_mode = initial_mode
    total = len(cleaned_lines)

    for idx, (cmd, is_prep) in enumerate(cleaned_lines):
        chunk.append((cmd, is_prep))
        if not is_prep:
            chunk_has_user_cmd = True
        low = cmd.strip().lower()
        canon = _canon_mode_cmd(low)
        if low in _SHUTDOWN_CMDS:
            chunk_saw_shutdown = True
        pred_mode = _predict_mode_after(pred_mode, cmd)

        if idx + 1 >= total or not chunk_has_user_cmd:
            continue

        next_low = cleaned_lines[idx + 1][0].strip().lower()
        next_canon = _canon_mode_cmd(next_low)
        next_starts_block = next_low.startswith(_TOP_LEVEL_BLOCK_PREFIXES)
        next_is_exec_tail = next_canon in _EXEC_TAIL_CMDS

        should_split = False
        needs_settle = False
        if (
            is_switch
            and chunk_saw_shutdown
            and (low == "exit" or next_is_exec_tail or next_starts_block)
        ):
            should_split = True
            needs_settle = True
        elif (
            canon not in _EXEC_TAIL_CMDS
            and next_canon == "end"
            and ((is_switch and len(chunk) >= 3) or len(chunk) >= chunk_limit)
        ):
            should_split = True
            needs_settle = is_switch
        elif len(chunk) >= chunk_limit and (
            low == "exit"
            or pred_mode in {CLIPromptMode.GLOBAL_CONFIG, CLIPromptMode.PRIVILEGED_EXEC}
            or next_starts_block
            or next_is_exec_tail
            or len(chunk) >= chunk_limit + 6
        ):
            should_split = True
            needs_settle = is_switch and chunk_saw_shutdown

        if should_split:
            chunks.append((chunk, needs_settle))
            chunk = []
            chunk_has_user_cmd = False
            chunk_saw_shutdown = False

    if chunk:
        chunks.append((chunk, False))
    return chunks


def _record_skipped_batch_lines(
    lines: list[tuple[str, bool]],
    *,
    start_line_num: int,
    mode: CLIPromptMode,
    transcripts: list[CommandTranscript],
    warnings: list[str],
) -> None:
    """Append SKIPPED_AFTER_ERROR transcripts for unexecuted trailing batch commands."""
    for offset, (cmd, _) in enumerate(lines):
        redacted_cmd = redact_cli_text(cmd)
        skip_diag = CLIDiagnostic(
            line_number=start_line_num + offset,
            command=redacted_cmd,
            severity="warning",
            code="SKIPPED_AFTER_ERROR",
            message=(
                f"Skipped '{redacted_cmd}' because stop_on_error=True "
                "after an earlier command failed."
            ),
        )
        warnings.append(skip_diag.message)
        transcripts.append(
            CommandTranscript(
                command=redacted_cmd,
                mode_before=mode,
                mode_after=mode,
                raw_output="",
                diagnostics=[skip_diag],
                succeeded=False,
                elapsed_ms=0.0,
            )
        )


def _predict_mode_after(current: CLIPromptMode, cmd: str) -> CLIPromptMode:
    """Predict likely IOS prompt mode transition for a single command in a batch."""
    low = cmd.strip().lower()
    if low in {"en", "enable"}:
        return CLIPromptMode.PRIVILEGED_EXEC if current == CLIPromptMode.USER_EXEC else current
    if low in {"conf t", "config t", "configure terminal"}:
        return CLIPromptMode.GLOBAL_CONFIG
    if low == "end":
        return CLIPromptMode.PRIVILEGED_EXEC if current != CLIPromptMode.USER_EXEC else current
    if low == "disable":
        return CLIPromptMode.USER_EXEC
    if low == "exit":
        if current == CLIPromptMode.GLOBAL_CONFIG:
            return CLIPromptMode.PRIVILEGED_EXEC
        if current == CLIPromptMode.PRIVILEGED_EXEC:
            return CLIPromptMode.USER_EXEC
        if current not in {CLIPromptMode.USER_EXEC, CLIPromptMode.UNKNOWN, CLIPromptMode.PC_PROMPT}:
            return CLIPromptMode.GLOBAL_CONFIG
        return current
    if low.startswith(("interface range ", "int range ")):
        return CLIPromptMode.INTERFACE_RANGE_CONFIG
    if low.startswith(("interface ", "int ")):
        return CLIPromptMode.SUBINTERFACE_CONFIG if "." in low else CLIPromptMode.INTERFACE_CONFIG
    if low.startswith("router "):
        return CLIPromptMode.ROUTER_CONFIG
    if low.startswith("ip dhcp pool "):
        return CLIPromptMode.DHCP_CONFIG
    if low.startswith("line "):
        return CLIPromptMode.LINE_CONFIG
    if low.startswith("vlan "):
        return CLIPromptMode.VLAN_CONFIG
    if low.startswith(("ip access-list ", "access-list ")):
        return CLIPromptMode.ACL_CONFIG
    if low.startswith("crypto isakmp policy "):
        return CLIPromptMode.CRYPTO_ISAKMP_CONFIG
    if low.startswith("crypto map ") and len(low.split()) >= 4:
        return CLIPromptMode.CRYPTO_MAP_CONFIG
    if low.startswith("zone security "):
        return CLIPromptMode.ZONE_CONFIG
    if low.startswith("zone-pair security "):
        return CLIPromptMode.ZONE_PAIR_CONFIG
    if low.startswith("policy-map "):
        return CLIPromptMode.POLICY_MAP_CONFIG
    if low.startswith("class-map "):
        return CLIPromptMode.CLASS_MAP_CONFIG
    if low == "telephony-service":
        return CLIPromptMode.TELEPHONY_CONFIG
    if low.startswith("ephone-dn "):
        return CLIPromptMode.EPHONE_DN_CONFIG
    if low.startswith("ephone "):
        return CLIPromptMode.EPHONE_CONFIG
    return current


def _compute_batch_timeout(base_timeout_s: float, commands: list[str]) -> float:
    """Scale batch timeout cleanly when slow ping/traceroute/DHCP commands are present."""
    slow_cmds = sum(
        1
        for cmd in commands
        if cmd.strip().lower().startswith(("ping ", "traceroute ", "tracert ", "ipconfig /renew"))
    )
    return max(float(base_timeout_s), 20.0) + slow_cmds * 10.0 + len(commands) * 0.4


def _split_batch_output(cleaned_out: str, commands: list[str]) -> list[str]:
    """Best-effort per-command output splitter when bridge omits `command_outputs`."""
    if not commands:
        return []
    if len(commands) == 1 or not cleaned_out.strip():
        return [cleaned_out] + [""] * (len(commands) - 1)

    lines = cleaned_out.splitlines()
    starts: list[int | None] = [None] * len(commands)
    cursor = 0
    for cmd_idx, cmd in enumerate(commands):
        want = cmd.strip().lower()
        if not want:
            continue
        for line_idx in range(cursor, len(lines)):
            low = lines[line_idx].strip().lower()
            if low == want or low.endswith(f"#{want}") or low.endswith(f">{want}"):
                starts[cmd_idx] = line_idx
                cursor = line_idx + 1
                break

    found_positions = [(idx, pos) for idx, pos in enumerate(starts) if pos is not None]
    if len(found_positions) < 2:
        # Couldn't cleanly locate multiple command boundaries; put full output on last
        # command rather than duplicating the entire transcript N times.
        out = [""] * len(commands)
        out[-1] = cleaned_out
        return out

    slices = [""] * len(commands)
    for k, (cmd_idx, pos) in enumerate(found_positions):
        end_pos = found_positions[k + 1][1] if k + 1 < len(found_positions) else len(lines)
        start_pos = 0 if k == 0 else pos
        slices[cmd_idx] = "\n".join(lines[start_pos:end_pos]).strip()
    return slices


class DeviceConsoleEngine(ConsoleBackend):
    """State-machine-driven Cisco IOS & Packet Tracer host CLI execution engine."""

    def __init__(
        self,
        *,
        catalog: DeviceCatalog | None = None,
        transport: ConsoleTransport | None = None,
        gui_backend: WindowsGuiBackend | None = None,
    ) -> None:
        self.catalog = catalog or DEFAULT_CATALOG
        if transport is not None:
            self.transport = transport
        elif gui_backend is not None and platform.system() == "Windows":
            self.transport = WindowsGuiConsoleTransport(gui_backend)
        else:
            self.transport = UnavailableConsoleTransport()
        self._sessions: dict[str, ConsoleSessionState] = {}
        self._sessions_lock = threading.RLock()

    def _get_or_init_session(self, device_name: str, model: str) -> ConsoleSessionState:
        with self._sessions_lock:
            if device_name not in self._sessions:
                self._sessions[device_name] = ConsoleSessionState(
                    device_name=device_name,
                    model=model,
                    transport_name=self.transport.transport_name,
                )
            session = self._sessions[device_name]
            session.transport_name = self.transport.transport_name
            return session

    def _recover_until_usable(
        self,
        device_name: str,
        initial_buffer: str,
        *,
        timeout_s: float,
        max_attempts: int,
    ) -> tuple[str, int]:
        """Handle setup dialogs, Press RETURN, and --More-- prompts cleanly."""
        buf = initial_buffer
        parsed = PromptDetector.parse(buf)
        recoveries = 0

        for _ in range(max_attempts):
            if parsed.mode in {
                CLIPromptMode.USER_EXEC,
                CLIPromptMode.PRIVILEGED_EXEC,
                CLIPromptMode.GLOBAL_CONFIG,
                CLIPromptMode.PC_PROMPT,
            }:
                break
            inputs = ConsoleStateMachine.recovery_inputs(parsed)
            if not inputs:
                break
            for item in inputs:
                chunk = self.transport.send_line(device_name, item, timeout_s=timeout_s)
                buf = f"{buf}\n{chunk}" if buf else chunk
                recoveries += 1
            parsed = PromptDetector.parse(buf)

        return buf, recoveries

    def _execute_send_batch_chunk(
        self,
        device_name: str,
        session: ConsoleSessionState,
        profile: Any,
        chunk_lines: list[tuple[str, bool]],
        *,
        start_line_num: int,
        stop_on_error: bool,
        enable_password: str | None,
        single_user_show: bool,
        transcripts: list[CommandTranscript],
        failed_commands: list[str],
        warnings: list[str],
    ) -> tuple[float, str, bool]:
        """Dispatch one micro-batch via `send_batch` and reconcile session/transcript state."""
        batch_cmds = [cmd for cmd, _ in chunk_lines]
        batch_timeout_s = _compute_batch_timeout(profile.command_timeout_seconds, batch_cmds)
        t0 = time.perf_counter()
        send_batch_fn = self.transport.send_batch  # type: ignore[attr-defined]
        batch_kwargs: dict[str, Any] = {"timeout_s": batch_timeout_s}
        if _callable_accepts_kwarg(send_batch_fn, "stop_on_error"):
            batch_kwargs["stop_on_error"] = bool(stop_on_error)
        if enable_password and _callable_accepts_kwarg(send_batch_fn, "enable_password"):
            batch_kwargs["enable_password"] = enable_password
        batch_res = send_batch_fn(device_name, batch_cmds, **batch_kwargs)
        batch_elapsed = round((time.perf_counter() - t0) * 1000.0, 2)

        raw_out = str(batch_res.get("raw_output", ""))
        cleaned_out = redact_cli_text(strip_paging_and_control(raw_out))
        prompt_str = str(batch_res.get("prompt", "")).strip()
        statuses_raw = batch_res.get("command_statuses", [])
        raw_cmd_outputs = batch_res.get("command_outputs")
        stopped_on_error = bool(batch_res.get("stopped_on_error", False))
        non_fatal_set = {
            str(c).strip().lower() for c in batch_res.get("non_fatal_commands", []) if c
        }
        timed_out = bool(batch_res.get("timed_out", False))

        # Filter out harmless paging-disable errors already flagged non-fatal by bridge
        diags_source = cleaned_out
        if "terminal length 0" in non_fatal_set or "terminal pager 0" in non_fatal_set:
            diags_source = "\n".join(
                ln
                for ln in cleaned_out.splitlines()
                if "terminal length 0" not in ln.lower()
                and "terminal pager 0" not in ln.lower()
            )
        diags = parse_cli_output(diags_source)

        status_iter = (
            [entry for entry in statuses_raw if isinstance(entry, dict)]
            if isinstance(statuses_raw, list)
            else []
        )
        per_cmd_failed: list[bool] = [False] * len(chunk_lines)
        s_idx = 0
        for idx, (cmd, _) in enumerate(chunk_lines):
            if cmd.endswith("?"):
                continue
            canon = _canon_mode_cmd(cmd)
            matched_entry: dict[str, Any] | None = None
            for probe in range(s_idx, len(status_iter)):
                s_cmd = _canon_mode_cmd(str(status_iter[probe].get("command", "")))
                if s_cmd == canon or (canon == "enable" and s_cmd == "end"):
                    matched_entry = status_iter[probe]
                    s_idx = probe + 1
                    break
            if matched_entry is not None:
                is_nf = bool(matched_entry.get("non_fatal", False))
                if int(matched_entry.get("status", 0)) != 0 and not is_nf:
                    per_cmd_failed[idx] = True

        # If bridge didn't pinpoint failures (e.g. mock backend) but IOS printed errors
        per_cmd_diags: dict[int, list[CLIDiagnostic]] = {}
        if diags and not any(per_cmd_failed):
            for d_item in diags:
                matched_any = False
                d_cmd_low = d_item.command.strip().lower()
                if d_cmd_low:
                    for idx, (cmd, _) in enumerate(chunk_lines):
                        if cmd.endswith("?"):
                            continue
                        if cmd.lower() == d_cmd_low or d_cmd_low in cmd.lower():
                            per_cmd_failed[idx] = True
                            per_cmd_diags.setdefault(idx, []).append(d_item)
                            matched_any = True
                if not matched_any and chunk_lines:
                    fallback_idx = 0
                    for idx, (cmd, is_prep) in enumerate(chunk_lines):
                        if not is_prep and not cmd.endswith("?"):
                            fallback_idx = idx
                            if cmd.lower() in cleaned_out.lower():
                                break
                    per_cmd_failed[fallback_idx] = True
                    per_cmd_diags.setdefault(fallback_idx, []).append(d_item)

        if stopped_on_error and not any(per_cmd_failed) and chunk_lines:
            fail_pos = min(max(len(status_iter) - 1, 0), len(chunk_lines) - 1)
            per_cmd_failed[fail_pos] = True

        first_fail_idx = next((idx for idx, flag in enumerate(per_cmd_failed) if flag), None)
        fallback_slices = (
            _split_batch_output(cleaned_out, batch_cmds)
            if not (isinstance(raw_cmd_outputs, list) and len(raw_cmd_outputs) > 0)
            else None
        )
        per_cmd_ms = round(batch_elapsed / len(chunk_lines), 2) if chunk_lines else 0.0
        chunk_transcripts: list[CommandTranscript] = []

        for idx, (cmd, is_prep) in enumerate(chunk_lines):
            if stop_on_error and first_fail_idx is not None and idx > first_fail_idx:
                _record_skipped_batch_lines(
                    chunk_lines[idx:],
                    start_line_num=start_line_num + idx,
                    mode=session.current_mode,
                    transcripts=chunk_transcripts,
                    warnings=warnings,
                )
                break

            redacted_cmd = redact_cli_text(cmd)
            mode_before = session.current_mode
            mode_after = _predict_mode_after(mode_before, cmd)
            session.current_mode = mode_after
            ok = True if cmd.endswith("?") else not per_cmd_failed[idx]
            cmd_diags: list[CLIDiagnostic] = []
            if not ok:
                cmd_diags = per_cmd_diags.get(idx) or diags or [
                    CLIDiagnostic(
                        line_number=start_line_num + idx,
                        command=redacted_cmd,
                        severity="error",
                        code="CLI_COMMAND_FAILED",
                        message=(
                            f"Device returned non-zero IOS status for '{redacted_cmd}'."
                        ),
                    )
                ]
                session.errors_detected += len(cmd_diags)
                failed_commands.append(redacted_cmd)
                if not is_prep:
                    warnings.append(
                        f"CLI error after '{redacted_cmd}': "
                        f"{cmd_diags[0].code} - {cmd_diags[0].message}"
                    )
            elif idx == len(chunk_lines) - 1 and timed_out:
                ok = False
                failed_commands.append(redacted_cmd)
                warnings.append(f"CLI batch timed out around '{redacted_cmd}'.")

            if isinstance(raw_cmd_outputs, list) and idx < len(raw_cmd_outputs):
                slice_clean = redact_cli_text(
                    strip_paging_and_control(str(raw_cmd_outputs[idx]))
                )
                if idx == 0 and is_prep and single_user_show and len(raw_cmd_outputs) > 1:
                    user_slice = redact_cli_text(
                        strip_paging_and_control(str(raw_cmd_outputs[-1]))
                    )
                    transcript_out = (
                        f"{slice_clean}\n{user_slice}".strip()
                        if slice_clean.strip()
                        else (user_slice or cleaned_out)
                    )
                else:
                    transcript_out = slice_clean
            elif fallback_slices is not None and idx < len(fallback_slices):
                transcript_out = fallback_slices[idx]
            else:
                transcript_out = cleaned_out if idx == len(chunk_lines) - 1 else ""

            chunk_transcripts.append(
                CommandTranscript(
                    command=redacted_cmd,
                    mode_before=mode_before,
                    mode_after=mode_after,
                    raw_output=transcript_out,
                    diagnostics=cmd_diags,
                    succeeded=ok,
                    elapsed_ms=per_cmd_ms,
                )
            )

        transcripts.extend(chunk_transcripts)

        # Bug A fix: when `prompt_str` is empty and the last executed command produced
        # empty `raw_output` (e.g. `end` / `write memory`), `cleaned_out` ends at an
        # earlier prompt (such as `Switch0(config)#`) — do NOT revert predicted mode back.
        last_exec = next(
            (
                t
                for t in reversed(chunk_transcripts)
                if not any(d.code == "SKIPPED_AFTER_ERROR" for d in t.diagnostics)
            ),
            None,
        )
        can_infer_from_output = bool(last_exec is None or last_exec.raw_output.strip())
        final_parsed = (
            PromptDetector.parse(prompt_str)
            if prompt_str
            else (
                PromptDetector.parse(cleaned_out)
                if (cleaned_out and can_infer_from_output)
                else None
            )
        )
        if final_parsed is not None and final_parsed.mode != CLIPromptMode.UNKNOWN:
            session.current_mode = final_parsed.mode
            if last_exec is not None:
                last_exec.mode_after = final_parsed.mode
        if final_parsed is not None and final_parsed.hostname:
            session.hostname = final_parsed.hostname
        elif cleaned_out:
            hostname_probe = PromptDetector.parse(cleaned_out)
            if hostname_probe.hostname:
                session.hostname = hostname_probe.hostname
        if final_parsed is not None and final_parsed.raw_prompt:
            session.last_prompt = final_parsed.raw_prompt
        elif prompt_str:
            session.last_prompt = prompt_str

        return batch_elapsed, cleaned_out, bool(stop_on_error and first_fail_idx is not None)

    def _preflight_elevate_batch(
        self,
        device_name: str,
        session: ConsoleSessionState,
        profile: Any,
        *,
        enable_password: str | None = None,
    ) -> bool:
        """Wake a cold IOS/ASA console (e.g. `Press RETURN` on `Switch>`) and confirm `#`."""
        send_batch_fn = self.transport.send_batch  # type: ignore[attr-defined]
        supports_stop = _callable_accepts_kwarg(send_batch_fn, "stop_on_error")
        supports_epw = bool(
            enable_password and _callable_accepts_kwarg(send_batch_fn, "enable_password")
        )
        pre_timeout = max(float(profile.command_timeout_seconds), 20.0)

        def _enable_seq(prefix: list[str]) -> list[str]:
            seq = [*prefix, "enable"]
            if enable_password and not supports_epw:
                seq.append(enable_password)
            return seq

        cmds = _enable_seq([])
        for attempt in range(1, 4):
            kwargs: dict[str, Any] = {"timeout_s": pre_timeout}
            if supports_stop:
                kwargs["stop_on_error"] = False
            if supports_epw and enable_password:
                kwargs["enable_password"] = enable_password
            res = send_batch_fn(device_name, cmds, **kwargs)
            prompt_str = str(res.get("prompt", "")).strip()
            raw_out = str(res.get("raw_output", ""))
            parsed = PromptDetector.parse(prompt_str or raw_out)
            if parsed.mode == CLIPromptMode.UNKNOWN and raw_out:
                parsed = PromptDetector.parse(raw_out)

            if parsed.hostname:
                session.hostname = parsed.hostname
            if parsed.raw_prompt:
                session.last_prompt = parsed.raw_prompt
            elif prompt_str:
                session.last_prompt = prompt_str
            if parsed.mode != CLIPromptMode.UNKNOWN:
                session.current_mode = parsed.mode
            session.is_open = True
            if raw_out:
                session.last_output_tail = redact_cli_text(strip_paging_and_control(raw_out))[-800:]

            if parsed.mode in _PRIVILEGED_OR_CONFIG_MODES:
                return True
            if parsed.mode == CLIPromptMode.UNKNOWN and not prompt_str:
                return True

            session.recoveries_performed += 1
            tail_low = raw_out[-240:].lower()
            if "[yes/no]" in tail_low or parsed.mode == CLIPromptMode.INITIAL_SETUP_DIALOG:
                cmds = _enable_seq(["no", ""])
            elif (
                "press return" in tail_low
                or parsed.mode == CLIPromptMode.PRESS_RETURN
                or attempt >= 2
            ):
                cmds = _enable_seq([""])
            else:
                cmds = _enable_seq([])

        return session.current_mode not in {
            CLIPromptMode.USER_EXEC,
            CLIPromptMode.PASSWORD_PROMPT,
            CLIPromptMode.INITIAL_SETUP_DIALOG,
            CLIPromptMode.PRESS_RETURN,
        }

    def open_console(
        self,
        device_name: str,
        *,
        model: str = "2911",
        disable_paging: bool = True,
    ) -> dict[str, Any]:
        """Open and stabilize the CLI session for `device_name`."""
        profile = get_console_profile(model, catalog=self.catalog)
        if profile.interaction_kind == ConsoleInteractionKind.GUI_ONLY:
            raise IOSConfigError(
                f"Device '{device_name}' ({profile.model}) does not have an interactive console.",
                details={"device_name": device_name, "model": profile.model},
                remediation=(
                    "Configure wireless/printer devices via GUI or Packet Tracer Config tab."
                ),
            )

        session = self._get_or_init_session(device_name, profile.model)
        raw_buf = self.transport.open_device(device_name, profile)
        buf, recoveries = self._recover_until_usable(
            device_name,
            raw_buf,
            timeout_s=profile.command_timeout_seconds,
            max_attempts=profile.max_recovery_attempts,
        )
        parsed = PromptDetector.parse(buf)

        if (
            disable_paging
            and profile.supports_paging_disable
            and self.transport.transport_name != "script_bridge"
            and (
                parsed.mode == CLIPromptMode.PRIVILEGED_EXEC
                or (
                    parsed.mode == CLIPromptMode.USER_EXEC
                    and profile.interaction_kind != ConsoleInteractionKind.ASA_CLI
                )
            )
        ):
            chunk = self.transport.send_line(
                device_name,
                profile.paging_disable_command,
                timeout_s=profile.command_timeout_seconds,
            )
            buf = f"{buf}\n{chunk}"
            parsed = PromptDetector.parse(buf)

        session.is_open = True
        session.current_mode = parsed.mode
        session.hostname = parsed.hostname
        session.last_prompt = parsed.raw_prompt
        session.recoveries_performed += recoveries
        session.last_output_tail = redact_cli_text(strip_paging_and_control(buf))[-800:]

        return {
            "session": session.model_dump(mode="json"),
            "profile": profile.model_dump(mode="json"),
            "state_level": StateLevel.VERIFIED.value,
        }

    def execute_commands(
        self,
        device_name: str,
        commands: list[str],
        *,
        model: str = "2911",
        target_mode: str = "preserve",
        verification_commands: list[str] | None = None,
        stop_on_error: bool = True,
        dry_run: bool = False,
        enable_password: str | None = None,
    ) -> dict[str, Any]:
        """Execute validated CLI commands through the console state machine."""
        profile = get_console_profile(model, catalog=self.catalog)
        if profile.interaction_kind == ConsoleInteractionKind.GUI_ONLY:
            raise IOSConfigError(
                f"Model '{profile.model}' has no CLI console to execute commands.",
                details={"device_name": device_name, "model": profile.model},
            )

        if profile.interaction_kind == ConsoleInteractionKind.PT_DESKTOP_CMD and target_mode in {
            "global_config",
            "privileged_exec",
        }:
            raise IOSConfigError(
                f"Device '{device_name}' ({profile.model}) uses PT Desktop Command Prompt, "
                "not Cisco IOS configuration modes.",
                details={"device_name": device_name, "model": profile.model},
                remediation="Run ping/ipconfig commands with target_mode='preserve'.",
            )

        session = self._get_or_init_session(device_name, profile.model)
        if dry_run:
            return {
                "dry_run": True,
                "device_name": device_name,
                "model": profile.model,
                "target_mode": target_mode,
                "planned_commands": [redact_cli_text(c) for c in commands],
                "verification_commands": verification_commands or [],
                "state_level": StateLevel.PLANNED.value,
            }

        can_batch_fn = getattr(self.transport, "can_batch", None)
        use_batch = bool(callable(can_batch_fn) and can_batch_fn())
        send_batch_fn = getattr(self.transport, "send_batch", None) if use_batch else None
        batch_handles_enable_pw = bool(
            use_batch
            and enable_password
            and callable(send_batch_fn)
            and _callable_accepts_kwarg(send_batch_fn, "enable_password")
        )

        was_open = session.is_open
        if not use_batch and not was_open:
            self.open_console(device_name, model=profile.model)
            session = self._sessions[device_name]
        elif use_batch and not was_open:
            session.is_open = True
            if session.current_mode == CLIPromptMode.UNKNOWN:
                session.current_mode = (
                    CLIPromptMode.PC_PROMPT
                    if profile.interaction_kind == ConsoleInteractionKind.PT_DESKTOP_CMD
                    else CLIPromptMode.USER_EXEC
                )

        non_empty_user_cmds = [c.strip() for c in commands if c.strip()]
        needs_elevate_preflight = bool(
            use_batch
            and profile.supports_ios_cli
            and hasattr(self.transport, "router")
            and callable(send_batch_fn)
            and non_empty_user_cmds
            and (not was_open or session.current_mode not in _PRIVILEGED_OR_CONFIG_MODES)
            and (
                target_mode in {"privileged_exec", "global_config"}
                or (
                    target_mode == "preserve"
                    and _canon_mode_cmd(non_empty_user_cmds[0]) in {"enable", "configure terminal"}
                )
            )
        )

        transcripts: list[CommandTranscript] = []
        failed_commands: list[str] = []
        evidence: list[str] = []
        warnings: list[str] = []
        verification_output: dict[str, str] = {}

        if needs_elevate_preflight:
            try:
                elevated = self._preflight_elevate_batch(
                    device_name,
                    session,
                    profile,
                    enable_password=enable_password,
                )
            except AdapterUnavailableError:
                fallback = getattr(self.transport, "fallback", None)
                if fallback is None or not fallback.is_available():
                    raise
                use_batch = False
                session.is_open = False
                self.open_console(device_name, model=profile.model)
                session = self._sessions[device_name]
            else:
                if not elevated and (
                    target_mode in {"privileged_exec", "global_config"}
                    or _canon_mode_cmd(non_empty_user_cmds[0]) == "configure terminal"
                ):
                    msg = (
                        f"Failed to elevate '{device_name}' to privileged EXEC ('#') before "
                        f"executing batch (mode='{session.current_mode.value}', "
                        f"prompt={session.last_prompt!r})."
                    )
                    session.errors_detected += 1
                    report = ConsoleExecutionReport(
                        device_name=device_name,
                        state_level=StateLevel.EXECUTED,
                        session=session,
                        transcripts=[
                            CommandTranscript(
                                command="enable",
                                mode_before=session.current_mode,
                                mode_after=session.current_mode,
                                raw_output=session.last_output_tail,
                                diagnostics=[
                                    CLIDiagnostic(
                                        line_number=1,
                                        command="enable",
                                        severity="error",
                                        code="PRIVILEGE_ESCALATION_FAILED",
                                        message=msg,
                                    )
                                ],
                                succeeded=False,
                                elapsed_ms=0.0,
                            )
                        ],
                        all_commands_succeeded=False,
                        failed_commands=["enable"],
                        verification_output={},
                        evidence=[],
                        warnings=[msg],
                    )
                    return report.model_dump(mode="json")

        prep_enable_pw = None if batch_handles_enable_pw else enable_password
        prep_cmds: list[str] = []
        if target_mode == "privileged_exec":
            prep_cmds = ConsoleStateMachine.transition_commands(
                session.current_mode,
                CLIPromptMode.PRIVILEGED_EXEC,
                enable_password=prep_enable_pw,
            )
        elif target_mode == "global_config":
            prep_cmds = ConsoleStateMachine.transition_commands(
                session.current_mode,
                CLIPromptMode.GLOBAL_CONFIG,
                enable_password=prep_enable_pw,
            )
        elif target_mode == "user_exec":
            prep_cmds = ConsoleStateMachine.transition_commands(
                session.current_mode,
                CLIPromptMode.USER_EXEC,
            )

        if use_batch:
            prep_cmds = _dedupe_prep_commands(prep_cmds, commands)
            cleaned_lines = [
                (raw_cmd.strip(), is_prep)
                for raw_cmd, is_prep in (
                    [(c, True) for c in prep_cmds] + [(c, False) for c in commands]
                )
                if raw_cmd.strip()
            ]
            batch_handled = False
            batch_elapsed = 0.0
            sent_batch_count = 0
            all_cleaned_outputs: list[str] = []
            if cleaned_lines:
                single_user_show = (
                    len([c for c in commands if c.strip()]) == 1
                    and next(c.strip().lower() for c in commands if c.strip()).startswith("show")
                )
                if hasattr(self.transport, "router") and profile.supports_ios_cli:
                    micro_batches = _partition_ios_micro_batches(
                        cleaned_lines,
                        session.current_mode,
                        is_switch=_is_switch_model(self.catalog, profile.model),
                    )
                else:
                    micro_batches = [(cleaned_lines, False)]
                sleep_fn = _get_batch_sleep_fn(self.transport)
                halted_after_error = False
                line_cursor = 1
                try:
                    for chunk_idx, (chunk_lines, needs_settle) in enumerate(micro_batches):
                        if halted_after_error:
                            _record_skipped_batch_lines(
                                chunk_lines,
                                start_line_num=line_cursor,
                                mode=session.current_mode,
                                transcripts=transcripts,
                                warnings=warnings,
                            )
                            line_cursor += len(chunk_lines)
                            continue
                        chunk_ms, chunk_out, halted_after_error = self._execute_send_batch_chunk(
                            device_name,
                            session,
                            profile,
                            chunk_lines,
                            start_line_num=line_cursor,
                            stop_on_error=stop_on_error,
                            enable_password=enable_password,
                            single_user_show=single_user_show,
                            transcripts=transcripts,
                            failed_commands=failed_commands,
                            warnings=warnings,
                        )
                        sent_batch_count += 1
                        batch_elapsed += chunk_ms
                        if chunk_out:
                            all_cleaned_outputs.append(chunk_out)
                        line_cursor += len(chunk_lines)
                        if (
                            needs_settle
                            and not halted_after_error
                            and chunk_idx + 1 < len(micro_batches)
                        ):
                            sleep_fn(_MICRO_BATCH_SETTLE_SECONDS)
                    batch_handled = True
                except AdapterUnavailableError:
                    fallback = getattr(self.transport, "fallback", None)
                    if sent_batch_count > 0 or fallback is None or not fallback.is_available():
                        raise
            else:
                sent_batch_count = 1
                batch_handled = True

            if batch_handled:
                combined_cleaned = "\n".join(all_cleaned_outputs)
                if combined_cleaned or not all_cleaned_outputs:
                    session.last_output_tail = combined_cleaned[-800:]

                if verification_commands and not failed_commands:
                    if (
                        hasattr(self.transport, "router")
                        and profile.supports_ios_cli
                        and any(c.strip().lower() in _SHUTDOWN_CMDS for c, _ in cleaned_lines)
                    ):
                        _get_batch_sleep_fn(self.transport)(_MICRO_BATCH_SETTLE_SECONDS)
                    end_cmds = ConsoleStateMachine.transition_commands(
                        session.current_mode, CLIPromptMode.PRIVILEGED_EXEC
                    )
                    to_send = [*end_cmds, *verification_commands]
                    v_timeout = _compute_batch_timeout(profile.command_timeout_seconds, to_send)
                    send_batch_fn = self.transport.send_batch  # type: ignore[attr-defined]
                    v_kwargs: dict[str, Any] = {"timeout_s": v_timeout}
                    if _callable_accepts_kwarg(send_batch_fn, "stop_on_error"):
                        v_kwargs["stop_on_error"] = False
                    vres = send_batch_fn(device_name, to_send, **v_kwargs)
                    v_raw_full = redact_cli_text(
                        strip_paging_and_control(str(vres.get("raw_output", "")))
                    )
                    v_cmd_outputs = vres.get("command_outputs")
                    v_fallback_slices = (
                        None
                        if (isinstance(v_cmd_outputs, list) and len(v_cmd_outputs) >= len(to_send))
                        else _split_batch_output(v_raw_full, to_send)
                    )
                    offset = len(end_cmds)
                    for v_idx, vcmd in enumerate(verification_commands):
                        out_pos = offset + v_idx
                        if isinstance(v_cmd_outputs, list) and out_pos < len(v_cmd_outputs):
                            vclean = redact_cli_text(
                                strip_paging_and_control(str(v_cmd_outputs[out_pos]))
                            )
                            if not vclean.strip() and len(verification_commands) == 1:
                                vclean = v_raw_full
                        elif v_fallback_slices is not None and out_pos < len(v_fallback_slices):
                            vclean = v_fallback_slices[out_pos]
                            if not vclean.strip() and len(verification_commands) == 1:
                                vclean = v_raw_full
                        else:
                            vclean = v_raw_full
                        verification_output[vcmd] = vclean
                        vdiags = parse_cli_output(vclean)
                        if vdiags:
                            failed_commands.append(vcmd)
                        else:
                            evidence.append(
                                f"Verified '{vcmd}' output ({len(vclean.splitlines())} lines)."
                            )
                    session.current_mode = CLIPromptMode.PRIVILEGED_EXEC
                    v_prompt = PromptDetector.parse(
                        str(vres.get("prompt", "")).strip() or v_raw_full
                    )
                    if v_prompt.raw_prompt:
                        session.last_prompt = v_prompt.raw_prompt
                    if v_raw_full:
                        session.last_output_tail = v_raw_full[-800:]

                if not evidence and not failed_commands:
                    batch_word = "batch" if sent_batch_count == 1 else "batches"
                    evidence.append(
                        f"Dispatched {len(transcripts)} command(s) in {sent_batch_count} "
                        f"{batch_word} ({batch_elapsed:.1f}ms) via {self.transport.transport_name}."
                    )

                all_ok = len(failed_commands) == 0
                state_level = (
                    StateLevel.VERIFIED if (all_ok and verification_output) else StateLevel.EXECUTED
                )
                report = ConsoleExecutionReport(
                    device_name=device_name,
                    state_level=state_level,
                    session=session,
                    transcripts=transcripts,
                    all_commands_succeeded=all_ok,
                    failed_commands=failed_commands,
                    verification_output=verification_output,
                    evidence=evidence,
                    warnings=warnings,
                )
                return report.model_dump(mode="json")

        all_lines = [(c, True) for c in prep_cmds] + [(c, False) for c in commands]
        for raw_cmd, is_prep in all_lines:
            cmd = raw_cmd.strip()
            if not cmd:
                continue

            mode_before = session.current_mode
            t0 = time.perf_counter()
            raw_out = self.transport.send_line(
                device_name,
                cmd,
                timeout_s=profile.command_timeout_seconds,
            )

            # Handle interactive password/confirmation/setup prompts, then drain paging.
            parsed = PromptDetector.parse(raw_out)
            interactive_guard = 0
            while interactive_guard < 4 and parsed.mode in {
                CLIPromptMode.PASSWORD_PROMPT,
                CLIPromptMode.CONFIRM_PROMPT,
                CLIPromptMode.INITIAL_SETUP_DIALOG,
            }:
                if parsed.mode == CLIPromptMode.PASSWORD_PROMPT:
                    reply = enable_password or ""
                elif parsed.mode == CLIPromptMode.INITIAL_SETUP_DIALOG:
                    reply = "no"
                elif "how many bits in the modulus" in raw_out.lower():
                    reply = "1024"
                else:
                    reply = ""
                extra_prompt = self.transport.send_line(
                    device_name, reply, timeout_s=profile.command_timeout_seconds
                )
                raw_out = f"{raw_out}\n{extra_prompt}"
                parsed = PromptDetector.parse(raw_out)
                interactive_guard += 1

            drain_guard = 0
            while parsed.has_paging and drain_guard < 12:
                extra = self.transport.send_line(
                    device_name, " ", timeout_s=profile.command_timeout_seconds
                )
                raw_out = f"{raw_out}\n{extra}"
                parsed = PromptDetector.parse(raw_out)
                drain_guard += 1

            elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
            cleaned_out = redact_cli_text(strip_paging_and_control(raw_out))
            diags = [] if cmd.endswith("?") else parse_cli_output(cleaned_out)
            ok = len(diags) == 0

            mode_after = (
                parsed.mode if parsed.mode != CLIPromptMode.UNKNOWN else session.current_mode
            )
            session.current_mode = mode_after
            if parsed.hostname:
                session.hostname = parsed.hostname
            if parsed.raw_prompt:
                session.last_prompt = parsed.raw_prompt
            session.last_output_tail = cleaned_out[-800:]

            redacted_cmd = redact_cli_text(cmd)
            if not ok:
                session.errors_detected += len(diags)
                failed_commands.append(redacted_cmd)
                if not is_prep:
                    warnings.append(
                        f"CLI error after '{redacted_cmd}': {diags[0].code} - {diags[0].message}"
                    )

            transcripts.append(
                CommandTranscript(
                    command=redacted_cmd,
                    mode_before=mode_before,
                    mode_after=mode_after,
                    raw_output=cleaned_out,
                    diagnostics=diags,
                    succeeded=ok,
                    elapsed_ms=elapsed,
                )
            )
            if not ok and stop_on_error:
                break

        if verification_commands and not failed_commands:
            end_cmds = ConsoleStateMachine.transition_commands(
                session.current_mode, CLIPromptMode.PRIVILEGED_EXEC
            )
            for ec in end_cmds:
                self.transport.send_line(device_name, ec, timeout_s=profile.command_timeout_seconds)
                session.current_mode = CLIPromptMode.PRIVILEGED_EXEC
            for vcmd in verification_commands:
                vraw = self.transport.send_line(
                    device_name, vcmd, timeout_s=profile.command_timeout_seconds
                )
                parsed_v = PromptDetector.parse(vraw)
                drain = 0
                while parsed_v.has_paging and drain < 12:
                    more_chunk = self.transport.send_line(
                        device_name, " ", timeout_s=profile.command_timeout_seconds
                    )
                    vraw = f"{vraw}\n{more_chunk}"
                    parsed_v = PromptDetector.parse(vraw)
                    drain += 1
                vclean = redact_cli_text(strip_paging_and_control(vraw))
                verification_output[vcmd] = vclean
                vdiags = parse_cli_output(vclean)
                if vdiags:
                    failed_commands.append(vcmd)
                else:
                    evidence.append(f"Verified '{vcmd}' output ({len(vclean.splitlines())} lines).")

        all_ok = len(failed_commands) == 0
        state_level = (
            StateLevel.VERIFIED if (all_ok and verification_output) else StateLevel.EXECUTED
        )
        if not evidence and all_ok:
            evidence.append(
                f"Dispatched {len(transcripts)} command(s) via {self.transport.transport_name}."
            )

        report = ConsoleExecutionReport(
            device_name=device_name,
            state_level=state_level,
            session=session,
            transcripts=transcripts,
            all_commands_succeeded=all_ok,
            failed_commands=failed_commands,
            verification_output=verification_output,
            evidence=evidence,
            warnings=warnings,
        )
        return report.model_dump(mode="json")

    def capture_output(self, device_name: str, *, model: str = "2911") -> dict[str, Any]:
        """Read the current terminal buffer, parse active prompt/mode, and flag IOS errors."""
        raw = self.transport.read_buffer(device_name)
        cleaned = redact_cli_text(strip_paging_and_control(raw))
        parsed = PromptDetector.parse(cleaned)
        diags = parse_cli_output(cleaned)

        session = self._get_or_init_session(device_name, model)
        session.is_open = True
        session.current_mode = parsed.mode
        if parsed.hostname:
            session.hostname = parsed.hostname
        session.last_prompt = parsed.raw_prompt
        session.last_output_tail = cleaned[-800:]

        return {
            "device_name": device_name,
            "captured_output": cleaned,
            "parsed_prompt": parsed.model_dump(mode="json"),
            "diagnostics": [d.model_dump(mode="json") for d in diags],
            "state_level": StateLevel.VERIFIED.value,
        }

    def inspect_session(self, device_name: str, *, model: str = "2911") -> dict[str, Any]:
        """Inspect current tracked console session state and refresh buffer if open."""
        profile = get_console_profile(model, catalog=self.catalog)
        session = self._sessions.get(device_name)
        refreshed = False
        if self.transport.is_available():
            try:
                buf = self.transport.read_buffer(device_name)
                if buf:
                    parsed = PromptDetector.parse(buf)
                    session = self._get_or_init_session(device_name, profile.model)
                    session.is_open = True
                    session.current_mode = parsed.mode
                    session.hostname = parsed.hostname or session.hostname
                    session.last_prompt = parsed.raw_prompt
                    session.last_output_tail = redact_cli_text(strip_paging_and_control(buf))[-800:]
                    refreshed = True
            except Exception:
                refreshed = False

        if session is None:
            session = ConsoleSessionState(
                device_name=device_name,
                model=profile.model,
                is_open=False,
                transport_name=self.transport.transport_name,
            )

        return {
            "session": session.model_dump(mode="json"),
            "profile": profile.model_dump(mode="json"),
            "refreshed_from_transport": refreshed,
            "state_level": StateLevel.VERIFIED.value if refreshed else StateLevel.PLANNED.value,
        }
