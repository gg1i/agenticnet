"""Device Console Engine implementing recoverable CLI execution and verification."""

from __future__ import annotations

import platform
import threading
import time
from typing import Any

from netforge.adapters.base import ConsoleBackend
from netforge.console.models import (
    CLIPromptMode,
    CommandTranscript,
    ConsoleExecutionReport,
    ConsoleInteractionKind,
    ConsoleSessionState,
)
from netforge.console.profiles import get_console_profile
from netforge.console.state_machine import (
    ConsoleStateMachine,
    PromptDetector,
    strip_paging_and_control,
)
from netforge.console.transport import (
    ConsoleTransport,
    UnavailableConsoleTransport,
    WindowsGuiConsoleTransport,
)
from netforge.core.enums import StateLevel
from netforge.core.exceptions import AdapterUnavailableError, IOSConfigError
from netforge.devices import DEFAULT_CATALOG, DeviceCatalog
from netforge.gui.windows_backend import WindowsGuiBackend
from netforge.ios.models import CLIDiagnostic
from netforge.ios.validators import parse_cli_output
from netforge.security.redaction import redact_cli_text


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
    elif remaining and _canon_mode_cmd(remaining[-1]) == user_cmds[0]:
        return raw_remaining[:-1]
    return raw_remaining


def _predict_mode_after(current: CLIPromptMode, cmd: str) -> CLIPromptMode:
    """Predict likely IOS prompt mode transition for a single command in a batch."""
    low = cmd.strip().lower()
    if low in {"en", "enable"}:
        return CLIPromptMode.PRIVILEGED_EXEC if current == CLIPromptMode.USER_EXEC else current
    if low in {"conf t", "config t", "configure terminal"}:
        return CLIPromptMode.GLOBAL_CONFIG
    if low == "end":
        return CLIPromptMode.PRIVILEGED_EXEC
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
    return current


def _compute_batch_timeout(base_timeout_s: float, commands: list[str]) -> float:
    """Scale batch timeout cleanly when slow ping/traceroute/DHCP commands are present."""
    slow_cmds = sum(
        1
        for cmd in commands
        if cmd.strip().lower().startswith(("ping ", "traceroute ", "ipconfig /renew"))
    )
    return max(float(base_timeout_s), 20.0) + slow_cmds * 10.0 + len(commands) * 0.4


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
            and parsed.mode in {CLIPromptMode.USER_EXEC, CLIPromptMode.PRIVILEGED_EXEC}
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

        if not use_batch and not session.is_open:
            self.open_console(device_name, model=profile.model)
            session = self._sessions[device_name]
        elif use_batch and not session.is_open:
            session.is_open = True
            if session.current_mode == CLIPromptMode.UNKNOWN:
                session.current_mode = (
                    CLIPromptMode.PC_PROMPT
                    if profile.interaction_kind == ConsoleInteractionKind.PT_DESKTOP_CMD
                    else CLIPromptMode.USER_EXEC
                )

        prep_cmds: list[str] = []
        if target_mode == "privileged_exec":
            prep_cmds = ConsoleStateMachine.transition_commands(
                session.current_mode,
                CLIPromptMode.PRIVILEGED_EXEC,
                enable_password=enable_password,
            )
        elif target_mode == "global_config":
            prep_cmds = ConsoleStateMachine.transition_commands(
                session.current_mode,
                CLIPromptMode.GLOBAL_CONFIG,
                enable_password=enable_password,
            )
        elif target_mode == "user_exec":
            prep_cmds = ConsoleStateMachine.transition_commands(
                session.current_mode,
                CLIPromptMode.USER_EXEC,
            )

        transcripts: list[CommandTranscript] = []
        failed_commands: list[str] = []
        evidence: list[str] = []
        warnings: list[str] = []
        verification_output: dict[str, str] = {}

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
            if cleaned_lines:
                batch_cmds = [cmd for cmd, _ in cleaned_lines]
                batch_timeout_s = _compute_batch_timeout(
                    profile.command_timeout_seconds, batch_cmds
                )
                try:
                    t0 = time.perf_counter()
                    batch_res = self.transport.send_batch(  # type: ignore[attr-defined]
                        device_name,
                        batch_cmds,
                        timeout_s=batch_timeout_s,
                    )
                    batch_elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
                    batch_handled = True
                except AdapterUnavailableError:
                    fallback = getattr(self.transport, "fallback", None)
                    if fallback is None or not fallback.is_available():
                        raise
            else:
                batch_res = {"ok": True, "raw_output": "", "prompt": "", "command_statuses": []}
                batch_elapsed = 0.0
                batch_handled = True

            if batch_handled:
                raw_out = str(batch_res.get("raw_output", ""))
                cleaned_out = redact_cli_text(strip_paging_and_control(raw_out))
                prompt_str = str(batch_res.get("prompt", "")).strip()
                statuses_raw = batch_res.get("command_statuses", [])
                non_fatal_set = {
                    str(c).strip().lower() for c in batch_res.get("non_fatal_commands", []) if c
                }
                timed_out = bool(batch_res.get("timed_out", False))

                # Filter out harmless `terminal length 0` errors already flagged non-fatal by bridge
                diags_source = cleaned_out
                if "terminal length 0" in non_fatal_set:
                    diags_source = "\n".join(
                        ln
                        for ln in cleaned_out.splitlines()
                        if "terminal length 0" not in ln.lower()
                    )
                diags = parse_cli_output(diags_source)

                status_iter = [
                    entry for entry in statuses_raw if isinstance(entry, dict)
                ] if isinstance(statuses_raw, list) else []
                per_cmd_failed: list[bool] = [False] * len(cleaned_lines)
                s_idx = 0
                for idx, (cmd, _) in enumerate(cleaned_lines):
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
                            for idx, (cmd, _) in enumerate(cleaned_lines):
                                if cmd.lower() == d_cmd_low or d_cmd_low in cmd.lower():
                                    per_cmd_failed[idx] = True
                                    per_cmd_diags.setdefault(idx, []).append(d_item)
                                    matched_any = True
                        if not matched_any and cleaned_lines:
                            fallback_idx = len(cleaned_lines) - 1
                            for idx, (cmd, _) in reversed(list(enumerate(cleaned_lines))):
                                if cmd.lower() in cleaned_out.lower():
                                    fallback_idx = idx
                                    break
                            per_cmd_failed[fallback_idx] = True
                            per_cmd_diags.setdefault(fallback_idx, []).append(d_item)

                per_cmd_ms = round(batch_elapsed / len(cleaned_lines), 2) if cleaned_lines else 0.0
                for idx, (cmd, is_prep) in enumerate(cleaned_lines):
                    mode_before = session.current_mode
                    mode_after = _predict_mode_after(mode_before, cmd)
                    session.current_mode = mode_after
                    redacted_cmd = redact_cli_text(cmd)
                    ok = not per_cmd_failed[idx]
                    cmd_diags: list[CLIDiagnostic] = []
                    if not ok:
                        cmd_diags = per_cmd_diags.get(idx) or diags or [
                            CLIDiagnostic(
                                line_number=idx + 1,
                                command=redacted_cmd,
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
                    elif idx == len(cleaned_lines) - 1 and timed_out:
                        ok = False
                        failed_commands.append(redacted_cmd)
                        warnings.append(f"CLI batch timed out around '{redacted_cmd}'.")

                    transcripts.append(
                        CommandTranscript(
                            command=redacted_cmd,
                            mode_before=mode_before,
                            mode_after=mode_after,
                            raw_output=cleaned_out if idx == len(cleaned_lines) - 1 else "",
                            diagnostics=cmd_diags,
                            succeeded=ok,
                            elapsed_ms=per_cmd_ms,
                        )
                    )

                final_parsed = PromptDetector.parse(prompt_str or cleaned_out)
                if final_parsed.mode != CLIPromptMode.UNKNOWN:
                    session.current_mode = final_parsed.mode
                    if transcripts:
                        transcripts[-1].mode_after = final_parsed.mode
                if final_parsed.hostname:
                    session.hostname = final_parsed.hostname
                if final_parsed.raw_prompt:
                    session.last_prompt = final_parsed.raw_prompt
                elif prompt_str:
                    session.last_prompt = prompt_str
                session.last_output_tail = cleaned_out[-800:]

                if verification_commands and not failed_commands:
                    end_cmds = ConsoleStateMachine.transition_commands(
                        session.current_mode, CLIPromptMode.PRIVILEGED_EXEC
                    )
                    for v_idx, vcmd in enumerate(verification_commands):
                        to_send = ([*end_cmds, vcmd] if (v_idx == 0 and end_cmds) else [vcmd])
                        vres = self.transport.send_batch(  # type: ignore[attr-defined]
                            device_name,
                            to_send,
                            timeout_s=profile.command_timeout_seconds,
                        )
                        vclean = redact_cli_text(
                            strip_paging_and_control(str(vres.get("raw_output", "")))
                        )
                        verification_output[vcmd] = vclean
                        session.current_mode = CLIPromptMode.PRIVILEGED_EXEC
                        vdiags = parse_cli_output(vclean)
                        if vdiags:
                            failed_commands.append(vcmd)
                        else:
                            evidence.append(
                                f"Verified '{vcmd}' output ({len(vclean.splitlines())} lines)."
                            )

                if not evidence and not failed_commands:
                    evidence.append(
                        f"Dispatched {len(transcripts)} command(s) in 1 batch "
                        f"({batch_elapsed:.1f}ms) via {self.transport.transport_name}."
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

            # Drain any --More-- paging automatically if paging wasn't disabled.
            parsed = PromptDetector.parse(raw_out)
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
            diags = parse_cli_output(cleaned_out)
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
