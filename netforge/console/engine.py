"""Device Console Engine implementing recoverable CLI execution and verification."""

from __future__ import annotations

import platform
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
from netforge.core.exceptions import IOSConfigError
from netforge.devices import DEFAULT_CATALOG, DeviceCatalog
from netforge.gui.windows_backend import WindowsGuiBackend
from netforge.ios.validators import parse_cli_output
from netforge.security.redaction import redact_cli_text


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

    def _get_or_init_session(self, device_name: str, model: str) -> ConsoleSessionState:
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

        if not session.is_open:
            self.open_console(device_name, model=profile.model)
            session = self._sessions[device_name]

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

        verification_output: dict[str, str] = {}
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
