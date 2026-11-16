"""Benchmark protocol schema and offline/mock runner for evaluating lab-solving agents."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from netforge.adapters.base import ScriptBackend
from netforge.adapters.discovery import (
    gracefully_close_packet_tracer,
    require_interactive_desktop_for_launch,
)
from netforge.adapters.router import BackendRouter
from netforge.adapters.script_bridge import HttpScriptBridgeBackend, HttpScriptBridgeServer
from netforge.core.settings import NetForgeSettings
from netforge.diagnostics.lab_runner import evaluate_lab_status

DEFAULT_REFERENCE_DIR = Path(__file__).resolve().parents[2] / "benchmarks" / "reference"
MOCK_COMPARABILITY_NOTICE = (
    "MOCK BENCHMARK OUTPUT (offline_mock): synthesized CLI outputs only; "
    "NOT comparable to live Cisco Packet Tracer benchmark runs."
)
LIVE_COMPARABILITY_NOTICE = (
    "LIVE BENCHMARK OUTPUT (live_pt): scored against live Cisco Packet Tracer state."
)


class BenchmarkIterationRecord(BaseModel):
    """Single closed-loop evaluation snapshot during a lab benchmark run."""

    iteration: int = Field(ge=1)
    elapsed_seconds: float = Field(ge=0.0)
    overall_passed: bool
    verify_passed: int = Field(default=0, ge=0)
    verify_total: int = Field(default=0, ge=0)
    coverage_ratio: float | None = Field(default=None, ge=0.0, le=1.0)
    grade_percentage: float | None = Field(default=None, ge=0.0, le=100.0)
    remaining_items: int = Field(default=0, ge=0)


class BenchmarkReferenceScore(BaseModel):
    """Official score computed solely from human-authored hidden reference checks."""

    source: Literal["human_authored_reference"] = "human_authored_reference"
    reference_path: str
    requirements_passed: int = Field(ge=0)
    requirements_total: int = Field(ge=0)
    score_pct: float = Field(ge=0.0, le=100.0)
    all_reference_requirements_passed: bool
    grade_percentage: float | None = Field(default=None, ge=0.0, le=100.0)
    unmet_reference_items: list[dict[str, Any]] = Field(default_factory=list)
    unmet_grader_items: list[dict[str, Any]] = Field(default_factory=list)
    passed: bool


class BenchmarkAgentSelfReport(BaseModel):
    """Agent's own self-declared requirements & coverage (never counts toward score)."""

    counts_toward_score: Literal[False] = False
    verify_summary: dict[str, Any] | None = None
    task_coverage: dict[str, Any] | None = None
    overall_passed: bool | None = None


class BenchmarkEvidence(BaseModel):
    """Structured raw verification/grader evidence attached to a benchmark result."""

    reference_score: BenchmarkReferenceScore
    agent_self_report: BenchmarkAgentSelfReport | None = None
    verify_summary: dict[str, Any] | None = None
    grade_summary: dict[str, Any] | None = None
    task_coverage: dict[str, Any] | None = None
    what_is_left: dict[str, Any] = Field(default_factory=dict)
    raw_outputs: list[str] = Field(default_factory=list)
    iteration_history: list[BenchmarkIterationRecord] = Field(default_factory=list)


class BenchmarkResult(BaseModel):
    """Canonical JSON result schema emitted per benchmark run."""

    schema_version: str = "1.0.0"
    run_id: str = Field(default_factory=lambda: f"bench_{uuid4().hex[:12]}")
    timestamp_utc: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    lab: str
    agent: str
    model: str
    mock: bool = False
    mode: Literal["offline_mock", "live_pt"] = "offline_mock"
    comparability_notice: str = MOCK_COMPARABILITY_NOTICE
    tool_profile: str = "solve_lab"
    iterations: int = Field(ge=0)
    max_iterations: int = Field(ge=1)
    elapsed_seconds: float = Field(ge=0.0)
    time_budget_seconds: float = Field(gt=0.0)
    score_pct: float = Field(ge=0.0, le=100.0)
    passed: bool
    status: Literal["passed", "failed", "blocked", "budget_exceeded"]
    reference_score: BenchmarkReferenceScore
    agent_self_report: BenchmarkAgentSelfReport | None = None
    evidence: BenchmarkEvidence
    error: str | None = None


def build_iteration_record(
    iteration: int,
    elapsed_seconds: float,
    lab_status_data: dict[str, Any],
) -> BenchmarkIterationRecord:
    """Summarize one `lab_status` result dict into a `BenchmarkIterationRecord`."""
    verify = lab_status_data.get("verify") or {}
    summary = verify.get("summary") or {}
    cov = lab_status_data.get("task_coverage") or {}
    grade = lab_status_data.get("grade") or {}
    left = lab_status_data.get("what_is_left") or {}
    remaining = (
        len(left.get("failing_requirements", []))
        + len(left.get("unmet_grader_items", []))
        + len(left.get("uncovered_tasks", []))
    )
    grade_pct = grade.get("percentage_complete") if grade.get("readable") else None
    return BenchmarkIterationRecord(
        iteration=iteration,
        elapsed_seconds=round(max(0.0, elapsed_seconds), 4),
        overall_passed=bool(lab_status_data.get("overall_passed")),
        verify_passed=int(summary.get("passed", 0)),
        verify_total=int(summary.get("total", 0)),
        coverage_ratio=cov.get("coverage_ratio"),
        grade_percentage=float(grade_pct) if isinstance(grade_pct, (int, float)) else None,
        remaining_items=remaining,
    )


def extract_agent_lab_brief(lab_spec: dict[str, Any]) -> dict[str, Any]:
    """Return an agent-safe view of a lab spec without reference requirements or answers."""
    allowed_keys = ("lab_name", "description", "instructions", "devices", "links")
    return {k: lab_spec[k] for k in allowed_keys if k in lab_spec}


def load_reference_spec(
    lab_id: str,
    reference_dir: Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Load the human-authored hidden reference requirement set for `lab_id`."""
    base_dir = reference_dir or DEFAULT_REFERENCE_DIR
    ref_path = base_dir / f"{lab_id}.json"
    if not ref_path.is_file():
        raise FileNotFoundError(
            f"Human-authored benchmark reference not found for '{lab_id}': {ref_path}"
        )
    return ref_path, json.loads(ref_path.read_text(encoding="utf-8"))


def _compute_reference_score(
    ref_status_data: dict[str, Any],
    *,
    reference_label: str,
) -> BenchmarkReferenceScore:
    verify = ref_status_data.get("verify") or {}
    summary = verify.get("summary") or {}
    req_passed = int(summary.get("passed", 0))
    req_total = int(summary.get("total", 0))
    score_pct = round((req_passed / req_total) * 100.0, 2) if req_total > 0 else 0.0
    left = ref_status_data.get("what_is_left") or {}
    grade = ref_status_data.get("grade") or {}
    grade_pct = grade.get("percentage_complete") if grade.get("readable") else None
    all_req_ok = bool(verify.get("passed")) and req_total > 0
    return BenchmarkReferenceScore(
        reference_path=reference_label,
        requirements_passed=req_passed,
        requirements_total=req_total,
        score_pct=score_pct,
        all_reference_requirements_passed=all_req_ok,
        grade_percentage=float(grade_pct) if isinstance(grade_pct, (int, float)) else None,
        unmet_reference_items=list(left.get("failing_requirements", [])),
        unmet_grader_items=list(left.get("unmet_grader_items", [])),
        passed=bool(ref_status_data.get("overall_passed")),
    )


def build_agent_self_report(
    router: BackendRouter,
    *,
    agent_requirements: dict[str, Any] | list[dict[str, Any]] | None = None,
    agent_task_ids: list[str] | None = None,
) -> BenchmarkAgentSelfReport | None:
    """Evaluate client agent's self-declared requirements separately (never counts as score)."""
    if agent_requirements is None and agent_task_ids is None:
        return None
    status_data = evaluate_lab_status(
        router,
        requirements=agent_requirements,
        task_ids=agent_task_ids,
        include_activity_grade=False,
    )
    verify = status_data.get("verify")
    return BenchmarkAgentSelfReport(
        counts_toward_score=False,
        verify_summary=verify.get("summary") if isinstance(verify, dict) else None,
        task_coverage=status_data.get("task_coverage"),
        overall_passed=bool(status_data.get("overall_passed")),
    )


def finalize_benchmark_result(
    *,
    lab: str,
    agent: str,
    model: str,
    mode: Literal["offline_mock", "live_pt"],
    tool_profile: str,
    max_iterations: int,
    time_budget_seconds: float,
    elapsed_seconds: float,
    history: list[BenchmarkIterationRecord],
    final_status_data: dict[str, Any],
    reference_path: str = "benchmarks/reference",
    agent_self_report: BenchmarkAgentSelfReport | None = None,
    error: str | None = None,
    blocked: bool = False,
) -> BenchmarkResult:
    """Assemble and validate a canonical `BenchmarkResult` scored strictly on reference checks."""
    ref_score = _compute_reference_score(final_status_data, reference_label=reference_path)
    overall_passed = bool(ref_score.passed)
    iterations_used = len(history)
    if blocked:
        status: Literal["passed", "failed", "blocked", "budget_exceeded"] = "blocked"
        overall_passed = False
        ref_score = ref_score.model_copy(update={"passed": False})
    elif overall_passed:
        status = "passed"
    elif elapsed_seconds > time_budget_seconds or iterations_used >= max_iterations:
        status = "budget_exceeded"
    else:
        status = "failed"

    grade = final_status_data.get("grade")
    grade_summary = None
    if isinstance(grade, dict):
        grade_summary = {
            "state": grade.get("state"),
            "readable": grade.get("readable"),
            "percentage_complete": grade.get("percentage_complete"),
            "items_count": grade.get("items_count"),
            "correct_items_count": grade.get("correct_items_count"),
            "reason": grade.get("reason"),
        }

    verify = final_status_data.get("verify")
    verify_summary = verify.get("summary") if isinstance(verify, dict) else None
    is_mock = mode == "offline_mock"
    notice = MOCK_COMPARABILITY_NOTICE if is_mock else LIVE_COMPARABILITY_NOTICE

    return BenchmarkResult(
        lab=lab,
        agent=agent,
        model=model,
        mock=is_mock,
        mode=mode,
        comparability_notice=notice,
        tool_profile=tool_profile,
        iterations=iterations_used,
        max_iterations=max_iterations,
        elapsed_seconds=round(max(0.0, elapsed_seconds), 4),
        time_budget_seconds=time_budget_seconds,
        score_pct=ref_score.score_pct,
        passed=overall_passed,
        status=status,
        reference_score=ref_score,
        agent_self_report=agent_self_report,
        evidence=BenchmarkEvidence(
            reference_score=ref_score,
            agent_self_report=agent_self_report,
            verify_summary=verify_summary,
            grade_summary=grade_summary,
            task_coverage=final_status_data.get("task_coverage"),
            what_is_left=dict(final_status_data.get("what_is_left") or {}),
            raw_outputs=list(final_status_data.get("raw_evidence") or []),
            iteration_history=history,
        ),
        error=error,
    )


class _MockLabScriptBackend(ScriptBackend):
    """Minimal mocked ScriptBackend driving offline break -> fix benchmark simulations."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self._spec = spec
        self.fixed = False

    def is_connected(self) -> bool:
        return True

    def ping(self) -> dict[str, Any]:
        return {"ok": True, "backend": "mock_offline"}

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
        return {"ok": True, "linked": True}

    def read_activity_status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "is_activity_file": False,
            "state": "not_activity",
            "readable": False,
        }

    def execute_cli(
        self,
        device_name: str,
        commands: list[str],
        *,
        ensure_privileged: bool = True,
        timeout_seconds: float = 25.0,
    ) -> dict[str, Any]:
        cmd = commands[-1] if commands else ""
        outputs = (
            self._spec.get("mock_outputs_fixed", {})
            if self.fixed
            else self._spec.get("mock_outputs_broken", {})
        )
        text = outputs.get(f"{device_name}:{cmd}") or outputs.get(cmd) or _synthetic_output(
            device_name, cmd, self._spec, self.fixed
        )
        return {
            "ok": True,
            "raw_output": text,
            "results": [{"command": cmd, "status": 0, "output": text}],
        }


def _synthetic_output(device_name: str, cmd: str, spec: dict[str, Any], fixed: bool) -> str:
    """Synthesize plausible IOS output for offline sample-lab benchmark dry-runs."""
    reqs_block = spec.get("requirements") or spec.get("verify") or {}
    reqs = reqs_block.get("requirements", []) if isinstance(reqs_block, dict) else []
    lower = cmd.lower()
    if lower.startswith("show ip interface brief"):
        lines = ["Interface              IP-Address      OK? Method Status                Protocol"]
        for r in reqs:
            if r.get("device") == device_name and r.get("type") in {"interface_up", "ip_assigned"}:
                iface = r["interface"]
                ip = r.get("ip", "10.0.0.1") if fixed else "unassigned"
                st = "up" if fixed else "administratively down"
                pr = "up" if fixed else "down"
                lines.append(f"{iface:<23}{ip:<16}YES manual {st:<22}{pr}")
        return "\n".join(lines)
    if lower.startswith("show ip route"):
        lines = ["Gateway of last resort is not set"]
        if fixed:
            for r in reqs:
                if r.get("device") == device_name and r.get("type") == "route_exists":
                    net = r["network"]
                    nh = r.get("next_hop", "10.0.0.2")
                    proto = r.get("protocol_code") or (
                        "O" if r.get("protocol") == "ospf" else "S"
                    )
                    lines.append(f"{proto}    {net} [110/2] via {nh}, 00:00:10, Gi0/0")
        return "\n".join(lines)
    if lower.startswith("show vlan brief"):
        lines = [
            "VLAN Name                             Status    Ports",
            "---- -------------------------------- --------- -------------------------------",
            "1    default                          active    Fa0/1",
        ]
        if fixed:
            for r in reqs:
                if r.get("device") == device_name and r.get("type") == "vlan_exists":
                    ports = ", ".join(r.get("ports") or [])
                    lines.append(f"{r['vlan_id']}    {r.get('name', 'VLAN')} active    {ports}")
        return "\n".join(lines)
    if lower.startswith("show ip dhcp binding"):
        lines = ["IP address       Client-ID/              Lease expiration        Type"]
        if fixed:
            for r in reqs:
                if r.get("device") == device_name and r.get("type") == "dhcp_binding":
                    lines.append(
                        f"{r['ip']:<17}0001.0001.0001          --                     Automatic"
                    )
        return "\n".join(lines)
    if lower.startswith("show running-config"):
        if not fixed:
            return "!\nhostname Router\n!"
        parts = [f"hostname {device_name}"]
        for r in reqs:
            if r.get("device") == device_name and r.get("type") == "config_contains":
                parts.append(str(r.get("section", "")))
                parts.extend(f" {line}" for line in r.get("contains", []))
        return "\n".join(parts)
    if lower.startswith("show telephony-service"):
        if not fixed:
            return "% Telephony-service is not configured"
        for r in reqs:
            if r.get("device") == device_name and r.get("type") == "telephony_service":
                addr = r.get("source_address", "10.50.100.1")
                port = r.get("source_port", 2000)
                return (
                    f"CONFIG (Version=8.2):\nmax-ephones {r.get('min_ephones', 5)}\n"
                    f"ip source-address {addr} port {port}"
                )
    if lower.startswith("show ephone"):
        if not fixed:
            return ""
        for r in reqs:
            if r.get("device") == device_name and r.get("type") == "ephone_registered":
                mac = r.get("mac_address", "0001.1111.2222")
                dn = r.get("number", "1001")
                eid = r.get("ephone_id", 1)
                st = "REGISTERED" if r.get("require_registered") else "UNREGISTERED"
                return (
                    f"ephone-{eid} Mac:{mac} TCP socket:[1] activeLine:0 {st}\n"
                    f"button 1: dn 1 number {dn}"
                )
    if lower.startswith("ping "):
        return "Success rate is 100 percent (5/5)" if fixed else "Success rate is 0 percent (0/5)"
    return ""


def evaluate_benchmark_with_reference(
    router: BackendRouter,
    *,
    lab_id: str,
    agent_name: str,
    model_name: str,
    mode: Literal["offline_mock", "live_pt"] = "offline_mock",
    tool_profile: str = "solve_lab",
    max_iterations: int = 8,
    time_budget_seconds: float = 900.0,
    elapsed_seconds: float = 0.0,
    history: list[BenchmarkIterationRecord] | None = None,
    reference_dir: Path | None = None,
    agent_requirements: dict[str, Any] | list[dict[str, Any]] | None = None,
    agent_task_ids: list[str] | None = None,
    error: str | None = None,
    blocked: bool = False,
) -> BenchmarkResult:
    """Score a topology strictly against the hidden human-authored reference set."""
    ref_path, ref_spec = load_reference_spec(lab_id, reference_dir=reference_dir)
    ref_reqs = ref_spec.get("requirements", [])
    ref_task_ids = ref_spec.get("task_ids") or [
        str(r["id"]) for r in ref_reqs if r.get("id")
    ]
    ref_payload = {
        "lab_name": ref_spec.get("lab_name", lab_id),
        "task_ids": ref_task_ids,
        "requirements": ref_reqs,
    }
    ref_status = evaluate_lab_status(
        router,
        requirements=ref_payload,
        task_ids=ref_task_ids,
        include_activity_grade=True,
    )
    self_report = build_agent_self_report(
        router,
        agent_requirements=agent_requirements,
        agent_task_ids=agent_task_ids,
    )
    run_history = list(history or [build_iteration_record(1, elapsed_seconds, ref_status)])
    try:
        rel_ref = str(ref_path.relative_to(DEFAULT_REFERENCE_DIR.parents[1])).replace("\\", "/")
    except ValueError:
        rel_ref = f"benchmarks/reference/{ref_path.name}"
    return finalize_benchmark_result(
        lab=lab_id,
        agent=agent_name,
        model=model_name,
        mode=mode,
        tool_profile=tool_profile,
        max_iterations=max_iterations,
        time_budget_seconds=time_budget_seconds,
        elapsed_seconds=elapsed_seconds,
        history=run_history,
        final_status_data=ref_status,
        reference_path=rel_ref,
        agent_self_report=self_report,
        error=error,
        blocked=blocked,
    )


def run_offline_mock_benchmark(
    lab_path: Path,
    *,
    agent_name: str = "mock-agent",
    model_name: str = "offline-mock",
    max_iterations: int = 8,
    time_budget_seconds: float = 900.0,
    tool_profile: str = "solve_lab",
    reference_dir: Path | None = None,
    agent_requirements: dict[str, Any] | list[dict[str, Any]] | None = None,
    agent_task_ids: list[str] | None = None,
) -> BenchmarkResult:
    """Execute a 2-iteration offline mock run scored against the hidden human reference set."""
    t0 = time.monotonic()
    lab_file = Path(lab_path)
    lab_id = lab_file.stem
    spec = json.loads(lab_file.read_text(encoding="utf-8"))
    ref_path, ref_spec = load_reference_spec(lab_id, reference_dir=reference_dir)
    ref_reqs = ref_spec.get("requirements", [])
    ref_task_ids = ref_spec.get("task_ids") or [
        str(r["id"]) for r in ref_reqs if r.get("id")
    ]
    ref_payload = {
        "lab_name": ref_spec.get("lab_name", lab_id),
        "task_ids": ref_task_ids,
        "requirements": ref_reqs,
    }
    # Simulated device outputs follow the reference topology targets when fixed.
    sim_spec = {**spec, "requirements": ref_payload}
    mock_script = _MockLabScriptBackend(sim_spec)
    router = BackendRouter(script_backend=mock_script)
    history: list[BenchmarkIterationRecord] = []

    # Iteration 1: broken/unconfigured state evaluated against hidden human reference
    status_1 = evaluate_lab_status(
        router,
        requirements=ref_payload,
        task_ids=ref_task_ids,
        include_activity_grade=True,
    )
    history.append(build_iteration_record(1, time.monotonic() - t0, status_1))

    if max_iterations >= 2:
        # Iteration 2: fixed state evaluated against hidden human reference
        mock_script.fixed = True
        status_2 = evaluate_lab_status(
            router,
            requirements=ref_payload,
            task_ids=ref_task_ids,
            include_activity_grade=True,
        )
        history.append(build_iteration_record(2, time.monotonic() - t0, status_2))

    return evaluate_benchmark_with_reference(
        router,
        lab_id=lab_id,
        agent_name=agent_name,
        model_name=model_name,
        mode="offline_mock",
        tool_profile=tool_profile,
        max_iterations=max_iterations,
        time_budget_seconds=time_budget_seconds,
        elapsed_seconds=time.monotonic() - t0,
        history=history,
        reference_dir=ref_path.parent,
        agent_requirements=agent_requirements,
        agent_task_ids=agent_task_ids,
    )


def _gracefully_close_packet_tracer() -> None:
    gracefully_close_packet_tracer(timeout_seconds=5.0)
    time.sleep(0.5)


def run_live_pt_benchmark(
    lab_path: Path,
    *,
    agent_name: str = "netforge-auto-solver",
    model_name: str = "live-pt-8.2.2",
    max_iterations: int = 8,
    time_budget_seconds: float = 900.0,
    tool_profile: str = "solve_lab",
    reference_dir: Path | None = None,
) -> BenchmarkResult:
    """Execute a zero-touch live Packet Tracer benchmark scored against the reference set."""
    require_interactive_desktop_for_launch("run_live_pt_benchmark")
    t0 = time.monotonic()
    lab_file = Path(lab_path)
    lab_id = lab_file.stem
    spec = json.loads(lab_file.read_text(encoding="utf-8"))
    ref_path, ref_spec = load_reference_spec(lab_id, reference_dir=reference_dir)
    ref_reqs = ref_spec.get("requirements", [])
    ref_task_ids = ref_spec.get("task_ids") or [
        str(r["id"]) for r in ref_reqs if r.get("id")
    ]
    ref_payload = {
        "lab_name": ref_spec.get("lab_name", lab_id),
        "task_ids": ref_task_ids,
        "requirements": ref_reqs,
    }
    try:
        rel_ref = str(ref_path.relative_to(DEFAULT_REFERENCE_DIR.parents[1])).replace("\\", "/")
    except ValueError:
        rel_ref = f"benchmarks/reference/{ref_path.name}"

    settings = NetForgeSettings.from_env()
    bridge = HttpScriptBridgeBackend(
        HttpScriptBridgeServer(session_file=settings.data_dir / "bridge_session.json"),
        default_timeout_seconds=30.0,
        auto_launch_pt=True,
        packet_tracer_path=settings.packet_tracer_path,
    )
    router = BackendRouter(script_backend=bridge)
    history: list[BenchmarkIterationRecord] = []

    _gracefully_close_packet_tracer()
    bridge.start()
    try:
        if not bridge.ensure_connected(timeout_seconds=45.0):
            return finalize_benchmark_result(
                lab=lab_id,
                agent=agent_name,
                model=model_name,
                mode="live_pt",
                tool_profile=tool_profile,
                max_iterations=max_iterations,
                time_budget_seconds=time_budget_seconds,
                elapsed_seconds=time.monotonic() - t0,
                history=history,
                final_status_data={"verify": {"summary": {"passed": 0, "total": len(ref_reqs)}}},
                reference_path=rel_ref,
                error="Packet Tracer Script Module bridge did not connect within timeout.",
                blocked=True,
            )

        for dev in spec.get("devices", []):
            backend, add_data, _, add_errs = router.add_device(
                dev["name"],
                dev["model"],
                category=dev.get("category", "router"),
                x=float(dev.get("x", 100.0)),
                y=float(dev.get("y", 100.0)),
            )
            if backend != "script_backend" or add_errs:
                raise RuntimeError(f"Failed adding live device '{dev['name']}': {add_errs}")
            if (
                dev.get("category") == "ip_phone" or str(dev.get("model")) == "7960"
            ) and not add_data.get("auto_powered"):
                router.attach_ip_phone_power(dev["name"])

        for link in spec.get("links", []):
            backend, _, _, lnk_errs = router.create_link(
                link["device1"],
                link["port1"],
                link["device2"],
                link["port2"],
                cable_type=link.get("conn_type", "auto"),
            )
            if backend != "script_backend" or lnk_errs:
                raise RuntimeError(f"Failed linking '{link}': {lnk_errs}")

        time.sleep(12.0)

        # Iteration 1: baseline unconfigured lab checked against reference
        status_1 = evaluate_lab_status(
            router,
            requirements=ref_payload,
            task_ids=ref_task_ids,
            include_activity_grade=True,
            poll_wait_seconds=0.0,
        )
        history.append(build_iteration_record(1, time.monotonic() - t0, status_1))

        if max_iterations >= 2:
            def _apply_cli_config_with_retry(dev_name: str, cmds: list[str], phase: str) -> None:
                pt_name = router.resolve_pt_device_name(dev_name)
                res = bridge.execute_cli(pt_name, cmds, timeout_seconds=45.0)
                if res.get("timed_out"):
                    bridge.execute_cli(pt_name, ["end"], timeout_seconds=10.0)
                    res = bridge.execute_cli(pt_name, cmds, timeout_seconds=45.0)
                if res.get("timed_out"):
                    raise RuntimeError(f"Timed out {phase} {dev_name} ({pt_name}).")

            for dev_name, cmds in spec.get("configs", {}).items():
                _apply_cli_config_with_retry(dev_name, list(cmds), "configuring")

            pre_settle = float(spec.get("pre_settle_seconds", 0.0))
            if pre_settle > 0:
                time.sleep(pre_settle)

            for dev_name, cmds in spec.get("post_configs", {}).items():
                _apply_cli_config_with_retry(dev_name, list(cmds), "post-configuring")

            settle = float(spec.get("settle_seconds", 3.0))
            if settle > 0:
                time.sleep(settle)

            status_2 = evaluate_lab_status(
                router,
                requirements=ref_payload,
                task_ids=ref_task_ids,
                include_activity_grade=True,
                poll_wait_seconds=45.0,
            )
            history.append(build_iteration_record(2, time.monotonic() - t0, status_2))

        return evaluate_benchmark_with_reference(
            router,
            lab_id=lab_id,
            agent_name=agent_name,
            model_name=model_name,
            mode="live_pt",
            tool_profile=tool_profile,
            max_iterations=max_iterations,
            time_budget_seconds=time_budget_seconds,
            elapsed_seconds=time.monotonic() - t0,
            history=history,
            reference_dir=ref_path.parent,
            agent_requirements=None,
            agent_task_ids=None,
        )
    finally:
        bridge.stop()
        _gracefully_close_packet_tracer()
