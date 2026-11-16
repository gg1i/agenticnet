# AgenticNet Benchmark Protocol (`BENCHMARK.md`)

This document defines the standardized evaluation protocol and JSON output format for measuring how reliably an AI client agent solves Cisco Packet Tracer labs using AgenticNet.

## 1. Architecture & Blind Scoring Principles
- **No embedded LLM in AgenticNet:** AgenticNet exposes deterministic MCP tools, prompts, and resources (`solve_lab`, `lab_open`, `lab_status`, `lab_save`). The external MCP client agent performs all planning and reasoning.
- **Process & Workspace Isolation (Mandatory):** Benchmark runs MUST launch the client agent inside a **separate, clean working directory containing only the installed `agenticnet` server** (no repo checkout, no `benchmarks/reference/`, no source tests or answer keys on disk). Official evaluation and scoring are performed afterward by a **separate harness process** with read access to `benchmarks/reference/`.
- **Hidden Human-Authored Reference Scoring:** Every benchmarked lab has a human-authored reference requirement set stored in `benchmarks/reference/<lab_id>.json` (`"authored_by": "human_reference"`, `"agent_visible": false`). The client agent **never** sees this reference requirement set (use `extract_agent_lab_brief()` when preparing prompts; MCP resources and prompts never expose `benchmarks/reference/`).
- **Public Demo Set vs. Held-Out Evaluation:** The 3 sample labs under `labs/` (`01_static_routing`, `02_vlan_dhcp`, `03_small_voice`) are a **public demo set** for smoke-testing and harness reproducibility, **not a held-out test**; held-out unseen labs are required for generalization claims.
- **Agent Self-Report Never Counts as Score:** During a run, the client agent writes its own requirements JSON and `task_ids` for iterative debugging via `lab_status`. That agent self-report (`verify_summary`, `task_coverage`) may be recorded under `agent_self_report` (`"counts_toward_score": false`), and **never** counts toward `score_pct` or `passed`. Only `reference_score` (and native `.pka` `grade_lab` when available) determines pass/fail.
- **Unmistakable Mock Labeling:** Offline harness dry-runs must set `"mock": true`, `"mode": "offline_mock"`, and `"comparability_notice"` stating that synthesized mock results are **not comparable** to live Packet Tracer runs. Public README benchmark tables must show **only live results** (`"mock": false`, `"mode": "live_pt"`).

## 2. Pass / Fail Criteria
A benchmark run is marked `"status": "passed"` (`"passed": true`) **only** when ALL applicable checks against the **hidden human-authored reference** hold before budget exhaustion:
1. All requirements in `benchmarks/reference/<lab_id>.json` pass (`reference_score.all_reference_requirements_passed == true`, `score_pct == 100.0`) with raw CLI evidence (`verified_live == true` in `live_pt` mode).
2. When native `.pka` grading returns `state == "available"` (`readable: true`), `grade.percentage_complete == 100.0` and `unmet_grader_items` is empty.
3. No lock or Assessment-mode bypass was attempted (`grade_lab` stays fail-closed on `"unavailable"`).

If budgets expire (`iterations >= max_iterations` or `elapsed_seconds > time_budget_seconds`), status is `"budget_exceeded"`. If blocked by an unrecoverable desktop/bridge gate, status is `"blocked"`.

## 3. Canonical JSON Result Format

```json
{
  "schema_version": "1.0.0",
  "run_id": "bench_0123456789ab",
  "timestamp_utc": "2026-11-15T00:00:00+00:00",
  "lab": "01_static_routing",
  "agent": "offline-harness",
  "model": "mock",
  "mock": true,
  "mode": "offline_mock",
  "comparability_notice": "MOCK BENCHMARK OUTPUT (offline_mock): synthesized CLI outputs only; NOT comparable to live Cisco Packet Tracer benchmark runs.",
  "tool_profile": "solve_lab",
  "iterations": 2,
  "max_iterations": 8,
  "elapsed_seconds": 0.042,
  "time_budget_seconds": 900.0,
  "score_pct": 100.0,
  "passed": true,
  "status": "passed",
  "reference_score": {
    "source": "human_authored_reference",
    "reference_path": "benchmarks/reference/01_static_routing.json",
    "requirements_passed": 8,
    "requirements_total": 8,
    "score_pct": 100.0,
    "all_reference_requirements_passed": true,
    "grade_percentage": null,
    "unmet_reference_items": [],
    "unmet_grader_items": [],
    "passed": true
  },
  "agent_self_report": {
    "counts_toward_score": false,
    "verify_summary": {"total": 2, "passed": 2, "failed": 0, "errors": 0},
    "task_coverage": {"coverage_ratio": 1.0, "all_tasks_covered": true},
    "overall_passed": true
  },
  "evidence": {
    "reference_score": {"...": "..."},
    "agent_self_report": {"...": "..."},
    "verify_summary": {"total": 8, "passed": 8, "failed": 0, "errors": 0},
    "grade_summary": {"state": "unavailable", "readable": false},
    "task_coverage": {"coverage_ratio": 1.0, "all_tasks_covered": true},
    "what_is_left": {"is_empty": true},
    "raw_outputs": ["..."],
    "iteration_history": [
      {"iteration": 1, "elapsed_seconds": 0.02, "overall_passed": false, "remaining_items": 8},
      {"iteration": 2, "elapsed_seconds": 0.04, "overall_passed": true, "remaining_items": 0}
    ]
  },
  "error": null
}
```

## 4. Public Demo Sample Labs & Runner CLI (`scripts/run_benchmark.py`)
Public demo reference sets implemented under `benchmarks/reference/` (**public demo set, not a held-out test**):
- [01_static_routing.json](../benchmarks/reference/01_static_routing.json)
- [02_vlan_dhcp.json](../benchmarks/reference/02_vlan_dhcp.json)
- [03_small_voice.json](../benchmarks/reference/03_small_voice.json)

Runner commands:
- Offline mock harness validation (not comparable to live):
  ```bash
  python scripts/run_benchmark.py --all-sample-labs --mock
  ```
- Live benchmark runs (`--live`) require an active Cisco Packet Tracer `8.2.2` Script Bridge connection (`agenticnet doctor`).
