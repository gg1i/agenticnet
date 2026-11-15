"""Benchmark runner skeleton for NetForge lab-solving evaluation (`offline_mock` / `live_pt`)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netforge.diagnostics.benchmark import (
    LIVE_COMPARABILITY_NOTICE,
    MOCK_COMPARABILITY_NOTICE,
    BenchmarkResult,
    run_live_pt_benchmark,
    run_offline_mock_benchmark,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LABS = [
    REPO_ROOT / "labs" / "01_static_routing.json",
    REPO_ROOT / "labs" / "02_vlan_dhcp.json",
    REPO_ROOT / "labs" / "03_small_voice.json",
]


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI parser for the NetForge lab benchmark harness."""
    parser = argparse.ArgumentParser(
        prog="run_benchmark",
        description="Run NetForge lab-solving benchmarks and emit canonical JSON reports.",
    )
    parser.add_argument(
        "--lab",
        default=None,
        help="Path to a single lab specification JSON file.",
    )
    parser.add_argument(
        "--all-sample-labs",
        action="store_true",
        help="Run all sample labs under labs/*.json.",
    )
    parser.add_argument("--agent", default="offline-harness", help="Client agent identifier.")
    parser.add_argument("--model", default="mock", help="Client LLM identifier.")
    parser.add_argument("--max-iterations", type=int, default=8, help="Iteration budget.")
    parser.add_argument(
        "--time-budget",
        type=float,
        default=900.0,
        help="Wall-clock budget in seconds.",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run deterministic offline mocked break -> fix simulation without Packet Tracer.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Target live Packet Tracer benchmark mode (requires --execute-live).",
    )
    parser.add_argument(
        "--execute-live",
        action="store_true",
        help="Confirm launching live Cisco Packet Tracer and running real lab benchmarks.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional output file path for canonical JSON report (outside tracked repo).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute offline mock or live PT benchmark and emit canonical JSON reports."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.live and not args.mock and not args.execute_live:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "passed": False,
                    "error": (
                        "Live PT benchmark requires --execute-live confirmation; "
                        "re-run with --mock for offline validation or pass --live --execute-live."
                    ),
                },
                indent=2,
            )
        )
        return 2

    if args.all_sample_labs:
        targets = SAMPLE_LABS
    elif args.lab:
        targets = [Path(args.lab).expanduser().resolve()]
    else:
        targets = [SAMPLE_LABS[0]]

    live_mode = bool(args.live and args.execute_live and not args.mock)
    results: list[BenchmarkResult] = []
    for target in targets:
        if args.all_sample_labs:
            print(f"[benchmark] running {target.stem}...", file=sys.stderr, flush=True)
        if live_mode:
            res = run_live_pt_benchmark(
                target,
                agent_name=args.agent,
                model_name=args.model if args.model != "mock" else "live-pt-8.2.2",
                max_iterations=args.max_iterations,
                time_budget_seconds=args.time_budget,
            )
        else:
            res = run_offline_mock_benchmark(
                target,
                agent_name=args.agent,
                model_name=args.model,
                max_iterations=args.max_iterations,
                time_budget_seconds=args.time_budget,
            )
        if args.all_sample_labs:
            print(
                f"[benchmark] finished {target.stem}: passed={res.passed} "
                f"score={res.reference_score.requirements_passed}/"
                f"{res.reference_score.requirements_total} "
                f"({res.score_pct:.1f}%, {res.elapsed_seconds:.1f}s)",
                file=sys.stderr,
                flush=True,
            )
        results.append(res)

    payload = (
        results[0].model_dump(mode="json")
        if len(results) == 1
        else {
            "schema_version": "1.0.0",
            "mock": not live_mode,
            "mode": "live_pt" if live_mode else "offline_mock",
            "comparability_notice": (
                LIVE_COMPARABILITY_NOTICE if live_mode else MOCK_COMPARABILITY_NOTICE
            ),
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "results": [r.model_dump(mode="json") for r in results],
        }
    )
    text = json.dumps(payload, indent=2)
    if args.output:
        out_path = Path(args.output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
    else:
        print(text)

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
