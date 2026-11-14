"""Benchmark runner skeleton for NetForge lab-solving evaluation (`offline_mock` / `live_pt`)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netforge.diagnostics.benchmark import (
    MOCK_COMPARABILITY_NOTICE,
    BenchmarkResult,
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
        help="Attempt live Packet Tracer benchmark (unavailable until PT bridge integration).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional output file path for canonical JSON report (outside tracked repo).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute offline mock benchmark or report live unavailability cleanly."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.live and not args.mock:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "passed": False,
                    "error": (
                        "Live PT benchmark runs are disabled in offline skeleton mode; "
                        "re-run with --mock for offline validation or wait for live Phase 5 gate."
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

    results: list[BenchmarkResult] = []
    for target in targets:
        res = run_offline_mock_benchmark(
            target,
            agent_name=args.agent,
            model_name=args.model,
            max_iterations=args.max_iterations,
            time_budget_seconds=args.time_budget,
        )
        results.append(res)

    payload = (
        results[0].model_dump(mode="json")
        if len(results) == 1
        else {
            "schema_version": "1.0.0",
            "mock": True,
            "mode": "offline_mock",
            "comparability_notice": MOCK_COMPARABILITY_NOTICE,
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
