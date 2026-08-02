#!/usr/bin/env python3
"""benchmark/run_benchmark.py — CLI entry point for the Elengenix benchmark.

Runs Elengenix against the local vulnerable Flask app and prints a
precision/recall/F1 report. This is the measurement tool that proves
whether Elengenix can actually find vulnerabilities — not just claim to.

Usage:
    python3 benchmark/run_benchmark.py
    python3 benchmark/run_benchmark.py --max-steps 50
    python3 benchmark/run_benchmark.py --target http://localhost:8080
    python3 benchmark/run_benchmark.py --legacy    # use legacy loop (unsupported)
    python3 benchmark/run_benchmark.py --json      # machine-readable output

    # Per-model sweep (the capability uplift):
    python3 benchmark/run_benchmark.py --models gemma2:9b,llama3.2
    python3 benchmark/run_benchmark.py --models gemma2:9b --repeat 3
    python3 benchmark/run_benchmark.py --history            # last stored runs
    python3 benchmark/run_benchmark.py --history --history-limit 50

Exit codes:
    0 — run(s) completed, recall/F1 > 0
    1 — run(s) completed but nothing found (real zero-result)
    2 — the benchmark itself could not run (missing deps, no AI key,
        unsupported mode, or every sweep run errored).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

logger = logging.getLogger(__name__)
from pathlib import Path

# Make the project root importable when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmark import results_store, sweep
from benchmark.grading import GROUND_TRUTH
from benchmark.runner import run_elengenix_benchmark


def _add_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--target", default=None,
        help="Target URL. If omitted, a fresh vulnerable app is started locally.",
    )
    # Scan intensity presets: mirror real engagement pacing.
    # -s/--intensity picks a preset; --max-steps overrides when explicitly set.
    # minimum:  quick smoke test / dev loop (5-15 min with a chat model)
    # medium:   standard bug-bounty depth (30-90 min; the current default)
    # full:     deep, methodical hunt for large scopes (multi-hour; what you'd
    #           run against Google/Microsoft-scale infrastructure)
    intensity = parser.add_mutually_exclusive_group()
    intensity.add_argument(
        "-s", "--intensity",
        choices=("minimum", "medium", "full"),
        default="medium",
        help="Scan depth preset: minimum (10 steps / ~5-15min), medium "
             "(30 steps / ~30-90min, default), full (120 steps / multi-hour, "
             "for large real-world scopes).",
    )
    intensity.add_argument(
        "--quick", dest="intensity", action="store_const", const="minimum",
        help="Alias for --intensity minimum.",
    )
    intensity.add_argument(
        "--deep", dest="intensity", action="store_const", const="full",
        help="Alias for --intensity full (deep multi-hour scan).",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=None,
        help="Max agent reasoning steps. Defaults by --intensity: "
             "minimum=10, medium=30, full=120.",
    )
    parser.add_argument(
        "--time-limit",
        type=int,
        default=None,
        help="Hard timeout in seconds. Defaults by --intensity: "
             "600s (10min) minimum, 3600s (1hr) medium, 28800s (8hrs) full.",
    )
    parser.add_argument(
        "--legacy", action="store_true",
        help="Use the legacy universal loop (UNSUPPORTED by the benchmark: it "
             "produces no structured findings, so exits non-zero).",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output machine-readable JSON instead of human text.",
    )
    parser.add_argument(
        "--models", default=None,
        help="Comma-separated model names for a per-model sweep, e.g. "
             "'gemma2:9b,llama3.2'. Each model runs the benchmark once per "
             "--repeat and results are aggregated + persisted.",
    )
    parser.add_argument(
        "--repeat", type=int, default=1,
        help="Repeat each model N times (sweep mode only; default: 1).",
    )
    parser.add_argument(
        "--provider", default=None,
        help="Optional provider override (rare; only for sweep/forced selection).",
    )
    # Difficulty tier for the local target. Stealth is now the default; --loud
    # restores the original behavior (index lists vulns, error paths echo the
    # raw SQL query / attempted path).
    tier = parser.add_mutually_exclusive_group()
    tier.add_argument(
        "--stealth", dest="stealth", action="store_true", default=True,
        help="Opaque target mode (default). No vuln hints on the index and no "
             "debug echo — the agent must discover and prove findings itself.",
    )
    tier.add_argument(
        "--loud", dest="stealth", action="store_false",
        help="Loud target mode (legacy): index lists endpoints/vulns and error "
             "paths echo raw query/attempted path. Easier, for smoke tests.",
    )
    parser.add_argument(
        "--flag", default=None,
        help="Explicit per-run impact FLAG value. Normally auto-generated; set "
             "only for reproducibility/debugging. Ignored with --target.",
    )
    parser.add_argument(
        "--history", action="store_true",
        help="Print a table of the most recent stored benchmark runs and exit.",
    )
    parser.add_argument(
        "--history-limit", type=int, default=20,
        help="How many stored runs to show with --history (default: 20).",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose logging.",
    )


def _cmd_history(args: argparse.Namespace) -> int:
    rows = results_store.load_history(limit=args.history_limit)
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(results_store.format_history(rows))
    return 0


def _cmd_sweep(args: argparse.Namespace) -> int:
    models = sweep.parse_models(args.models)
    if not models:
        print("error: --models given but no model names parsed", file=sys.stderr)
        return 2

    sweeps = sweep.run_sweep(
        models=models,
        repeat=args.repeat,
        target_url=args.target,
        max_steps=args.max_steps,
        provider=args.provider,
        stealth=args.stealth,
        flag=args.flag,
        persist=True,
        time_limit=args.time_limit,
    )

    if args.json:
        print(json.dumps(sweep.aggregate_dict(sweeps), indent=2))
    else:
        print(sweep.format_aggregate(sweeps))

    # Exit code mirrors single-run semantics:
    #   2  every run errored (benchmark broken)
    #   0  at least one ok run had recall > 0
    #   1  ok runs existed but none found anything
    any_ok = any(s.ok_runs for s in sweeps)
    if not any_ok:
        print("benchmark error: all sweep runs failed (broken benchmark, not "
              "a real zero).", file=sys.stderr)
        return 2
    best = max((r.f1() for s in sweeps for r in s.ok_runs), default=0.0)
    return 0 if best > 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Elengenix benchmark against a vulnerable target.",
    )
    _add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Resolve intensity preset → concrete max_steps. Explicit --max-steps wins.
    INTENSITY_STEPS = {"minimum": 10, "medium": 30, "full": 120}
    INTENSITY_TIMEOUTS = {"minimum": 600, "medium": 3600, "full": 28800}

    if args.max_steps is None:
        args.max_steps = INTENSITY_STEPS[args.intensity]
    if args.time_limit is None:
        args.time_limit = INTENSITY_TIMEOUTS[args.intensity]
    logger.info(
        "Benchmark intensity=%s → max_steps=%d%s",
        args.intensity,
        args.max_steps,
        f" (override of {INTENSITY_STEPS[args.intensity]})"
        if args.max_steps != INTENSITY_STEPS[args.intensity]
        else "",
    )

    # --history is a pure lookup; runs before anything heavy.
    if args.history:
        return _cmd_history(args)

    # --models switches into sweep mode.
    if args.models:
        return _cmd_sweep(args)

    print(f"Ground truth: {len(GROUND_TRUTH)} known vulnerabilities", file=sys.stderr)

    if args.legacy:
        print(
            "Legacy loop (--legacy) is not supported by the benchmark: "
            "process_universal returns a text summary with no structured "
            "findings to grade. Run without --legacy to use the canonical "
            "ScanLoop.",
            file=sys.stderr,
        )

    result = run_elengenix_benchmark(
        target_url=args.target,
        max_steps=args.max_steps,
        use_canonical_loop=not args.legacy,
        provider=args.provider,
        stealth=args.stealth,
        flag=args.flag,
    )

    # Persist every real single run so --history / sweeps stay comparable.
    # Record the effective model/provider for human context; read via the
    # existing config mechanism, never hard, so a lookup failure can't break
    # the benchmark.
    _eff_model = None
    _eff_provider = args.provider
    try:
        from tools.universal_ai_client import UniversalAIClient

        _probe = UniversalAIClient()
        _eff_model = getattr(_probe, "model", None)
        if not _eff_provider:
            _eff_provider = getattr(_probe, "provider", None)
    except Exception:
        pass

    try:
        results_store.save_result(result, model=_eff_model, provider=_eff_provider)
    except Exception as e:
        print(f"warning: failed to persist benchmark result: {e}", file=sys.stderr)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.summary())

    # Exit status is unambiguous:
    #   0  a real run completed and recall > 0 (the agent found at least one vuln)
    #   1  nothing found (real run, recall == 0)
    #   2  the benchmark itself could not run (missing deps, no AI key,
    #      unsupported mode, target failed to start). A broken benchmark must
    #      never masquerade as "agent found nothing".
    if result.error:
        print(f"benchmark error: {result.error}", file=sys.stderr)
        return 2
    return 0 if result.recall() > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
