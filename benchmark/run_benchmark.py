#!/usr/bin/env python3
"""benchmark/run_benchmark.py — CLI entry point for the Elengenix benchmark.

Runs Elengenix against the local vulnerable Flask app and prints a
precision/recall/F1 report. This is the measurement tool that proves
whether Elengenix can actually find vulnerabilities — not just claim to.

Usage:
    python3 benchmark/run_benchmark.py
    python3 benchmark/run_benchmark.py --max-steps 50
    python3 benchmark/run_benchmark.py --target http://localhost:8080
    python3 benchmark/run_benchmark.py --legacy   # use legacy loop
    python3 benchmark/run_benchmark.py --json     # machine-readable output
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Make the project root importable when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmark.grading import GROUND_TRUTH
from benchmark.runner import run_elengenix_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Elengenix benchmark against a vulnerable target.",
    )
    parser.add_argument(
        "--target", default=None,
        help="Target URL. If omitted, a fresh vulnerable app is started locally.",
    )
    parser.add_argument(
        "--max-steps", type=int, default=30,
        help="Max agent reasoning steps (default: 30).",
    )
    parser.add_argument(
        "--legacy", action="store_true",
        help="Use the legacy universal loop instead of the canonical ScanLoop.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output machine-readable JSON instead of human text.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose logging.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    print(f"Ground truth: {len(GROUND_TRUTH)} known vulnerabilities", file=sys.stderr)

    result = run_elengenix_benchmark(
        target_url=args.target,
        max_steps=args.max_steps,
        use_canonical_loop=not args.legacy,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.summary())

    # Exit code: 0 if recall > 0, 1 if nothing found
    return 0 if result.recall() > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
