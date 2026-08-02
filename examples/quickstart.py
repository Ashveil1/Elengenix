#!/usr/bin/env python3
"""Quick-start: run an autonomous Elengenix scan from Python.

Usage:
    python3 examples/quickstart.py [target]     # default target: example.com
    python3 examples/quickstart.py --help       # show this message and exit

Needs an AI provider key (e.g. `export OPENAI_API_KEY=sk-...`) or
`elengenix configure` once. Only scan targets you may legally test.
"""
from __future__ import annotations

import subprocess
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "example.com"


def main() -> int:
    import shutil

    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print(__doc__)
        return 0

    from elengenix.paths import get_reports_path  # noqa: F401  (ensures dirs exist)
    from elengenix.scope import is_valid_target

    if not is_valid_target(TARGET):
        print(f"Refusing to scan {TARGET!r}: not a valid in-scope target.")
        return 2
    if not shutil.which("elengenix"):
        print("Elengenix CLI not found on PATH — run: pip install elengenix")
        return 2

    reports_dir = get_reports_path()
    try:
        subprocess.run(["elengenix", "scan", TARGET], check=True)
    except subprocess.CalledProcessError as exc:
        print(f"Scan exited with code {exc.returncode} — run `elengenix doctor` for diagnostics.")
        return exc.returncode or 1
    except KeyboardInterrupt:
        print("\nScan interrupted — partial report may exist under", reports_dir)
        return 130

    print(f"Done. Reports: {reports_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
