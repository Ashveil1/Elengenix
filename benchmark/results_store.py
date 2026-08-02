"""benchmark/results_store.py — Persist & recall benchmark run results.

Each benchmark run (single or per-model sweep) is stored as one JSON file per
run under ``~/.elengenix/data/benchmark_results/`` — the codebase's own
persistence convention (``elengenix.paths.get_data_dir(subdir)`` creates the
subdir on demand, exactly like ``data/cot_logs`` / ``data/sessions``).

The store is deliberately a flat directory of JSON files (no DB, no new
dependency), matching how the rest of the project persists run state.

Public API
----------
    from benchmark.results_store import save_result, load_history, format_history

    path = save_result(result, model="gemma2:9b", provider="ollama")
    rows = load_history(limit=20)
    print(format_history(rows))
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.benchmark.results_store")

# Name of the data/ subdirectory that holds benchmark run JSON files.
STORE_SUBDIR = "benchmark_results"


def get_store_dir(create: bool = True) -> Path:
    """Return the benchmark results directory, following the codebase pattern.

    Uses ``elengenix.paths.get_data_dir`` so user data lands in
    ``~/.elengenix/data/benchmark_results/`` for pip installs. If paths are
    unavailable (bare checkout without the package), falls back to the
    repo-local ``data/benchmark_results/``.
    """
    try:
        from elengenix.paths import get_data_dir

        return get_data_dir(STORE_SUBDIR)
    except Exception:
        # Fallback: repo-local data/<subdir> (same layout, no ~/.elengenix).
        repo_root = Path(__file__).resolve().parent.parent
        p = repo_root / "data" / STORE_SUBDIR
        if create:
            p.mkdir(parents=True, exist_ok=True)
        return p


def _now_ts() -> float:
    return time.time()


def save_result(
    result: Any,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    sweep_id: Optional[str] = None,
    store_dir: Optional[Path] = None,
) -> Path:
    """Persist one BenchmarkResult as a JSON file.

    Args:
        result: A ``BenchmarkResult`` (from benchmark.grading). Its
            ``to_dict()`` must contain precision/recall/f1, error, steps_taken,
            time_to_first_finding_sec, scan_duration_sec.
        model: Model name for this run (per-model sweep entry point).
        provider: Provider name for this run.
        sweep_id: Optional id grouping runs launched in one sweep invocation.
        store_dir: Override directory (tests); default = get_store_dir().

    Returns:
        The Path of the written JSON file.
    """
    data: Dict[str, Any] = result.to_dict()

    record: Dict[str, Any] = {
        "timestamp": _now_ts(),
        "model": model,
        "provider": provider,
        "sweep_id": sweep_id,
        # Flatten the fields the history table cares about at the top level so
        # load_history never has to dig through the full result dict.
        "precision": data.get("precision", 0.0),
        "recall": data.get("recall", 0.0),
        "f1": data.get("f1", 0.0),
        "error": data.get("error"),
        "steps_taken": data.get("steps_taken", 0),
        "time_to_first_finding_sec": data.get("time_to_first_finding_sec", 0.0),
        "scan_duration_sec": data.get("scan_duration_sec", 0.0),
        # Full metrics payload for forensics.
        "result": data,
    }

    d = Path(store_dir) if store_dir else get_store_dir()
    d.mkdir(parents=True, exist_ok=True)

    # Deterministic, sortable filename: <epoch_ms>-<model-or-unknown>.json
    # Millisecond timestamps collide on fast repeat runs, so add a short
    # uniquifier only when the plain name is already taken.
    safe_model = "".join(c if (c.isalnum() or c in "-._") else "_" for c in (model or "unknown"))
    stem = int(record["timestamp"] * 1000)
    fname = f"{stem}-{safe_model}.json"
    path = d / fname
    n = 0
    while path.exists():
        n += 1
        path = d / f"{stem}-{safe_model}-{n}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True))
    logger.debug(f"Saved benchmark result to {path}")
    return path


def load_history(
    limit: int = 20,
    store_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Load stored runs, newest first, up to ``limit``.

    Corrupt/unreadable files are skipped so history never blows up on a
    half-written JSON.
    """
    d = Path(store_dir) if store_dir else get_store_dir()
    if not d.exists():
        return []

    rows: List[Dict[str, Any]] = []
    for p in sorted(d.glob("*.json"), reverse=True):  # filenames are epoch-prefixed
        try:
            rows.append(json.loads(p.read_text()))
        except Exception as e:
            logger.debug(f"Skipping unreadable benchmark result {p}: {e}")
        if len(rows) >= limit:
            break
    return rows


def _fmt_cell(value: Any, width: int) -> str:
    s = "" if value is None else str(value)
    return s.ljust(width)[:width]


def format_history(rows: List[Dict[str, Any]]) -> str:
    """Render history rows as a simple fixed-width table.

    Columns: model, provider, F1, recall, status, date. Error runs are marked
    clearly (``ERR``) and sorted to the bottom within each date view so a
    broken benchmark never masquerades as a low-F1 run.
    """
    if not rows:
        return "No benchmark history yet."

    header = f"{'MODEL':<{28}} {'PROVIDER':<{10}} {'F1':>6} {'RECALL':>7} {'STATUS':<8} DATE"
    lines = [header, "-" * len(header)]

    def _sort_key(r: Dict[str, Any]):
        # Errors sink below real runs; then newest first.
        return (r.get("error") is not None, -(r.get("timestamp") or 0.0))

    for r in sorted(rows, key=_sort_key):
        ts = r.get("timestamp") or 0.0
        date = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "?"
        status = "ERR" if r.get("error") else "ok"
        f1 = f"{r.get('f1', 0.0):.1%}"
        rec = f"{r.get('recall', 0.0):.1%}"
        lines.append(
            f"{_fmt_cell(r.get('model'), 28)} "
            f"{_fmt_cell(r.get('provider'), 10)} "
            f"{f1:>6} {rec:>7} {status:<8} {date}"
        )
    return "\n".join(lines)
