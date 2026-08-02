"""benchmark/sweep.py — Per-model benchmark sweep.

Runs the canonical benchmark once per model name (``--models a,b,c``),
optionally repeating each model ``--repeat N`` times, aggregates the results,
and persists every run to the results store so sweeps are comparable across
sessions ("smarter model -> better F1" becomes measurable).

Model selection reuses the *existing* config mechanism: passing ``model=``
into ``UniversalAIClient`` is constructor-param priority (highest) in
``tools/ai_config.resolve_provider_settings`` — the same path the CLI's
provider knob already uses. No new config plumbing.

Public API
----------
    from benchmark.sweep import run_sweep, aggregate

    agg = run_sweep(["gemma2:9b", "llama3.2"], repeat=2, max_steps=30)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from benchmark.grading import BenchmarkResult
from benchmark.runner import run_elengenix_benchmark
from benchmark import results_store

logger = logging.getLogger("elengenix.benchmark.sweep")


@dataclass
class ModelSweep:
    """Aggregated results for one model across repeat runs."""

    model: str
    provider: Optional[str] = None
    runs: List[BenchmarkResult] = field(default_factory=list)

    # -- stats -----------------------------------------------------------
    @property
    def ok_runs(self) -> List[BenchmarkResult]:
        """Runs that actually ran to completion (error is None)."""
        return [r for r in self.runs if r.error is None]

    @property
    def errors(self) -> List[str]:
        return [r.error for r in self.runs if r.error is not None]

    @property
    def n_runs(self) -> int:
        return len(self.runs)

    def _f1s(self) -> List[float]:
        return [r.f1() for r in self.ok_runs]

    def mean_f1(self) -> float:
        f1s = self._f1s()
        return sum(f1s) / len(f1s) if f1s else 0.0

    def min_f1(self) -> float:
        f1s = self._f1s()
        return min(f1s) if f1s else 0.0

    def max_f1(self) -> float:
        f1s = self._f1s()
        return max(f1s) if f1s else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "provider": self.provider,
            "n_runs": self.n_runs,
            "n_ok": len(self.ok_runs),
            "n_errors": len(self.errors),
            "mean_f1": self.mean_f1(),
            "min_f1": self.min_f1(),
            "max_f1": self.max_f1(),
            "errors": self.errors,
        }


def parse_models(models: Optional[str]) -> List[str]:
    """Parse ``--models a,b,c`` into a clean list of model names."""
    if not models:
        return []
    return [m.strip() for m in models.split(",") if m.strip()]


def run_sweep(
    models: List[str],
    repeat: int = 1,
    target_url: Optional[str] = None,
    max_steps: int = 30,
    provider: Optional[str] = None,
    stealth: bool = True,
    flag: Optional[str] = None,
    persist: bool = True,
    store_dir: Optional[Any] = None,
    runner_fn: Optional[Callable] = None,
    time_limit: Optional[int] = None,
) -> List[ModelSweep]:
    """Run the benchmark once per model, optionally repeated.

    Args:
        models: Model names to sweep.
        repeat: How many times to run each model (>=1).
        target_url: Passed to the runner; if None a fresh vuln app is started.
        max_steps: Max agent steps per run.
        provider: Optional provider override (rarely needed; the model
            param is the point of a sweep).
        stealth: Difficulty tier passed through to the runner (default True =
            opaque target). Forwarded so every sweep run uses the same tier.
        flag: Optional explicit FLAG; normally the runner generates one per
            run. Forwarded only for reproducibility.
        persist: If True, save every run to the results store.
        store_dir: Override store directory (tests).
        runner_fn: Optional callable replacing ``run_elengenix_benchmark``
            so tests stay offline. Signature must match the real runner.
        time_limit: Hard timeout in seconds per run, forwarded to the runner.
            None = use the intensity default.

    Returns:
        One ModelSweep per model, in the order given.
    """
    run = runner_fn or run_elengenix_benchmark
    repeat = max(1, repeat)
    sweep_id = f"sweep-{int(time.time())}"

    sweeps: List[ModelSweep] = []
    for model in models:
        ms = ModelSweep(model=model, provider=provider)
        for _ in range(repeat):
            kwargs = {
                "target_url": target_url,
                "max_steps": max_steps,
                "model": model,
                "provider": provider,
                "stealth": stealth,
                "flag": flag,
            }
            if time_limit is not None:
                kwargs["time_limit"] = time_limit
            result = run(**kwargs)
            ms.runs.append(result)
            if persist:
                try:
                    results_store.save_result(
                        result,
                        model=model,
                        provider=provider,
                        sweep_id=sweep_id,
                        store_dir=store_dir,
                    )
                except Exception as e:  # never let persistence break the sweep
                    logger.warning(f"failed to persist benchmark result: {e}")
        sweeps.append(ms)
    return sweeps


def aggregate_dict(sweeps: List[ModelSweep]) -> Dict[str, Any]:
    """Serialize sweep results to a machine-readable dict (--json output)."""
    return {
        "models": [s.to_dict() for s in sweeps],
        "generated_at": time.time(),
    }


def format_aggregate(sweeps: List[ModelSweep]) -> str:
    """Human-readable sweep report."""
    lines = [
        "═══ BENCHMARK SWEEP ═══",
        f"{'MODEL':<{30}} {'RUNS':>4} {'OK':>3} {'ERR':>3} "
        f"{'F1 mean':>8} {'F1 min':>8} {'F1 max':>8}",
        "-" * 68,
    ]
    for s in sweeps:
        lines.append(
            f"{s.model:<{30}} {s.n_runs:>4} {len(s.ok_runs):>3} "
            f"{len(s.errors):>3} {s.mean_f1():>8.1%} {s.min_f1():>8.1%} "
            f"{s.max_f1():>8.1%}"
        )
        # Surface run errors so a broken benchmark is never silent.
        for err in s.errors:
            lines.append(f"    ! {err}")
    return "\n".join(lines)
