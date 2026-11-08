"""benchmark/hard_benchmark.py — Elengenix "discrimination under noise" benchmark.

The canonical benchmark (run_benchmark.py) grades the agent against the 10
planted vulns in tests/vulnerable_target/app.py and measures *completeness*
(precision/recall/impact). This benchmark is different on purpose: it grades
the agent against a **harder, noisier** target
(tests/vulnerable_target/hard_target.py) and measures *discrimination*:

  * Can the agent find the 2 REAL vulns that the 10-vuln set never exercised
    (host-header injection, weak/hardcoded JWT secret) and PROVE the JWT one
    by forging an admin token?
  * Does it RESIST the 3 decoys that a naive substring scanner false-positives
    on (escaped reflection, reflected-but-not-traversed, leaked-but-strong
    secret)?

So the two scores are:
  - recall / precision / F1 against the 2 real vulns (finding capability), and
  - decoy_resistance = 1 - (decoys false-positived / decoys)  (precision under
    noise). An agent that "finds everything" by over-reporting scores 100%
    recall here only if it does NOT also flag the decoys.

Run:
    python3 benchmark/run_benchmark_hard.py            # stealth, canonical loop
    python3 benchmark/run_benchmark_hard.py --hunter   # deterministic hunter only
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from benchmark.grading import BenchmarkGrader, BenchmarkResult
from benchmark.runner import (
    _find_free_port,
    _python_for_vuln_app,
    _run_canonical_scan,
)

logger = logging.getLogger("benchmark.hard")

HARD_APP_PATH = Path(__file__).resolve().parent.parent / "tests" / "vulnerable_target" / "hard_target.py"

# The 2 REAL vulnerabilities planted in hard_target.py (ground truth).
HARD_GROUND_TRUTH: List[Dict[str, str]] = [
    {
        "vuln_class": "host_header_injection",
        "endpoint": "/reset",
        "description": "Password-reset link built from the attacker-controlled Host header",
    },
    {
        "vuln_class": "jwt_weak_secret",
        "endpoint": "/api/jwt/verify",
        "description": "JWT HS256 verifier signed with a weak/hardcoded secret (forgeable admin token)",
    },
]

# Decoys that LOOK vulnerable but are not. A discriminating agent must NOT
# report any of these; a naive substring scanner false-positives on them.
HARD_DECOYS: List[Dict[str, str]] = [
    {"vuln_class": "xss", "endpoint": "/search", "reason": "param reflected but HTML-escaped"},
    {"vuln_class": "path_traversal", "endpoint": "/download", "reason": "param echoed, no filesystem access"},
    {"vuln_class": "jwt_weak_secret", "endpoint": "/api/config", "reason": "secret leaked but strong (not forgeable)"},
]


class HardAppServer:
    """Spawn the hard (noisy) target in stealth mode on a free port."""

    def __init__(self, port: Optional[int] = None) -> None:
        self.port = port or _find_free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "HardAppServer":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> None:
        if not HARD_APP_PATH.exists():
            raise FileNotFoundError(f"Hard target not found at {HARD_APP_PATH}")
        env = os.environ.copy()
        env["PORT"] = str(self.port)
        env["ELENGENIX_BENCH_STEALTH"] = "1"
        self._proc = subprocess.Popen(
            [_python_for_vuln_app(), str(HARD_APP_PATH)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        import urllib.request

        # Generous deadline: Flask startup is slow under full-suite load
        # (the intermittent "Hard target did not start" flakes). A crashed
        # process is detected early so real failures still report fast.
        deadline = time.time() + 45
        while time.time() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                break
            try:
                urllib.request.urlopen(f"{self.base_url}/health", timeout=1)
                return
            except Exception:
                time.sleep(0.3)
        self.stop()
        raise RuntimeError(f"Hard target did not start on port {self.port}")

    def stop(self) -> None:
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None


def decoy_resistance(findings: List[Dict[str, Any]]) -> float:
    """1 - (decoys false-positived / total decoys).

    A decoy is 'false-positived' if a reported finding's (canonical class,
    endpoint) matches a decoy entry.
    """
    from benchmark.grading import canonicalize_vuln_class, endpoint_matches

    hits = 0
    for decoy in HARD_DECOYS:
        dc = canonicalize_vuln_class(decoy["vuln_class"])
        for f in findings:
            rc = canonicalize_vuln_class(str(f.get("type") or f.get("vuln_class") or ""))
            re_ = str(f.get("endpoint") or f.get("url") or "")
            if rc == dc and endpoint_matches(re_, decoy["endpoint"]):
                hits += 1
                break
    return 1.0 - (hits / len(HARD_DECOYS)) if HARD_DECOYS else 1.0


def run_hard_benchmark(
    max_steps: int = 8,
    stealth: bool = True,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    time_limit: int = 1200,
    callback: Optional[Callable] = None,
    hunter_only: bool = False,
) -> Dict[str, Any]:
    """Run the hard (noisy) benchmark and return a metrics dict.

    ``hunter_only=True`` runs the deterministic hunter directly (fast,
    model-independent) instead of the full canonical ScanLoop.
    """
    server = HardAppServer()
    try:
        server.start()
    except Exception as e:
        return {"error": f"hard target failed to start: {e}", "precision": 0.0, "recall": 0.0, "f1": 0.0}

    findings: List[Dict[str, Any]] = []
    steps = 0
    ttf = 0.0
    error: Optional[str] = None
    t0 = time.time()
    try:
        if hunter_only:
            from tools.webapp_hunter import run_webapp_hunt

            findings, _summary = run_webapp_hunt(server.base_url)
            steps = 0
        else:
            findings, steps, ttf, error = _run_canonical_scan(
                server.base_url, max_steps, callback,
                model=model, provider=provider, time_limit=time_limit,
            )
    finally:
        server.stop()

    grader = BenchmarkGrader(HARD_GROUND_TRUTH)
    result: BenchmarkResult = grader.grade(
        findings,
        scan_duration_sec=time.time() - t0,
        time_to_first_finding_sec=ttf,
        steps_taken=steps,
        error=error,
    )
    res = decoy_resistance(findings)

    return {
        "error": error,
        "precision": result.precision(),
        "recall": result.recall(),
        "f1": result.f1(),
        "true_positives": len(result.true_positives),
        "false_positives": len(result.false_positives),
        "false_negatives": len(result.false_negatives),
        "decoy_resistance": res,
        "steps_taken": steps,
        "findings": [
            {"type": f.get("type"), "endpoint": f.get("endpoint"),
             "weak_secret": f.get("weak_secret")}
            for f in findings
        ],
        "summary": result.summary(),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    hunter_only = "--hunter" in sys.argv
    print("[hard] running HARD (noisy) discrimination benchmark "
          f"({'hunter-only' if hunter_only else 'canonical loop'})...", flush=True)
    out = run_hard_benchmark(hunter_only=hunter_only)
    print(out["summary"])
    print(f"[hard] Precision : {out['precision']*100:.1f}%")
    print(f"[hard] Recall    : {out['recall']*100:.1f}%")
    print(f"[hard] F1        : {out['f1']:.3f}")
    print(f"[hard] Decoy resistance: {out['decoy_resistance']*100:.1f}% "
          f"({len(HARD_DECOYS)} decoys, {out['false_positives']} total FP)")
    if out.get("error"):
        print(f"[hard] ERROR: {out['error']}")
    sys.exit(0 if (out["recall"] > 0 and out["false_positives"] == 0) else 1)
