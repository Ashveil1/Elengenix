"""tests/test_hard_benchmark.py — the hard (noisy) discrimination benchmark.

Hermetic tests:
  - the deterministic hunter finds BOTH real vulns on the noisy target and
    resists ALL three decoys (100% precision/recall + 100% decoy resistance);
  - the decoy_resistance() metric behaves correctly on synthetic findings.

Integration test (marked): the full canonical ScanLoop on the hard target.
"""
from __future__ import annotations

import pytest

from benchmark.hard_benchmark import (
    HARD_DECOYS,
    HARD_GROUND_TRUTH,
    decoy_resistance,
    run_hard_benchmark,
)


class TestDecoyResistanceMetric:
    def test_no_findings_full_resistance(self):
        assert decoy_resistance([]) == 1.0

    def test_all_decoys_flagged_zero_resistance(self):
        findings = [
            {"type": d["vuln_class"], "endpoint": d["endpoint"]} for d in HARD_DECOYS
        ]
        assert decoy_resistance(findings) == 0.0

    def test_one_decoy_flagged_partial(self):
        findings = [{"type": "xss", "endpoint": "/search"}]
        assert decoy_resistance(findings) == pytest.approx(2 / 3)

    def test_real_findings_do_not_count(self):
        findings = [
            {"type": "host_header_injection", "endpoint": "/reset"},
            {"type": "jwt_weak_secret", "endpoint": "/api/jwt/verify"},
        ]
        assert decoy_resistance(findings) == 1.0


class TestHardHunter:
    """The deterministic hunter on the noisy target (hermetic, local only)."""

    @pytest.mark.timeout(180)
    def test_hunter_finds_real_vulns_and_resists_decoys(self):
        out = run_hard_benchmark(hunter_only=True)
        assert out["error"] is None
        # Both real vulns found (host-header + weak-secret JWT).
        assert out["true_positives"] == 2
        assert out["false_negatives"] == 0
        # No decoy false-positives.
        assert out["false_positives"] == 0
        assert out["decoy_resistance"] == 1.0
        types = {f["type"] for f in out["findings"]}
        assert "host_header_injection" in types
        assert "jwt_weak_secret" in types
        # The weak-secret finding must be the forged-admin proof, with the
        # proven secret named.
        weak = [f for f in out["findings"] if f["type"] == "jwt_weak_secret"]
        assert weak and weak[0]["endpoint"] == "/api/jwt/verify"
        assert weak[0].get("weak_secret")


@pytest.mark.integration
class TestHardCanonicalLoop:
    """The full canonical ScanLoop on the hard target (integration)."""

    @pytest.mark.timeout(900)
    def test_canonical_loop_finds_real_vulns(self):
        out = run_hard_benchmark(max_steps=3, time_limit=600)
        assert out["error"] is None
        assert out["recall"] >= 0.5  # at least one of the two real vulns
        assert out["false_positives"] == 0  # decoys must not be reported
        assert out["decoy_resistance"] == 1.0
