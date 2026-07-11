"""tests/test_hypothesis_boost.py

Verification for the hypothesis-driven boost that addresses the PentestPad
(2026) finding: AI is weak at creative, off-script discovery when stuck on
known patterns. The boost must emit distinct, cycling hypotheses and not
repeat itself until the pool is exhausted.
"""

from __future__ import annotations

from agents.hypothesis_boost import HypothesisBoost, build_stuck_guidance


def test_emit_distinct_hypotheses_before_repeat():
    boost = HypothesisBoost()
    seen = []
    n = 5  # pool size
    for i in range(n):
        h = boost.next_hypothesis(stuck_count=i)
        assert h not in seen, "hypothesis repeated before pool exhausted"
        seen.append(h)
    assert len(seen) == n


def test_cycles_after_pool_exhausted():
    boost = HypothesisBoost()
    first = boost.next_hypothesis()
    from agents.hypothesis_boost import _HYPOTHESIS_TEMPLATES
    pool_size = len(_HYPOTHESIS_TEMPLATES)
    # exhaust remaining distinct hypotheses, then one more to wrap to first
    for _ in range(pool_size - 1 + 1):
        boost.next_hypothesis()
    # after a full cycle it should repeat the first one
    assert boost.next_hypothesis() == first


def test_build_stuck_guidance_contains_hypothesis():
    boost = HypothesisBoost()
    g = build_stuck_guidance(boost, stuck_count=2)
    assert "REFLECTION" in g and "hypothesis" in g.lower()


def test_reset_clears_state():
    boost = HypothesisBoost()
    boost.next_hypothesis()
    boost.reset()
    assert boost.used == []
