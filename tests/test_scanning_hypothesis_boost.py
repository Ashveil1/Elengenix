"""Tests for elengix/scanning/hypothesis_boost.py — HypothesisBoost + build_stuck_guidance."""

from __future__ import annotations

import pytest

from elengenix.scanning.hypothesis_boost import HypothesisBoost, build_stuck_guidance


class TestHypothesisBoost:
    """Tests for the HypothesisBoost dataclass."""

    def test_default_used_empty(self):
        boost = HypothesisBoost()
        assert boost.used == []

    def test_next_hypothesis_returns_string(self):
        boost = HypothesisBoost()
        hyp = boost.next_hypothesis()
        assert isinstance(hyp, str)
        assert len(hyp) > 10

    def test_next_hypothesis_appends_used(self):
        boost = HypothesisBoost()
        hyp = boost.next_hypothesis()
        assert boost.used == [hyp]

    def test_next_hypothesis_cycles(self):
        boost = HypothesisBoost()
        # Get all unique hypotheses (there are 5 templates)
        seen = set()
        for _ in range(10):
            seen.add(boost.next_hypothesis())
        # All 5 templates should be cycled
        assert len(seen) == 5

    def test_next_hypothesis_with_stuck_count(self):
        """stuck_count is only used for logging, not selection."""
        boost = HypothesisBoost()
        h1 = boost.next_hypothesis(stuck_count=0)
        h2 = boost.next_hypothesis(stuck_count=3)
        h3 = boost.next_hypothesis(stuck_count=10)
        assert h1 != h2  # Different templates (cycling)
        assert len(boost.used) == 3

    def test_reset_clears_used(self):
        boost = HypothesisBoost()
        boost.next_hypothesis()
        boost.next_hypothesis()
        assert len(boost.used) == 2
        boost.reset()
        assert boost.used == []

    def test_reset_then_cycles_fresh(self):
        boost = HypothesisBoost()
        h1 = boost.next_hypothesis()
        boost.reset()
        h2 = boost.next_hypothesis()
        # Should restart at index 0
        assert h1 == h2

    def test_deterministic_order(self):
        """Same number of used hypotheses → same next pick."""
        b1, b2 = HypothesisBoost(), HypothesisBoost()
        h1_a, h1_b = b1.next_hypothesis(), b2.next_hypothesis()
        assert h1_a == h1_b
        h2_a, h2_b = b1.next_hypothesis(), b2.next_hypothesis()
        assert h2_a == h2_b


class TestBuildStuckGuidance:
    """Tests for the build_stuck_guidance standalone function."""

    def test_returns_string_with_hypothesis(self):
        boost = HypothesisBoost()
        guidance = build_stuck_guidance(boost)
        assert isinstance(guidance, str)
        assert "REFLECTION:" in guidance
        assert "hypothesis-driven" in guidance

    def test_includes_hypothesis_text(self):
        boost = HypothesisBoost()
        hyp = boost.next_hypothesis()
        # Reset so build_stuck_guidance also picks the first template
        boost.reset()
        guidance = build_stuck_guidance(boost)
        # The hypothesis text should be in the guidance
        assert hyp in guidance

    def test_stuck_count_propagated_to_next_hypothesis(self):
        boost = HypothesisBoost()
        guidance = build_stuck_guidance(boost, stuck_count=3)
        assert isinstance(guidance, str)
        # Should still be a valid guidance string regardless of stuck_count
        assert len(guidance) > 50

    def test_multiple_calls_cycle_guidance(self):
        boost = HypothesisBoost()
        g1 = build_stuck_guidance(boost)
        g2 = build_stuck_guidance(boost)
        g3 = build_stuck_guidance(boost)
        # All should be different since hypothesis cycles
        assert g1 != g2 or g2 != g3

    def test_reset_between_guidance(self):
        boost = HypothesisBoost()
        g1 = build_stuck_guidance(boost)
        boost.reset()
        g2 = build_stuck_guidance(boost)
        assert g1 == g2
