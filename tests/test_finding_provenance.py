"""tests/test_finding_provenance.py

Verification for the deterministic-vs-agentic provenance tagging that
implements the Vigolium/diviner critique: a finding from the agent and a
finding from a deterministic tool must never collapse into one queue entry
without a tag saying which produced it.
"""

from __future__ import annotations

from tools.finding_provenance import (
    Provenance,
    tag_provenance,
    infer_provenance,
    is_reproducible,
)
from tools.finding_dedup import deduplicate_findings


def _finding(**kw):
    base = {"type": "xss", "url": "https://example.com/a", "param": "q"}
    base.update(kw)
    return base


def test_infer_deterministic_from_source():
    f = _finding(source="auth_tester")
    assert infer_provenance(f) is Provenance.DETERMINISTIC
    assert tag_provenance(f)["trust_class"] == "reproducible"


def test_infer_agentic_from_source():
    f = _finding(source="ai_reasoning")
    assert infer_provenance(f) is Provenance.AGENTIC
    assert tag_provenance(f)["trust_class"] == "non_deterministic"


def test_agentic_finding_not_auto_reproducible():
    f = _finding(source="ai_reasoning", reproducibility=0.3)
    assert is_reproducible(f) is False


def test_high_repro_agentic_can_be_promoted():
    f = _finding(source="ai_reasoning", reproducibility=0.9)
    assert is_reproducible(f) is True


def test_source_hint_records_agentic():
    f = tag_provenance(_finding(), source_hint="ai_reasoning")
    assert f["source"] == "ai_reasoning"
    assert f["provenance"] == Provenance.AGENTIC.value


def test_merged_deterministic_plus_agentic_flagged_mixed():
    det = _finding(source="auth_tester")
    agt = _finding(source="ai_reasoning")
    result = deduplicate_findings([det, agt], merge_sources=True)
    # Same type+url+param => deduped into one entry
    assert len(result.unique_findings) == 1
    merged = result.unique_findings[0]
    assert merged["provenance"] == Provenance.MIXED.value
    assert merged.get("mixed_provenance") is True
    assert "auth_tester" in merged["source"] and "ai_reasoning" in merged["source"]


def test_pure_deterministic_merge_stays_deterministic():
    a = _finding(source="auth_tester")
    b = _finding(source="native_scanner")
    result = deduplicate_findings([a, b], merge_sources=True)
    merged = result.unique_findings[0]
    assert merged["provenance"] == Provenance.DETERMINISTIC.value
    assert merged.get("mixed_provenance") is not True


def test_dedup_tags_provenance_on_input():
    f = _finding(source="active_fuzzer")
    result = deduplicate_findings([f])
    assert result.unique_findings[0]["provenance"] == Provenance.DETERMINISTIC.value
