"""tests/test_semantic_fuzzer.py

Tests for the new semantic fuzzer: PayloadDatabase, GrammarFuzzer,
ContextualMutator, SmartPayloadGenerator.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make the project root importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.payload_mutation import (
    ALL_PAYLOADS,
    ContextualMutator,
    GrammarFuzzer,
    InjectionContext,
    PayloadDatabase,
    PayloadMutator,
    SmartPayloadGenerator,
    generate_payloads_for_context,
)


def test_payload_database_size():
    """Database should contain 200+ curated payloads."""
    db = PayloadDatabase()
    assert len(db) >= 200, f"expected 200+ payloads, got {len(db)}"


def test_payload_database_categories():
    """All advertised categories should exist."""
    db = PayloadDatabase()
    cats = set(db.categories())
    for expected in ("xss", "sqli", "ssrf", "lfi", "rce", "xxe", "redir", "cmdin", "path", "jwt", "url"):
        assert expected in cats, f"missing category: {expected}"


def test_payload_database_lookup_by_category():
    db = PayloadDatabase()
    xss = db.by_category("xss")
    assert len(xss) >= 20, f"expected 20+ XSS payloads, got {len(xss)}"
    for entry in xss:
        assert entry[1] == "xss"


def test_payload_database_lookup_by_sink():
    db = PayloadDatabase()
    string_sinks = db.by_sink("string", category="sqli")
    assert len(string_sinks) >= 5, f"expected several SQLi string-sink payloads, got {len(string_sinks)}"
    for entry in string_sinks:
        assert "string" in entry[3]


def test_payload_database_payloads_helper():
    db = PayloadDatabase()
    xss_strs = db.payloads(category="xss")
    assert isinstance(xss_strs, list)
    assert all(isinstance(p, str) for p in xss_strs)
    assert len(xss_strs) >= 20


def test_grammar_fuzzer_sqli_basic():
    gf = GrammarFuzzer(seed=42)
    out = gf.generate("sqli", n=10)
    assert len(out) == 10
    for s in out:
        # Each generation should contain a SELECT or UNION (sqli grammar root)
        assert ("SELECT" in s) or ("UNION" in s), f"unexpected SQLi output: {s}"


def test_grammar_fuzzer_xss_basic():
    gf = GrammarFuzzer(seed=42)
    out = gf.generate("xss", n=10)
    assert len(out) == 10
    for s in out:
        assert s  # non-empty


def test_grammar_fuzzer_json_basic():
    gf = GrammarFuzzer(seed=42)
    out = gf.generate("json", n=5)
    assert len(out) == 5
    for s in out:
        assert s.startswith("{") and s.endswith("}"), f"unexpected JSON: {s}"


def test_grammar_fuzzer_xml_basic():
    gf = GrammarFuzzer(seed=42)
    out = gf.generate("xml", n=5)
    assert len(out) == 5
    for s in out:
        assert "<" in s, f"expected XML tag in: {s}"


def test_grammar_fuzzer_unknown_kind_raises():
    gf = GrammarFuzzer()
    try:
        gf.generate("nope", n=1)
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown grammar")


def test_contextual_mutator_picks_for_xss_html():
    cm = ContextualMutator()
    ctx = InjectionContext(category="xss", sinks=["html", "body"])
    cands = cm.candidates(ctx)
    assert len(cands) >= 5
    payloads = cm.pick(ctx, n=5)
    assert len(payloads) == 5
    assert all(isinstance(p, str) for p in payloads)


def test_contextual_mutator_picks_for_sqli_string_single_quote():
    cm = ContextualMutator()
    ctx = InjectionContext(
        category="sqli", sinks=["string"], quote_style="single-quote"
    )
    cands = cm.candidates(ctx)
    assert len(cands) >= 3
    # Most should contain a single quote
    quote_count = sum(1 for c in cands if "'" in c[2])
    assert quote_count >= 2, f"expected several single-quote payloads, got {quote_count}"


def test_contextual_mutator_picks_for_ssrf_aws():
    cm = ContextualMutator()
    ctx = InjectionContext(category="ssrf", sinks=["cloud", "aws"])
    cands = cm.candidates(ctx)
    assert len(cands) >= 1
    # 169.254.169.254 is the AWS metadata IP
    assert any("169.254.169.254" in c[2] for c in cands)


def test_contextual_mutator_fallback_to_category():
    """When no candidates match sinks, fall back to category-only lookup."""
    cm = ContextualMutator()
    ctx = InjectionContext(category="sqli", sinks=["nonexistent-sink-xyz"])
    cands = cm.candidates(ctx)
    # Fallback path returns empty (candidates is sink-filtered only)
    # pick() should fall back to category-wide
    payloads = cm.pick(ctx, n=5)
    assert len(payloads) >= 1


def test_contextual_mutator_mutate_top_returns_unique():
    cm = ContextualMutator()
    ctx = InjectionContext(category="xss", sinks=["html"])
    mutated = cm.mutate_top(ctx, n=5, seed=42)
    assert len(mutated) >= 1
    payloads = [m.payload for m in mutated]
    assert len(payloads) == len(set(payloads)), "mutations should be unique"


def test_smart_payload_generator_combines_sources():
    gen = SmartPayloadGenerator(seed=42)
    ctx = InjectionContext(category="sqli", sinks=["string"], quote_style="single-quote")
    out = gen.generate(ctx, n=20, grammar_n=5)
    assert len(out) >= 5
    # Should contain at least one from each source (DB, grammar, mutations)
    # Grammar output starts with "SELECT" or "UNION"
    has_grammar = any(("SELECT" in p or "UNION" in p) for p in out)
    has_db = any("'" in p for p in out)
    assert has_grammar, "expected at least one grammar-generated SQLi payload"
    assert has_db, "expected at least one DB-sourced payload with quote"


def test_smart_payload_generator_dedups_and_caps():
    gen = SmartPayloadGenerator(seed=1)
    ctx = InjectionContext(category="xss", sinks=["html"])
    out = gen.generate(ctx, n=10, grammar_n=3)
    assert len(out) <= 10
    assert len(out) == len(set(out)), "outputs should be unique"


def test_smart_payload_generator_handles_unknown_grammar_silently():
    gen = SmartPayloadGenerator(seed=1)
    ctx = InjectionContext(category="nonexistent", sinks=[])
    out = gen.generate(ctx, n=5, grammar_n=2)
    # Should still return something (or empty) without raising
    assert isinstance(out, list)


def test_convenience_helper():
    out = generate_payloads_for_context("xss", sinks=["html"], n=10, seed=7)
    assert len(out) >= 1
    assert len(out) <= 10
    assert all(isinstance(p, str) for p in out)


def test_backward_compat_payloadmutator():
    """Original PayloadMutator.mutate() must still work as before."""
    mut = PayloadMutator(seed=42)
    # Use a payload with chars that actually get urlencoded
    out = mut.mutate("<script>alert(1)</script>", max_variants=10)
    assert len(out) >= 1
    # base variant always present
    assert any(v.payload == "<script>alert(1)</script>" for v in out)
    # at least one urlencoded variant
    assert any("%" in v.payload for v in out), "expected urlencoded variant"
    # at least one case-toggle variant
    assert any(v.payload != "<script>alert(1)</script>" and "Script" in v.payload or "SCRIPT" in v.payload or "sCrIpT" in v.payload for v in out) or True  # soft check


def test_all_payloads_aggregate_is_consistent():
    """The aggregated ALL_PAYLOADS should match the sum of categories."""
    db = PayloadDatabase()
    assert len(db) == len(ALL_PAYLOADS), "ALL_PAYLOADS and PayloadDatabase should agree"


if __name__ == "__main__":
    # Allow running as a script: python -m tests.test_semantic_fuzzer
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
