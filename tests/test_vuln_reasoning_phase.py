"""tests/test_vuln_reasoning_phase.py

Verification that the autonomous reasoning phase lets the AI *author*
vulnerability findings from raw evidence — without any deterministic tool —
and that those findings are tagged as agentic (not merged with tool output).

The LLM engine is mocked so the test is fast and offline.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from elengenix.scanning.vuln_reasoning_phase import run_reasoning_phase, _hypothesis_to_finding


class _FakeHypothesis:
    """Mimics tools.vuln_reasoning.VulnHypothesis (dataclass-like)."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


class _FakeResult:
    def __init__(self, hypotheses):
        self.hypotheses = hypotheses


class _FakeEngine:
    def __init__(self, hypotheses):
        self._hypotheses = hypotheses

    def analyze_output(self, **kwargs):
        return _FakeResult(self._hypotheses)


def _ctx(target="https://example.com"):
    return SimpleNamespace(target=target, all_findings=[])


def test_reasoning_phase_authors_finding_without_tool():
    hyp = _FakeHypothesis(
        title="Blind SSRF via webhook callback",
        vuln_class="ssrf",
        confidence=0.7,
        reasoning="The output shows an outbound webhook with a user-controlled URL.",
        evidence=["webhook_url param accepted arbitrary host"],
        suggested_tests=["Send http://169.254.169.254/ to webhook_url"],
        cwe="CWE-918",
        severity="High",
        target_endpoint="https://example.com/api/webhook",
        parameter="webhook_url",
        payload="http://169.254.169.254/latest/meta-data",
    )
    engine = _FakeEngine([hyp])
    ctx = _ctx()
    findings = run_reasoning_phase(
        ctx=ctx,
        raw_output="webhook_url=http://evil.example webhook dispatched",
        observation="",
        step=3,
        engine=engine,
        target=ctx.target,
    )
    assert len(findings) == 1
    f = findings[0]
    # AI authored it — must be tagged agentic, not deterministic
    assert f["source"] == "ai_reasoning"
    assert f["provenance"] == "agentic"
    assert f["trust_class"] == "non_deterministic"
    assert f["type"] == "ssrf"
    assert f["discovered_by"] == "vuln_reasoning_phase"


def test_low_confidence_hypothesis_dropped():
    hyp = _FakeHypothesis(
        title="maybe xss",
        vuln_class="xss",
        confidence=0.1,  # below default min 0.35
        reasoning="not sure",
        severity="Low",
    )
    engine = _FakeEngine([hyp])
    ctx = _ctx()
    findings = run_reasoning_phase(
        ctx=ctx, raw_output="some output", observation="", step=1, engine=engine, target=ctx.target
    )
    assert findings == []


def test_empty_output_yields_no_findings():
    engine = _FakeEngine([_FakeHypothesis(title="x", vuln_class="x", confidence=0.9)])
    ctx = _ctx()
    findings = run_reasoning_phase(
        ctx=ctx, raw_output="", observation="", step=1, engine=engine, target=ctx.target
    )
    assert findings == []


def test_multiple_hypotheses_all_tagged_agentic():
    hyps = [
        _FakeHypothesis(title="a", vuln_class="sqli", confidence=0.6, severity="High"),
        _FakeHypothesis(title="b", vuln_class="idor", confidence=0.5, severity="Medium"),
    ]
    engine = _FakeEngine(hyps)
    ctx = _ctx()
    findings = run_reasoning_phase(
        ctx=ctx, raw_output="login response", observation="", step=2, engine=engine, target=ctx.target
    )
    assert len(findings) == 2
    assert all(f["provenance"] == "agentic" for f in findings)


def test_hypothesis_to_finding_shape():
    f = _hypothesis_to_finding(
        {"title": "t", "vuln_class": "rce", "confidence": 0.8, "severity": "Critical"},
        "https://x.com",
        5,
    )
    assert f["severity"] == "critical"
    assert f["provenance"] == "agentic"
    assert f["discovered_at_step"] == 5
