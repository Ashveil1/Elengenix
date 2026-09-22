"""Tests for elengenix/reports/adapters.py — findings → canonical renderers.

Locks in the Phase-3 wiring: ``scan-report`` / ``report`` / ``pdf`` now
render through the canonical package (markdown → HTML/PDF) with CVSS
scoring computed by :mod:`elengenix.reports.cvss` from metric vectors.
"""

from __future__ import annotations

import json

import pytest

from elengenix.reports.adapters import (
    findings_json_to_markdown,
    findings_to_markdown,
    render_findings_html,
    render_findings_pdf,
)

VECTOR_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"  # 10.0


FINDINGS = [
    {
        "title": "IDOR on orders API",
        "severity": "High",
        "cvss": 8.2,
        "url": "https://x/api/orders",
        "type": "bola",
        "details": "No object-level authz",
        "remediation": "Add ownership checks",
        "evidence": "GET /api/orders/123 -> 200",
    },
    {
        "title": "RCE via template injection",
        "vector": VECTOR_CRITICAL,
        "url": "https://x/render",
        "type": "ssti",
        "details": "Jinja2 injection",
    },
    {"title": "Info disclosure", "severity": "Low", "cvss": 2.1, "type": "info"},
]


class TestFindingsToMarkdown:
    def test_structure_and_summary(self):
        md = findings_to_markdown(FINDINGS, title="Assessment — X", target="x.com")
        assert md.startswith("# Assessment — X\n")
        assert "**Target:** x.com" in md
        assert "**Total findings:** 3" in md
        assert "## Findings" in md
        # every finding gets a section
        for title in ("IDOR on orders API", "RCE via template injection", "Info disclosure"):
            assert f"### {title}" in md

    def test_vector_scored_by_canonical_cvss(self):
        md = findings_to_markdown(FINDINGS[1:2])
        assert "Severity: Critical" in md
        assert "CVSS: 10.0" in md
        assert f"`{VECTOR_CRITICAL}`" in md

    def test_sorted_by_severity_then_score(self):
        md = findings_to_markdown(FINDINGS)
        table = [l for l in md.splitlines() if l.startswith("| ") and "](#" in l]
        assert len(table) == 3
        # RCE (10.0 Critical) first, IDOR (8.2 High) second, info last
        assert "RCE via template injection" in table[0]
        assert "IDOR on orders API" in table[1]
        assert "Info disclosure" in table[2]

    def test_empty_findings_renders_placeholder(self):
        md = findings_to_markdown([])
        assert "No findings." in md

    def test_duck_typed_finding_objects(self):
        class F:
            title = "Obj finding"
            severity = "Medium"
            cvss = 5.0
            url = "https://x"
            vuln_class = "xss"
            description = "d"
            impact = "i"
            remediation = "r"
            evidence = ""
            cwe = ["CWE-79"]
            cve = "CVE-2026-0001"
            vector = None

        md = findings_to_markdown([F()])
        assert "### Obj finding" in md
        assert "CWE-79" in md and "CVE-2026-0001" in md


class TestRenderers:
    def test_html_document(self):
        html = render_findings_html(FINDINGS, title="Assessment — X", target="x.com")
        assert "<html" in html.lower()
        assert "IDOR on orders API" in html

    def test_pdf_bytes(self):
        pdf = render_findings_pdf(FINDINGS, title="Assessment — X")
        assert pdf[:5] == b"%PDF-"
        assert len(pdf) > 2000


class TestJsonEntry:
    def test_findings_json_to_markdown(self, tmp_path):
        payload = {"target": "acme.com", "findings": FINDINGS[:1]}
        f = tmp_path / "findings.json"
        f.write_text(json.dumps(payload), encoding="utf-8")
        md = findings_json_to_markdown(str(f))
        assert "acme.com" in md
        assert "IDOR on orders API" in md

    def test_bare_list_json(self, tmp_path):
        f = tmp_path / "findings.json"
        f.write_text(json.dumps(FINDINGS), encoding="utf-8")
        md = findings_json_to_markdown(str(f))
        assert "RCE via template injection" in md


class TestCliWiring:
    def test_scan_report_uses_canonical_renderer(self):
        """The scan-report handler must import the canonical adapter, not the
        legacy renderer, for its markdown/HTML output."""
        from pathlib import Path

        src = Path(__file__).resolve().parent.parent / "main.py"
        text = src.read_text(encoding="utf-8")
        assert "from elengenix.reports.adapters import findings_to_markdown" in text
        # raw dicts are passed (so vector fields survive normalization)
        assert "findings_to_markdown(findings_raw" in text

    def test_report_pdf_handler_uses_canonical_renderers(self):
        from pathlib import Path

        src = Path(__file__).resolve().parent.parent / "main.py"
        text = src.read_text(encoding="utf-8")
        assert "render_findings_pdf" in text
        assert "render_findings_html" in text
        # the old weasyprint path is gone
        assert "pip install weasyprint" not in text

    def test_report_commands_are_explicit(self):
        """report/pdf/pd/scan-report must never be swallowed by target
        auto-detection (the old bug turned `elengenix pdf findings.json`
        into an AI file-analysis session)."""
        from pathlib import Path

        src = Path(__file__).resolve().parent.parent / "main.py"
        text = src.read_text(encoding="utf-8")
        start = text.index("explicit_commands = {")
        end = text.index("}", start)
        block = text[start:end]
        for name in ("report", "pdf", "pd", "scan-report"):
            assert f'"{name}"' in block, name
