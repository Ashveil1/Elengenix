"""test_report_gen.py — Tests for report generator."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.report_gen import (
    ExecutiveSummary,
    FindingReport,
    ReportFormat,
    export_report,
    generate_html,
    generate_markdown,
    generate_sarif,
)


def make_finding(**kw):
    defaults = dict(
        id="VULN-TEST1",
        title="SQL Injection in search",
        severity="Critical",
        cvss=9.8,
        url="http://x.com/api?id=1",
        vuln_class="injection",
        description="User input concatenated into SQL",
        impact="Full database access",
        remediation="Use parameterized queries",
        cwe=["CWE-89"],
        cve=None,
        evidence="Got MySQL error: '1' ORDER BY",
        confidence=0.95,
    )
    defaults.update(kw)
    return FindingReport(**defaults)


def make_summary(findings):
    by_sev = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return ExecutiveSummary(
        target="http://example.com",
        scan_date="2026-06-07 16:00:00",
        duration_seconds=42.5,
        total_findings=len(findings),
        critical=by_sev.get("Critical", 0),
        high=by_sev.get("High", 0),
        medium=by_sev.get("Medium", 0),
        low=by_sev.get("Low", 0),
        info=by_sev.get("Informational", 0),
        ai_provider="nvidia/meta/llama-3.3-70b-instruct",
        top_3_findings=findings[:3],
        risk_score=8.5,
    )


def test_html_generation():
    f = make_finding()
    s = make_summary([f])
    html = generate_html(s, [f])
    assert "ELENGENIX" in html
    assert "example.com" in html
    assert "SQL Injection" in html
    assert "9.8" in html
    assert "CWE-89" in html
    assert "Critical" in html
    print("[OK] test_html_generation")


def test_html_severity_styling():
    f1 = make_finding(severity="Critical", title="C1")
    f2 = make_finding(severity="High", title="H1", id="VULN-TEST2")
    s = make_summary([f1, f2])
    html = generate_html(s, [f1, f2])
    assert "finding critical" in html
    assert "finding high" in html
    print("[OK] test_html_severity_styling")


def test_sarif_generation():
    f = make_finding()
    s = make_summary([f])
    sarif = generate_sarif(s, [f])
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Elengenix"
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["ruleId"] == "CWE-89"
    print("[OK] test_sarif_generation")


def test_markdown_generation():
    f = make_finding()
    s = make_summary([f])
    md = generate_markdown(s, [f])
    assert "# Elengenix Security Report" in md
    assert "Critical" in md
    assert "9.8" in md
    assert "```" in md
    print("[OK] test_markdown_generation")


def test_export_html(tmp_path=None):
    f = make_finding()
    s = make_summary([f])
    p = export_report(s, [f], "/tmp/test_report.html", ReportFormat.HTML)
    assert p.exists()
    assert p.stat().st_size > 1000
    content = p.read_text()
    assert "ELENGENIX" in content
    print(f"[OK] test_export_html ({p.stat().st_size} bytes)")


def test_export_sarif():
    f = make_finding()
    s = make_summary([f])
    p = export_report(s, [f], "/tmp/test_report.sarif.json", ReportFormat.SARIF)
    data = json.loads(p.read_text())
    assert data["version"] == "2.1.0"
    print(f"[OK] test_export_sarif ({p.stat().st_size} bytes)")


def test_export_all_formats():
    f = make_finding()
    s = make_summary([f])
    for fmt in [ReportFormat.HTML, ReportFormat.JSON, ReportFormat.MARKDOWN, ReportFormat.TEXT]:
        p = export_report(s, [f], f"/tmp/test_{fmt.value}", fmt)
        assert p.exists()
        assert p.stat().st_size > 0
    print("[OK] test_export_all_formats")


def test_empty_findings():
    s = make_summary([])
    html = generate_html(s, [])
    assert "0" in html or "No" in html or "Findings (0)" in html
    print("[OK] test_empty_findings")


def test_risk_level():
    s_high = make_summary([make_finding(cvss=9.5)])
    s_high.risk_score = 9.5
    s_low = make_summary([make_finding(cvss=2.0, severity="Low")])
    s_low.risk_score = 2.0
    assert s_high.risk_level in ("HIGH", "CRITICAL")
    assert s_low.risk_level in ("LOW", "INFORMATIONAL")
    print(f"[OK] test_risk_level (high={s_high.risk_level}, low={s_low.risk_level})")


if __name__ == "__main__":
    test_html_generation()
    test_html_severity_styling()
    test_sarif_generation()
    test_markdown_generation()
    test_export_html()
    test_export_sarif()
    test_export_all_formats()
    test_empty_findings()
    test_risk_level()
    print("\n[OK] All 9 tests passed")
