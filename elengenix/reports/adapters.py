"""Canonical findings renderers: findings → markdown / HTML / PDF.

Every report surface (CLI ``report``/``pdf``/``scan-report``, dashboards)
renders through these adapters so CVSS scoring, severity classification and
ordering are computed in exactly one place.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from elengenix.reports.cvss import cvss_result, cvss_severity, parse_cvss_vector
from elengenix.reports.export import render_html
from elengenix.reports.markdown import slugify_github
from elengenix.reports.pdf import render_to_pdf_bytes

__all__ = [
    "findings_to_markdown",
    "render_findings_html",
    "render_findings_pdf",
    "findings_json_to_markdown",
]

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "none": 5,
}

_CVE_URL = "https://nvd.nist.gov/vuln/detail/{cve}"


def _field(finding: Any, *names: str, default: Any = None) -> Any:
    """First non-None field across dict keys / attribute names."""
    for name in names:
        if isinstance(finding, dict):
            value = finding.get(name)
        else:
            value = getattr(finding, name, None)
        if value is not None:
            return value
    return default


def _normalize(finding: Any) -> Dict[str, Any]:
    """Normalize a finding (dict or duck-typed object) to canonical fields."""
    vector = _field(finding, "vector")
    score = _field(finding, "cvss", "cvss_score", "score")
    severity = _field(finding, "severity")

    vector_string: Optional[str] = None
    if vector:
        try:
            result = cvss_result(parse_cvss_vector(str(vector)))
            vector_string = result.vector_string
            score = result.base_score
            severity = severity or result.severity
        except ValueError:
            vector_string = None

    if score is not None:
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = None

    if severity is None:
        severity = cvss_severity(score) if score is not None else "Info"
    severity = str(severity).capitalize()

    cwe = _field(finding, "cwe")
    if isinstance(cwe, (list, tuple)):
        cwe = ", ".join(str(c) for c in cwe) if cwe else None

    return {
        "title": str(_field(finding, "title", default="Untitled finding")),
        "severity": severity,
        "score": score,
        "vector": vector_string,
        "url": _field(finding, "url", "endpoint"),
        "vuln_class": _field(finding, "type", "vuln_class", "category"),
        "description": _field(finding, "details", "description"),
        "impact": _field(finding, "impact"),
        "remediation": _field(finding, "remediation", "fix", "recommendation"),
        "evidence": _field(finding, "evidence", "proof"),
        "cwe": cwe,
        "cve": _field(finding, "cve"),
    }


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.lower(), 5)


def _sorted_findings(findings: Sequence[Any]) -> List[Dict[str, Any]]:
    normalized = [_normalize(f) for f in findings]
    normalized.sort(key=lambda f: (_severity_rank(f["severity"]), -(f["score"] or 0.0)))
    return normalized


def findings_to_markdown(
    findings: Sequence[Any],
    title: str = "Security Assessment",
    target: Optional[str] = None,
    author: Optional[str] = None,
) -> str:
    """Render findings as the canonical markdown assessment report."""
    normalized = _sorted_findings(findings)

    lines: List[str] = [f"# {title}", ""]
    if target:
        lines.append(f"**Target:** {target}")
    if author:
        lines.append(f"**Author:** {author}")
    lines.append(f"**Total findings:** {len(normalized)}")
    lines.append("")

    if not normalized:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("## Summary")
    lines.append("")
    lines.append("| Finding | Severity | CVSS | Class |")
    lines.append("|---------|----------|------|-------|")
    for f in normalized:
        anchor = slugify_github(f["title"])
        score = f"{f['score']:.1f}" if f["score"] is not None else "-"
        lines.append(
            f"| [{f['title']}](#{anchor}) | {f['severity']} | {score} | {f['vuln_class'] or '-'} |"
        )
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for f in normalized:
        lines.append(f"### {f['title']}")
        lines.append("")
        lines.append(f"- Severity: {f['severity']}")
        if f["score"] is not None:
            lines.append(f"- CVSS: {f['score']:.1f}")
        if f["vector"]:
            lines.append(f"- Vector: `{f['vector']}`")
        if f["url"]:
            lines.append(f"- URL: {f['url']}")
        if f["vuln_class"]:
            lines.append(f"- Type: {f['vuln_class']}")
        if f["description"]:
            lines.append(f"- Details: {f['description']}")
        if f["impact"]:
            lines.append(f"- Impact: {f['impact']}")
        if f["remediation"]:
            lines.append(f"- Remediation: {f['remediation']}")
        if f["evidence"]:
            lines.append(f"- Evidence: {f['evidence']}")
        if f["cwe"]:
            lines.append(f"- CWE: {f['cwe']}")
        if f["cve"]:
            lines.append(
                f"- CVE: [{f['cve']}]({_CVE_URL.format(cve=f['cve'])})"
            )
        lines.append("")

    return "\n".join(lines)


def render_findings_html(
    findings: Sequence[Any],
    title: str = "Security Assessment",
    target: Optional[str] = None,
    author: Optional[str] = None,
) -> str:
    """Render findings as a full HTML document."""
    md_text = findings_to_markdown(findings, title=title, target=target, author=author)
    return render_html(md_text, include_css=True, title=title)


def render_findings_pdf(
    findings: Sequence[Any],
    title: str = "Security Assessment",
    target: Optional[str] = None,
    author: Optional[str] = None,
) -> bytes:
    """Render findings as PDF bytes."""
    md_text = findings_to_markdown(findings, title=title, target=target, author=author)
    return render_to_pdf_bytes(md_text)


def findings_json_to_markdown(path: str) -> str:
    """Load a findings JSON file (``{"target", "findings"}`` or a bare list)
    and render it as the canonical markdown report."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        target = data.get("target")
        title = data.get("title") or (
            f"Security Assessment \u2014 {target}" if target else "Security Assessment"
        )
        return findings_to_markdown(data.get("findings", []), title=title, target=target)
    return findings_to_markdown(data)
