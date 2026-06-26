"""
report_gen.py — Elengenix Professional Report Generator
Executive + technical reports, evidence packages, PDF (Jensen-ready).
Version: 1.0.0
"""

from __future__ import annotations

import html
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

logger = logging.getLogger("elengenix.report")

# ═══════════════════════════════════════════════════════════════════════════
# 1. REPORT MODELS
# ═══════════════════════════════════════════════════════════════════════════


class ReportFormat(Enum):
    HTML = "html"
    JSON = "json"
    MARKDOWN = "md"
    TEXT = "txt"
    SARIF = "sarif"  # GitHub Security tab


@dataclass
class FindingReport:
    """A single finding formatted for report."""

    id: str
    title: str
    severity: str
    cvss: float
    url: str
    vuln_class: str
    description: str
    impact: str
    remediation: str
    evidence: str = ""
    cwe: List[str] = field(default_factory=list)
    cve: Optional[str] = None
    chain: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def severity_color(self) -> str:
        return {
            "Critical": "#ff3b30",
            "High": "#ff9500",
            "Medium": "#ffcc00",
            "Low": "#34c759",
            "Informational": "#5ac8fa",
        }.get(self.severity, "#999")

    @property
    def severity_icon(self) -> str:
        return {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
            "Informational": "🔵",
        }.get(self.severity, "⚪")


@dataclass
class ExecutiveSummary:
    target: str
    scan_date: str
    duration_seconds: float
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    ai_provider: str
    top_3_findings: List[FindingReport] = field(default_factory=list)
    risk_score: float = 0.0
    business_impact: str = ""

    @property
    def risk_level(self) -> str:
        if self.risk_score >= 9:
            return "CRITICAL"
        if self.risk_score >= 7:
            return "HIGH"
        if self.risk_score >= 4:
            return "MEDIUM"
        if self.risk_score > 0:
            return "LOW"
        return "INFORMATIONAL"


# ═══════════════════════════════════════════════════════════════════════════
# 2. HTML REPORT — Apple-level aesthetic
# ═══════════════════════════════════════════════════════════════════════════

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Elengenix Security Report — {target}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', sans-serif;
  background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
  color: #e0e0e0; line-height: 1.6; padding: 40px 20px; min-height: 100vh;
}}
.container {{ max-width: 1100px; margin: 0 auto; }}
.header {{
  text-align: center; padding: 60px 20px; margin-bottom: 40px;
  background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
  border-radius: 16px; border: 1px solid #333;
  box-shadow: 0 20px 60px rgba(0,0,0,0.5);
}}
.header h1 {{
  font-size: 36px; font-weight: 700; letter-spacing: -0.5px;
  background: linear-gradient(135deg, #ff5555 0%, #ff9500 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  margin-bottom: 8px;
}}
.header .subtitle {{ color: #888; font-size: 14px; letter-spacing: 1px; text-transform: uppercase; }}
.target-badge {{
  display: inline-block; margin-top: 24px; padding: 12px 24px;
  background: rgba(255,85,85,0.1); border: 1px solid rgba(255,85,85,0.3);
  border-radius: 100px; color: #ff8888; font-family: 'SF Mono', monospace;
  font-size: 14px; font-weight: 500;
}}
.stats-grid {{
  display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px;
  margin-bottom: 32px;
}}
.stat-card {{
  background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px;
  padding: 20px; text-align: center; transition: all 0.2s ease;
}}
.stat-card:hover {{ transform: translateY(-2px); border-color: #444; }}
.stat-value {{ font-size: 32px; font-weight: 700; margin-bottom: 4px; }}
.stat-label {{ font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px; }}
.crit .stat-value {{ color: #ff3b30; }}
.high .stat-value {{ color: #ff9500; }}
.med .stat-value {{ color: #ffcc00; }}
.low .stat-value {{ color: #34c759; }}
.info .stat-value {{ color: #5ac8fa; }}
.section {{
  background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px;
  padding: 32px; margin-bottom: 24px;
}}
.section h2 {{
  font-size: 22px; margin-bottom: 20px; padding-bottom: 12px;
  border-bottom: 1px solid #2a2a2a; color: #fff;
}}
.finding {{
  background: #0d0d0d; border-left: 4px solid #555;
  border-radius: 8px; padding: 20px; margin-bottom: 16px;
  transition: all 0.2s ease;
}}
.finding:hover {{ background: #111; }}
.finding.critical {{ border-left-color: #ff3b30; }}
.finding.high {{ border-left-color: #ff9500; }}
.finding.medium {{ border-left-color: #ffcc00; }}
.finding.low {{ border-left-color: #34c759; }}
.finding.info {{ border-left-color: #5ac8fa; }}
.finding-header {{
  display: flex; justify-content: space-between; align-items: start;
  margin-bottom: 12px;
}}
.finding-title {{ font-size: 16px; font-weight: 600; color: #fff; }}
.finding-sev {{
  padding: 4px 10px; border-radius: 100px; font-size: 11px;
  font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
}}
.sev-Critical {{ background: rgba(255,59,48,0.15); color: #ff5555; }}
.sev-High {{ background: rgba(255,149,0,0.15); color: #ffb84d; }}
.sev-Medium {{ background: rgba(255,204,0,0.15); color: #ffd84d; }}
.sev-Low {{ background: rgba(52,199,89,0.15); color: #5dd870; }}
.sev-Informational {{ background: rgba(90,200,250,0.15); color: #7dd5fc; }}
.finding-url {{
  font-family: 'SF Mono', monospace; font-size: 12px; color: #888;
  background: #000; padding: 6px 10px; border-radius: 4px;
  display: inline-block; margin: 8px 0; word-break: break-all;
}}
.finding-detail {{ color: #ccc; font-size: 14px; margin: 8px 0; }}
.evidence-block {{
  background: #000; border: 1px solid #222; border-radius: 6px;
  padding: 12px; font-family: 'SF Mono', monospace; font-size: 12px;
  color: #a0a0a0; margin-top: 8px; overflow-x: auto; white-space: pre-wrap;
}}
.meta-row {{
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;
  margin-top: 12px; font-size: 12px;
}}
.meta-item {{ color: #888; }}
.meta-item strong {{ color: #ccc; }}
.footer {{
  text-align: center; padding: 40px 20px; color: #555;
  font-size: 12px; border-top: 1px solid #2a2a2a; margin-top: 40px;
}}
.footer .brand {{ color: #ff5555; font-weight: 600; }}
.exec-summary {{
  background: linear-gradient(135deg, rgba(255,85,85,0.05) 0%, rgba(255,149,0,0.05) 100%);
  border: 1px solid rgba(255,85,85,0.2); border-radius: 12px;
  padding: 24px; margin-bottom: 24px;
}}
.exec-summary h3 {{ color: #ff8888; margin-bottom: 12px; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }}
.exec-summary p {{ color: #ddd; font-size: 15px; line-height: 1.7; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>ELENGENIX</h1>
    <div class="subtitle">Autonomous Security Research Report</div>
    <div class="target-badge">{target}</div>
  </div>

  <div class="stats-grid">
    <div class="stat-card crit">
      <div class="stat-value">{critical}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card high">
      <div class="stat-value">{high}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card med">
      <div class="stat-value">{medium}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card low">
      <div class="stat-value">{low}</div>
      <div class="stat-label">Low</div>
    </div>
    <div class="stat-card info">
      <div class="stat-value">{info}</div>
      <div class="stat-label">Info</div>
    </div>
  </div>

  <div class="exec-summary">
    <h3>Executive Summary</h3>
    <p>{exec_summary_text}</p>
  </div>

  <div class="section">
    <h2>Findings ({total_findings})</h2>
    {findings_html}
  </div>

  <div class="footer">
    <div>Generated by <span class="brand">Elengenix</span> v3.0 — Autonomous AI Security Framework</div>
    <div style="margin-top:8px;">{scan_date} • {duration}s scan • AI: {ai_provider}</div>
  </div>
</div>
</body>
</html>"""


def render_finding(f: FindingReport) -> str:
    cwe_str = ", ".join(f.cwe) if f.cwe else "N/A"
    return f"""
    <div class="finding {f.severity.lower()}">
      <div class="finding-header">
        <div>
          <div class="finding-title">{f.severity_icon} {escape(f.title)}</div>
          <div class="finding-url">{escape(f.url)}</div>
        </div>
        <div class="finding-sev sev-{f.severity}">{f.severity}</div>
      </div>
      <div class="finding-detail">{escape(f.description)}</div>
      <div class="meta-row">
        <div class="meta-item"><strong>CVSS:</strong> {f.cvss}</div>
        <div class="meta-item"><strong>Class:</strong> {escape(f.vuln_class)}</div>
        <div class="meta-item"><strong>CWE:</strong> {escape(cwe_str)}</div>
        {f'<div class="meta-item"><strong>CVE:</strong> {escape(f.cve)}</div>' if f.cve else ''}
        <div class="meta-item"><strong>Confidence:</strong> {int(f.confidence * 100)}%</div>
        <div class="meta-item"><strong>ID:</strong> {f.id}</div>
      </div>
      {f'<div class="evidence-block">{escape(f.evidence)}</div>' if f.evidence else ''}
      <div class="finding-detail" style="margin-top:12px;"><strong style="color:#ff8888;">Impact:</strong> {escape(f.impact)}</div>
      <div class="finding-detail"><strong style="color:#5dd870;">Remediation:</strong> {escape(f.remediation)}</div>
    </div>
    """


def generate_html(summary: ExecutiveSummary, findings: List[FindingReport]) -> str:
    """Generate Apple-aesthetic HTML report."""
    findings_html = "\n".join(render_finding(f) for f in findings)
    exec_text = summary.business_impact or (
        f"Scan of <b>{summary.target}</b> identified {summary.total_findings} findings. "
        f"Risk level: <b>{summary.risk_level}</b>. "
        f"Top concerns: {', '.join(f.title for f in summary.top_3_findings[:3]) or 'None'}."
    )
    return HTML_TEMPLATE.format(
        target=escape(summary.target),
        critical=summary.critical,
        high=summary.high,
        medium=summary.medium,
        low=summary.low,
        info=summary.info,
        total_findings=summary.total_findings,
        exec_summary_text=exec_text,
        findings_html=findings_html,
        scan_date=summary.scan_date,
        duration=f"{summary.duration_seconds:.1f}",
        ai_provider=escape(summary.ai_provider),
    )


# ═══════════════════════════════════════════════════════════════════════════
# 3. SARIF — GitHub Security tab compatible
# ═══════════════════════════════════════════════════════════════════════════

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def severity_to_sarif_level(sev: str) -> str:
    return {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "Informational": "note",
    }.get(sev, "note")


def generate_sarif(
    summary: ExecutiveSummary, findings: List[FindingReport], tool_name: str = "Elengenix"
) -> Dict:
    """Generate SARIF v2.1.0 for GitHub Security tab."""
    results = []
    rules = []
    seen_rules = set()
    for f in findings:
        rule_id = f.cwe[0] if f.cwe else "custom"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "name": f.vuln_class,
                    "shortDescription": {"text": f.vuln_class},
                    "fullDescription": {"text": f.title},
                    "help": {"text": f.remediation},
                    "defaultConfiguration": {"level": severity_to_sarif_level(f.severity)},
                }
            )
        result = {
            "ruleId": rule_id,
            "level": severity_to_sarif_level(f.severity),
            "message": {"text": f.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.url},
                    }
                }
            ],
        }
        if f.cve:
            result["properties"] = {"cve": f.cve, "cvss": f.cvss}
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "3.0.0",
                        "informationUri": "https://github.com/Ashveil1/Elengenix",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════
# 4. MARKDOWN — GitHub-friendly
# ═══════════════════════════════════════════════════════════════════════════


def generate_markdown(summary: ExecutiveSummary, findings: List[FindingReport]) -> str:
    lines = [f"# Elengenix Security Report — `{summary.target}`", ""]
    lines.append(f"**Scan Date:** {summary.scan_date}  ")
    lines.append(f"**Duration:** {summary.duration_seconds:.1f}s  ")
    lines.append(f"**AI Provider:** {summary.ai_provider}  ")
    lines.append(f"**Risk Level:** **{summary.risk_level}** ({summary.risk_score:.1f}/10)")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| 🔴 Critical | {summary.critical} |")
    lines.append(f"| 🟠 High | {summary.high} |")
    lines.append(f"| 🟡 Medium | {summary.medium} |")
    lines.append(f"| 🟢 Low | {summary.low} |")
    lines.append(f"| 🔵 Informational | {summary.info} |")
    lines.append("")
    lines.append("## Findings")
    for f in findings:
        lines.append(f"### {f.severity_icon} [{f.severity}] {f.title}")
        lines.append(f"- **URL:** `{f.url}`")
        lines.append(
            f"- **CVSS:** {f.cvss} | **Class:** {f.vuln_class} | **CWE:** {', '.join(f.cwe)}"
        )
        if f.cve:
            lines.append(f"- **CVE:** {f.cve}")
        lines.append(f"- **Description:** {f.description}")
        lines.append(f"- **Impact:** {f.impact}")
        lines.append(f"- **Remediation:** {f.remediation}")
        if f.evidence:
            lines.append(f"\n```\n{f.evidence}\n```")
        lines.append("")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# 5. CONVENIENCE EXPORT
# ═══════════════════════════════════════════════════════════════════════════


def export_report(
    summary: ExecutiveSummary,
    findings: List[FindingReport],
    output_path: str,
    fmt: ReportFormat = ReportFormat.HTML,
) -> Path:
    """Generate and save report."""
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if fmt == ReportFormat.HTML:
        p.write_text(generate_html(summary, findings))
    elif fmt == ReportFormat.JSON:
        p.write_text(
            json.dumps(
                {
                    "summary": summary.__dict__,
                    "findings": [f.__dict__ for f in findings],
                },
                indent=2,
                default=str,
            )
        )
    elif fmt == ReportFormat.MARKDOWN:
        p.write_text(generate_markdown(summary, findings))
    elif fmt == ReportFormat.SARIF:
        p.write_text(json.dumps(generate_sarif(summary, findings), indent=2))
    elif fmt == ReportFormat.TEXT:
        lines = [f"ELENGENIX REPORT — {summary.target}", f"Risk: {summary.risk_level}", ""]
        for f in findings:
            lines.append(f"[{f.severity}] {f.title} ({f.url})")
            lines.append(f"  CVSS: {f.cvss} | {f.vuln_class}")
            lines.append(f"  {f.description}")
            lines.append(f"  Fix: {f.remediation}")
            lines.append("")
        p.write_text("\n".join(lines))
    logger.info(f"Report saved: {p} ({fmt.value}, {p.stat().st_size} bytes)")
    return p


__all__ = [
    "ReportFormat",
    "FindingReport",
    "ExecutiveSummary",
    "generate_html",
    "generate_sarif",
    "generate_markdown",
    "export_report",
]
