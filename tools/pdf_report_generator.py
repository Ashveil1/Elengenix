"""tools/pdf_report_generator.py

Professional PDF Report Generator for Bug Bounty Findings.

Purpose:
- Generate professional PDF reports suitable for submission
- Include findings with evidence, severity, and remediation
- Executive summary and technical details sections
- CWE/CVE mapping
- Custom branding support

Output:
- Professional PDF reports
- Standalone HTML reports (fallback)
- Both formats include full evidence and remediation
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger("elengenix.pdf_report")

@dataclass
class Finding:
 """Structured finding for report generation."""
 title: str
 severity: str # critical/high/medium/low/info
 cvss_score: float
 description: str
 impact: str
 evidence: str
 remediation: str
 cwe_id: Optional[str] = None
 cve_id: Optional[str] = None
 affected_urls: List[str] = None
 references: List[str] = None
 
 def __post_init__(self):
 if self.affected_urls is None:
 self.affected_urls = []
 if self.references is None:
 self.references = []

@dataclass
class ReportMetadata:
 """Report metadata."""
 title: str
 target: str
 author: str
 date: str
 version: str = "1.0"
 confidential: bool = True
 classification: str = "Confidential - For Authorized Eyes Only"

class PDFReportGenerator:
 """
 Generate professional PDF reports for bug bounty findings.
 
 Note: Uses HTML-to-PDF approach for better styling without
 heavy dependencies like ReportLab.
 """

 def __init__(self, output_dir: Path = Path("reports")):
 self.output_dir = output_dir
 self.output_dir.mkdir(parents=True, exist_ok=True)

 def generate_from_findings(
 self,
 findings: List[Dict[str, Any]],
 metadata: ReportMetadata,
 template: str = "professional",
 ) -> Dict[str, Path]:
 """
 Generate reports from list of findings.
 Returns dict with paths to generated files.
 """
 # Convert raw findings to structured objects
 structured_findings = self._structure_findings(findings)
 
 # Sort by severity
 severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
 structured_findings.sort(key=lambda f: severity_order.get(f.severity.lower(), 99))
 
 results = {}
 
 # Generate HTML report (always available)
 html_path = self._generate_html(structured_findings, metadata, template)
 results["html"] = html_path
 
 # Try to generate PDF if weasyprint is available
 pdf_path = self._try_generate_pdf(html_path, metadata)
 if pdf_path:
 results["pdf"] = pdf_path
 
 return results

 def _structure_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Finding]:
 """Convert raw finding dicts to structured Finding objects."""
 findings = []
 
 for raw in raw_findings:
 # Extract evidence text
 evidence_parts = []
 if isinstance(raw.get("evidence"), dict):
 for key, value in raw["evidence"].items():
 evidence_parts.append(f"{key}: {json.dumps(value, indent=2)}")
 else:
 evidence_parts.append(str(raw.get("evidence", "N/A")))
 
 # Determine severity
 sev = raw.get("severity", "info").lower()
 if sev not in ["critical", "high", "medium", "low", "info"]:
 sev = "info"
 
 # Map CVSS score
 cvss = raw.get("cvss_score", 0.0)
 if not cvss and sev == "critical":
 cvss = 9.0
 elif not cvss and sev == "high":
 cvss = 7.5
 elif not cvss and sev == "medium":
 cvss = 5.0
 elif not cvss:
 cvss = 2.0
 
 finding = Finding(
 title=raw.get("title") or raw.get("type", "Unknown"),
 severity=sev,
 cvss_score=cvss,
 description=raw.get("description", raw.get("statement", "No description provided")),
 impact=raw.get("impact", self._generate_impact_text(sev)),
 evidence="\n\n".join(evidence_parts),
 remediation=raw.get("remediation", "No specific remediation provided. Review and implement appropriate security controls."),
 cwe_id=raw.get("cwe_id"),
 cve_id=raw.get("cve_id"),
 affected_urls=raw.get("affected_urls", [raw.get("target", "N/A")]),
 references=raw.get("references", []),
 )
 findings.append(finding)
 
 return findings

 def _generate_impact_text(self, severity: str) -> str:
 """Generate impact text based on severity."""
 impacts = {
 "critical": "Successful exploitation could lead to complete system compromise, data exfiltration, or unauthorized administrative access.",
 "high": "Exploitation could lead to significant security impact including access to sensitive data or elevated privileges.",
 "medium": "Exploitation could lead to limited security impact or information disclosure that could aid further attacks.",
 "low": "Exploitation has minimal direct security impact but represents a security weakness that should be addressed.",
 "info": "Informational finding that does not represent an immediate security risk but may indicate areas for security improvement.",
 }
 return impacts.get(severity.lower(), impacts["info"])

 def _generate_html(self, findings: List[Finding], metadata: ReportMetadata, template: str) -> Path:
 """Generate HTML report."""
 timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
 html_path = self.output_dir / f"report_{metadata.target.replace('/', '_')}_{timestamp}.html"
 
 html_content = self._render_html_template(findings, metadata, template)
 html_path.write_text(html_content, encoding="utf-8")
 
 return html_path

 def _render_html_template(self, findings: List[Finding], metadata: ReportMetadata, template: str) -> str:
 """Render HTML template with findings."""
 
 # Severity colors
 severity_colors = {
 "critical": "#dc2626",
 "high": "#ea580c",
 "medium": "#ca8a04",
 "low": "#16a34a",
 "info": "#2563eb",
 }
 
 # Count by severity
 severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
 for f in findings:
 if f.severity in severity_counts:
 severity_counts[f.severity] += 1
 
 # Build findings sections
 findings_html = []
 for i, f in enumerate(findings, 1):
 color = severity_colors.get(f.severity, "#6b7280")
 cwe_section = f"<p><strong>CWE:</strong> {f.cwe_id}</p>" if f.cwe_id else ""
 cve_section = f"<p><strong>CVE:</strong> {f.cve_id}</p>" if f.cve_id else ""
 urls_section = ""
 if f.affected_urls:
 urls_html = "\n".join([f"<li>{url}</li>" for url in f.affected_urls[:5]])
 urls_section = f"<h4>Affected URLs:</h4><ul>{urls_html}</ul>"
 
 refs_section = ""
 if f.references:
 refs_html = "\n".join([f'<li><a href="{ref}">{ref}</a></li>' for ref in f.references])
 refs_section = f"<h4>References:</h4><ul>{refs_html}</ul>"
 
 finding_html = f"""
 <div class="finding severity-{f.severity}" id="finding-{i}">
 <div class="finding-header">
 <span class="finding-number">{i}</span>
 <span class="finding-title">{f.title}</span>
 <span class="severity-badge" style="background-color: {color}">
 {f.severity.upper()} ({f.cvss_score})
 </span>
 </div>
 
 <div class="finding-body">
 <h4>Description</h4>
 <p>{f.description}</p>
 
 <h4>Impact</h4>
 <p>{f.impact}</p>
 
 <h4>Evidence</h4>
 <pre class="evidence">{f.evidence}</pre>
 
 <h4>Remediation</h4>
 <div class="remediation">
 {f.remediation}
 </div>
 
 {urls_section}
 {cwe_section}
 {cve_section}
 {refs_section}
 </div>
 </div>
 """
 findings_html.append(finding_html)
 
 summary_cards = []
 for sev, count in severity_counts.items():
 if count > 0:
 color = severity_colors.get(sev, "#6b7280")
 summary_cards.append(f"""
 <div class="summary-card" style="border-color: {color}">
 <div class="summary-count" style="color: {color}">{count}</div>
 <div class="summary-label">{sev.upper()}</div>
 </div>
 """)
 
 html = f"""<!DOCTYPE html>
<html lang="en">
<head>
 <meta charset="UTF-8">
 <meta name="viewport" content="width=device-width, initial-scale=1.0">
 <title>{metadata.title}</title>
 <style>
 * {{
 margin: 0;
 padding: 0;
 box-sizing: border-box;
 }}
 
 body {{
 font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
 line-height: 1.6;
 color: #1f2937;
 background: #f9fafb;
 }}
 
 .container {{
 max-width: 1200px;
 margin: 0 auto;
 padding: 40px 20px;
 background: white;
 box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
 }}
 
 .header {{
 text-align: center;
 padding-bottom: 40px;
 border-bottom: 3px solid #dc2626;
 margin-bottom: 40px;
 }}
 
 .confidential-banner {{
 background: #dc2626;
 color: white;
 padding: 10px;
 text-align: center;
 font-weight: bold;
 margin-bottom: 30px;
 }}
 
 .logo {{
 font-size: 28px;
 font-weight: bold;
 color: #dc2626;
 margin-bottom: 10px;
 }}
 
 .report-title {{
 font-size: 32px;
 font-weight: bold;
 margin-bottom: 20px;
 color: #111827;
 }}
 
 .metadata {{
 display: grid;
 grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
 gap: 20px;
 background: #f3f4f6;
 padding: 20px;
 border-radius: 8px;
 margin-bottom: 40px;
 }}
 
 .metadata-item {{
 display: flex;
 flex-direction: column;
 }}
 
 .metadata-label {{
 font-size: 12px;
 color: #6b7280;
 text-transform: uppercase;
 letter-spacing: 0.5px;
 }}
 
 .metadata-value {{
 font-size: 16px;
 font-weight: 600;
 color: #111827;
 }}
 
 .executive-summary {{
 background: #eff6ff;
 border-left: 4px solid #2563eb;
 padding: 20px;
 margin-bottom: 40px;
 }}
 
 .executive-summary h2 {{
 color: #1e40af;
 margin-bottom: 15px;
 }}
 
 .severity-summary {{
 display: grid;
 grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
 gap: 15px;
 margin-bottom: 40px;
 }}
 
 .summary-card {{
 background: white;
 border: 2px solid;
 border-radius: 8px;
 padding: 20px;
 text-align: center;
 }}
 
 .summary-count {{
 font-size: 36px;
 font-weight: bold;
 margin-bottom: 5px;
 }}
 
 .summary-label {{
 font-size: 14px;
 color: #6b7280;
 text-transform: uppercase;
 }}
 
 .findings-section h2 {{
 color: #111827;
 margin-bottom: 30px;
 padding-bottom: 10px;
 border-bottom: 2px solid #e5e7eb;
 }}
 
 .finding {{
 background: white;
 border: 1px solid #e5e7eb;
 border-radius: 8px;
 margin-bottom: 30px;
 overflow: hidden;
 }}
 
 .finding-header {{
 background: #f9fafb;
 padding: 20px;
 display: flex;
 align-items: center;
 gap: 15px;
 border-bottom: 1px solid #e5e7eb;
 }}
 
 .finding-number {{
 width: 32px;
 height: 32px;
 background: #dc2626;
 color: white;
 border-radius: 50%;
 display: flex;
 align-items: center;
 justify-content: center;
 font-weight: bold;
 flex-shrink: 0;
 }}
 
 .finding-title {{
 flex: 1;
 font-size: 18px;
 font-weight: 600;
 }}
 
 .severity-badge {{
 padding: 6px 12px;
 border-radius: 4px;
 color: white;
 font-size: 12px;
 font-weight: 600;
 text-transform: uppercase;
 }}
 
 .finding-body {{
 padding: 20px;
 }}
 
 .finding-body h4 {{
 color: #374151;
 margin-top: 20px;
 margin-bottom: 10px;
 font-size: 14px;
 text-transform: uppercase;
 letter-spacing: 0.5px;
 }}
 
 .finding-body p {{
 margin-bottom: 15px;
 color: #4b5563;
 }}
 
 .evidence {{
 background: #1f2937;
 color: #e5e7eb;
 padding: 15px;
 border-radius: 6px;
 overflow-x: auto;
 font-family: 'Monaco', 'Menlo', monospace;
 font-size: 13px;
 line-height: 1.5;
 }}
 
 .remediation {{
 background: #ecfdf5;
 border-left: 4px solid #10b981;
 padding: 15px;
 border-radius: 0 6px 6px 0;
 }}
 
 .footer {{
 text-align: center;
 padding-top: 40px;
 border-top: 1px solid #e5e7eb;
 color: #6b7280;
 font-size: 14px;
 }}
 
 @media print {{
 .container {{
 box-shadow: none;
 }}
 
 .finding {{
 break-inside: avoid;
 page-break-inside: avoid;
 }}
 }}
 </style>
</head>
<body>
 <div class="container">
 <div class="confidential-banner">
 {metadata.classification}
 </div>
 
 <div class="header">
 <div class="logo"> Elengenix Security</div>
 <h1 class="report-title">{metadata.title}</h1>
 </div>
 
 <div class="metadata">
 <div class="metadata-item">
 <span class="metadata-label">Target</span>
 <span class="metadata-value">{metadata.target}</span>
 </div>
 <div class="metadata-item">
 <span class="metadata-label">Author</span>
 <span class="metadata-value">{metadata.author}</span>
 </div>
 <div class="metadata-item">
 <span class="metadata-label">Date</span>
 <span class="metadata-value">{metadata.date}</span>
 </div>
 <div class="metadata-item">
 <span class="metadata-label">Version</span>
 <span class="metadata-value">{metadata.version}</span>
 </div>
 </div>
 
 <div class="executive-summary">
 <h2>Executive Summary</h2>
 <p>
 This report contains the findings from a security assessment of <strong>{metadata.target}</strong>.
 A total of <strong>{len(findings)} vulnerabilities</strong> were identified across various
 severity levels. Immediate attention is recommended for all Critical and High severity findings.
 </p>
 </div>
 
 <div class="severity-summary">
 {''.join(summary_cards)}
 </div>
 
 <div class="findings-section">
 <h2>Detailed Findings</h2>
 {''.join(findings_html)}
 </div>
 
 <div class="footer">
 <p>Generated by Elengenix v2.0.0 - Professional Security Assessment Platform</p>
 <p>Report ID: {str(uuid4())[:8]} | {metadata.date}</p>
 </div>
 </div>
</body>
</html>
"""
 return html

 def _try_generate_pdf(self, html_path: Path, metadata: ReportMetadata) -> Optional[Path]:
 """Try to generate PDF from HTML using weasyprint if available."""
 try:
 import weasyprint
 
 pdf_path = self.output_dir / f"report_{metadata.target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
 
 weasyprint.HTML(filename=str(html_path)).write_pdf(str(pdf_path))
 logger.info(f"PDF generated: {pdf_path}")
 return pdf_path
 
 except ImportError:
 logger.debug("weasyprint not available, skipping PDF generation")
 return None
 except Exception as e:
 logger.error(f"PDF generation failed: {e}")
 return None

def format_report_summary(report_paths: Dict[str, Path]) -> str:
 """Format report generation summary."""
 lines = []
 lines.append("=" * 60)
 lines.append(" REPORT GENERATION COMPLETE")
 lines.append("=" * 60)
 
 if "pdf" in report_paths:
 lines.append(f" PDF Report: {report_paths['pdf']}")
 
 if "html" in report_paths:
 lines.append(f" HTML Report: {report_paths['html']}")
 lines.append("")
 lines.append(" Open HTML report in browser for best viewing experience")
 lines.append(" Install weasyprint for PDF generation:")
 lines.append(" pip install weasyprint")
 
 lines.append("=" * 60)
 return "\n".join(lines)
