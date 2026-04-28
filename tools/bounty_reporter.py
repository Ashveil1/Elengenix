"""tools/bounty_reporter.py

Artifact capture and report generation for bug bounty submissions.

Purpose:
- Capture request/response samples for findings
- Generate standardized bounty report (markdown) with:
 - Summary with CVSS
 - Reproduction steps
 - Evidence (HTTP samples)
 - Impact and remediation
 - CWE/CVE references

Output: reports/bounty/{target}_{timestamp}/report.md + evidence/
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.bounty_reporter")

@dataclass
class FindingArtifact:
 finding_id: str
 finding_type: str
 severity: str
 confidence: float
 url: str
 title: str
 description: str
 cvss_score: Optional[float]
 cwe_id: Optional[str]
 request_sample: Optional[str] = None
 response_sample: Optional[str] = None
 evidence_screenshot_hint: Optional[str] = None

class BountyReporter:
 def __init__(self, target: str, output_dir: Optional[Path] = None):
 self.target = target
 self.timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
 if output_dir is None:
 safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", target)[:80]
 self.base_dir = Path("reports") / "bounty" / f"{safe_target}_{self.timestamp}"
 else:
 self.base_dir = output_dir
 self.base_dir.mkdir(parents=True, exist_ok=True)
 self.evidence_dir = self.base_dir / "evidence"
 self.evidence_dir.mkdir(exist_ok=True)

 def add_artifact(
 self,
 artifact: FindingArtifact,
 ) -> None:
 """Store artifact evidence files."""
 safe_id = re.sub(r"[^a-zA-Z0-9._-]", "_", artifact.finding_id)[:60]

 if artifact.request_sample:
 req_path = self.evidence_dir / f"{safe_id}_request.txt"
 req_path.write_text(artifact.request_sample, encoding="utf-8")

 if artifact.response_sample:
 resp_path = self.evidence_dir / f"{safe_id}_response.txt"
 resp_path.write_text(artifact.response_sample[:2000], encoding="utf-8")

 def generate_report(
 self,
 findings: List[FindingArtifact],
 executive_summary: Optional[str] = None,
 ) -> Path:
 """Generate markdown bounty report."""
 lines: List[str] = []

 # Header
 lines.append(f"# Bug Bounty Report: {self.target}")
 lines.append(f"**Date**: {datetime.utcnow().isoformat()}Z")
 lines.append(f"**Tool**: Elengenix v2.0.0 - Expert System")
 lines.append("")

 # Executive Summary
 lines.append("## Executive Summary")
 if executive_summary:
 lines.append(executive_summary)
 else:
 lines.append(f"This report contains {len(findings)} potential security findings identified through automated and semi-automated analysis.")
 lines.append("")

 # Severity summary
 sev_counts: Dict[str, int] = {}
 for f in findings:
 sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
 lines.append("### Severity Summary")
 for sev in ["critical", "high", "medium", "low", "info"]:
 if sev in sev_counts:
 lines.append(f"- **{sev.upper()}**: {sev_counts[sev]}")
 lines.append("")

 # Detailed findings
 for i, f in enumerate(findings, 1):
 lines.append(f"## Finding {i}: {f.title}")
 lines.append(f"- **Type**: {f.finding_type}")
 lines.append(f"- **Severity**: {f.severity}")
 lines.append(f"- **Confidence**: {f.confidence:.0%}")
 if f.cvss_score:
 lines.append(f"- **CVSS Score**: {f.cvss_score}")
 if f.cwe_id:
 lines.append(f"- **CWE**: {f.cwe_id}")
 lines.append(f"- **URL**: {f.url}")
 lines.append("")

 lines.append("### Description")
 lines.append(f.description if f.description else "*No detailed description available.*")
 lines.append("")

 lines.append("### Evidence")
 safe_id = re.sub(r"[^a-zA-Z0-9._-]", "_", f.finding_id)[:60]
 if (self.evidence_dir / f"{safe_id}_request.txt").exists():
 lines.append(f"- Request: `evidence/{safe_id}_request.txt`")
 if (self.evidence_dir / f"{safe_id}_response.txt").exists():
 lines.append(f"- Response: `evidence/{safe_id}_response.txt`")
 lines.append("")

 lines.append("### Impact")
 lines.append("*Describe business impact here - e.g., data leakage, unauthorized access.*")
 lines.append("")

 lines.append("### Remediation")
 lines.append("*Describe recommended fix - e.g., add authorization check, rate limiting.*")
 lines.append("")

 lines.append("---")
 lines.append("")

 # Appendix
 lines.append("## Appendix: Testing Methodology")
 lines.append("- Differential testing with multiple account sessions")
 lines.append("- Tool-assisted reconnaissance and scanning")
 lines.append("- Payload mutation analysis (non-executing)")
 lines.append("- Governance-gated high-risk actions")
 lines.append("")

 report_path = self.base_dir / "report.md"
 report_path.write_text("\n".join(lines), encoding="utf-8")
 logger.info(f"Bounty report generated: {report_path}")
 return report_path

 def export_json(
 self,
 findings: List[FindingArtifact],
 mission_summary: Optional[Dict[str, Any]] = None,
 ) -> Path:
 """Export machine-readable JSON report."""
 data = {
 "target": self.target,
 "timestamp": datetime.utcnow().isoformat() + "Z",
 "tool": "Elengenix v2.0.0",
 "findings": [
 {
 "id": f.finding_id,
 "type": f.finding_type,
 "severity": f.severity,
 "confidence": f.confidence,
 "title": f.title,
 "description": f.description,
 "url": f.url,
 "cvss_score": f.cvss_score,
 "cwe_id": f.cwe_id,
 "has_request": (self.evidence_dir / f"{re.sub(r'[^a-zA-Z0-9._-]', '_', f.finding_id)[:60]}_request.txt").exists(),
 "has_response": (self.evidence_dir / f"{re.sub(r'[^a-zA-Z0-9._-]', '_', f.finding_id)[:60]}_response.txt").exists(),
 }
 for f in findings
 ],
 "mission": mission_summary or {},
 }
 json_path = self.base_dir / "report.json"
 json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
 return json_path
