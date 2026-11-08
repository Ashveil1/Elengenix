"""Professional report templates (vulnerability / executive / technical / compliance).

All templates use ``{placeholder}`` fields; :func:`render_template`
substitutes missing fields with empty strings instead of raising.
Templates must not contain literal braces — escape any literal ``{`` as
``{{`` is NOT supported; keep templates brace-free except placeholders.
"""

from __future__ import annotations

import re
from typing import Dict

__all__ = [
    "VULNERABILITY_TEMPLATE",
    "EXECUTIVE_SUMMARY_TEMPLATE",
    "TECHNICAL_REPORT_TEMPLATE",
    "COMPLIANCE_REPORT_TEMPLATE",
    "render_template",
]

_PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


def render_template(template: str, values: Dict[str, object]) -> str:
    """Substitute ``{placeholder}`` fields; missing fields become ``""``."""
    return _PLACEHOLDER_RE.sub(lambda m: str(values.get(m.group(1), "")), template)


VULNERABILITY_TEMPLATE = """# Vulnerability Report — {cve_id}

## Overview

- **CVE ID:** {cve_id}
- **Severity:** {severity}
- **CVSS Base Score:** {cvss_score}
- **CVSS Vector:** {cvss_vector}
- **Affected Component:** {affected_component}
- **Reference:** {cve_url}
- **Vendor Advisory:** {vendor_advisory}
- **OWASP Reference:** {owasp_reference}

## Description

{description}

## Exploitation

### Commands

{exploitation_commands}

### Evidence

{evidence}

## Impact

{impact}

## Remediation

### Immediate Fix

{immediate_fix}

### Long-Term Fix

{long_term_fix}

### Compensating Controls

{compensating_controls}
"""

EXECUTIVE_SUMMARY_TEMPLATE = """# Executive Summary — {engagement_name}

**Client:** {client_name}
**Engagement:** {engagement_name}
**Assessment Date:** {assessment_date}
**Prepared By:** {author}

## Risk Posture

Overall risk rating: {overall_risk}

| Severity | Count |
|----------|-------|
| Critical | {critical_count} |
| High | {high_count} |
| Medium | {medium_count} |
| Low | {low_count} |
| Info | {info_count} |

## Key Findings

{key_findings}

## Recommendations

{recommendations}
"""

TECHNICAL_REPORT_TEMPLATE = """# Technical Report — {engagement_name}

## Overview

{overview}

**Target:** {target}
**Assessment Type:** {assessment_type}
**Date Range:** {date_range}

## Methodology

{methodology}

## Tools Used

{tools_used}

## Reconnaissance Summary

{recon_summary}

## Findings Summary

{findings_summary}

## Exploit Chains

{exploit_chains}

## Remediation Plan

### Immediate Remediation

{immediate_remediation}

### Strategic Remediation

{strategic_remediation}

## Appendices

### Appendix A — Raw Output

{appendix_raw_output}
"""

COMPLIANCE_REPORT_TEMPLATE = """# Compliance Report — {engagement_name}

**Client:** {client_name}
**Framework Coverage:** PCI-DSS, SOC 2, ISO/IEC 27001

## Executive Overview

{executive_overview}

## PCI-DSS Assessment

{pci_dss_summary}

| Requirement | Status | Notes |
|-------------|--------|-------|
{pci_dss_table}

## SOC 2 Assessment

{soc2_summary}

| Trust Service Criteria | Status | Notes |
|------------------------|--------|-------|
{soc2_table}

## ISO/IEC 27001 Assessment

{iso27001_summary}

| Control (Annex A) | Status | Notes |
|-------------------|--------|-------|
{iso27001_table}

## Remediation & Compliance Roadmap

{compliance_roadmap}
"""
