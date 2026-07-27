"""elengenix.reports.templates — Report templates for various report types."""
from __future__ import annotations

from typing import Any

# Template strings (Jinja2-compatible, but rendered with simple str.format)
EXECUTIVE_SUMMARY_TEMPLATE = """# Executive Summary — {title}

## Overview
{overview}

## Key Findings
{findings}

## Recommendations
{recommendations}

## Risk Assessment
{risk_assessment}
"""

TECHNICAL_REPORT_TEMPLATE = """# Technical Report — {title}

## Scope
{scope}

## Methodology
{methodology}

## Detailed Findings
{findings}

## Technical Details
{technical_details}

## Remediation
{remediation}
"""

VULNERABILITY_TEMPLATE = """# Vulnerability Report — {title}

## Vulnerability Details
- **CVSS Score:** {cvss_score}
- **Severity:** {severity}
- **CVSS Vector:** {cvss_vector}

## Description
{description}

## Affected Components
{affected}

## Proof of Concept
{poc}

## Remediation
{remediation}

## References
{references}
"""

COMPLIANCE_REPORT_TEMPLATE = """# Compliance Report — {title}

## Compliance Status
{status}

## Controls Assessed
{controls}

## Findings
{findings}

## Gap Analysis
{gap_analysis}

## Remediation Plan
{remediation_plan}
"""


def render_template(template: str, **kwargs: Any) -> str:
    """Render a template string with the provided keyword arguments.

    Uses simple str.format() — missing keys are left as-is.
    """
    try:
        return template.format(**kwargs)
    except KeyError:
        # If any key is missing, do a safe partial render
        result = template
        for key, value in kwargs.items():
            result = result.replace("{" + key + "}", str(value))
        return result
