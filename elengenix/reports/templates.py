"""elengenix.reports.templates — Report templates for the Elengenix report suite.

Each template is a plain string with ``{placeholder}`` markers. Rendering is
performed by :func:`render_template`, which accepts a single positional
``fields`` dict, substitutes every recognised placeholder with the matching
value, and replaces any missing key with an empty string (never raises
``KeyError``, never leaves ``{placeholder}`` text in the output).

Public surface (importable via ``from elengenix.reports.templates import *``):
    VULNERABILITY_TEMPLATE, EXECUTIVE_SUMMARY_TEMPLATE,
    TECHNICAL_REPORT_TEMPLATE, COMPLIANCE_REPORT_TEMPLATE, render_template
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Optional

# Matches a single ``{identifier}`` placeholder (Python-identifier characters).
_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


# ---------------------------------------------------------------------------
# Vulnerability report template
# ---------------------------------------------------------------------------

VULNERABILITY_TEMPLATE = """# Vulnerability Report — {title}

## Engagement
- **Engagement Name:** {engagement_name}

## Overview
{overview}

## Vulnerability Details
- **CVE ID:** {cve_id}
- **CVSS Score:** {cvss_score}
- **Severity:** {severity}
- **CVSS Vector:** {cvss_vector}
- **CVE URL:** {cve_url}
- **Vendor Advisory:** {vendor_advisory}
- **OWASP Reference:** {owasp_reference}

## Description
{description}

## Affected Components
{affected}

## Affected Component
{affected_component}

## Proof of Concept
{poc}

## Exploitation Commands
{exploitation_commands}

## Evidence
{evidence}

## Impact
{impact}

## Remediation
{remediation}

## Immediate Fix
{immediate_fix}

## Long-Term Fix
{long_term_fix}

## Compensating Controls
{compensating_controls}

## References
{references}
"""


# ---------------------------------------------------------------------------
# Executive summary template
# ---------------------------------------------------------------------------

EXECUTIVE_SUMMARY_TEMPLATE = """# Executive Summary — {title}

## Engagement
- **Engagement Name:** {engagement_name}
- **Client Name:** {client_name}

## Overview
{overview}

## Findings Summary
- **Critical:** {critical_count}
- **High:** {high_count}
- **Medium:** {medium_count}
- **Low:** {low_count}
- **Info:** {info_count}

## Compliance Alignment
This assessment is aligned with industry security frameworks, including
PCI-DSS, SOC 2, and ISO/IEC 27001, to support organisational compliance
objectives.
"""


# ---------------------------------------------------------------------------
# Technical report template
# ---------------------------------------------------------------------------

TECHNICAL_REPORT_TEMPLATE = """# Technical Report — {title}

## Overview
{overview}

## Scope
{scope}

## Methodology
{methodology}

## Tools Used
{tools_used}

## Reconnaissance Summary
{recon_summary}

## Findings
{findings}

## Findings Summary
{findings_summary}

## Technical Details
{technical_details}

## Exploit Chains
{exploit_chains}

## Immediate Remediation
{immediate_remediation}

## Remediation
{remediation}

## Appendix — Raw Output
{appendix_raw_output}
"""


# ---------------------------------------------------------------------------
# Compliance report template
# ---------------------------------------------------------------------------

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

## PCI-DSS Compliance
{pci_dss_table}

## SOC 2 Compliance
{soc2_table}

## ISO/IEC 27001 Compliance
{iso27001_table}
"""


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


def render_template(
    template: str,
    fields: Optional[Mapping[str, Any]] = None,
    **kwargs: Any,
) -> str:
    """Render ``template`` substituting ``{placeholder}`` markers from ``fields``.

    Args:
        template: The template string containing ``{key}`` markers.
        fields: A mapping of placeholder name → value. Missing keys are
            replaced with the empty string (no ``KeyError`` is raised).
        **kwargs: Additional keyword overrides merged on top of ``fields``
            (kept for backward compatibility).

    Returns:
        The rendered string with **no** ``{placeholder}`` markers remaining.
    """
    merged: dict[str, Any] = {}
    if isinstance(fields, Mapping):
        merged.update(fields)
    if kwargs:
        merged.update(kwargs)

    def _replace(match: "re.Match[str]") -> str:
        key = match.group(1)
        if key in merged:
            value = merged[key]
            return "" if value is None else str(value)
        return ""

    return _PLACEHOLDER_RE.sub(_replace, template)
