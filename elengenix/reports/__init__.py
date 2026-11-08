"""elengenix.reports — canonical report rendering package.

Modules:
- ``cvss``      CVSS v3.1 parsing / scoring / severity classification
- ``markdown``  markdown report assembly (flows → markdown, TOC, anchors)
- ``pdf``       markdown → PDF rendering (reportlab, CJK + emoji safe)
- ``templates`` professional report templates (vuln / executive / technical / compliance)
- ``export``    multi-format export (markdown / html / json / pdf)
- ``adapters``  findings → markdown / HTML / PDF canonical renderers
"""

from elengenix.reports.cvss import (
    CVSSResult,
    CVSSVector,
    calculate_cvss_score,
    cvss_result,
    cvss_severity,
    format_cvss_vector,
    parse_cvss_vector,
)
from elengenix.reports.markdown import (
    DEFAULT_STATUS_EMOJI,
    generate_anchors,
    generate_report_markdown,
    shift_markdown_headers,
    slugify_github,
    status_emoji,
)

__all__ = [
    "CVSSResult",
    "CVSSVector",
    "calculate_cvss_score",
    "cvss_result",
    "cvss_severity",
    "format_cvss_vector",
    "parse_cvss_vector",
    "DEFAULT_STATUS_EMOJI",
    "generate_anchors",
    "generate_report_markdown",
    "shift_markdown_headers",
    "slugify_github",
    "status_emoji",
]
