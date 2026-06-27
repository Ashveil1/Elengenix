"""tui/findings_display.py - Enhanced findings display for Elengenix TUI.

Provides:
    * :class:`FindingsDisplay` - Sortable, filterable findings display
    * :func:`render_findings_table` - Standalone Rich renderable for findings
    * :func:`render_finding_detail` - Detailed view of a single finding

Features:
    - Sort by severity, date, type, or location
    - Filter by severity level or vulnerability type
    - Expandable detail view for each finding
    - Severity badges with color coding
    - Quick actions (export, copy, mark as false positive)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.box import HEAVY, ROUNDED, SIMPLE
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Severity configuration
SEVERITY_CONFIG = {
    "critical": {"color": "#ff003c", "badge": "CRIT", "priority": 0},
    "high": {"color": "#ff5500", "badge": "HIGH", "priority": 1},
    "medium": {"color": "#ffb300", "badge": "MED", "priority": 2},
    "low": {"color": "#81C784", "badge": "LOW", "priority": 3},
    "info": {"color": "#888888", "badge": "INFO", "priority": 4},
    "informational": {"color": "#888888", "badge": "INFO", "priority": 4},
}


@dataclass
class Finding:
    """A single security finding."""

    id: str
    title: str
    severity: str
    category: str
    location: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cve_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    is_false_positive: bool = False
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def severity_config(self) -> Dict[str, str]:
        return SEVERITY_CONFIG.get(self.severity.lower(), SEVERITY_CONFIG["info"])


@dataclass
class FindingFilter:
    """Filter criteria for findings display."""

    severities: Optional[List[str]] = None
    categories: Optional[List[str]] = None
    search_query: str = ""
    show_false_positives: bool = False

    def matches(self, finding: Finding) -> bool:
        """Check if a finding matches this filter."""
        # Severity filter
        if self.severities and finding.severity.lower() not in [s.lower() for s in self.severities]:
            return False

        # Category filter
        if self.categories and finding.category.lower() not in [c.lower() for c in self.categories]:
            return False

        # Search query
        if self.search_query:
            query = self.search_query.lower()
            searchable = f"{finding.title} {finding.description} {finding.location} {finding.category}".lower()
            if query not in searchable:
                return False

        # False positive filter
        if not self.show_false_positives and finding.is_false_positive:
            return False

        return True


class FindingsDisplay:
    """Sortable, filterable findings display widget.

    Features:
        - Sort by severity, date, type, or location
        - Filter by severity level or vulnerability type
        - Expandable detail view for each finding
        - Severity badges with color coding

    Example:
        display = FindingsDisplay()
        display.add_finding(Finding(
            id="1",
            title="SQL Injection",
            severity="critical",
            category="sqli",
            location="/api/users",
        ))
        print(display.render())
    """

    def __init__(self, max_display: int = 50):
        """Initialize the findings display.

        Args:
            max_display: Maximum number of findings to display.
        """
        self.findings: List[Finding] = []
        self.max_display = max_display
        self.sort_by: str = "severity"
        self.sort_ascending: bool = False
        self.filter = FindingFilter()
        self.selected_index: int = 0
        self.expanded_index: int = -1

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the display.

        Args:
            finding: The finding to add.
        """
        self.findings.append(finding)

    def add_findings(self, findings: List[Finding]) -> None:
        """Add multiple findings to the display.

        Args:
            findings: List of findings to add.
        """
        self.findings.extend(findings)

    def clear(self) -> None:
        """Clear all findings."""
        self.findings.clear()

    def set_sort(self, by: str, ascending: bool = False) -> None:
        """Set the sort criteria.

        Args:
            by: Sort field (severity, date, category, location, title).
            ascending: Sort direction.
        """
        self.sort_by = by
        self.sort_ascending = ascending

    def set_filter(self, filter: FindingFilter) -> None:
        """Set the filter criteria.

        Args:
            filter: The filter to apply.
        """
        self.filter = filter

    def get_filtered_sorted(self) -> List[Finding]:
        """Get findings filtered and sorted.

        Returns:
            List of findings matching filter, sorted by current criteria.
        """
        # Apply filter
        filtered = [f for f in self.findings if self.filter.matches(f)]

        # Sort
        def sort_key(f: Finding):
            if self.sort_by == "severity":
                # Lower priority number = more severe (critical=0, high=1, etc.)
                # We want critical first, so sort ascending by priority
                return (
                    SEVERITY_CONFIG.get(f.severity.lower(), {}).get("priority", 99),
                    f.timestamp,
                )
            elif self.sort_by == "date":
                return (
                    f.timestamp,
                    SEVERITY_CONFIG.get(f.severity.lower(), {}).get("priority", 99),
                )
            elif self.sort_by == "category":
                return (f.category.lower(), f.timestamp)
            elif self.sort_by == "location":
                return (f.location.lower(), f.timestamp)
            elif self.sort_by == "title":
                return (f.title.lower(), f.timestamp)
            return (f.timestamp,)

        # For severity, always sort ascending (critical first)
        # For others, use the sort_ascending flag
        if self.sort_by == "severity":
            filtered.sort(key=sort_key)  # ascending = critical first
        else:
            filtered.sort(key=sort_key, reverse=not self.sort_ascending)

        return filtered[: self.max_display]

    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about findings.

        Returns:
            Dictionary with severity counts and totals.
        """
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in self.findings:
            if not f.is_false_positive:
                severity = f.severity.lower()
                if severity in stats:
                    stats[severity] += 1
                stats["total"] += 1
        return stats

    def render(
        self,
        primary: str = "#ff2222",
        text_color: str = "#ffffff",
        muted: str = "#888888",
        width: int = 100,
    ) -> Panel:
        """Render the findings display as a Rich Panel.

        Args:
            primary: Primary theme color.
            text_color: Main text color.
            muted: Muted text color.
            width: Panel width.

        Returns:
            Rich Panel with findings display.
        """
        filtered = self.get_filtered_sorted()
        stats = self.get_statistics()

        # Header with statistics
        header = Text()
        header.append(" FINDINGS ", style=f"bold {primary}")
        header.append("  Total: ", style=muted)
        header.append(str(stats["total"]), style=f"bold {text_color}")
        header.append("  |  ", style=muted)

        for sev in ["critical", "high", "medium", "low", "info"]:
            if stats[sev] > 0:
                config = SEVERITY_CONFIG[sev]
                header.append(f" {config['badge']}: ", style=muted)
                header.append(str(stats[sev]), style=f"bold {config['color']}")

        # Findings table
        if not filtered:
            table_text = Text("  (no findings match filter)", style=muted)
        else:
            table = Table(
                show_header=True,
                header_style=f"bold {primary}",
                box=SIMPLE,
                padding=(0, 1),
                expand=True,
            )
            table.add_column("#", width=4, justify="right")
            table.add_column("Sev", width=6, justify="center")
            table.add_column("Title", ratio=3)
            table.add_column("Category", ratio=1)
            table.add_column("Location", ratio=2)
            table.add_column("CVSS", width=6, justify="center")

            for i, finding in enumerate(filtered[: self.max_display]):
                # Severity badge
                config = finding.severity_config
                sev_badge = Text(f" {config['badge']} ", style=f"bold white on {config['color']}")

                # Title with selection indicator
                title_text = Text()
                if i == self.selected_index:
                    title_text.append("> ", style=f"bold {primary}")
                elif i == self.expanded_index:
                    title_text.append("v ", style=f"bold {primary}")
                else:
                    title_text.append("  ")
                title_text.append(
                    finding.title,
                    style=f"bold {text_color}" if i == self.selected_index else text_color,
                )

                # CVSS score
                cvss_text = f"{finding.cvss_score:.1f}" if finding.cvss_score > 0 else "-"

                table.add_row(
                    str(i + 1),
                    sev_badge,
                    title_text,
                    finding.category,
                    finding.location[:30],
                    cvss_text,
                )

            table_text = table

        # Expanded detail view
        detail_text = None
        if 0 <= self.expanded_index < len(filtered):
            finding = filtered[self.expanded_index]
            detail_text = self._render_detail(finding, primary, text_color, muted)

        # Assemble
        parts = [header, Text(""), table_text]
        if detail_text:
            parts.extend([Text(""), detail_text])

        body = Group(*parts)

        return Panel(
            body,
            title=f"[bold {primary}]SECURITY FINDINGS[/bold {primary}]",
            border_style=primary,
            box=ROUNDED,
            padding=(0, 1),
            width=width,
        )

    def _render_detail(
        self,
        finding: Finding,
        primary: str,
        text_color: str,
        muted: str,
    ) -> Panel:
        """Render detailed view of a finding.

        Args:
            finding: The finding to detail.
            primary: Primary theme color.
            text_color: Main text color.
            muted: Muted text color.

        Returns:
            Rich Panel with finding details.
        """
        table = Table(
            show_header=False,
            box=SIMPLE,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("Key", style=muted, width=14)
        table.add_column("Value", style=text_color)

        # Severity with color
        config = finding.severity_config
        sev_text = Text(f" {config['badge']} ", style=f"bold white on {config['color']}")
        sev_text.append(f" ({finding.severity.upper()})", style=config["color"])

        table.add_row("ID", finding.id)
        table.add_row("Severity", sev_text)
        table.add_row("Category", finding.category)
        table.add_row("Location", finding.location)
        if finding.cvss_score > 0:
            table.add_row("CVSS", f"{finding.cvss_score:.1f}/10.0")
        if finding.cve_id:
            table.add_row("CVE", finding.cve_id)
        table.add_row("Timestamp", finding.timestamp.strftime("%Y-%m-%d %H:%M:%S"))

        if finding.description:
            table.add_row("Description", finding.description[:200])
        if finding.evidence:
            table.add_row("Evidence", finding.evidence[:200])
        if finding.remediation:
            table.add_row("Remediation", finding.remediation[:200])
        if finding.tags:
            table.add_row("Tags", ", ".join(finding.tags))

        return Panel(
            table,
            title=f"[bold {primary}]FINDING DETAIL: {finding.title}[/bold {primary}]",
            border_style=primary,
            box=HEAVY,
            padding=(0, 1),
        )


def render_findings_table(
    findings: List[Finding],
    sort_by: str = "severity",
    primary: str = "#ff2222",
    text_color: str = "#ffffff",
    muted: str = "#888888",
) -> Panel:
    """Render findings as a standalone Rich Panel.

    Args:
        findings: List of findings to display.
        sort_by: Sort field (severity, date, category, location).
        primary: Primary theme color.
        text_color: Main text color.
        muted: Muted text color.

    Returns:
        Rich Panel with findings table.
    """
    display = FindingsDisplay()
    display.add_findings(findings)
    display.set_sort(sort_by)
    return display.render(primary=primary, text_color=text_color, muted=muted)


def render_finding_detail(
    finding: Finding,
    primary: str = "#ff2222",
    text_color: str = "#ffffff",
    muted: str = "#888888",
) -> Panel:
    """Render detailed view of a single finding.

    Args:
        finding: The finding to detail.
        primary: Primary theme color.
        text_color: Main text color.
        muted: Muted text color.

    Returns:
        Rich Panel with finding details.
    """
    display = FindingsDisplay()
    return display._render_detail(finding, primary, text_color, muted)
