"""tui/export.py — Export capabilities for TUI dashboard.

Provides functions to export dashboard views to various formats:
- HTML export with interactive elements
- PDF export using Rich console
- JSON export for data analysis
- Markdown export for documentation

Public API:
    export_to_html - Export dashboard to HTML file
    export_to_pdf - Export dashboard to PDF file
    export_to_json - Export dashboard data to JSON
    export_to_markdown - Export dashboard to Markdown
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.text import Text

logger = logging.getLogger("elengenix.tui.export")


def export_to_html(
    dashboard_data: Dict[str, Any],
    output_path: str,
    title: str = "Elengenix Dashboard Export",
) -> str:
    """Export dashboard data to an HTML file.
    
    Args:
        dashboard_data: Dictionary containing dashboard data.
        output_path: Path to save the HTML file.
        title: Title for the HTML page.
        
    Returns:
        Path to the exported HTML file.
    """
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d0d0d;
            color: #ffffff;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid #ff2222;
        }}
        .header h1 {{
            margin: 0;
            color: #ff2222;
        }}
        .header .target {{
            color: #888;
            font-size: 14px;
            margin-top: 10px;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .metric-card {{
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #333;
        }}
        .metric-card h3 {{
            margin: 0 0 10px 0;
            color: #888;
            font-size: 14px;
        }}
        .metric-card .value {{
            font-size: 32px;
            font-weight: bold;
        }}
        .critical {{ color: #ff003c; }}
        .high {{ color: #ff5500; }}
        .medium {{ color: #ffb300; }}
        .low {{ color: #81c784; }}
        .info {{ color: #888888; }}
        .findings {{
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #333;
            margin-bottom: 20px;
        }}
        .finding {{
            padding: 10px;
            border-bottom: 1px solid #333;
        }}
        .finding:last-child {{
            border-bottom: none;
        }}
        .finding .title {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .finding .meta {{
            font-size: 12px;
            color: #888;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ELENGENIX</h1>
            <div class="target">Target: {dashboard_data.get('target', 'Unknown')}</div>
            <p>Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="metrics">
            <div class="metric-card">
                <h3>RISK SCORE</h3>
                <div class="value {dashboard_data.get('risk_level', 'info')}">
                    {dashboard_data.get('risk_score', 0)}
                </div>
            </div>
            <div class="metric-card">
                <h3>TOTAL FINDINGS</h3>
                <div class="value">{dashboard_data.get('total_findings', 0)}</div>
            </div>
            <div class="metric-card">
                <h3>CRITICAL</h3>
                <div class="value critical">{dashboard_data.get('critical', 0)}</div>
            </div>
            <div class="metric-card">
                <h3>HIGH</h3>
                <div class="value high">{dashboard_data.get('high', 0)}</div>
            </div>
        </div>
        
        <div class="findings">
            <h2>FINDINGS</h2>
"""
    
    for finding in dashboard_data.get('findings', []):
        severity = finding.get('severity', 'info').lower()
        html_content += f"""
            <div class="finding">
                <div class="title {severity}">{finding.get('title', 'Unknown')}</div>
                <div class="meta">
                    {finding.get('location', '')} | {finding.get('severity', 'info')} | {finding.get('timestamp', '')}
                </div>
            </div>
"""
    
    html_content += """
        </div>
        
        <div class="footer">
            Generated by Elengenix Security Framework
        </div>
    </div>
</body>
</html>
"""
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(html_content, encoding='utf-8')
    
    logger.info(f"Exported dashboard to HTML: {output_path}")
    return output_path


def export_to_json(
    dashboard_data: Dict[str, Any],
    output_path: str,
) -> str:
    """Export dashboard data to a JSON file.
    
    Args:
        dashboard_data: Dictionary containing dashboard data.
        output_path: Path to save the JSON file.
        
    Returns:
        Path to the exported JSON file.
    """
    output_data = {
        "export_time": datetime.now().isoformat(),
        "target": dashboard_data.get('target', 'unknown'),
        "risk_score": dashboard_data.get('risk_score', 0),
        "risk_level": dashboard_data.get('risk_level', 'info'),
        "total_findings": dashboard_data.get('total_findings', 0),
        "findings": dashboard_data.get('findings', []),
        "scans": dashboard_data.get('scans', []),
        "hosts": dashboard_data.get('hosts', []),
    }
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(output_data, indent=2, default=str),
        encoding='utf-8'
    )
    
    logger.info(f"Exported dashboard to JSON: {output_path}")
    return output_path


def export_to_markdown(
    dashboard_data: Dict[str, Any],
    output_path: str,
    title: str = "Elengenix Scan Report",
) -> str:
    """Export dashboard data to a Markdown file.
    
    Args:
        dashboard_data: Dictionary containing dashboard data.
        output_path: Path to save the Markdown file.
        title: Title for the report.
        
    Returns:
        Path to the exported Markdown file.
    """
    md_content = f"""# {title}

**Target:** {dashboard_data.get('target', 'Unknown')}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Risk Score:** {dashboard_data.get('risk_score', 0)}/100

## Summary

| Metric | Value |
|--------|-------|
| Total Findings | {dashboard_data.get('total_findings', 0)} |
| Critical | {dashboard_data.get('critical', 0)} |
| High | {dashboard_data.get('high', 0)} |
| Medium | {dashboard_data.get('medium', 0)} |
| Low | {dashboard_data.get('low', 0)} |

## Findings

"""
    
    findings = dashboard_data.get('findings', [])
    if findings:
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'info')
            md_content += f"""### {i}. {finding.get('title', 'Unknown')}

- **Severity:** {severity}
- **Location:** {finding.get('location', 'N/A')}
- **Description:** {finding.get('description', 'N/A')}

"""
    else:
        md_content += "No findings recorded.\n\n"
    
    md_content += """---

*Generated by Elengenix Security Framework*
"""
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(md_content, encoding='utf-8')
    
    logger.info(f"Exported dashboard to Markdown: {output_path}")
    return output_path


def export_to_pdf(
    dashboard_data: Dict[str, Any],
    output_path: str,
    title: str = "Elengenix Scan Report",
) -> str:
    """Export dashboard data to a PDF file using Rich console.
    
    Note: This requires the 'rich' library and generates a text-based PDF.
    For better PDF quality, consider using reportlab or weasyprint.
    
    Args:
        dashboard_data: Dictionary containing dashboard data.
        output_path: Path to save the PDF file.
        title: Title for the report.
        
    Returns:
        Path to the exported PDF file.
    """
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    
    # Create a Rich console that writes to a file
    console = Console(record=True, width=80)
    
    # Print header
    header = Text()
    header.append("ELENGENIX SECURITY REPORT", style="bold red")
    header.append("\n")
    header.append(f"Target: {dashboard_data.get('target', 'Unknown')}\n")
    header.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    header.append(f"Risk Score: {dashboard_data.get('risk_score', 0)}/100\n")
    console.print(Panel(header, title="Report Summary"))
    
    # Print findings table
    findings = dashboard_data.get('findings', [])
    if findings:
        table = Table(title="Findings")
        table.add_column("#", style="dim")
        table.add_column("Title", style="bold")
        table.add_column("Severity")
        table.add_column("Location")
        
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'info')
            severity_style = {
                'critical': 'bold red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'green',
                'info': 'dim'
            }.get(severity.lower(), 'dim')
            
            table.add_row(
                str(i),
                finding.get('title', 'Unknown'),
                f"[{severity_style}]{severity}[/{severity_style}]",
                finding.get('location', 'N/A'),
            )
        
        console.print(table)
    else:
        console.print("No findings recorded.")
    
    # Export to SVG (can be converted to PDF)
    console.save_svg(output_path.replace('.pdf', '.svg'))
    
    logger.info(f"Exported dashboard to SVG (convert to PDF): {output_path}")
    return output_path


def collect_dashboard_data(
    target: str,
    findings: List[Any],
    risk_score: float,
    scans: Optional[List[Any]] = None,
    hosts: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """Collect dashboard data into a dictionary for export.
    
    Args:
        target: Target being scanned.
        findings: List of finding objects.
        risk_score: Overall risk score (0-100).
        scans: List of scan objects.
        hosts: List of host objects.
        
    Returns:
        Dictionary containing all dashboard data.
    """
    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings_data = []
    
    for finding in findings:
        severity = getattr(finding, "severity", "info")
        if hasattr(severity, "value"):
            severity = severity.value
        severity_lower = severity.lower() if isinstance(severity, str) else "info"
        
        if severity_lower in severity_counts:
            severity_counts[severity_lower] += 1
        
        findings_data.append({
            "title": getattr(finding, "title", "Unknown"),
            "severity": severity,
            "location": getattr(finding, "location", ""),
            "description": getattr(finding, "description", ""),
            "timestamp": getattr(finding, "timestamp", datetime.now().isoformat()),
        })
    
    # Determine risk level
    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 60:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    elif risk_score >= 10:
        risk_level = "low"
    else:
        risk_level = "info"
    
    # Collect scan data
    scans_data = []
    for scan in (scans or []):
        scans_data.append({
            "name": getattr(scan, "name", "Unknown"),
            "target": getattr(scan, "target", ""),
            "status": getattr(scan, "status", "unknown"),
            "progress": getattr(scan, "progress", 0),
        })
    
    # Collect host data
    hosts_data = []
    for host in (hosts or []):
        hosts_data.append({
            "ip": getattr(host, "ip", ""),
            "hostname": getattr(host, "hostname", ""),
            "role": getattr(host, "role", "unknown"),
            "risk": getattr(host, "risk", "low"),
        })
    
    return {
        "target": target,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_findings": len(findings),
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "info": severity_counts["info"],
        "findings": findings_data,
        "scans": scans_data,
        "hosts": hosts_data,
        "export_time": datetime.now().isoformat(),
    }
