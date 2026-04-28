"""
tools/omni_scan.py — Elengenix Full-Scale Scan Entry Point (v3.0.0)
- Coordinates the complete hunting pipeline with Tool Registry
- Enhanced with CVSS scoring and new tool integrations
- recon → port scan → live-check → vuln-scan → secrets → fuzzing → report
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Any

# Safe import for nest_asyncio (for async compatibility)
try:
 import nest_asyncio
 nest_asyncio.apply()
except ImportError:
 pass # nest_asyncio not available, but not critical for omni_scan

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

# Make sure project root is on sys.path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
 sys.path.insert(0, str(project_root))

from bot_utils import send_telegram_notification
from orchestrator import run_standard_scan, is_in_scope, normalize_target
from tools.tool_registry import registry, ToolResult
from tools.cvss_calculator import CVSSCalculator, Severity
from tools.reporter import generate_bug_report
from tools.html_reporter import generate_html_report

logger = logging.getLogger("elengenix.omni_scan")
console = Console()

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")

def sanitize_target(target: str) -> str:
 """Strips protocol/path and validates the hostname."""
 clean = re.sub(r"^https?://", "", target).split("/")[0].split("?")[0].lower()
 if not _DOMAIN_RE.match(clean):
 raise ValueError(f"Invalid target format: {target!r}")
 return clean

def run_omni_scan(
 target: str, 
 rate_limit: int = 5,
 use_new_tools: bool = True,
 enable_cvss: bool = True
) -> None:
 """
 CLI entry point. Runs the full pipeline synchronously (wraps async).
 
 Args:
 target: Target domain or IP
 rate_limit: Max concurrent operations
 use_new_tools: Enable new Tool Registry tools (dalfox, arjun, etc.)
 enable_cvss: Calculate CVSS scores for findings
 """
 try:
 safe_target = sanitize_target(target)
 except ValueError as e:
 console.print(f"[bold red] Security Error: {e}[/bold red]")
 return

 if not is_in_scope(safe_target):
 console.print(
 f"[bold red] SCOPE VIOLATION: '{safe_target}' is not in the authorized scope.[/bold red]"
 )
 return

 # Check available tools
 available_tools = registry.list_available_tools()
 tool_count = sum(1 for info in available_tools.values() if info["available"])
 
 console.print(Panel(
 f"[bold red] ELENGENIX FULL-SCALE MISSION v3.0[/bold red]\n"
 f" Target: [cyan]{safe_target}[/cyan]\n"
 f" Tools Available: {tool_count}/{len(available_tools)}\n"
 f" Rate Limit: {rate_limit} concurrent | CVSS: {'' if enable_cvss else ''}",
 border_style="red",
 ))
 
 if tool_count == 0:
 console.print("[yellow] Warning: No tools available. Install required binaries.[/yellow]")
 console.print("[dim]Run: elengenix doctor[/dim]")
 
 send_telegram_notification(f" Full scan v3.0 initiated: `{safe_target}`")

 with Progress(
 SpinnerColumn(),
 TextColumn("[bold cyan]{task.description}"),
 BarColumn(),
 console=console,
 transient=True,
 ) as progress:
 task = progress.add_task("Running pipeline...", total=None)

 try:
 # Use updated orchestrator with registry support
 report_dir = asyncio.run(
 run_standard_scan(
 safe_target, 
 rate_limit=rate_limit,
 use_registry=use_new_tools
 )
 )
 progress.update(task, description="Processing results...")
 except Exception as e:
 logger.exception(f"Pipeline failed: {e}")
 console.print(f"[bold red] Pipeline error: {e}[/bold red]")
 return

 if not report_dir:
 console.print("[bold yellow] Scan returned no report directory.[/bold yellow]")
 return

 progress.update(task, description="Generating reports...")
 
 # Load and process findings from registry results
 findings = _load_registry_findings(report_dir)
 
 # Calculate CVSS if enabled
 cvss_scores = {}
 if enable_cvss and findings:
 cvss_calc = CVSSCalculator(use_ai=True)
 for i, finding in enumerate(findings):
 score = cvss_calc.from_finding(
 finding.get("type", "unknown"),
 finding.get("url", safe_target),
 finding.get("evidence", str(finding.get("details", "")))
 )
 cvss_scores[i] = score
 
 # Update findings with CVSS
 for i, finding in enumerate(findings):
 if i in cvss_scores:
 finding["cvss_score"] = cvss_scores[i].base_score
 finding["cvss_severity"] = (cvss_scores[i].adjusted_severity or cvss_scores[i].severity).value
 finding["cvss_vector"] = cvss_scores[i].vector_string

 # Generate reports
 report_path = os.path.join(report_dir, "professional_report.md")
 html_path = os.path.join(report_dir, "dashboard.html")
 json_path = os.path.join(report_dir, "findings.json")

 # Save JSON findings
 with open(json_path, "w") as f:
 json.dump({
 "target": safe_target,
 "findings_count": len(findings),
 "findings": findings,
 "cvss_enabled": enable_cvss,
 }, f, indent=2)

 generate_bug_report(safe_target, findings, report_path)
 generate_html_report(safe_target, findings, html_path)

 # Print findings summary
 _print_findings_table(findings)

 console.print(Panel(
 f"[bold green] MISSION COMPLETE[/bold green]\n"
 f" Reports: [cyan]{report_dir}[/cyan]\n"
 f" Markdown: {report_path}\n"
 f" Dashboard: {html_path}\n"
 f" JSON Data: {json_path}",
 border_style="green",
 ))
 
 # Send detailed notification
 critical_count = len([f for f in findings if f.get("cvss_severity", "").upper() == "CRITICAL"])
 high_count = len([f for f in findings if f.get("cvss_severity", "").upper() == "HIGH"])
 
 notification = f" Scan complete: `{safe_target}`\n"
 notification += f" Findings: {len(findings)} total"
 if critical_count > 0:
 notification += f"\n CRITICAL: {critical_count}"
 if high_count > 0:
 notification += f"\n HIGH: {high_count}"
 
 send_telegram_notification(notification)

def _load_registry_findings(report_dir: Path) -> List[Dict[str, Any]]:
 """Load findings from all tool registry results."""
 findings = []
 
 # Load from cvss_scores.json if exists (new format)
 cvss_file = report_dir / "cvss_scores.json"
 if cvss_file.exists():
 try:
 data = json.loads(cvss_file.read_text())
 for item in data:
 finding = item.get("finding", {})
 finding["tool"] = item.get("tool", "unknown")
 finding["cvss_score"] = item.get("cvss_score", 0)
 finding["cvss_severity"] = item.get("severity", "Unknown")
 finding["cvss_vector"] = item.get("vector", "")
 findings.append(finding)
 return findings
 except Exception as e:
 logger.warning(f"Failed to load CVSS results: {e}")
 
 # Fallback: Parse individual tool outputs
 tool_files = {
 "nuclei": "nuclei_results.json",
 "dalfox": "dalfox_results.json",
 "trufflehog": "trufflehog_results.json",
 }
 
 for tool_name, filename in tool_files.items():
 file_path = report_dir / filename
 if file_path.exists():
 try:
 content = file_path.read_text()
 for line in content.strip().split('\n'):
 if line:
 try:
 data = json.loads(line)
 data["tool"] = tool_name
 findings.append(data)
 except json.JSONDecodeError:
 pass
 except Exception as e:
 logger.warning(f"Failed to parse {filename}: {e}")
 
 return findings

def _print_findings_table(findings: List[Dict[str, Any]]) -> None:
 """Print a formatted table of findings."""
 if not findings:
 console.print("[dim]ℹ No findings detected.[/dim]")
 return
 
 table = Table(title=f"\n Findings Summary ({len(findings)} total)")
 table.add_column("Severity", style="bold", width=12)
 table.add_column("Type", width=20)
 table.add_column("Tool", width=12)
 table.add_column("CVSS", justify="right", width=6)
 table.add_column("URL/Details", width=50)
 
 # Sort by severity
 severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 5}
 sorted_findings = sorted(
 findings,
 key=lambda x: severity_order.get(x.get("cvss_severity", x.get("severity", "Unknown")).capitalize(), 5)
 )
 
 for finding in sorted_findings:
 severity = finding.get("cvss_severity", finding.get("severity", "Unknown")).capitalize()
 finding_type = finding.get("type", "unknown")
 tool = finding.get("tool", "unknown")
 cvss = finding.get("cvss_score", "N/A")
 cvss_str = f"{cvss}" if isinstance(cvss, (int, float)) else str(cvss)
 
 # Truncate URL/details
 details = finding.get("url", finding.get("details", ""))
 if len(details) > 47:
 details = details[:44] + "..."
 
 # Color by severity
 severity_style = {
 "Critical": "red",
 "High": "orange3",
 "Medium": "yellow",
 "Low": "green",
 "Info": "blue",
 }.get(severity, "white")
 
 table.add_row(
 f"[{severity_style}]{severity}[/{severity_style}]",
 finding_type,
 tool,
 cvss_str,
 details
 )
 
 console.print(table)

def _parse_nuclei_findings(findings_file: str) -> list:
 """Legacy: Parse nuclei output into structured finding dicts."""
 findings = []
 if not os.path.exists(findings_file):
 return findings
 try:
 with open(findings_file, "r", encoding="utf-8") as f:
 for line in f:
 line = line.strip()
 if not line:
 continue
 m = re.match(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)", line)
 if m:
 findings.append({
 "name": m.group(1),
 "severity": m.group(2).upper(),
 "url": m.group(3),
 "details": line,
 "tool": "nuclei",
 })
 else:
 findings.append({"name": line[:80], "severity": "INFO", "url": "-", "details": line, "tool": "nuclei"})
 except Exception as e:
 logger.warning(f"Could not parse findings: {e}")
 return findings

def list_available_tools() -> None:
 """Print list of available tools from registry."""
 tools = registry.list_available_tools()
 
 table = Table(title=" Registered Security Tools")
 table.add_column("Tool", style="bold cyan")
 table.add_column("Category", style="dim")
 table.add_column("Available", justify="center")
 table.add_column("Description")
 
 for name, info in sorted(tools.items()):
 available = "[green][/green]" if info["available"] else "[red][/red]"
 table.add_row(name, info["category"], available, info["description"][:50])
 
 console.print(table)
 console.print(f"\n[dim]Total: {len(tools)} tools | Available: {sum(1 for i in tools.values() if i['available'])}[/dim]")

if __name__ == "__main__":
 if len(sys.argv) < 2:
 console.print("[yellow]Usage: python omni_scan.py <target> [--list-tools][/yellow]")
 console.print("[dim]Example: python omni_scan.py example.com[/dim]")
 sys.exit(1)
 
 if sys.argv[1] == "--list-tools":
 list_available_tools()
 else:
 run_omni_scan(sys.argv[1])
