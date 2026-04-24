"""
tools/omni_scan.py — Elengenix Full-Scale Scan Entry Point (v2.0.0)
Coordinates the complete hunting pipeline:
  recon → live-check → crawl → vuln-scan → JS analysis → API discovery → report
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

# Make sure project root is on sys.path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from bot_utils import send_telegram_notification
from orchestrator import run_standard_scan, is_in_scope, normalize_target
from tools.reporter import generate_bug_report
from tools.html_reporter import generate_html_report

logger  = logging.getLogger("elengenix.omni_scan")
console = Console()

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")


def sanitize_target(target: str) -> str:
    """Strips protocol/path and validates the hostname."""
    clean = re.sub(r"^https?://", "", target).split("/")[0].split("?")[0].lower()
    if not _DOMAIN_RE.match(clean):
        raise ValueError(f"Invalid target format: {target!r}")
    return clean


def run_omni_scan(target: str, rate_limit: int = 5) -> None:
    """
    CLI entry point. Runs the full pipeline synchronously (wraps async).
    """
    try:
        safe_target = sanitize_target(target)
    except ValueError as e:
        console.print(f"[bold red]❌ Security Error: {e}[/bold red]")
        return

    if not is_in_scope(safe_target):
        console.print(
            f"[bold red]❌ SCOPE VIOLATION: '{safe_target}' is not in the authorized scope.[/bold red]"
        )
        return

    console.print(Panel(
        f"[bold red]⚔️  ELENGENIX FULL-SCALE MISSION: {safe_target}[/bold red]\n"
        f"[dim]Rate limit: {rate_limit} concurrent tools[/dim]",
        border_style="red",
    ))
    send_telegram_notification(f"⚔️ Full scan initiated: `{safe_target}`")

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Running pipeline...", total=None)

        try:
            report_dir = asyncio.run(
                run_standard_scan(safe_target, rate_limit=rate_limit)
            )
        except Exception as e:
            logger.exception(f"Pipeline failed: {e}")
            console.print(f"[bold red]❌ Pipeline error: {e}[/bold red]")
            return

        progress.update(task, description="Generating reports...")

    if not report_dir:
        console.print("[bold yellow]⚠️  Scan returned no report directory.[/bold yellow]")
        return

    # Generate Markdown + HTML reports
    report_path = os.path.join(report_dir, "professional_report.md")
    html_path   = os.path.join(report_dir, "dashboard.html")

    # Parse findings from nuclei output if available
    findings = _parse_nuclei_findings(os.path.join(report_dir, "findings.txt"))

    generate_bug_report(safe_target, findings, report_path)
    generate_html_report(safe_target, findings, html_path)

    console.print(Panel(
        f"[bold green]✅ MISSION COMPLETE[/bold green]\n"
        f"📁 Reports: [cyan]{report_dir}[/cyan]\n"
        f"📄 Markdown: {report_path}\n"
        f"🌐 Dashboard: {html_path}",
        border_style="green",
    ))
    send_telegram_notification(
        f"✅ Full scan complete: `{safe_target}`\n📁 Reports saved."
    )


def _parse_nuclei_findings(findings_file: str) -> list:
    """Parse nuclei output into structured finding dicts."""
    findings = []
    if not os.path.exists(findings_file):
        return findings
    try:
        with open(findings_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # nuclei format: [template-id] [severity] url [matcher]
                m = re.match(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)", line)
                if m:
                    findings.append({
                        "name":     m.group(1),
                        "severity": m.group(2).upper(),
                        "url":      m.group(3),
                        "details":  line,
                    })
                else:
                    findings.append({"name": line[:80], "severity": "INFO", "url": "-", "details": line})
    except Exception as e:
        logger.warning(f"Could not parse findings: {e}")
    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[yellow]Usage: python omni_scan.py <target>[/yellow]")
        sys.exit(1)
    run_omni_scan(sys.argv[1])
