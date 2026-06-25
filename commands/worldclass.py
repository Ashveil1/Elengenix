"""
commands/worldclass.py — World-class security commands for Elengenix.

Registers commands that expose the flagship engines:
    - zero-day      : advanced zero-day heuristic probing
    - logic         : business logic vulnerability engine
    - supply-chain  : SBOM + CVE + typosquatting + dep-confusion analyzer
    - hypothesis    : AI-driven attack hypothesis generation
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

from commands.registry import command, CommandRegistry


def _console():
    from ui_components import console
    return console


def _show_section(title: str) -> None:
    from ui_components import show_section
    show_section(title)


def _print(msg: str) -> None:
    from ui_components import print_info
    print_info(msg)


def _ok(msg: str) -> None:
    from ui_components import print_success
    print_success(msg)


def _err(msg: str) -> None:
    from ui_components import print_error
    print_error(msg)


# ═══════════════════════════════════════════════════════════════════════════
# LAUNCH COMMAND — TUI dashboard
# ═══════════════════════════════════════════════════════════════════════════

@command(
    name="launch",
    category="world-class",
    aliases=["ui"],
    help_text="Launch TUI dashboard (themes: cyberpunk/matrix/synthwave)",
    examples=[
        "elengenix launch",
        "elengenix launch example.com --theme cyberpunk",
    ],
)
async def cmd_launch(args) -> int:
    """Launch themed TUI dashboard."""
    target = getattr(args, "target", "") or ""
    theme = getattr(args, "theme", "DEFAULT") or "DEFAULT"

    try:
        from tui.hunt_view import run_launcher
    except ImportError as e:
        _err(f"Cannot load TUI launcher: {e}")
        return 1

    if theme and theme != "DEFAULT":
        theme = theme.upper()

    try:
        run_launcher(target, theme_name=theme)
        return 0
    except Exception as e:
        _err(f"Launcher failed: {e}")
        return 1


# ═══════════════════════════════════════════════════════════════════════════
# HUNT COMMAND — main scanner
# ═══════════════════════════════════════════════════════════════════════════

@command(
    name="hunt",
    category="world-class",
    aliases=["h", "scan-all", "find"],
    help_text="ONE command to find every vulnerability: recon + smart + zero-day + logic",
    requires_target=True,
    examples=[
        "elengenix hunt example.com",
        "elengenix hunt httpbin.org --quiet",
        "elengenix h https://target.com",
    ],
)
async def cmd_hunt(args) -> int:
    """Single unified hunt command — runs EVERY engine in optimal order.

    Phases:
        1. RECON         — endpoint discovery, technology detection
        2. SMART         — BOLA, WAF, fuzzing, injection
        3. ZERO-DAY      — 10 detection classes (JWT, SSTI, deserialization, ...)
        4. LOGIC         — 9 business-logic classes (price, race, state, auth, ...)
        5. CORRELATION   — chain findings, score impact

    Produces one unified report at reports/hunt_<target>_<timestamp>/
    """
    target = args.target
    quiet = getattr(args, "quiet", False)

    _show_section(f"Elengenix HUNT — {target}")

    try:
        from tools.hunt_engine import HuntEngine, report_to_console, save_report
    except ImportError as e:
        _err(f"Cannot load hunt engine: {e}")
        return 1

    engine = HuntEngine(target=target, quiet=quiet)
    try:
        report = await engine.hunt()
    except Exception as e:
        _err(f"Hunt failed: {e}")
        logger = __import__("logging").getLogger("elengenix.cmd")
        logger.exception("hunt failed")
        return 1

    # Print the unified report
    c = _console()
    c.print(report_to_console(report))

    # Save
    out_dir = save_report(report)
    _ok(f"Report saved: {out_dir}")

    # Show top LIVE findings (exclude static candidates + informational)
    live_critical = [f for f in report.findings
                     if f.severity in ("Critical", "High")
                     and "CANDIDATE" not in f.title.upper()
                     and "not tested" not in f.title.lower()
                     and (f.url or f.details)]
    if live_critical:
        c.print()
        c.print("  [bold]HIGHLIGHTED LIVE FINDINGS[/bold]")
        c.print("  " + "-" * 66)
        for f in live_critical[:3]:
            c.print(f"  [{f.severity}] [bold]{f.title}[/bold]")
            if f.details:
                c.print(f"      {f.details[:120]}")
    elif not report.findings or all(
        "CANDIDATE" in f.title.upper() or f.severity == "Informational"
        for f in report.findings
    ):
        # Be honest when no real vulnerabilities were found
        c.print()
        c.print("  >> RESULT: No live vulnerabilities detected.")
        c.print("  Static forgery candidates (if any) require manual")
        c.print("  verification against a real JWT-protected endpoint.")

    if report.chains:
        c.print()
        c.print(f"  [bold][CHAIN][/bold] {len(report.chains)} vulnerability chain(s) detected:")
        for ch in report.chains[:3]:
            c.print(f"      - {ch.get('chain_type', 'unknown')}")

    # NEW: Render integrated TUI dashboard with hunt results
    try:
        theme = getattr(args, "theme", "DEFAULT") or "DEFAULT"
        if theme and theme != "DEFAULT":
            theme = theme.upper()
        from tui.hunt_view import show_hunt_results
        c.print()
        c.print(f"  [bold]Rendering TUI dashboard (theme: {theme})...[/bold]")
        c.print()
        show_hunt_results(target, report, theme_name=theme)
    except Exception as e:
        logger = __import__("logging").getLogger("elengenix.cmd")
        logger.debug("TUI hunt view failed: %s", e)

    return 0
