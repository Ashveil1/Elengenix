"""commands/scan.py — Scan Command Handler (Unified → True AI Agent)

Replaces the old script-driven scan pipeline with a VulnAgent-based
autonomous vulnerability scanning agent. Every scan path — full, phase,
interactive — now delegates to the AI agent which reasons about what
tools to use, in what order, and how to pivot.

Usage:
    elengenix scan <target>                    — Full VulnAgent scan
    elengenix scan <target> --phase recon      — (redirected: AI decides phases)
    elengenix scan --interactive bola <url>    — (redirected: AI-driven)
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from elengenix.paths import get_reports_path
from typing import Any, Dict

from cli.ui_components import console, print_error, print_info, print_success, prompt_target

logger = logging.getLogger("elengenix.commands.scan")

# Available phases (for compat / help display — all now handled by AI)
AVAILABLE_PHASES = ["recon", "waf", "fuzz", "bola", "learn", "coverage"]
INTERACTIVE_MODES = ["bola", "waf", "recon"]


def handle_scan(args) -> int:
    """Handle the scan command — all variants delegate to VulnAgent.

    Args:
        args: Parsed command arguments.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    from main import require_authorized_scan_target

    phase = getattr(args, "phase", None)
    interactive_mode = getattr(args, "interactive", None)

    target = args.target or prompt_target()
    if not target:
        return 1

    if not require_authorized_scan_target(target):
        return 1

    # If phase or interactive mode given, print redirect notice
    if phase:
        # AI agent is smart enough to pick the right tools
        pass

    return _vulnagent_scan(target, phase=phase, interactive=interactive_mode, args=args)


def _vulnagent_scan(
    target: str,
    phase: str | None = None,
    interactive: str | None = None,
    args: Any = None,
) -> int:
    """Run a full autonomous vulnerability hunt using VulnAgent.

    This is the TRUE AI agent path — no script chains, no locked phases,
    no forced ordering. The AI reasons, pivots, and uses its 25 tools
    as it sees fit.
    """
    console.print("")
    console.print("[bold #ffffff]  ELENGENIX AI SCAN 1.0.0[/bold #ffffff]")
    console.print(f"  Target: [red]{target}[/red]")
    if phase:
        console.print(f"  Mode: [dim]AI-driven phase: {phase} (AI selects tools)[/dim]")
    if interactive:
        console.print(f"  Mode: [dim]AI-driven interactive: {interactive}[/dim]")
    console.print("")

    # ── Start MCP server in background ──
    try:
        from commands.mcp_runner import start_mcp_if_enabled

        start_mcp_if_enabled()
    except Exception:
        pass

    # ── Build AI agent mission ──
    from elengenix.agent import VulnAgent
    from elengenix.agent.memory import AgentMemory
    from tools.universal_ai_client import create_default_client

    memory = AgentMemory()
    client = create_default_client()
    agent = VulnAgent(target=target, client=client, memory=memory)

    print_info("Starting AI-driven vulnerability scan...")
    print_info(f"Target: {target}")
    if memory._vector:
        print_info("Cross-session memory: ACTIVE")
    console.print("")

    # Build mission prompt
    if interactive:
        mission = (
            f"Perform interactive {interactive} testing on {target}. "
            f"Use your full toolset — probe, analyze, think, pivot freely. "
            f"Focus on {interactive}-related vulnerabilities but don't be limited by it."
        )
    elif phase:
        mission = (
            f"Scan {target} for vulnerabilities. "
            f"The user requested a focus on {phase}-related checks, "
            f"but use your judgment — examine all angles and pivot as needed."
        )
    else:
        mission = (
            f"Perform a comprehensive security assessment of {target}. "
            f"You have 25 tools at your disposal — use them intelligently. "
            f"Start with reconnaissance, then probe for vulnerabilities, "
            f"and escalate as you find footholds. Document everything."
        )

    # ── Run VulnAgent ──
    try:
        report = agent.hunt()
        report_text = report.render()

        print_success("Scan complete!")
        console.print(report_text)

        # Save report
        safe_name = re.sub(r"[^a-zA-Z0-9.-]", "_", target)[:40]
        report_path = get_reports_path(f"scan_{safe_name}_{int(time.time())}.md")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report_text)
        print_info(f"Full report: {report_path}")

        return 0
    except KeyboardInterrupt:
        print_info("Scan interrupted by user")
        return 1
    except Exception as e:
        print_error(f"Scan error: {e}")
        return 1
