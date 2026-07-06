"""
commands/scan.py — Scan Command Handler (Unified)
Handles all scan-related commands with phase filtering.

Usage:
    elengenix scan <target>                  — Full auto scan
    elengenix scan <target> --phase recon    — Recon only
    elengenix scan <target> --phase waf      — WAF detection only
    elengenix scan <target> --phase bola     — BOLA testing only
    elengenix scan <target> --phase fuzz     — Fuzzing only
    elengenix scan --interactive bola <url>  — Interactive BOLA (advanced)
    elengenix scan --interactive waf <url>   — Interactive WAF bypass (advanced)
    elengenix scan --interactive recon <url> — Interactive recon (advanced)
"""

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from cli.ui_components import console, prompt_target

# Available phases for --phase flag
AVAILABLE_PHASES = ["recon", "waf", "fuzz", "bola", "learn", "coverage"]

# Interactive mode commands (advanced tools)
INTERACTIVE_MODES = ["bola", "waf", "recon"]


def handle_scan(args) -> int:
    """Handle the scan command.

    Supports both auto mode (default) and interactive mode.

    Args:
        args: Parsed command arguments.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    # Check for interactive mode
    interactive_mode = getattr(args, "interactive", None)
    if interactive_mode:
        return _handle_interactive_scan(args, interactive_mode)

    # Check for phase-specific scan
    phase = getattr(args, "phase", None)
    if phase:
        return _handle_phase_scan(args, phase)

    # Default: full auto scan
    return _handle_full_scan(args)


def _handle_full_scan(args) -> int:
    """Run the full automated scan pipeline."""
    from shutil import which

    from core.agent import get_agent
    from main import require_authorized_scan_target

    # Start MCP server if enabled
    try:
        from mcp.manager import start_mcp
        start_mcp()
    except Exception:
        pass

    # Register cleanup for MCP server
    import atexit
    try:
        from mcp.manager import stop_mcp
        atexit.register(stop_mcp)
    except Exception:
        pass

    # Silence INFO logs during scan
    logging.getLogger().setLevel(logging.WARNING)

    target = args.target or prompt_target()
    if not target:
        return 1

    if not require_authorized_scan_target(target):
        return 1

    env_models = [m.strip() for m in os.environ.get("ACTIVE_MODELS", "").split(",") if m.strip()]
    team_size = len(env_models)

    print()
    console.print("\n[bold #ffffff]  ELENGENIX AI SCAN 1.0.0[/bold #ffffff]")
    console.print(f"  Target: [red]{target}[/red]")
    if team_size >= 2:
        console.print(f"  Team: [red]{team_size} agents[/red]")
    print()

    # Phase 0: Pre-flight
    console.print("[bold #ffffff]Phase 0: Elengenix Framework Pre-flight[/bold #ffffff]")

    subdomain_hint = ""
    preflight_findings = []
    preflight_file = None
    try:
        from core.orchestrator import run_elengenix_modules

        preflight_dir = Path(f"reports/preflight_{target.replace('/', '_')}_{int(time.time())}")
        preflight_dir.mkdir(parents=True, exist_ok=True)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            preflight_findings = loop.run_until_complete(
                asyncio.wait_for(
                    run_elengenix_modules(target, preflight_dir, timeout=90), timeout=110
                )
            )
        finally:
            loop.close()
        if preflight_findings:
            preflight_file = preflight_dir / "elengenix_findings.json"
            preflight_file.write_text(json.dumps(preflight_findings, indent=2, default=str))
            console.print(
                f"  [OK] Pre-flight: {len(preflight_findings)} findings saved to {preflight_file}"
            )
            finding_summary = "\n".join(
                f"  - [{f.get('severity', '?')}] {f.get('type', '?')}: {f.get('title', '?')[:80]}"
                for f in preflight_findings[:20]
            )
            subdomain_hint += f"\nPre-flight Elengenix framework findings ({len(preflight_findings)} total):\n{finding_summary}\n"
        else:
            console.print("  [dim]Pre-flight: 0 findings (target may be down or unreachable)[/dim]")
    except Exception as e:
        console.print(f"  [WARN] Pre-flight failed: {e}")

    # Phase 1: AI-driven reconnaissance
    console.print("[bold #ffffff]Phase 1: AI-Driven Reconnaissance[/bold #ffffff]")

    # Pre-seed subdomains via OTX
    initial_subs = set()
    try:
        from urllib.parse import urlparse

        from tools.wayback_tool import fetch_otx_urls

        urls = fetch_otx_urls(target)
        for u in urls:
            host = urlparse(u).hostname
            if host and host.endswith(f".{target.lstrip('www.')}"):
                initial_subs.add(host.lower())
        if initial_subs:
            console.print(f"  [dim][OTX] {len(initial_subs)} subdomains pre-seeded[/dim]")
            for s in sorted(initial_subs)[:5]:
                console.print(f"    {s}")
            if len(initial_subs) > 5:
                console.print(f"    ... +{len(initial_subs) - 5} more")
    except Exception:
        pass

    agent = get_agent()

    # Check available tools
    tool_map = {
        "curl": which("curl"),
        "dig": which("dig"),
        "jq": which("jq"),
        "python3": which("python3"),
    }
    avail_tools = [name for name, path in tool_map.items() if path]
    tools_context = f"\nAvailable tools on system: {', '.join(sorted(avail_tools))}\n"
    tools_context += "\nElengenix has built-in Python scanners for: SSRF, SSTI, XXE, Deserialization, GraphQL, Race Conditions, CORS, JWT, Business Logic, Supply Chain, API Schema Diff\n"

    def scan_callback(msg):
        import re

        try:
            safe_msg = re.sub(r"\[/?[^\]]+\]", "", msg)

            if msg.startswith("### AI THINKING:"):
                thought = msg.replace("### AI THINKING:", "").strip()
                console.print(f"\n[THINKING] {thought[:150]}")
            elif msg.startswith("[THINKING]"):
                console.print(f"  {msg[:150]}")
            elif "[RUN]" in msg or "[OK]" in msg or "[FAIL]" in msg:
                console.print(f"  {safe_msg[:200]}")
            else:
                console.print(f"  {safe_msg[:200]}")
        except Exception:
            console.print(f"  {msg[:200]}")

    # Run AI scan
    try:
        response = agent.process_universal(
            f"Perform a full security reconnaissance and vulnerability assessment on {target}. "
            "Your mission:\n"
            "- Use the built-in Python scanners (ssrf_scanner, ssti_scanner, xxe_scanner, etc.)\n"
            "- Use shell commands for DNS, HTTP requests, and network operations\n"
            f"{subdomain_hint}"
            f"{tools_context}"
            "TIPS:\n"
            "- Use curl for HTTP requests: curl -s https://target.com\n"
            "- Use dig for DNS: dig target.com ANY\n"
            "- Use Python for scripting: python3 -c 'import requests; ...'\n"
            "- You can use pipes (|) and redirects (>) in your shell commands\n"
            "- If a tool is missing, ask the user with ask_user action\n"
            "- Run actual tools, report results honestly. If something fails, try another approach.\n"
            "- IMPORTANT: Write temp files to current directory (./subdomains.txt) NOT /tmp\n",
            target=target,
            callback=scan_callback,
            mode="bug_bounty",
            preflight_findings=preflight_findings,
        )
        if response:
            import re

            safe_response = re.sub(r"\[/?[^\]]+\]", "", response[:2000])
            console.print("\nAI Analysis:")
            console.print(f"  {safe_response[:2000]}")
            report_file = Path(f"reports/scan_{target}_{int(time.time())}.md")
            report_file.parent.mkdir(parents=True, exist_ok=True)
            report_file.write_text(f"# Scan Report: {target}\n\n{response}", encoding="utf-8")
            console.print(f"\n[OK] Report saved: {report_file}")
            return 0
        else:
            console.print("[FAIL] No response from AI agent")
            return 1
    except Exception as e:
        console.print(f"[FAIL] Scan error: {e}")
        return 1


def _handle_phase_scan(args, phase: str) -> int:
    """Run a specific phase of the scan pipeline.

    Args:
        args: Parsed command arguments.
        phase: Phase to run (recon, waf, fuzz, bola, learn, coverage).

    Returns:
        Exit code (0 for success, 1 for error).
    """
    from main import require_authorized_scan_target

    if phase not in AVAILABLE_PHASES:
        console.print(f"[FAIL] Unknown phase: {phase}")
        console.print(f"[dim]Available phases: {', '.join(AVAILABLE_PHASES)}[/dim]")
        return 1

    target = args.target or prompt_target()
    if not target:
        return 1

    if not require_authorized_scan_target(target):
        return 1

    console.print(f"\n[bold #ffffff]  ELENGENIX {phase.upper()} SCAN[/bold #ffffff]")
    console.print(f"  Target: [red]{target}[/red]")
    console.print(f"  Phase: [red]{phase}[/red]\n")

    # Run only the specified phase
    try:
        from pipeline.phase_registry import Phase, PhaseContext, PhaseRegistry
        from pipeline.scope import ScopeManager

        # Validate scope
        sm = ScopeManager()
        if not sm.is_in_scope(target):
            console.print("[FAIL] Target not in scope")
            return 1

        # Create phase registry with only the requested phase
        from pipeline.unified import (
            _phase_bola,
            _phase_coverage,
            _phase_fuzz,
            _phase_learn,
            _phase_recon,
            _phase_waf,
        )

        registry = PhaseRegistry()
        phase_map = {
            "recon": (_phase_recon, []),
            "waf": (_phase_waf, []),
            "fuzz": (_phase_fuzz, ["recon"]),
            "bola": (_phase_bola, ["recon"]),
            "learn": (_phase_learn, []),
            "coverage": (_phase_coverage, []),
        }

        func, deps = phase_map[phase]
        registry.register(Phase(name=phase, func=func, deps=deps))

        # Create context
        normalized = sm.normalize_target(target)
        base_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        report_dir = Path("reports").resolve() / normalized.replace(".", "_")
        report_dir.mkdir(parents=True, exist_ok=True)

        ctx = PhaseContext(
            target=normalized,
            base_url=base_url,
            report_dir=report_dir,
            timeout=300,
        )

        # Run the phase
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(registry.run(ctx))
        finally:
            loop.close()

        # Report results
        for r in results:
            if r.success:
                console.print(f"[OK] {phase}: {len(r.findings)} findings")
                for f in r.findings[:10]:
                    console.print(f"  - [{f.get('severity', '?')}] {f.get('type', '?')}: {f.get('title', '?')[:60]}")
            else:
                console.print(f"[FAIL] {phase}: {r.error}")

        # Save findings
        if ctx.findings:
            findings_path = report_dir / f"{phase}_findings.json"
            findings_path.write_text(json.dumps(ctx.findings, indent=2, default=str))
            console.print(f"\n[OK] Findings saved: {findings_path}")

        return 0

    except Exception as e:
        console.print(f"[FAIL] Phase scan error: {e}")
        return 1


def _handle_interactive_scan(args, mode: str) -> int:
    """Run an interactive scan mode (advanced).

    Args:
        args: Parsed command arguments.
        mode: Interactive mode (bola, waf, recon).

    Returns:
        Exit code (0 for success, 1 for error).
    """
    if mode == "bola":
        return _run_interactive_bola(args)
    elif mode == "waf":
        return _run_interactive_waf(args)
    elif mode == "recon":
        return _run_interactive_recon(args)
    else:
        console.print(f"[FAIL] Unknown interactive mode: {mode}")
        console.print(f"[dim]Available modes: {', '.join(INTERACTIVE_MODES)}[/dim]")
        return 1


def _run_interactive_bola(args) -> int:
    """Run interactive BOLA/IDOR testing."""
    from tools.bola_harness import BOLAHarness, parse_headers_input
    from cli.ui_components import print_error, print_info, print_success, show_section

    from main import require_authorized_scan_target

    show_section("BOLA/IDOR Differential Harness")
    base_url = (
        args.target
        or console.input("[red]Base URL[/red] (e.g., https://target.tld): ").strip()
    )
    if not base_url:
        print_error("Base URL is required")
        return 1
    if not require_authorized_scan_target(base_url):
        return 1

    print_info("Paste headers for Account A (one per line: Header: value). Empty line to finish.")
    lines_a = []
    while True:
        line = console.input("").rstrip("\n")
        if not line.strip():
            break
        lines_a.append(line)

    print_info("Paste headers for Account B (one per line: Header: value). Empty line to finish.")
    lines_b = []
    while True:
        line = console.input("").rstrip("\n")
        if not line.strip():
            break
        lines_b.append(line)

    headers_a = parse_headers_input("\n".join(lines_a))
    headers_b = parse_headers_input("\n".join(lines_b))

    if not headers_a or not headers_b:
        print_error("Both Account A and Account B headers are required for differential testing")
        return 1

    harness = BOLAHarness(base_url=base_url, rate_limit_rps=max(0.5, float(args.rate_limit)))
    ids_a, ids_b, notes = harness.discover_identities(headers_a, headers_b)

    print_info("Optional: paste endpoint seeds to test (paths or full URLs). Empty line to finish.")
    seeds = []
    while True:
        line = console.input("").rstrip("\n")
        if not line.strip():
            break
        seeds.append(line.strip())

    common = harness.run_common_idor_checks(headers_a, headers_b, ids_a, ids_b)
    seeded = harness.run_seeded_checks(headers_a, headers_b, ids_a, ids_b, seeds)
    result_findings = (common.findings or []) + (seeded.findings or [])

    for n in notes:
        console.print(f"[dim]- {n}[/dim]")

    if not result_findings:
        print_info("No strong BOLA/IDOR signals detected.")
        return 0

    print_success(f"Potential issues: {len(result_findings)}")
    for i, f in enumerate(result_findings, 1):
        console.print(f"\n[bold red]{i}. {f.get('type', 'finding').upper()}[/bold red]")
        console.print(f"[white]{f.get('url', '')}[/white]")
    return 0


def _run_interactive_waf(args) -> int:
    """Run interactive WAF detection & bypass testing."""
    from tools.waf_evasion import WAFEvasionEngine
    from cli.ui_components import print_error, print_info, print_success, print_warning, show_section

    from main import require_authorized_scan_target

    show_section("WAF Detection & Evasion Testing")
    target_url = (
        args.target
        or console.input("[red]Target URL[/red] (e.g., https://target.tld/search): ").strip()
    )
    if not target_url:
        print_error("Target URL is required")
        return 1
    if not require_authorized_scan_target(target_url):
        return 1

    base_payload = console.input(
        "[red]Base payload[/red] [dim](default: <script>alert(1)</script>)[/dim]: "
    ).strip()
    if not base_payload:
        base_payload = "<script>alert(1)</script>"

    print_info("Initializing WAF evasion engine...")
    engine = WAFEvasionEngine(
        base_url=target_url, rate_limit_rps=max(0.3, float(args.rate_limit) / 5)
    )

    print_info("Phase 1: Detecting WAF...")
    waf_type, confidence = engine.detect_waf(target_url, base_payload)
    if waf_type:
        print_success(f"WAF detected: {waf_type} (confidence: {confidence:.0%})")
    else:
        print_warning("No WAF detected")

    print_info("Phase 2: Testing mutations...")
    results = engine.test_bypass(target_url, base_payload, waf_type, 12)

    blocked_count = sum(1 for r in results if r.blocked)
    bypass_count = len(results) - blocked_count
    print_info(f"Results: {blocked_count} blocked, {bypass_count} potentially bypassed")

    best = engine.get_best_bypass(results)
    if best:
        print_success("Potential bypass found!")
        console.print(f"[bold white]Payload:[/bold white] {best.payload[:80]}...")
        console.print(f"[bold white]Techniques:[/bold white] {', '.join(best.techniques)}")
    else:
        print_info("No bypass found. Try different base payload.")

    return 0


def _run_interactive_recon(args) -> int:
    """Run interactive smart reconnaissance."""
    from tools.smart_recon import SmartReconEngine, format_recon_for_display
    from cli.ui_components import print_error, print_info, print_success, show_section

    from main import require_authorized_scan_target

    show_section("Smart Reconnaissance - Asset Correlation Engine")
    target = (
        args.target
        or console.input("[red]Target domain[/red] (e.g., example.com): ").strip()
    )
    if not target:
        print_error("Target domain is required")
        return 1
    if not require_authorized_scan_target(target):
        return 1

    print_info(f"Starting smart recon for {target}...")

    try:
        engine = SmartReconEngine(
            target_domain=target,
            rate_limit_rps=max(1.0, float(args.rate_limit) / 2),
        )

        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(engine.run_full_recon())
        finally:
            loop.close()

        if result:
            console.print(format_recon_for_display(result))
        else:
            print_info("Recon completed with no results.")

        return 0

    except Exception as e:
        console.print(f"[FAIL] Recon error: {e}")
        return 1
