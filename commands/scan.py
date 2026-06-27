"""
commands/scan.py — Scan Command Handler
Extracted from main.py for better code organization.
"""

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from ui_components import console, prompt_target


def handle_scan(args) -> int:
    """Handle the scan command.

    Args:
        args: Parsed command arguments.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    from shutil import which

    from agent import get_agent
    from main import require_authorized_scan_target

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
        from orchestrator import run_elengenix_modules

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
