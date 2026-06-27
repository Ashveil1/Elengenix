"""
commands/system.py — Enterprise System Commands
=================================================
Commands: api, compliance, ml-filter
"""

from __future__ import annotations

import time

from commands.registry import command


@command(
    name="api",
    category="enterprise",
    help_text="Launch the Enterprise REST API server for CI/CD integration",
    examples=["elengenix api", "elengenix api --port 8443"],
)
async def cmd_api(args):
    """Enterprise REST API server with web dashboard, WebSocket, CI/CD webhooks."""
    from ui_components import print_error, print_info, print_success, show_section

    show_section("Elengenix Enterprise API Server")
    host = getattr(args, "host", "0.0.0.0")
    port = getattr(args, "port", 8443)
    try:
        from tools.api_server import run_server

        print_success(f"Starting API server on {host}:{port}")
        print_info(f"  Dashboard: http://{host}:{port}/")
        print_info(f"  API Docs:  http://{host}:{port}/docs")
        print_info(f"  ReDoc:     http://{host}:{port}/redoc")
        run_server(host=host, port=port)
    except ImportError as e:
        print_error("API server requires FastAPI: pip install fastapi uvicorn")
    except Exception as e:
        print_error(f"API server error: {e}")


@command(
    name="compliance",
    category="enterprise",
    aliases=["audit", "pci", "soc"],
    help_text="Run compliance assessment against PCI DSS, SOC2, ISO 27001, OWASP",
    examples=[
        "elengenix compliance pci_dss",
        "elengenix compliance soc2 --findings findings.json",
    ],
)
async def cmd_compliance(args):
    """Enterprise compliance assessment across 4 major standards."""
    from ui_components import print_error, print_info, print_success, show_section

    standard = args.target or "pci_dss"
    show_section(f"Enterprise Compliance Assessment — {standard.upper()}")
    try:
        from tools.compliance_engine import ComplianceEngine

        engine = ComplianceEngine()
        std = engine.get_standard(standard)
        if not std:
            print_error(f"Unknown standard: {standard}")
            available = ", ".join(s["name"] for s in engine.list_standards())
            print_info(f"Available: {available}")
            return
        print_info(f"Standard: {std.name} v{std.version} — {len(std.controls)} controls")
        # Load findings if provided
        findings = []
        findings_path = getattr(args, "findings", None) or getattr(args, "output", None)
        if findings_path:
            import json
            import os

            if os.path.exists(findings_path):
                with open(findings_path) as f:
                    findings = json.load(f)
                print_info(f"Loaded {len(findings)} findings from {findings_path}")
        assessment = engine.assess(findings, standard)
        path = engine.generate_report(
            assessment,
            f"reports/compliance_{standard}_{int(time.time())}.html",
            "html",
        )
        print_success(f"Compliance report: {path}")
        console = __import__("ui_components", fromlist=["console"]).console
        console.print(f"[bold white]  Score:[/bold white] {assessment['compliance_pct']}%")
        console.print(
            f"  [green]Passed:[/green] {assessment['passed']}  "
            f"[red]Failed:[/red] {assessment['failed']}  "
            f"[dim]Not tested:[/dim] {assessment['not_tested']}"
        )
        if assessment.get("critical_failures", 0) > 0:
            console.print(f"  [red]Critical failures: {assessment['critical_failures']}[/red]")
        console.print(
            f"  Risk level: [{'red' if assessment.get('critical_failures', 0) > 0 else 'green'}]{assessment['risk_level']}[/]"
        )
    except Exception as e:
        print_error(f"Compliance error: {e}")


@command(
    name="ml-filter",
    category="enterprise",
    aliases=["ml", "filter"],
    help_text="ML-based false positive filter for scan findings",
    examples=[
        "elengenix ml-filter findings.json",
        "elengenix ml-filter findings.json --output filtered.json",
    ],
)
async def cmd_ml_filter(args):
    """ML-powered false positive filter using Bayesian scoring + signal analysis."""
    from ui_components import print_error, print_info, print_success, show_section

    target = args.target
    if not target:
        print_error("Usage: elengenix ml-filter <findings.json> [--output filtered.json]")
        return
    import os

    if not os.path.exists(target):
        print_error(f"File not found: {target}")
        return
    show_section("ML False Positive Filter")
    try:
        from tools.ml_filter import filter_scan_results

        output = getattr(args, "output", None) or target.replace(".json", "_filtered.json")
        result = filter_scan_results(target, output, min_confidence=0.3)
        print_info(f"Total findings: {result['total']}")
        print_info(f"  High confidence (kept): [green]{result['high_confidence']}[/green]")
        print_info(f"  Low confidence (removed): [red]{result['low_confidence']}[/red]")
        print_info(f"  Savings: {result['savings_pct']}% fewer findings to review")
        print_info(f"  Patterns learned: {result['stats']['patterns']}")
        print_success(f"Filtered results: {output}")
    except Exception as e:
        print_error(f"ML filter error: {e}")


@command(
    name="dashboard",
    category="enterprise",
    aliases=["dash", "monitor"],
    help_text="Launch the world-class TUI security dashboard",
    examples=["elengenix dashboard", "elengenix dashboard example.com"],
)
async def cmd_dashboard(args):
    """Launch the real-time TUI security monitoring dashboard."""
    from ui_components import show_section

    show_section("Elenginx Security Dashboard")
    target = getattr(args, "target", None)
    try:
        from tools.tui_dashboard import run_dashboard, run_minimal

        try:
            run_dashboard(target)
        except Exception:
            run_minimal()
    except Exception as e:
        print(f"[FAIL] Dashboard error: {e}")
        # Fallback to minimal
        try:
            from tools.tui_dashboard import run_minimal

            run_minimal()
        except Exception:
            pass
