#!/usr/bin/env python3
"""
main.py — Elengenix Professional CLI Entry Point (v1.5.0)
- Secure Dependency Management (No --break-system-packages)
- Robust Subprocess Execution for Telegram Gateway
- Strict Target Validation and Rate Limit Propagation
- Enterprise-grade Logging and Error Handling
"""

import sys
import os
import logging
import subprocess
import argparse
import re
import time
from pathlib import Path

# --- Rich & Interactive UI ---
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import questionary
except ImportError:
    # Fallback for initial run before dependencies are installed
    print("[*] Initializing system for the first time...")

# ── Logging Setup ─────────────────────────────────────────────────────────────
LOG_DIR = Path("data")
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "elengenix.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("elengenix.main")
console = Console()

# ── Dependency Management ─────────────────────────────────────────────────────
def ensure_dependencies():
    """Safety-first dependency checker with no-break logic."""
    required = {
        "yaml": "pyyaml", "rich": "rich", "questionary": "questionary",
        "requests": "requests", "google.generativeai": "google-generativeai",
        "openai": "openai", "anthropic": "anthropic", "trafilatura": "trafilatura",
        "dotenv": "python-dotenv", "nest_asyncio": "nest-asyncio", "tenacity": "tenacity"
    }
    
    missing = []
    for mod, pkg in required.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
            
    if not missing: return True

    console.print(Panel(f"[yellow]⚠️  System update required. Missing: {', '.join(missing)}[/yellow]"))
    
    with Progress(SpinnerColumn(), TextColumn("[bold cyan]Updating Environment...[/]"), console=console) as progress:
        progress.add_task("install", total=None)
        try:
            # 🛡️ SECURITY: Using --user instead of breaking system packages
            cmd = [sys.executable, "-m", "pip", "install", "--quiet", "--user"] + missing
            subprocess.run(cmd, check=True, capture_output=True)
            console.print("[bold green]✅ Environment ready. Restarting...[/bold green]\n")
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as e:
            logger.error(f"Auto-update failed: {e}")
            sys.exit(1)

# ── Validation ────────────────────────────────────────────────────────────────
def validate_target(target: str) -> bool:
    """Strict domain/IP validation for safety and legal compliance."""
    if not target or len(target) > 253: return False
    # Domain and IPv4 Regex
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(pattern, target.replace("http://", "").replace("https://", "").split("/")[0]))

# ── Main Logic ────────────────────────────────────────────────────────────────
def show_banner():
    """Clean minimal banner."""
    from ui_components import show_main_banner
    show_main_banner()

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(description="Elengenix CLI", add_help=False)
    parser.add_argument("command", nargs="?", default="menu", 
                        choices=["ai", "scan", "gateway", "configure", "update", "doctor", "arsenal", "memory", "cve-update", "bola", "waf", "recon", "soc", "mobile", "cloud", "sast", "proto", "dashboard", "chain", "predict", "workflow", "acm", "schema", "menu"])
    parser.add_argument("target", nargs="?", help="Target domain or IP")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second")
    
    args, _ = parser.parse_known_args()

    # Interactive Menu
    if args.command == "menu":
        from ui_components import create_main_menu, format_menu_item, console
        menu_items = create_main_menu()
        
        while True:
            try:
                console.print("\n[bold cyan]Main Menu[/bold cyan]\n")
                for i, (title, desc, _) in enumerate(menu_items, 1):
                    console.print(format_menu_item(i, title, desc))
                console.print()
                
                choice_num = console.input("[cyan]Select[/cyan] [dim](1-9)[/dim]: ")
                try:
                    idx = int(choice_num) - 1
                    if 0 <= idx < len(menu_items):
                        choice_key = menu_items[idx][2]
                    else:
                        console.print("[red]Invalid selection[/red]")
                        continue
                except ValueError:
                    console.print("[red]Invalid input[/red]")
                    continue
                
                # Handle exit
                if choice_key == "exit":
                    sys.exit(0)
                
                args.command = choice_key
                break
                
            except KeyboardInterrupt:
                sys.exit(0)

    # Command Router
    try:
        if args.command == "scan":
            from ui_components import prompt_target, print_error, show_spinner
            
            target = args.target or prompt_target()
            if not target: return
            if not validate_target(target):
                print_error("SECURITY ERROR: Invalid target format")
                return
            
            from dependency_manager import check_and_install_dependencies
            from tools.omni_scan import run_omni_scan
            
            check_and_install_dependencies()
            
            with show_spinner(f"Initiating scan on {target}..."):
                pass  # Spinner shows while loading
            
            console.print(f"[cyan]Target:[/cyan] {target}  [dim]Rate: {args.rate_limit} req/s[/dim]")
            run_omni_scan(target, rate_limit=args.rate_limit)

        elif args.command == "ai":
            import cli
            cli.main()

        elif args.command == "universal":
            from ui_components import show_cli_banner
            show_cli_banner("universal")
            
            import cli
            cli.main(mode="universal")

        elif args.command == "gateway":
            bot_path = Path(__file__).parent / "bot.py"
            if not bot_path.exists():
                print_error("bot.py not found")
                return
            console.print("[cyan]Starting Telegram Gateway...[/cyan]")
            subprocess.run([sys.executable, str(bot_path)])

        elif args.command == "doctor":
            from tools.doctor import check_health
            console.print("[cyan]Running system health check...[/cyan]")
            check_health()

        elif args.command == "configure":
            import wizard
            wizard.main()

        elif args.command == "arsenal":
            from tools_menu import show_tools_menu
            show_tools_menu()

        elif args.command == "update":
            console.print("[dim]To update, run:[/dim]")
            console.print("  [cyan]git pull && ./setup.sh[/cyan]")

        elif args.command == "memory":
            from ui_components import console, show_section, print_info, create_status_table
            
            try:
                from tools.vector_memory import get_vector_memory, get_vector_memory as vm_get
                
                show_section("AI Memory System")
                
                vm = vm_get()
                stats = vm.get_memory_stats()
                
                # Display stats table
                table = create_status_table("Memory Statistics")
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="white")
                
                table.add_row("Status", stats.get("status", "unknown"))
                table.add_row("Total memories", str(stats.get("total_memories", 0)))
                table.add_row("Unique targets", str(stats.get("unique_targets", 0)))
                
                console.print(table)
                
                # Memory management menu
                console.print("\n[dim]Options:[/dim]")
                console.print("  1. Search memories")
                console.print("  2. List all targets")
                console.print("  3. Clear target memory")
                console.print("  4. Back")
                
                mem_choice = console.input("\n[cyan]Select[/cyan] [dim](1-4)[/dim]: ")
                
                if mem_choice == "1":
                    query = console.input("[cyan]Search query[/cyan]: ")
                    target = console.input("[dim]Target filter (optional)[/dim]: ")
                    if query:
                        from tools.vector_memory import recall
                        results = recall(query, target or None, n_results=10)
                        
                        if results:
                            console.print(f"\n[cyan]Found {len(results)} memories:[/cyan]\n")
                            for i, mem in enumerate(results, 1):
                                content = mem['content'][:80]
                                sim = mem.get('similarity', 0)
                                console.print(f"  {i}. {content}... [dim]({sim:.0%})[/dim]")
                        else:
                            print_info("No matching memories found")
                            
                elif mem_choice == "2":
                    targets = vm.get_all_targets()
                    if targets:
                        console.print(f"\n[cyan]Known Targets ({len(targets)}):[/cyan]\n")
                        for t in targets[:20]:
                            console.print(f"  • {t}")
                        if len(targets) > 20:
                            print_info(f"... and {len(targets) - 20} more")
                    else:
                        print_info("No targets in memory")
                        
                elif mem_choice == "3":
                    target = console.input("[cyan]Target to clear[/cyan]: ")
                    if target:
                        from ui_components import confirm
                        if confirm(f"Delete all memories for '{target}'?", default=False):
                            vm.delete_target_memories(target)
                            print_success(f"Deleted memories for {target}")
                            
            except Exception as e:
                print_error(f"Memory system error: {e}")

        elif args.command == "bola":
            from ui_components import show_section, print_info, print_success, print_error, console
            from tools.bola_harness import BOLAHarness, parse_headers_input

            show_section("BOLA/IDOR Differential Harness")
            base_url = args.target or console.input("[cyan]Base URL[/cyan] (e.g., https://target.tld): ").strip()
            if not base_url:
                print_error("Base URL is required")
                return

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
                return

            harness = BOLAHarness(base_url=base_url, rate_limit_rps=max(0.5, float(args.rate_limit)))
            ids_a, ids_b, notes = harness.discover_identities(headers_a, headers_b)

            print_info("Optional: paste endpoint seeds to test (paths or full URLs). Empty line to finish.")
            print_info("You may use templates like /api/orders/{id} or /api/accounts/{account_id}")
            seeds = []
            while True:
                line = console.input("").rstrip("\n")
                if not line.strip():
                    break
                seeds.append(line.strip())

            common = harness.run_common_idor_checks(headers_a, headers_b, ids_a, ids_b)
            seeded = harness.run_seeded_checks(headers_a, headers_b, ids_a, ids_b, seeds)
            result_findings = (common.findings or []) + (seeded.findings or [])
            result_notes = (common.notes or []) + (seeded.notes or [])

            for n in notes:
                console.print(f"[dim]- {n}[/dim]")

            for n in result_notes:
                console.print(f"[dim]- {n}[/dim]")

            if not result_findings:
                print_info("No strong BOLA/IDOR signals detected with common checks.")
                return

            print_success(f"Potential issues: {len(result_findings)}")
            for i, f in enumerate(result_findings, 1):
                conf = f.get("confidence", "?")
                sev = f.get("severity", "unknown")
                url = f.get("url", "")
                console.print(f"\n[bold cyan]{i}. {f.get('type','finding').upper()}[/bold cyan] [dim]({sev}, conf={conf})[/dim]")
                console.print(f"[white]{url}[/white]")
                ev = f.get("evidence", {})
                if isinstance(ev, dict):
                    console.print(f"[dim]A: {ev.get('account_a',{})}[/dim]")
                    console.print(f"[dim]B: {ev.get('account_b',{})}[/dim]")

        elif args.command == "waf":
            from ui_components import show_section, print_info, print_success, print_warning, print_error, console
            from tools.waf_evasion import WAFEvasionEngine

            show_section("WAF Detection & Evasion Testing")
            target_url = args.target or console.input("[cyan]Target URL to test[/cyan] (e.g., https://target.tld/search): ").strip()
            if not target_url:
                print_error("Target URL is required")
                return

            base_payload = console.input("[cyan]Base payload to test[/cyan] [dim](default: <script>alert(1)</script>)[/dim]: ").strip()
            if not base_payload:
                base_payload = "<script>alert(1)</script>"

            print_info("Initializing WAF evasion engine...")
            engine = WAFEvasionEngine(base_url=target_url, rate_limit_rps=max(0.3, float(args.rate_limit) / 5))

            # Phase 1: WAF Detection
            print_info("Phase 1: Detecting WAF...")
            waf_type, confidence = engine.detect_waf(target_url, base_payload)
            if waf_type:
                print_success(f"WAF detected: {waf_type} (confidence: {confidence:.0%})")
            else:
                print_warning("No WAF detected or unable to identify")

            # Phase 2: Generate and test mutations
            print_info("Phase 2: Testing mutations...")
            max_attempts = 12
            results = engine.test_bypass(target_url, base_payload, waf_type, max_attempts)

            blocked_count = sum(1 for r in results if r.blocked)
            bypass_count = len(results) - blocked_count

            print_info(f"Results: {blocked_count} blocked, {bypass_count} potentially bypassed")

            # Show best bypass
            best = engine.get_best_bypass(results)
            if best:
                print_success("Potential bypass found!")
                console.print(f"[green]Payload:[/green] {best.payload[:80]}...")
                console.print(f"[green]Techniques:[/green] {', '.join(best.techniques)}")
                console.print(f"[green]Status:[/green] {best.status_code}")
            else:
                print_info("No bypass found in this run. Try different base payload or more attempts.")

            # Show all results table
            console.print("\n[bold cyan]Test Results:[/bold cyan]")
            for i, r in enumerate(results[:10], 1):
                status_color = "red" if r.blocked else "green"
                console.print(f"{i}. [{status_color}]{'BLOCKED' if r.blocked else 'BYPASS'}[/{status_color}] {r.payload[:50]}... (tech: {', '.join(r.techniques)})")

        elif args.command == "recon":
            from ui_components import show_section, print_info, print_success, print_warning, print_error, console
            from tools.smart_recon import SmartReconEngine, format_recon_for_display

            show_section("Smart Reconnaissance - Asset Correlation Engine")
            target = args.target or console.input("[cyan]Target domain[/cyan] (e.g., example.com): ").strip()
            if not target:
                print_error("Target domain is required")
                return

            print_info(f"Starting smart recon for {target}...")
            print_info("This will discover subdomains, resolve IPs, fingerprint services, and correlate assets.")
            
            try:
                engine = SmartReconEngine(
                    target_domain=target,
                    rate_limit_rps=max(1.0, float(args.rate_limit) / 2),
                    max_workers=10,
                )
                result = engine.run_full_recon()
                
                # Display formatted results
                output = format_recon_for_display(result)
                console.print(output)
                
                # Summary
                print_success(f"Recon complete! Found {result.stats.get('domains', 0)} domains, {result.stats.get('ips', 0)} IPs, {result.stats.get('endpoints', 0)} endpoints")
                
                # Priority targets
                priority_count = len([f for f in result.findings if f.get("type") == "priority"])
                if priority_count > 0:
                    console.print(f"\n[yellow]📌 {priority_count} high-priority targets identified[/yellow]")
                
                # Correlation findings
                corr_count = len([f for f in result.findings if f.get("type") == "correlation"])
                if corr_count > 0:
                    console.print(f"[cyan]🔗 {corr_count} asset correlations discovered[/cyan]")
                    
            except Exception as e:
                print_error(f"Recon failed: {e}")
                logger.exception("Smart recon failed")

        elif args.command == "cve-update":
            from ui_components import show_section, print_info, print_success, print_error, console
            from tools.cve_database import get_cve_database
            
            show_section("CVE Database Update")
            print_info("Fetching latest CVEs from NVD (National Vulnerability Database)...")
            print_info("This may take a few minutes depending on your connection.")
            
            try:
                db = get_cve_database(auto_update=False)
                result = db.update_database(days_back=30)
                
                if result.get("status") == "success":
                    print_success(f"CVE database updated successfully!")
                    console.print(f"  [green]Added:[/green] {result['added']} new CVEs")
                    console.print(f"  [green]Updated:[/green] {result['updated']} existing CVEs")
                    console.print(f"  [cyan]Total in database:[/cyan] {result['total']} CVEs")
                else:
                    print_error(f"Update failed: {result.get('error', 'Unknown error')}")
                    console.print("[dim]Note: You can still use Elengenix without CVE database updates.[/dim]")
            except Exception as e:
                print_error(f"CVE update error: {e}")
                console.print("[dim]Run 'elengenix doctor' to check system status.[/dim]")

        elif args.command == "soc":
            from ui_components import show_section, print_info, print_success, print_warning, print_error, console
            from tools.soc_analyzer import SOCAnalyzer, format_soc_report
            from tools.threat_intel import ThreatIntelDB
            from pathlib import Path

            show_section("SOC Alert Analysis & Triage")
            
            log_file = args.target or console.input("[cyan]Log file path[/cyan] (e.g., /var/log/alerts.json): ").strip()
            if not log_file:
                print_error("Log file path is required")
                return
            
            log_path = Path(log_file)
            if not log_path.exists():
                print_error(f"File not found: {log_file}")
                return
            
            source_hint = console.input("[cyan]Source system[/cyan] [dim](e.g., suricata, wazuh, crowdsec)[/dim]: ").strip()
            
            print_info("Initializing SOC analyzer...")
            
            # Initialize with threat intel
            ti_db = ThreatIntelDB()
            builtin_count = ti_db.add_builtin_iocs()
            print_info(f"Loaded {builtin_count} built-in IOCs")
            
            analyzer = SOCAnalyzer(ioc_db={
                "ip": {}, "domain": {}, "hash": {}, "url": {}, "user_agent": {}, "process": {}
            })
            
            print_info(f"Analyzing {log_path.name}...")
            try:
                report = analyzer.analyze_log_file(log_path, source_hint or None)
                
                if "error" in report:
                    print_error(report["error"])
                    return
                
                # Display formatted report
                output = format_soc_report(report)
                console.print(output)
                
                # Summary
                print_success(f"Analysis complete! Processed {report.get('total_alerts', 0)} alerts")
                
                if report.get('ioc_matches_found', 0) > 0:
                    console.print(f"\n[red]🚨 {report['ioc_matches_found']} IOC matches found![/red]")
                
                if report.get('threat_actors_identified'):
                    console.print(f"\n[yellow]⚠️ Threat actors identified: {', '.join(report['threat_actors_identified'])}[/yellow]")
                
                # Export detection rules
                if report.get('generated_rules'):
                    rules_file = log_path.parent / f"{log_path.stem}_sigma_rules.yml"
                    with open(rules_file, 'w') as f:
                        f.write("# Auto-generated Sigma rules from Elengenix SOC Analyzer\n")
                        f.write(f"# Source: {log_file}\n")
                        f.write(f"# Generated: {__import__('datetime').datetime.utcnow().isoformat()}\n\n")
                        for rule in report['generated_rules']:
                            f.write(f"---\n")
                            f.write(f"title: {rule['title']}\n")
                            f.write(f"status: experimental\n")
                            f.write(f"level: {rule['level']}\n")
                            f.write(f"tags: {', '.join(rule['tags'])}\n")
                            f.write(f"# Add logsource and detection sections manually\n\n")
                    print_success(f"Sigma rules exported to: {rules_file}")
                
            except Exception as e:
                print_error(f"SOC analysis failed: {e}")
                logger.exception("SOC analysis failed")

        elif args.command == "mobile":
            from ui_components import show_section, print_info, print_success, print_error, console
            from tools.mobile_api_tester import MobileAPITester, format_mobile_report
            from pathlib import Path

            show_section("Mobile API Security Testing")
            
            input_path = args.target or console.input("[cyan]Burp export or manifest file path[/cyan]: ").strip()
            if not input_path:
                print_error("File path is required")
                return
            
            file_path = Path(input_path)
            if not file_path.exists():
                print_error(f"File not found: {input_path}")
                return
            
            print_info("Initializing mobile API tester...")
            tester = MobileAPITester()
            
            try:
                if file_path.suffix == '.json':
                    endpoints = tester.parse_burp_export(file_path)
                    print_info(f"Parsed {len(endpoints)} endpoints from Burp export")
                    
                    report = tester.run_full_analysis(endpoints)
                    output = format_mobile_report(report)
                    console.print(output)
                    
                    print_success(f"Analysis complete! Found {report.get('total_findings', 0)} issues")
                    
                    if report.get('critical_findings'):
                        console.print(f"\n[red]🚨 {len(report['critical_findings'])} critical/high findings![/red]")
                else:
                    # Assume manifest file
                    with open(file_path, 'r') as f:
                        manifest = f.read()
                    findings = tester.check_deep_links(manifest)
                    print_success(f"Found {len(findings)} deep link issues")
                    
            except Exception as e:
                print_error(f"Mobile API analysis failed: {e}")
                logger.exception("Mobile analysis failed")

        elif args.command == "cloud":
            from ui_components import show_section, print_info, print_success, print_error, console
            from tools.cloud_scanner import CloudScanner, format_cloud_report
            from pathlib import Path

            show_section("Cloud Security Posture Scan")
            
            scan_path = args.target or console.input("[cyan]Path to scan[/cyan] (CloudFormation/Terraform files): ").strip()
            if not scan_path:
                print_error("Path is required")
                return
            
            path = Path(scan_path)
            if not path.exists():
                print_error(f"Path not found: {scan_path}")
                return
            
            print_info("Initializing cloud scanner...")
            scanner = CloudScanner()
            
            try:
                report = scanner.scan_directory(path)
                output = format_cloud_report(report)
                console.print(output)
                
                print_success(f"Scan complete! Found {report.get('total_findings', 0)} misconfigurations")
                
                if report.get('critical_findings'):
                    console.print(f"\n[red]🚨 {len(report['critical_findings'])} critical/high findings![/red]")
                    
            except Exception as e:
                print_error(f"Cloud scan failed: {e}")
                logger.exception("Cloud scan failed")

        elif args.command == "sast":
            from ui_components import show_section, print_info, print_success, print_error, console
            from tools.sast_engine import SASTEngine, format_sast_report
            from pathlib import Path

            show_section("Static Application Security Testing (SAST)")
            
            repo_path = args.target or console.input("[cyan]Repository path to scan[/cyan]: ").strip()
            if not repo_path:
                print_error("Repository path is required")
                return
            
            path = Path(repo_path)
            if not path.exists():
                print_error(f"Path not found: {repo_path}")
                return
            
            print_info("Initializing SAST engine...")
            print_info("Scanning for: SQL injection, XSS, hardcoded secrets, weak crypto, command injection...")
            
            engine = SASTEngine()
            
            try:
                report = engine.scan_repository(path)
                output = format_sast_report(report)
                console.print(output)
                
                print_success(f"Scan complete! Scanned {report.get('files_scanned', 0)} files")
                
                if report.get('total_vulnerabilities', 0) > 0:
                    sev_dist = report.get('severity_distribution', {})
                    crit_count = sev_dist.get('critical', 0)
                    high_count = sev_dist.get('high', 0)
                    if crit_count > 0 or high_count > 0:
                        console.print(f"\n[red]🚨 Found {crit_count} critical and {high_count} high severity vulnerabilities![/red]")
                    else:
                        console.print(f"\n[yellow]⚠️ Found {report['total_vulnerabilities']} vulnerabilities (medium/low)[/yellow]")
                else:
                    console.print("\n[green]✅ No vulnerabilities found in scanned files[/green]")
                    
            except Exception as e:
                print_error(f"SAST scan failed: {e}")
                logger.exception("SAST failed")

        elif args.command == "proto":
            from ui_components import show_section, print_info, print_success, print_error, console
            from tools.protocol_analyzer import ProtocolAnalyzer, format_protocol_report

            show_section("IoT/ICS/gRPC Protocol Analyzer")
            
            hex_input = args.target or console.input("[cyan]Hex dump or PCAP data[/cyan]: ").strip()
            if not hex_input:
                print_error("Protocol data is required")
                return
            
            print_info("Initializing protocol analyzer...")
            analyzer = ProtocolAnalyzer()
            
            try:
                result = analyzer.analyze_hex_dump(hex_input)
                
                if "error" in result:
                    print_error(result["error"])
                    return
                
                console.print(f"\n[cyan]Detected Protocol:[/cyan] {result['protocol'].upper()}")
                console.print(f"[dim]Length: {result['length']} bytes[/dim]")
                console.print(f"[dim]Entropy: {result['analysis']['entropy']}[/dim]")
                
                # If we detected a known protocol, do deeper analysis
                if result['protocol'] != 'unknown_binary':
                    from pathlib import Path
                    src_addr = ("127.0.0.1", 1883 if result['protocol'] == 'mqtt' else 502)
                    dst_addr = ("127.0.0.1", 12345)
                    
                    data = bytes.fromhex(hex_input.replace(' ', '').replace('\n', ''))
                    analyzer.analyze_packet(data, src_addr, dst_addr)
                    
                    report = analyzer.generate_report()
                    output = format_protocol_report(report)
                    console.print(output)
                    
                    if report.get('total_findings', 0) > 0:
                        console.print(f"\n[red]🚨 Found {report['total_findings']} protocol security issues![/red]")
                else:
                    console.print("\n[yellow]⚠️ Unknown binary protocol - showing analysis:[/yellow]")
                    console.print(f"Printable ratio: {result['analysis']['printable_ratio']:.2%}")
                    console.print(f"Null bytes: {result['analysis']['null_bytes']}")
                    if result['analysis']['common_patterns']:
                        console.print(f"Patterns: {', '.join(result['analysis']['common_patterns'])}")
                    
            except Exception as e:
                print_error(f"Protocol analysis failed: {e}")
                logger.exception("Protocol analysis failed")

        elif args.command == "dashboard":
            from ui_components import show_section, print_info, print_success, print_error, console
            from tools.dashboard_server import start_dashboard
            from tools.mission_state import MissionState

            show_section("Interactive Web Dashboard")
            
            port = 0
            if args.target and args.target.isdigit():
                port = int(args.target)
            
            print_info("Starting web dashboard server...")
            print_info("Dashboard will show real-time findings, mission state, and statistics")
            
            try:
                # Create or load mission state
                mission_key = f"dashboard:{int(time.time())}"
                mission_state = MissionState(mission_id=mission_key, target="dashboard")
                
                # Start dashboard
                actual_port, thread = start_dashboard(
                    mission_state=mission_state,
                    port=port,
                    open_browser=True
                )
                
                print_success(f"Dashboard started at http://localhost:{actual_port}")
                console.print(f"\n[cyan]📊 Dashboard Features:[/cyan]")
                console.print("  • Real-time findings view with filtering")
                console.print("  • Severity statistics (Critical/High/Medium/Low)")
                console.print("  • Mission state visualization")
                console.print("  • Export to JSON and HTML")
                console.print("  • Auto-refresh every 5 seconds")
                console.print(f"\n[yellow]Press Ctrl+C to stop the dashboard[/yellow]")
                
                # Keep running until interrupted
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    console.print("\n[dim]Dashboard stopped[/dim]")
                    
            except Exception as e:
                print_error(f"Failed to start dashboard: {e}")
                logger.exception("Dashboard failed")

        elif args.command == "chain":
            from ui_components import show_section, print_info, print_success, print_error, console
            from tools.exploit_chain_builder import analyze_findings_for_chains, format_chain_report
            from pathlib import Path
            import json

            show_section("Exploit Chain Builder - Attack Path Discovery")
            
            findings_file = args.target or console.input("[cyan]Findings JSON file path[/cyan] (from previous scans): ").strip()
            if not findings_file:
                print_error("Findings file path is required")
                return
            
            file_path = Path(findings_file)
            if not file_path.exists():
                print_error(f"File not found: {findings_file}")
                return
            
            print_info("Loading findings and building attack chains...")
            
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # Support both direct findings list and nested format
                findings = data if isinstance(data, list) else data.get('findings', [])
                
                print_info(f"Loaded {len(findings)} findings, analyzing for exploit chains...")
                
                report = analyze_findings_for_chains(findings)
                output = format_chain_report(report.get('chains', []))
                console.print(output)
                
                # Summary
                print_success(f"Analysis complete! Found {report.get('total_chains', 0)} chains, {report.get('high_value_chains', 0)} high-value")
                
                if report.get('high_value_chains', 0) > 0:
                    console.print(f"\n[red]🎯 {report['high_value_chains']} high-value exploit chains discovered![/red]")
                    console.print("\n[cyan]💰 These chains have high bounty potential - consider submitting as combined impact![/cyan]")
                else:
                    console.print("\n[yellow]⚠️ No high-value chains found. Try running more diverse scans.[/yellow]")
                    
            except Exception as e:
                print_error(f"Chain analysis failed: {e}")
                logger.exception("Chain analysis failed")

        elif args.command == "predict":
            from ui_components import show_section, print_info, print_success, print_error, console
            from tools.bounty_predictor import predict_bounty_for_findings, format_prediction_report
            from pathlib import Path
            import json

            show_section("ML-Based Bounty Predictor")
            
            findings_file = args.target or console.input("[cyan]Findings JSON file path[/cyan]: ").strip()
            if not findings_file:
                print_error("Findings file path is required")
                return
            
            file_path = Path(findings_file)
            if not file_path.exists():
                print_error(f"File not found: {findings_file}")
                return
            
            print_info("Loading findings and analyzing bounty potential...")
            print_info("Using statistical feature extraction + industry patterns...")
            
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # Support both direct findings list and nested format
                findings = data if isinstance(data, list) else data.get('findings', [])
                
                if not findings:
                    print_error("No findings found in file")
                    return
                
                print_info(f"Analyzing {len(findings)} findings for bounty potential...")
                
                report = predict_bounty_for_findings(findings)
                output = format_prediction_report(report.get('predictions', []))
                console.print(output)
                
                # Summary
                high = report.get('high_value_count', 0)
                med = report.get('medium_value_count', 0)
                low = report.get('low_value_count', 0)
                
                print_success(f"Analysis complete! {high} high-value, {med} medium, {low} low")
                
                if high > 0:
                    console.print(f"\n[green]💰 Submit these {high} findings first for best results![/green]")
                
                # Export prioritized list
                if report.get('prioritized_list'):
                    priority_file = file_path.parent / f"{file_path.stem}_prioritized.txt"
                    with open(priority_file, 'w') as f:
                        f.write("# Elengenix Bounty Prediction - Prioritized List\n")
                        f.write(f"# Generated: {__import__('datetime').datetime.utcnow().isoformat()}\n\n")
                        for i, fid in enumerate(report['prioritized_list'][:10], 1):
                            f.write(f"{i}. {fid}\n")
                    print_success(f"Prioritized list saved to: {priority_file}")
                    
            except Exception as e:
                print_error(f"Bounty prediction failed: {e}")
                logger.exception("Bounty prediction failed")

        elif args.command == "workflow":
            from ui_components import show_section, print_info, print_success, print_warning, print_error, console
            from tools.workflow_fuzzer import WorkflowFuzzer, format_workflow_plans

            show_section("Workflow / Business-Logic Fuzzer (Stateful, Safe)")
            base_url = args.target or console.input("[cyan]Base URL[/cyan] (e.g., https://target.tld): ").strip()
            if not base_url:
                print_error("Base URL is required")
                return

            fuzzer = WorkflowFuzzer(base_url=base_url, rate_limit_rps=max(0.3, float(args.rate_limit) / 5))
            plans = fuzzer.propose_common_plans()
            console.print(format_workflow_plans(plans))

            sel = console.input("[cyan]Select plan number[/cyan] (default 1): ").strip() or "1"
            try:
                idx = max(1, int(sel)) - 1
            except Exception:
                idx = 0
            if idx < 0 or idx >= len(plans):
                idx = 0
            plan = plans[idx]

            print_info("Paste headers for session (one per line: Header: value). Empty line to finish.")
            lines = []
            while True:
                line = console.input("").rstrip("\n")
                if not line.strip():
                    break
                lines.append(line)
            from tools.bola_harness import parse_headers_input
            headers = parse_headers_input("\n".join(lines))

            template_vars = {}
            try:
                from tools.bola_harness import BOLAHarness
                use_auto = console.input("[cyan]Auto-fill {id}/{user_id}/{account_id} from session identity?[/cyan] (Y/n): ").strip().lower()
                if use_auto not in ("n", "no"):
                    harness = BOLAHarness(base_url=base_url, rate_limit_rps=max(0.3, float(args.rate_limit) / 5))
                    ids_a, _, notes = harness.discover_identities(headers, headers)
                    for n in notes[:5]:
                        console.print(f"[dim]- {n}[/dim]")
                    # best-effort mapping
                    if ids_a.get("id"):
                        template_vars["id"] = ids_a.get("id")
                    if ids_a.get("user_id"):
                        template_vars["user_id"] = ids_a.get("user_id")
                    if ids_a.get("account_id"):
                        template_vars["account_id"] = ids_a.get("account_id")
            except Exception as e:
                logger.debug(f"Workflow identity auto-fill failed: {e}")

            dry = console.input("[cyan]Dry-run only?[/cyan] (Y/n): ").strip().lower()
            dry_run = False if dry in ("n", "no") else True
            if not dry_run:
                print_warning("Execution is GET-only by default. Use this only on authorized targets.")

            result = fuzzer.execute_plan(plan, headers=headers, allow_non_get=False, dry_run=dry_run, template_vars=template_vars)
            if result.anomalies:
                print_success(f"Anomalies detected: {len(result.anomalies)}")
                for a in result.anomalies[:10]:
                    console.print(f"- {a.get('type')}: {a.get('note','')} ({a.get('url','')})")
            else:
                print_info("No anomalies flagged by heuristics (this does not mean safe).")

        elif args.command == "acm":
            from ui_components import show_section, print_info, print_success, print_warning, print_error, console
            from tools.access_control_matrix import AccessControlMatrixTester, format_acm_result
            from tools.bola_harness import parse_headers_input

            show_section("Access-Control Matrix Tester (Differential AuthZ)")
            base_url = args.target or console.input("[cyan]Base URL[/cyan] (e.g., https://target.tld): ").strip()
            if not base_url:
                print_error("Base URL is required")
                return

            print_info("Paste headers for Account A (empty line to finish)")
            la = []
            while True:
                line = console.input("").rstrip("\n")
                if not line.strip():
                    break
                la.append(line)

            print_info("Paste headers for Account B (empty line to finish)")
            lb = []
            while True:
                line = console.input("").rstrip("\n")
                if not line.strip():
                    break
                lb.append(line)

            headers_a = parse_headers_input("\n".join(la))
            headers_b = parse_headers_input("\n".join(lb))
            if not headers_a or not headers_b:
                print_error("Both accounts headers are required")
                return

            eps = []

            # (A) Load endpoints from katana/httpx output file
            use_file = console.input("[cyan]Load endpoints from file (katana/httpx output)?[/cyan] (y/N): ").strip().lower()
            if use_file in ("y", "yes"):
                fp = console.input("[cyan]File path[/cyan]: ").strip()
                try:
                    p = Path(fp)
                    raw = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                    for ln in raw:
                        ln = ln.strip()
                        if not ln:
                            continue
                        # Accept full URL or path
                        if ln.startswith("http://") or ln.startswith("https://") or ln.startswith("/"):
                            eps.append(ln)
                    print_info(f"Loaded {len(eps)} endpoints from {p.name}")
                except Exception as e:
                    print_warning(f"Failed to load endpoints from file: {e}")

            # (B) Load endpoints from OpenAPI schema
            use_schema = console.input("[cyan]Load endpoints from OpenAPI schema?[/cyan] (y/N): ").strip().lower()
            if use_schema in ("y", "yes"):
                src = console.input("[cyan]OpenAPI path or URL[/cyan]: ").strip()
                if src:
                    try:
                        from tools.api_schema_diff import OpenAPISchemaDiff
                        sd = OpenAPISchemaDiff()
                        if src.startswith("http://") or src.startswith("https://"):
                            schema = sd.load_from_url(src, headers=headers_a)
                        else:
                            schema = sd.load_from_path(Path(src))
                        surf = sd.surface(schema)
                        # add GET only for safety
                        for m, pth in surf.endpoints:
                            if m == "GET":
                                eps.append(pth)
                        print_info(f"Loaded {len([1 for m,_ in surf.endpoints if m=='GET'])} GET endpoints from OpenAPI")
                    except Exception as e:
                        print_warning(f"Failed to load OpenAPI endpoints: {e}")

            print_info("Paste endpoints (paths or URLs) to test (empty line to finish)")
            while True:
                line = console.input("").rstrip("\n")
                if not line.strip():
                    break
                eps.append(line.strip())

            # De-duplicate
            seen = set()
            eps2 = []
            for e in eps:
                if e not in seen:
                    seen.add(e)
                    eps2.append(e)
            eps = eps2
            if not eps:
                print_error("At least 1 endpoint is required")
                return

            dry = console.input("[cyan]Dry-run only?[/cyan] (Y/n): ").strip().lower()
            dry_run = False if dry in ("n", "no") else True
            if not dry_run:
                print_warning("ACM runs GET requests against provided endpoints. Ensure scope/permission.")

            tester = AccessControlMatrixTester(base_url=base_url, rate_limit_rps=max(0.3, float(args.rate_limit) / 5))
            res = tester.run(headers_a=headers_a, headers_b=headers_b, endpoints=eps, methods=["GET"], dry_run=dry_run)
            console.print(format_acm_result(res))
            if res.findings:
                print_success(f"Signals: {len(res.findings)}")

        elif args.command == "schema":
            from ui_components import show_section, print_info, print_success, print_error, console
            from tools.api_schema_diff import OpenAPISchemaDiff, format_schema_diff

            show_section("API Schema Surface & Diff (OpenAPI)")
            src_a = args.target or console.input("[cyan]Schema A (path or URL)[/cyan]: ").strip()
            if not src_a:
                print_error("Schema A is required")
                return
            src_b = console.input("[cyan]Schema B (path or URL)[/cyan] (optional): ").strip()

            diff = OpenAPISchemaDiff()

            def load(src: str):
                if src.startswith("http://") or src.startswith("https://"):
                    return diff.load_from_url(src)
                return diff.load_from_path(Path(src))

            try:
                a = diff.surface(load(src_a))
                print_success(f"Loaded A: {a.title} {a.version} endpoints={len(a.endpoints)}")
                if not src_b:
                    for m, p in a.endpoints[:50]:
                        console.print(f"- {m} {p}")
                    return
                b = diff.surface(load(src_b))
                print_success(f"Loaded B: {b.title} {b.version} endpoints={len(b.endpoints)}")
                d = diff.diff(a, b)
                console.print(format_schema_diff(d))
            except Exception as e:
                print_error(f"Schema analysis failed: {e}")

    except KeyboardInterrupt:
        console.print("\n[dim]Operation canceled[/dim]")
        sys.exit(0)
    except Exception as e:
        logger.exception("Operational breakdown")
        print_error(f"SYSTEM FAILURE: {e}")
        from ui_components import confirm
        if confirm("Attempt emergency repair?", default=True):
            from tools.doctor import check_health
            check_health(fix=True)

if __name__ == "__main__":
    ensure_dependencies()
    main()
