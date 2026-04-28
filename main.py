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
from datetime import datetime
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
    parser.add_argument("command", nargs="?", default="auto", 
                        choices=["ai", "scan", "gateway", "configure", "update", "doctor", "arsenal", "memory", "cve-update", "bola", "waf", "recon", "evasion", "report", "menu", "auto", "help", "bb", "check", "test", "red", "pdf", "hack"])
    parser.add_argument("target", nargs="?", help="Target domain or IP")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second")
    
    args, _ = parser.parse_known_args()

    # Help shortcut
    if args.command == "help":
        from tools.auto_detector import CommandSimplifier
        console.print(CommandSimplifier.get_help_text())
        return
    
    # Auto-detect mode (default) - Smart routing based on target
    if args.command == "auto" or (args.command and args.target):
        # If we have both command and target, or just target without specific command
        effective_target = args.target or args.command
        
        # Check if command is actually a shortcut
        from tools.auto_detector import CommandSimplifier, AutoDetector
        simplified = CommandSimplifier.simplify(args.command)
        
        if simplified != args.command:
            # It's a shortcut, use the simplified command
            args.command = simplified
        elif effective_target and effective_target != "auto":
            # Auto-detect what to do with this target
            detection = AutoDetector.detect(effective_target)
            
            # Show clear module selection
            console.print(f"[cyan]� Input detected:[/cyan] {detection['explanation']}")
            
            if detection['confidence'] > 0.7:
                module_name = {
                    "bola": "🐛 BOLA/IDOR Tester",
                    "waf": "🛡️ WAF/XSS Scanner", 
                    "recon": "🔍 Reconnaissance",
                    "predict": "💰 Bounty Predictor",
                    "mobile": "📱 Mobile API Tester",
                    "cloud": "☁️ Cloud Scanner",
                    "sast": "💻 SAST Engine",
                    "soc": "🚨 SOC Analyzer",
                    "proto": "🔌 Protocol Analyzer",
                    "schema": "📊 Schema Analyzer",
                    "ai": "🤖 AI Assistant",
                }.get(detection['action'], detection['action'])
                
                console.print(f"[green]✓ Selected module:[/green] {module_name}")
                console.print(f"[dim]   (Use --manual to override)[/dim]\n")
                
                args.command = detection['action']
                args.target = effective_target
            else:
                console.print("[yellow]⚠ Low confidence detection. Starting AI assistant...[/yellow]")
                args.command = "ai"
                args.target = effective_target
    
    # Interactive Menu (Wizard)
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
            from tools.conversation_memory import ConversationMemory, ProfessionalAIPrompts
            from ui_components import console, print_info, print_success, print_error
            
            # Initialize conversation memory
            memory = ConversationMemory()
            
            # Detect language (simple heuristic)
            lang = "th"  # Default Thai
            
            # Create new session
            session_id = memory.create_session(target=args.target, mode="bug_bounty")
            
            # Show professional welcome
            console.print(ProfessionalAIPrompts.get_welcome(lang))
            
            # Main chat loop
            while True:
                try:
                    user_input = console.input("[bold]>[/bold] ").strip()
                    
                    if not user_input:
                        continue
                    
                    # Special commands
                    if user_input in ["/exit", "/quit", "exit", "quit"]:
                        console.print("[dim]Saving conversation and exiting...[/dim]")
                        break
                    
                    if user_input == "/help":
                        console.print("""
[bold]Available commands:[/bold]
  /exit, /quit, exit, quit  - Exit
  /save                     - Save conversation
  /summary                  - Show conversation summary
  /target <url>             - Set target
  /clear                    - Clear screen
  (Type anything naturally)
""")
                        continue
                    
                    if user_input == "/summary":
                        summary = memory.get_conversation_summary(session_id)
                        console.print(summary)
                        continue
                    
                    if user_input == "/save":
                        export_path = memory.export_session(session_id, "markdown")
                        if export_path:
                            print_success(f"Saved conversation: {export_path}")
                        else:
                            print_error("Could not save")
                        continue
                    
                    if user_input.startswith("/target "):
                        new_target = user_input[8:].strip()
                        args.target = new_target
                        print_success(f"Set target: {new_target}")
                        continue
                    
                    if user_input == "/clear":
                        console.clear()
                        continue
                    
                    # Save user message
                    memory.add_message(session_id, "user", user_input)
                    
                    # Get context for AI
                    context = memory.get_recent_context(session_id, limit=10)
                    
                    # Build professional prompt
                    prompt = ProfessionalAIPrompts.build_context_aware_prompt(
                        user_input=user_input,
                        conversation_history=context,
                        target=args.target,
                        language=lang
                    )
                    
                    # Call AI using Universal Client (OpenClaw-style)
                    console.print("[dim]AI is thinking...[/dim]")
                    
                    try:
                        from tools.universal_ai_client import AIClientManager, AIMessage
                        
                        # Initialize AI manager with fallback chain
                        ai_manager = AIClientManager(preferred_order=["gemini", "openai", "groq", "ollama"])
                        
                        if not ai_manager.active_client:
                            console.print("[yellow]No AI provider found[/yellow]")
                            console.print("[dim]Please configure one of these:[/dim]")
                            console.print("  • GEMINI_API_KEY (free) - https://aistudio.google.com/app/apikey")
                            console.print("  • OPENAI_API_KEY - https://platform.openai.com/api-keys")
                            console.print("  • Or install Ollama (no API key needed)")
                            continue
                        
                        # Build messages with context
                        messages = [
                            AIMessage(role="system", content=prompt),
                            AIMessage(role="user", content=user_input)
                        ]
                        
                        # Get response from AI
                        response_obj = ai_manager.chat(messages, temperature=0.7, max_tokens=2048)
                        response = response_obj.content
                        
                        console.print(f"🤖 {response}\n")
                        
                        # Save AI response with metadata
                        memory.add_message(session_id, "assistant", response, metadata={
                            "provider": ai_manager.get_active_provider(),
                            "model": response_obj.model,
                            "usage": response_obj.usage,
                        })
                        
                    except Exception as e:
                        logger.error(f"AI error: {e}")
                        console.print(f"[red]AI Error: {str(e)[:100]}[/red]")
                        console.print("[dim]Check API key or use Ollama (local) instead[/dim]")
                        
                except KeyboardInterrupt:
                    console.print("\n[dim]Exiting...[/dim]")
                    break
                except EOFError:
                    break
            
            # Show summary on exit
            console.print("\n" + memory.get_conversation_summary(session_id))
            console.print("[dim]Conversation saved. Use 'elengenix ai' again to continue[/dim]")

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
            from tools.config_wizard import run_config_wizard
            run_config_wizard()

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

        elif args.command == "evasion":
            from ui_components import show_section, print_info, print_success, print_warning, print_error, console
            from tools.edr_evasion import EDREvasionEngine, format_edr_report

            show_section("🔴 EDR/AV Evasion - Red Team Payload Generator")
            print_warning("⚠️ FOR AUTHORIZED RED TEAM USE ONLY - ALL ACTIVITY IS LOGGED")
            
            engine = EDREvasionEngine()
            
            action = console.input(
                "[cyan]Select action[/cyan] [list/generate/plan]: "
            ).strip().lower()
            
            if action == "list":
                category = console.input("[cyan]Filter by category[/cyan] [amsi/process/memory/sandbox/signature/all]: ").strip()
                if category == "all":
                    category = None
                techniques = engine.list_techniques(category=category)
                
                print_success(f"Found {len(techniques)} techniques:")
                for t in techniques:
                    risk_emoji = "🔴" if t.detection_risk == "high" else "🟡" if t.detection_risk == "medium" else "🟢"
                    console.print(f"  {risk_emoji} [{t.difficulty}] {t.name} ({t.category}) - {t.platform}")
                    
            elif action == "generate":
                tech_name = console.input("[cyan]Technique name[/cyan]: ").strip()
                if not tech_name:
                    print_error("Technique name required")
                    return
                    
                result = engine.generate_payload(tech_name)
                if "error" in result:
                    print_error(result["error"])
                    return
                
                console.print(format_edr_report(result))
                
                # Save to file
                save = console.input("[cyan]Save payload to file?[/cyan] (y/N): ").strip().lower()
                if save in ("y", "yes"):
                    from pathlib import Path
                    timestamp = int(time.time())
                    out_path = Path(f"reports/evasion_{tech_name.replace(' ', '_').lower()}_{timestamp}.txt")
                    out_path.parent.mkdir(exist_ok=True)
                    out_path.write_text(result["generated_code"], encoding="utf-8")
                    print_success(f"Saved to: {out_path}")
                    
            elif action == "plan":
                target_edr = console.input("[cyan]Target EDR[/cyan] (e.g., crowdstrike/sentinelone/defender): ").strip()
                objectives = console.input("[cyan]Objectives[/cyan] [persistence,privilege,escalation,evasion]: ").strip()
                obj_list = [o.strip() for o in objectives.split(",") if o.strip()]
                
                plan = engine.generate_red_team_plan(target_edr=target_edr or None, objectives=obj_list or None)
                console.print(format_edr_report(plan))
                
            else:
                print_info("Available actions: list, generate, plan")

        elif args.command == "report":
            from ui_components import show_section, print_info, print_success, print_error, console
            from tools.pdf_report_generator import PDFReportGenerator, ReportMetadata, format_report_summary
            from pathlib import Path
            import json

            show_section("📄 Professional Report Generator")
            
            findings_file = args.target or console.input("[cyan]Findings JSON file[/cyan]: ").strip()
            if not findings_file:
                print_error("Findings file required")
                return
            
            file_path = Path(findings_file)
            if not file_path.exists():
                print_error(f"File not found: {findings_file}")
                return
            
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                findings = data if isinstance(data, list) else data.get('findings', [])
                if not findings:
                    print_error("No findings found")
                    return
                
                print_success(f"Loaded {len(findings)} findings")
                
                # Get metadata
                target = console.input("[cyan]Target name[/cyan]: ").strip() or "Unknown Target"
                author = console.input("[cyan]Author name[/cyan]: ").strip() or "Elengenix Security"
                title = console.input("[cyan]Report title[/cyan]: ").strip() or f"Security Assessment - {target}"
                
                metadata = ReportMetadata(
                    title=title,
                    target=target,
                    author=author,
                    date=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                )
                
                generator = PDFReportGenerator()
                report_paths = generator.generate_from_findings(findings, metadata)
                
                console.print(format_report_summary(report_paths))
                
                if "pdf" in report_paths:
                    print_success(f"PDF report ready for submission: {report_paths['pdf']}")
                else:
                    print_success(f"HTML report ready: {report_paths['html']}")
                    print_info("Install weasyprint for PDF: pip install weasyprint")
                
            except Exception as e:
                print_error(f"Report generation failed: {e}")
                logger.exception("Report generation failed")

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
