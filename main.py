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
import importlib.util
import time
import json
from datetime import datetime
from pathlib import Path

# --- Load .env file (API keys, model preferences, etc.) ---
try:
    from dotenv import load_dotenv
    load_dotenv(override=False)  # Don't override existing env vars
except ImportError:
    pass  # python-dotenv not installed, user must set env vars manually

# --- Rich & Interactive UI ---
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import questionary

try:
    from ui_components import console
except ImportError:
    console = Console()

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

# ── Dependency Management ─────────────────────────────────────────────────────
def _check_module(module_name: str) -> bool:
    """Safely check if a module is importable, handles dotted paths & namespace packages."""
    try:
        spec = importlib.util.find_spec(module_name)
        return spec is not None
    except (ModuleNotFoundError, ValueError):
        return False


def ensure_dependencies():
    """Dependency checker. Hard-fails on core packages, warns on optional AI SDKs."""
    # These MUST be present for the framework to run at all
    core_required = {
        "yaml":           "pyyaml",
        "rich":           "rich",
        "questionary":    "questionary",
        "prompt_toolkit": "prompt_toolkit",
        "requests":       "requests",
        "dotenv":         "python-dotenv",
        "tenacity":       "tenacity",
        "nest_asyncio":   "nest-asyncio",
    }
    # These are optional — framework still runs if missing (user just can't use that provider)
    optional_providers = {
        "openai":              "openai",
        "anthropic":           "anthropic",
        "google.generativeai": "google-generativeai",
        "cohere":              "cohere",
        "huggingface_hub":     "huggingface-hub",
        "replicate":           "replicate",
        "telegram":            "python-telegram-bot",
        "trafilatura":         "trafilatura",
        "googlesearch":        "googlesearch-python",
    }

    missing_core = [pkg for mod, pkg in core_required.items() if not _check_module(mod)]
    if missing_core:
        console.print(Panel(
            f"[grey70]Required dependencies missing: {', '.join(missing_core)}[/grey70]\n"
            "[dim]Run ./setup.sh (or termux_setup.sh) to install.[/dim]"
        ))
        return False

    missing_optional = [pkg for mod, pkg in optional_providers.items() if not _check_module(mod)]
    if missing_optional:
        logger.debug(f"Optional providers not installed: {', '.join(missing_optional)}")

    return True

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

    command_choices = [
        "ai", "universal", "scan", "gateway", "configure", "update", "doctor",
        "arsenal", "memory", "cve-update", "bola", "waf", "recon", "evasion",
        "report", "menu", "auto", "help", "bb", "check", "test", "red", "pdf",
        "hack", "research", "poc", "autonomous", "welcome", "quick", "deep",
        "bounty", "stealth", "api", "web", "profile", "history", "programs",
        "intel", "mission", "pause", "resume", "cli",
        # New unified commands
        "sast", "cloud", "mobile", "soc", "dashboard",
    ]

    parser = argparse.ArgumentParser(description="Elengenix CLI", add_help=False)
    parser.add_argument("command", nargs="?", default="auto", choices=command_choices)
    parser.add_argument("target", nargs="?", help="Target domain or IP")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second")
    parser.add_argument("--framework", type=str, default="generic", help="Target framework for PoC generation")
    parser.add_argument("--version", type=str, default="", help="Target version for PoC generation")
    parser.add_argument("--mode", type=str, default="ask", choices=["strict", "ask", "auto"], help="Governance mode for autonomous operations")
    
    args, _ = parser.parse_known_args()

    # Welcome wizard on first run (before processing command)
    if args.command == "welcome":
        from tools.welcome_wizard import WelcomeWizard
        wizard = WelcomeWizard()
        wizard.run_setup()
        return
    
    # Auto-run welcome if first time (unless running specific commands)
    skip_welcome_commands = ["doctor", "configure", "update", "welcome", "cli"]
    if args.command not in skip_welcome_commands:
        from tools.welcome_wizard import WelcomeWizard
        wizard = WelcomeWizard()
        config = wizard.run_if_first_time()
        if config:
            # First run completed, continue with user's command
            pass
    
    # Initialize history tracking
    from tools.history_manager import get_history_manager
    history = get_history_manager()
    
    # Help shortcut
    if args.command == "help":
        from tools.auto_detector import CommandSimplifier
        console.print(CommandSimplifier.get_help_text())
        
        # Show contextual suggestions from history
        suggestions = history.get_contextual_suggestions()
        if suggestions:
            console.print("\n[dim]Based on your history, try:[/dim]")
            for sugg in suggestions:
                console.print(f"  [red]elengenix {sugg.split(' -- ')[0]}[/red]")
        return
    
    # Handle unknown commands with smart suggestions
    valid_commands = set(command_choices)
    
    if args.command and args.command not in valid_commands and args.command != "auto":
        from tools.command_suggest import handle_command_error, CommandSuggester
        from ui_components import confirm
        
        suggester = CommandSuggester()
        correction = suggester.suggest_correction(args.command)
        
        if correction:
            console.print(f"\n[grey70]Unknown command: '{args.command}'[/grey70]")
            console.print(f"[red]Did you mean:[/red] [bold]elengenix {correction}[/bold]")
            
            if confirm(f"Run 'elengenix {correction}' instead?", default=True):
                args.command = correction
                # Continue with corrected command
            else:
                # Show help with history context
                console.print(f"[grey70]Unknown command: {args.command}[/grey70]")
                console.print("Run 'elengenix help' for available commands")
                # Show recent history
                recent = history.get_recent_commands(hours=24, limit=5)
                if recent:
                    console.print("\n[dim]Recent commands:[/dim]")
                    for entry in recent:
                        console.print(f"  [red]elengenix {entry.command} {entry.args}[/red]")
                return
        else:
            # No suggestion found, show help
            console.print(f"[grey70]Unknown command: {args.command}[/grey70]")
            console.print("Run 'elengenix help' for available commands")
            # Show recent history
            recent = history.get_recent_commands(hours=24, limit=5)
            if recent:
                console.print("\n[dim]Recent commands:[/dim]")
                for entry in recent:
                    console.print(f"  [red]elengenix {entry.command} {entry.args}[/red]")
            return

    # ── Shortcut Pre-Processing ── resolve aliases BEFORE auto-detect block
    # e.g. 'elengenix bb', 'elengenix hack', 'elengenix red' (no target needed)
    from tools.auto_detector import CommandSimplifier
    _simplified = CommandSimplifier.simplify(args.command)
    if _simplified != args.command:
        args.command = _simplified

    # Auto-detect mode (default) - Smart routing based on target
    if args.command == "auto" or (args.command and args.target):
        # If we have both command and target, or just target without specific command
        effective_target = args.target or args.command

        # Auto-detect target type and route to correct module
        from tools.auto_detector import AutoDetector
        if effective_target and effective_target != "auto":
            # Auto-detect what to do with this target
            detection = AutoDetector.detect(effective_target)
            
            # Show clear module selection
            console.print(f"[red]Input detected:[/red] {detection['explanation']}")
            
            if detection['confidence'] > 0.7:
                module_name = {
                    "bola": "BOLA/IDOR Tester",
                    "waf": "WAF/XSS Scanner",
                    "recon": "Reconnaissance",
                    "predict": "Bounty Predictor",
                    "mobile": "Mobile API Tester",
                    "cloud": "Cloud Scanner",
                    "sast": "SAST Engine",
                    "soc": "SOC Analyzer",
                    "proto": "Protocol Analyzer",
                    "schema": "Schema Analyzer",
                    "ai": "AI Assistant",
                }.get(detection['action'], detection['action'])
                
                console.print(f"[bold white]Selected module:[/bold white] {module_name}")
                console.print(f"[dim]   (Use --manual to override)[/dim]\n")
                
                detected_action = detection.get("action", "ai")
                detected_module = detection.get("module", "ai")
                action_fallback_map = {
                    "bola_test": "bola",
                    "web_scan": "waf",
                    "protocol": "ai",
                    "mobile_api": "ai",
                    "cloud_scan": "ai",
                    "soc_analysis": "ai",
                    "analyze_findings": "ai",
                    "json_analysis": "ai",
                    "admin_test": "ai",
                    "file_analysis": "ai",
                    "schema": "ai",
                    "swarm": "ai",
                }

                candidate_command = detected_action
                if candidate_command not in valid_commands:
                    candidate_command = detected_module
                if candidate_command not in valid_commands:
                    candidate_command = action_fallback_map.get(detected_action, "ai")

                args.command = candidate_command
                args.target = effective_target
            else:
                console.print("[grey70]Low confidence detection. Starting AI assistant...[/grey70]")
                args.command = "ai"
                args.target = effective_target
    
    # Interactive Menu (Wizard)
    if args.command == "menu":
        from ui_components import show_categorized_menu, create_main_menu
        menu_items = create_main_menu()   # flat list for index lookup

        while True:
            try:
                show_categorized_menu()

                choice_raw = console.input("[red]Select[/red] [dim](number or command)[/dim]: ").strip()

                # Allow typing a command directly (e.g. "ai", "recon")
                if choice_raw.isalpha() and choice_raw in [c for _, _, c in menu_items]:
                    args.command = choice_raw
                    break

                try:
                    idx = int(choice_raw) - 1
                    if 0 <= idx < len(menu_items):
                        choice_key = menu_items[idx][2]
                    else:
                        console.print("[red]Invalid selection[/red]")
                        continue
                except ValueError:
                    console.print("[red]Invalid input — enter a number or command name[/red]")
                    continue

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
            
            console.print(f"[red]Target:[/red] {target}  [dim]Rate: {args.rate_limit} req/s[/dim]")
            run_omni_scan(target, rate_limit=args.rate_limit)

        elif args.command == "ai":
            from tools.conversation_memory import ConversationMemory, ProfessionalAIPrompts
            from ui_components import print_info, print_success, print_error
            
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
                        
                        # Initialize AI manager with all providers (fallback chain)
                        ai_manager = AIClientManager()
                        
                        if not ai_manager.active_client:
                            console.print("[grey70]No AI provider found[/grey70]")
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
                        
                        console.print(f"{response}\n")
                        
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
            console.print("[red]Starting Telegram Gateway...[/red]")
            subprocess.run([sys.executable, str(bot_path)])

        elif args.command == "doctor":
            from tools.doctor import check_health
            console.print("[red]Running system health check...[/red]")
            check_health()

        elif args.command == "configure":
            from tools.config_wizard import run_config_wizard
            run_config_wizard()

        elif args.command == "cli":
            from cli import main as cli_main
            cli_main()

        elif args.command == "research":
            """Vulnerability Research Engine - Research CVEs and generate PoCs."""
            from tools.vuln_researcher import VulnerabilityResearcher
            from ui_components import print_success, print_error

            researcher = VulnerabilityResearcher()

            if not args.target:
                console.print("Usage: elengenix research <cve-id|vuln-type>")
                console.print("Examples:")
                console.print("  elengenix research CVE-2024-21626")
                console.print("  elengenix research rce")
                console.print("  elengenix research sqli")
                return

            target = args.target

            # Check if CVE
            if target.upper().startswith("CVE-"):
                console.print(f"[bold]Researching {target}...[/bold]")
                result = researcher.research_cve(target)

                if result:
                    console.print(f"\n[bold red]CVE Research: {result.cve_id}[/bold red]")
                    console.print(f"CVSS Score: {result.cvss_score} ({result.severity})")
                    console.print(f"\n[bold]Description:[/bold]\n{result.description[:400]}...")
                    console.print(f"\n[bold]Prerequisites:[/bold] {', '.join(result.exploitation_requirements) or 'None listed'}")

                    if result.available_pocs:
                        console.print(f"\n[bold]Available PoCs:[/bold]")
                        for poc in result.available_pocs[:5]:
                            console.print(f"  • {poc.get('source', 'Unknown')}: {poc.get('url', 'N/A')[:60]}")

                    print_success(f"Research complete (confidence: {result.confidence:.0%})")
                else:
                    print_error(f"No data found for {target}")
            else:
                # Exploitation guide
                guide = researcher.get_exploitation_guide(target)

                console.print(f"\n[bold red]Exploitation Guide: {target.upper()}[/bold red]")
                console.print(f"{guide.get('description', 'N/A')}")
                console.print(f"\n[bold]Impact:[/bold] {guide.get('impact', 'Unknown')}")
                console.print(f"[bold]CVSS Base:[/bold] {guide.get('cvss_base', 'N/A')}")

                console.print(f"\n[bold]Common Vectors:[/bold]")
                for vector in guide.get('common_vectors', []):
                    console.print(f"  • {vector}")

                console.print(f"\n[bold]Detection Methods:[/bold]")
                for method in guide.get('detection_methods', []):
                    console.print(f"  • {method}")

                # Generate PoC
                poc = researcher.generate_custom_poc(
                    vuln_type=target,
                    target_context={
                        "framework": "generic",
                        "version": "",
                        "language": "python",
                    }
                )

                if poc:
                    console.print(f"\n[bold]Generated PoC Template:[/bold]")
                    console.print(f"[dim]Language: {poc.language}, Framework: {poc.target_framework}[/dim]")
                    console.print(f"\n[dim]Save to file with: elengenix research {target} > poc.py[/dim]")

        elif args.command == "poc":
            """Generate custom PoC for vulnerability type."""
            from tools.vuln_researcher import VulnerabilityResearcher
            from ui_components import print_success, print_error

            if not args.target:
                console.print("Usage: elengenix poc <vuln-type> [--framework <name>] [--version <ver>]")
                console.print("Examples:")
                console.print("  elengenix poc rce --framework spring-boot")
                console.print("  elengenix poc sqli --framework django")
                console.print("  elengenix poc ssrf")
                return

            framework = getattr(args, 'framework', 'generic')
            version = getattr(args, 'version', '')

            researcher = VulnerabilityResearcher()
            poc = researcher.generate_custom_poc(
                vuln_type=args.target,
                target_context={
                    "framework": framework,
                    "version": version,
                    "language": "python",
                }
            )

            if poc:
                print_success(f"Generated {args.target.upper()} PoC for {framework}")
                console.print(f"\n{poc.code}")
            else:
                print_error(f"Could not generate PoC for {args.target}")

        elif args.command == "autonomous":
            """Fully autonomous AI mode - AI controls everything."""
            from tools.autonomous_agent import AutonomousAgent
            from ui_components import print_success, print_error, print_warning

            if not args.target:
                console.print("Usage: elengenix autonomous <target> [--mode {strict|ask|auto}]")
                console.print("Examples:")
                console.print("  elengenix autonomous https://target.com")
                console.print("  elengenix autonomous https://api.target.com --mode auto")
                console.print("")
                console.print("Modes:")
                console.print("  strict - Ask for every action (safest)")
                console.print("  ask    - Ask for dangerous operations only (default)")
                console.print("  auto   - Auto-approve everything (fastest, requires trust)")
                return

            # Parse mode from args
            mode = "ask"
            if hasattr(args, 'mode') and args.mode:
                mode = args.mode

            console.print(f"[bold]Elengenix Autonomous Mode[/bold]")
            console.print(f"Target: [red]{args.target}[/red]")
            console.print(f"Governance: [grey70]{mode}[/grey70]")
            console.print("")

            if mode == "auto":
                print_warning("Auto mode: AI will create tools and install deps without asking!")
                if not confirm("Continue?", default=False):
                    return

            agent = AutonomousAgent(governance_mode=mode)
            result = agent.run_autonomous_scan(args.target)

            console.print("\n" + "="*60)
            console.print(result.summary)
            console.print("="*60)

            if result.report_path:
                print_success(f"Report saved: {result.report_path}")

            if result.success:
                print_success("Autonomous scan complete!")
            else:
                print_error(f"Scan failed: {result.summary}")

        elif args.command == "arsenal":
            from tools_menu import show_tools_menu
            show_tools_menu()

        elif args.command == "sast":
            from ui_components import show_section, print_info, print_success, print_error
            show_section("SAST — Static Application Security Testing")
            target = args.target or console.input("[red]File or directory to scan[/red]: ").strip()
            if not target:
                print_error("Path is required")
                return
            try:
                from tools.sast_engine import SASTEngine
                engine = SASTEngine()
                results = engine.scan(target)
                for finding in results.get("findings", []):
                    sev = finding.get("severity", "info").upper()
                    color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "grey70", "LOW": "dim"}.get(sev, "dim")
                    console.print(f"[{color}][{sev}][/{color}] {finding.get('message', '')} [{finding.get('file', '')}:{finding.get('line', '')}]")
                total = len(results.get("findings", []))
                print_success(f"SAST scan complete — {total} findings")
            except Exception as e:
                print_error(f"SAST error: {e}")

        elif args.command == "cloud":
            from ui_components import show_section, print_info, print_success, print_error
            show_section("Cloud / IaC Security Review")
            target = args.target or console.input("[red]File or directory[/red] (Terraform, YAML, JSON): ").strip()
            if not target:
                print_error("Path is required")
                return
            try:
                from tools.cloud_scanner import CloudScanner
                scanner = CloudScanner()
                result = scanner.scan(target)
                for finding in result.get("findings", []):
                    sev = finding.get("severity", "info").upper()
                    color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "grey70"}.get(sev, "dim")
                    console.print(f"[{color}][{sev}][/{color}] {finding.get('message', '')}")
                total = len(result.get("findings", []))
                print_success(f"Cloud scan complete — {total} findings")
            except Exception as e:
                print_error(f"Cloud scan error: {e}")

        elif args.command == "mobile":
            from ui_components import show_section, print_info, print_success, print_error
            show_section("Mobile API Analyzer")
            target = args.target or console.input("[red]Target URL or Burp export file[/red]: ").strip()
            if not target:
                print_error("Target is required")
                return
            try:
                from tools.mobile_api_tester import MobileAPITester
                tester = MobileAPITester()
                result = tester.analyze(target)
                for finding in result.get("findings", []):
                    console.print(f"[grey70][-][/grey70] {finding.get('type', '')} — {finding.get('description', '')}")
                total = len(result.get("findings", []))
                print_success(f"Mobile API analysis complete — {total} findings")
            except Exception as e:
                print_error(f"Mobile API error: {e}")

        elif args.command == "soc":
            from ui_components import show_section, print_info, print_success, print_error
            show_section("SOC Analyzer — Security Log Intelligence")
            target = args.target or console.input("[red]Log file or SIEM export (or press Enter for interactive)[/red]: ").strip()
            try:
                from tools.soc_analyzer import SOCAnalyzer
                analyzer = SOCAnalyzer()
                result = analyzer.analyze(target or None)
                for alert in result.get("alerts", []):
                    sev = alert.get("severity", "info").upper()
                    color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "grey70"}.get(sev, "dim")
                    console.print(f"[{color}][{sev}][/{color}] {alert.get('message', '')}")
                print_success(f"SOC analysis complete — {len(result.get('alerts', []))} alerts")
            except Exception as e:
                print_error(f"SOC analyzer error: {e}")

        elif args.command == "dashboard":
            from ui_components import show_section, print_info, print_success, print_error
            show_section("Interactive Security Dashboard")
            
            host = "127.0.0.1"
            port = 8080
            
            try:
                from tools.interactive_dashboard import InteractiveDashboard
                dash = InteractiveDashboard(host=host, port=port)
                dash.run()
            except Exception as e:
                # Fallback to simple dashboard if interactive fails
                try:
                    from tools.dashboard_server import DashboardServer, DashboardHandler
                    print_info(f"Fallback: Starting base dashboard on http://{host}:{port}")
                    server = DashboardServer((host, port), DashboardHandler)
                    server.serve_forever()
                except Exception as ex:
                    print_error(f"Dashboard failed to start: {ex}")

        elif args.command == "update":
            console.print("[dim]To update, run:[/dim]")
            console.print("  [red]git pull && ./setup.sh[/red]")

        elif args.command == "memory":
            from ui_components import show_section, print_info, create_status_table
            
            try:
                from tools.vector_memory import get_vector_memory, get_vector_memory as vm_get
                
                show_section("AI Memory System")
                
                vm = vm_get()
                stats = vm.get_memory_stats()
                
                # Display stats table
                table = create_status_table("Memory Statistics")
                table.add_column("Metric", style="red")
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
                
                mem_choice = console.input("\n[red]Select[/red] [dim](1-4)[/dim]: ")
                
                if mem_choice == "1":
                    query = console.input("[red]Search query[/red]: ")
                    target = console.input("[dim]Target filter (optional)[/dim]: ")
                    if query:
                        from tools.vector_memory import recall
                        results = recall(query, target or None, n_results=10)
                        
                        if results:
                            console.print(f"\n[red]Found {len(results)} memories:[/red]\n")
                            for i, mem in enumerate(results, 1):
                                content = mem['content'][:80]
                                sim = mem.get('similarity', 0)
                                console.print(f"  {i}. {content}... [dim]({sim:.0%})[/dim]")
                        else:
                            print_info("No matching memories found")
                            
                elif mem_choice == "2":
                    targets = vm.get_all_targets()
                    if targets:
                        console.print(f"\n[red]Known Targets ({len(targets)}):[/red]\n")
                        for t in targets[:20]:
                            console.print(f"  • {t}")
                        if len(targets) > 20:
                            print_info(f"... and {len(targets) - 20} more")
                    else:
                        print_info("No targets in memory")
                        
                elif mem_choice == "3":
                    target = console.input("[red]Target to clear[/red]: ")
                    if target:
                        from ui_components import confirm
                        if confirm(f"Delete all memories for '{target}'?", default=False):
                            vm.delete_target_memories(target)
                            print_success(f"Deleted memories for {target}")
                            
            except Exception as e:
                print_error(f"Memory system error: {e}")

        elif args.command == "bola":
            from ui_components import show_section, print_info, print_success, print_error
            from tools.bola_harness import BOLAHarness, parse_headers_input

            show_section("BOLA/IDOR Differential Harness")
            base_url = args.target or console.input("[red]Base URL[/red] (e.g., https://target.tld): ").strip()
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
                console.print(f"\n[bold red]{i}. {f.get('type','finding').upper()}[/bold red] [dim]({sev}, conf={conf})[/dim]")
                console.print(f"[white]{url}[/white]")
                ev = f.get("evidence", {})
                if isinstance(ev, dict):
                    console.print(f"[dim]A: {ev.get('account_a',{})}[/dim]")
                    console.print(f"[dim]B: {ev.get('account_b',{})}[/dim]")

        elif args.command == "waf":
            from ui_components import show_section, print_info, print_success, print_warning, print_error
            from tools.waf_evasion import WAFEvasionEngine

            show_section("WAF Detection & Evasion Testing")
            target_url = args.target or console.input("[red]Target URL to test[/red] (e.g., https://target.tld/search): ").strip()
            if not target_url:
                print_error("Target URL is required")
                return

            base_payload = console.input("[red]Base payload to test[/red] [dim](default: <script>alert(1)</script>)[/dim]: ").strip()
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
                console.print(f"[bold white]Payload:[/bold white] {best.payload[:80]}...")
                console.print(f"[bold white]Techniques:[/bold white] {', '.join(best.techniques)}")
                console.print(f"[bold white]Status:[/bold white] {best.status_code}")
            else:
                print_info("No bypass found in this run. Try different base payload or more attempts.")

            # Show all results table
            console.print("\n[bold red]Test Results:[/bold red]")
            for i, r in enumerate(results[:10], 1):
                status_color = "red" if r.blocked else "bold white"
                console.print(f"{i}. [{status_color}]{'BLOCKED' if r.blocked else 'BYPASS'}[/{status_color}] {r.payload[:50]}... (tech: {', '.join(r.techniques)})")

        elif args.command == "recon":
            from ui_components import show_section, print_info, print_success, print_warning, print_error
            from tools.smart_recon import SmartReconEngine, format_recon_for_display

            show_section("Smart Reconnaissance - Asset Correlation Engine")
            target = args.target or console.input("[red]Target domain[/red] (e.g., example.com): ").strip()
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
                    console.print(f"\n[grey70]{priority_count} high-priority targets identified[/grey70]")
                
                # Correlation findings
                corr_count = len([f for f in result.findings if f.get("type") == "correlation"])
                if corr_count > 0:
                    console.print(f"[red]{corr_count} asset correlations discovered[/red]")
                    
            except Exception as e:
                print_error(f"Recon failed: {e}")
                logger.exception("Smart recon failed")

        elif args.command == "cve-update":
            from ui_components import show_section, print_info, print_success, print_error
            from tools.cve_database import get_cve_database
            
            show_section("CVE Database Update")
            print_info("Fetching latest CVEs from NVD (National Vulnerability Database)...")
            print_info("This may take a few minutes depending on your connection.")
            
            try:
                db = get_cve_database(auto_update=False)
                result = db.update_database(days_back=30)
                
                if result.get("status") == "success":
                    print_success(f"CVE database updated successfully!")
                    console.print(f"  [bold white]Added:[/bold white] {result['added']} new CVEs")
                    console.print(f"  [bold white]Updated:[/bold white] {result['updated']} existing CVEs")
                    console.print(f"  [red]Total in database:[/red] {result['total']} CVEs")
                else:
                    print_error(f"Update failed: {result.get('error', 'Unknown error')}")
                    console.print("[dim]Note: You can still use Elengenix without CVE database updates.[/dim]")
            except Exception as e:
                print_error(f"CVE update error: {e}")
                console.print("[dim]Run 'elengenix doctor' to check system status.[/dim]")

        elif args.command == "evasion":
            from ui_components import show_section, print_info, print_success, print_warning, print_error
            from tools.edr_evasion import EDREvasionEngine, format_edr_report

            show_section("EDR/AV Evasion - Red Team Payload Generator")
            print_warning("FOR AUTHORIZED RED TEAM USE ONLY - ALL ACTIVITY IS LOGGED")
            
            engine = EDREvasionEngine()
            
            action = console.input(
                "[red]Select action[/red] [list/generate/plan]: "
            ).strip().lower()
            
            if action == "list":
                category = console.input("[red]Filter by category[/red] [amsi/process/memory/sandbox/signature/all]: ").strip()
                if category == "all":
                    category = None
                techniques = engine.list_techniques(category=category)
                
                print_success(f"Found {len(techniques)} techniques:")
                for t in techniques:
                    risk_marker = "[H]" if t.detection_risk == "high" else "[M]" if t.detection_risk == "medium" else "[L]"
                    console.print(f"  {risk_marker} [{t.difficulty}] {t.name} ({t.category}) - {t.platform}")
                    
            elif action == "generate":
                tech_name = console.input("[red]Technique name[/red]: ").strip()
                if not tech_name:
                    print_error("Technique name required")
                    return
                    
                result = engine.generate_payload(tech_name)
                if "error" in result:
                    print_error(result["error"])
                    return
                
                console.print(format_edr_report(result))
                
                # Save to file
                save = console.input("[red]Save payload to file?[/red] (y/N): ").strip().lower()
                if save in ("y", "yes"):
                    timestamp = int(time.time())
                    out_path = Path(f"reports/evasion_{tech_name.replace(' ', '_').lower()}_{timestamp}.txt")
                    out_path.parent.mkdir(exist_ok=True)
                    out_path.write_text(result["generated_code"], encoding="utf-8")
                    print_success(f"Saved to: {out_path}")
                    
            elif action == "plan":
                target_edr = console.input("[red]Target EDR[/red] (e.g., crowdstrike/sentinelone/defender): ").strip()
                objectives = console.input("[red]Objectives[/red] [persistence,privilege,escalation,evasion]: ").strip()
                obj_list = [o.strip() for o in objectives.split(",") if o.strip()]
                
                plan = engine.generate_red_team_plan(target_edr=target_edr or None, objectives=obj_list or None)
                console.print(format_edr_report(plan))
                
            else:
                print_info("Available actions: list, generate, plan")

        elif args.command == "report":
            from ui_components import show_section, print_info, print_success, print_error
            from tools.pdf_report_generator import PDFReportGenerator, ReportMetadata, format_report_summary

            show_section("Professional Report Generator")
            
            findings_file = args.target or console.input("[red]Findings JSON file[/red]: ").strip()
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
                target = console.input("[red]Target name[/red]: ").strip() or "Unknown Target"
                author = console.input("[red]Author name[/red]: ").strip() or "Elengenix Security"
                title = console.input("[red]Report title[/red]: ").strip() or f"Security Assessment - {target}"
                
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

        elif args.command == "profile":
            """Profile management - list, create, delete profiles."""
            from tools.profile_manager import ProfileManager
            from ui_components import print_info, print_success, print_error
            
            manager = ProfileManager()
            
            if not args.target:
                # List profiles
                console.print(manager.format_profile_list())
            else:
                subcommand = args.target
                
                if subcommand == "list":
                    console.print(manager.format_profile_list())
                
                elif subcommand == "create":
                    console.print("[red]Create custom profile[/red]")
                    name = console.input("Profile name: ").strip()
                    if not name:
                        print_error("Name required")
                        return
                    
                    base = console.input("Base on profile [quick]: ").strip() or "quick"
                    desc = console.input("Description: ").strip()
                    
                    # Collect options
                    options = {}
                    print_info("Add options (empty line to finish):")
                    while True:
                        opt = console.input("  Option (e.g., rate-limit 10): ").strip()
                        if not opt:
                            break
                        parts = opt.split()
                        if len(parts) >= 2:
                            options[parts[0]] = parts[1]
                        elif len(parts) == 1:
                            options[parts[0]] = True
                    
                    success = manager.clone_profile(
                        base, name,
                        modifications={
                            "description": desc or f"Custom {name}",
                            "add_options": options,
                            "tags": ["custom"],
                        }
                    )
                    
                    if success:
                        print_success(f"Created profile: {name}")
                    else:
                        print_error("Failed to create profile")
                
                elif subcommand == "delete":
                    name = console.input("Profile name to delete: ").strip()
                    if manager.delete_profile(name):
                        print_success(f"Deleted profile: {name}")
                    else:
                        print_error("Failed to delete profile")
                
                else:
                    print_error(f"Unknown profile command: {subcommand}")
                    console.print("Usage: elengenix profile [list|create|delete]")

        elif args.command in ["programs", "intel", "bounty"]:  # Phase 1: Intelligence Discovery
            """Discover and rank bug bounty programs from HackerOne."""
            from tools.bounty_intelligence import BountyIntelligence
            from ui_components import print_info, print_success, print_error, print_warning
            
            # Check for API credentials
            api_key = os.environ.get("HACKERONE_API_KEY")
            api_user = os.environ.get("HACKERONE_API_USER")
            
            intel = BountyIntelligence(api_key=api_key, api_username=api_user)
            
            if args.target == "api":
                # Force API mode
                if not api_key:
                    print_error("HACKERONE_API_KEY not set")
                    console.print("Set with: export HACKERONE_API_KEY=your_key")
                    console.print("Get key at: https://hackerone.com/settings/api")
                    return
                
                print_info("Discovering programs via HackerOne API...")
                programs = intel.discover_programs_api(min_bounty=500, limit=15)
            
            elif args.target == "public":
                # Force public scraping mode
                print_info("Discovering programs via public scraping...")
                programs = intel.discover_programs_public(limit=15)
            
            elif args.target == "top":
                # Get single top recommendation
                print_info("Finding top bounty program...")
                top = intel.get_top_recommendation(min_bounty=500)
                
                if top:
                    print_success(f"Top Pick: {top.name}")
                    console.print(f"  Reward: {top.bounty_range}")
                    console.print(f"  URL: {top.url}")
                    if top.response_time_hours:
                        days = top.response_time_hours / 24
                        console.print(f"  Response: ~{days:.1f} days")
                    console.print(f"  Score: {top.score_total:.1f}/100")
                    console.print(f"\n[red]Start scanning:[/red]")
                    console.print(f"  elengenix deep {top.url}")
                    console.print(f"  elengenix autonomous {top.url} --mode auto")
                else:
                    print_error("No programs found")
                return
            
            else:
                # Auto mode: API if available, else public
                if api_key:
                    print_info("Mode: API (authenticated)")
                    programs = intel.discover_programs_api(min_bounty=500, limit=10)
                else:
                    print_info("Mode: Public (no API key)")
                    print_warning("Set HACKERONE_API_KEY for more programs and data")
                    programs = intel.discover_programs_public(limit=10)
            
            if not programs:
                print_error("No programs found. Check connection or try later.")
                return
            
            # Rank programs
            print_info(f"Ranking {len(programs)} programs...")
            ranked = intel.rank_programs(programs)
            
            # Display results
            console.print(intel.format_programs_list(ranked, show_scores=True))
            
            # Show top recommendation
            top = ranked[0]
            print_success(f"\nTop recommendation: {top.name}")
            console.print(f"  Potential reward: {top.bounty_range}")
            console.print(f"  Start scan: [red]elengenix quick {top.url}[/red]")
            
            # Offer to start scanning
            from ui_components import confirm
            if confirm("Start scanning now?", default=False):
                args.command = "quick"
                args.target = top.url.replace("https://", "").replace("http://", "")
                # Fall through to quick command handler

        elif args.command == "mission":
            """Mission control - start autonomous scanning mission."""
            from tools.smart_scanner import SmartScanner
            from tools.token_manager import get_token_manager
            from ui_components import print_info, print_success, print_error
            
            if not args.target:
                print_error("Usage: elengenix mission <target>")
                console.print("\n  Start autonomous scanning mission with:")
                console.print("    elengenix mission target.com")
                console.print("    elengenix mission target.com --pause-after 2")
                return
            
            target = args.target
            pause_after = 3  # Default: pause after 3 hours without findings
            
            # Parse pause-after option
            if "--pause-after" in sys.argv:
                idx = sys.argv.index("--pause-after")
                if idx + 1 < len(sys.argv):
                    try:
                        pause_after = int(sys.argv[idx + 1])
                    except ValueError:
                        print_error("Invalid pause-after value")
                        return
            
            print_info(f"Starting autonomous mission for {target}")
            print_info(f"Auto-pause after {pause_after}h without findings")
            
            try:
                scanner = SmartScanner(
                    target=target,
                    auto_pause=True,
                    pause_after_hours=pause_after,
                )
                results = scanner.run()
                
                print_success(f"\nMission {results['mission_id']} completed")
                console.print(f"  Status: {results['status']}")
                console.print(f"  Findings: {len(results.get('findings', []))}")
                console.print(f"  Tokens used: {results['tokens_used']}")
                console.print(f"  Duration: {results['duration_seconds']:.0f}s")
                
                if results['status'] == 'paused':
                    console.print(f"\n[dim]Mission paused. Resume with:[/dim]")
                    console.print(f"  elengenix resume {results['mission_id']}")
                
            except Exception as e:
                print_error(f"Mission failed: {e}")
                logger.exception("Mission failed")

        elif args.command == "pause":
            """Pause a running mission."""
            from tools.smart_scanner import SmartScanner
            from ui_components import print_info, print_success, print_error
            
            if not args.target:
                print_error("Usage: elengenix pause <mission_id>")
                return
            
            mission_id = args.target
            scanner = SmartScanner.load(mission_id)
            
            if not scanner:
                print_error(f"Mission not found: {mission_id}")
                return
            
            scanner.pause()
            print_success(f"Mission {mission_id} paused")

        elif args.command == "resume":
            """Resume a paused mission."""
            from tools.smart_scanner import SmartScanner
            from ui_components import print_info, print_success, print_error
            
            if not args.target:
                print_error("Usage: elengenix resume <mission_id>")
                return
            
            mission_id = args.target
            scanner = SmartScanner.load(mission_id)
            
            if not scanner:
                print_error(f"Mission not found: {mission_id}")
                return
            
            print_info(f"Resuming mission {mission_id}")
            results = scanner.resume()
            
            print_success(f"Mission {mission_id} resumed")
            console.print(f"  Status: {results['status']}")
            console.print(f"  Findings: {len(results.get('findings', []))}")

        elif args.command == "history":
            """Command history management."""
            from tools.history_manager import get_history_manager
            from ui_components import print_info, print_success, print_error
            
            history_mgr = get_history_manager()
            
            subcommand = args.target or "list"
            
            if subcommand == "list" or subcommand == "ls":
                console.print(history_mgr.format_history_list())
            
            elif subcommand == "stats":
                stats = history_mgr.get_stats()
                console.print("\n[bold]Command History Statistics[/bold]")
                console.print(f"  Total runs: {stats['total_commands']}")
                console.print(f"  Unique commands: {stats['unique_commands']}")
                console.print(f"  Favorites: {stats['favorite_commands']}")
                console.print(f"  Success rate: {stats['success_rate']:.1%}")
                
                if stats['most_used']:
                    cmd, count = stats['most_used']
                    console.print(f"\n[dim]Most used: {cmd} ({count} times)[/dim]")
            
            elif subcommand == "search":
                query = console.input("Search query: ").strip()
                if query:
                    results = history_mgr.search(query)
                    if results:
                        console.print(f"\n[bold white]Found {len(results)} matches:[/bold white]")
                        for entry in results[:10]:
                            console.print(f"  • elengenix {entry.command} {entry.args}")
                    else:
                        print_info("No matches found")
            
            elif subcommand == "suggest":
                suggestions = history_mgr.get_contextual_suggestions()
                if suggestions:
                    console.print("\n[bold]Suggested commands:[/bold]")
                    for i, sugg in enumerate(suggestions, 1):
                        console.print(f"  {i}. elengenix {sugg}")
                else:
                    print_info("Try: elengenix quick <target>")
            
            elif subcommand == "clear":
                from ui_components import confirm
                if confirm("Clear all history?"):
                    history_mgr.clear_history()
                    print_success("History cleared")
            
            else:
                console.print(history_mgr.format_history_list())

        elif args.command in ["quick", "deep", "bounty", "stealth", "api", "web"]:
            """Profile shortcuts - one-command execution."""
            from tools.profile_manager import ProfileManager
            from ui_components import print_success, print_error
            
            manager = ProfileManager()
            
            if not args.target:
                print_error(f"Usage: elengenix {args.command} <target>")
                console.print(f"\nProfile: {args.command}")
                profile = manager.get_profile(args.command)
                if profile:
                    console.print(f"Description: {profile.description}")
                    console.print(f"Based on: {profile.base_command}")
                return
            
            # Expand profile to actual command
            expanded = manager.expand_profile(args.command, args.target)
            
            if not expanded:
                print_error(f"Profile not found: {args.command}")
                return
            
            cmd, cmd_args = expanded
            print_success(f"Profile '{args.command}' → elengenix {cmd} {' '.join(cmd_args[:3])}...")
            
            # Re-route to actual command handler
            args.command = cmd
            # args._profile_expanded = True  # Mark as expanded to prevent recursion
            
            # Re-process with new command
            # This is handled by falling through to the next elif blocks
            # Store original args
            original_target = args.target
            args.target = None  # Will be set from cmd_args
            
            # Extract target from cmd_args if present
            for arg in cmd_args:
                if not arg.startswith("--"):
                    args.target = arg
                    break
            
            # Apply options
            for i, arg in enumerate(cmd_args):
                if arg.startswith("--"):
                    key = arg[2:].replace("-", "_")
                    if i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith("--"):
                        setattr(args, key, cmd_args[i + 1])
                    else:
                        setattr(args, key, True)
            
            # Now let the actual command handler run
            # Fall through to the next matching elif

        # Record successful command in history
        if args.command and args.command != "auto":
            history.record_command(
                command=args.command,
                args=args.target or "",
                duration=0,  # Would need timing from start
                success=True,
                target=args.target or "",
            )

    except KeyboardInterrupt:
        console.print("\n[dim]Operation canceled[/dim]")
        # Record failed command
        if args.command and args.command != "auto":
            history.record_command(
                command=args.command,
                args=args.target or "",
                success=False,
                target=args.target or "",
            )
        sys.exit(0)
    except Exception as e:
        from ui_components import print_error, confirm
        # Log to file for debugging, but keep console clean
        logger.debug("Full Traceback:", exc_info=True)
        
        # Display short error message
        error_msg = str(e)
        if "NameError" in error_msg or "UnboundLocalError" in error_msg:
            print_error(f"CRITICAL CODE ERROR: {error_msg}")
        else:
            print_error(f"SYSTEM FAILURE: {error_msg[:100]}...")
            
        # Record failed command
        if args.command and args.command != "auto":
            history.record_command(
                command=args.command,
                args=args.target or "",
                success=False,
                target=args.target or "",
            )
            
        if confirm("Attempt emergency repair (doctor)?", default=True):
            from tools.doctor import check_health
            check_health()

if __name__ == "__main__":
    ensure_dependencies()
    main()
