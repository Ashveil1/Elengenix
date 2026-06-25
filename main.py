#!/usr/bin/env python3
"""
main.py — Elengenix Professional CLI Entry Point
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
import asyncio
from datetime import datetime, timezone
from pathlib import Path

# --- Load .env file (API keys, model preferences, etc.) ---
try:
    from dotenv import load_dotenv
    load_dotenv(override=False)  # Don't override existing env vars
except ImportError:
    pass  # python-dotenv not installed, user must set env vars manually

# --- Suppress urllib3 InsecureRequestWarning (we intentionally use verify=False for hostile targets) ---
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except (ImportError, AttributeError):
    pass

# --- Rich & Interactive UI ---
from rich.console import Console
from rich.panel import Panel

try:
    from ui_components import console, show_section, print_error, print_success, print_info, show_progress_bar
except ImportError:
    console = Console()
    def show_section(*a, **kw): pass
    def print_error(*a, **kw): pass
    def print_success(*a, **kw): pass
    def print_info(*a, **kw): pass
    def show_progress_bar(*a, **kw):  # type: ignore[no-redef]
        from rich.progress import Progress
        return Progress(*a, **kw)

# ── Logging Setup ─────────────────────────────────────────────────────────────
LOG_DIR = Path("data")
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "elengenix.log", encoding="utf-8"),
        logging.StreamHandler(sys.stderr)
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
    import ipaddress
    # Strip protocol and path
    cleaned = target.replace("http://", "").replace("https://", "").split("/")[0]
    # Block shell metacharacters
    forbidden = ["|", "&", ";", "`", "$(", "${", ">", "<", "\\", "'", '"', "!", "\n", "\r"]
    if any(c in cleaned for c in forbidden):
        return False
    # Block private/loopback IPs
    try:
        ip = ipaddress.ip_address(cleaned)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            return False
    except ValueError:
        pass  # Not an IP, continue with domain check
    # Domain and IPv4 Regex
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(pattern, cleaned))


def is_authorized_scan_target(target: str) -> bool:
    """Return True when target format is valid and target is in configured scope."""
    if not validate_target(target):
        return False

    from orchestrator import is_in_scope
    return is_in_scope(target)


def require_authorized_scan_target(target: str) -> bool:
    """Validate scan target and print a clear error for invalid or out-of-scope input."""
    if not validate_target(target):
        print_error("[FAIL] SECURITY ERROR: Invalid target format")
        return False

    from orchestrator import is_in_scope, normalize_target
    normalized = normalize_target(target)
    if not is_in_scope(target):
        print_error(f"[FAIL] SCOPE VIOLATION: '{normalized}' is not in the authorized scope")
        console.print("[dim]Configure scope with scope.txt or ELENGENIX_SCOPE.[/dim]")
        return False

    return True

# ── Main Logic ────────────────────────────────────────────────────────────────
def ensure_path_priorities() -> None:
    """Ensure Go tools and local binaries take priority in PATH."""
    go_first = str(Path.home() / "Downloads" / "go-tools" / "bin")
    go_second = str(Path.home() / "go" / "bin")
    local_bin = str(Path.home() / ".local" / "bin")
    current = os.environ.get("PATH", "")
    new_parts = [p for p in [go_first, go_second, local_bin] if Path(p).is_dir() and p not in current]
    if new_parts:
        os.environ["PATH"] = ":".join(new_parts + [current])

def show_banner():
    """Clean minimal banner."""
    from ui_components import show_main_banner
    show_main_banner()

def main():
    ensure_path_priorities()
    show_banner()

    command_choices = [
        "universal", "scan", "gateway", "configure", "update", "doctor",
        "arsenal", "memory", "cve-update", "bola", "waf", "recon", "evasion",
        "report", "menu", "auto", "help", "bb", "check", "test", "red", "pdf",
        "hack", "hunt", "research", "poc", "autonomous", "welcome", "quick", "deep",
        "bounty", "stealth", "api", "web", "profile", "history", "programs",
        "intel", "mission", "pause", "resume", "cli", "tui", "cli-textual", "cli-legacy", "clitest",
        # New unified commands
        "sast", "cloud", "mobile", "soc", "dashboard", "compliance",
        "list-tools", "examples", "prefetch", "scan-report",
        "marketplace", "plugins",
    ]

    parser = argparse.ArgumentParser(description="Elengenix CLI", add_help=False)
    parser.add_argument("command", nargs="?", default="auto", help="Command to run")
    parser.add_argument("target", nargs="?", help="Target domain or IP")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second")
    parser.add_argument("--framework", type=str, default="generic", help="Target framework for PoC generation")
    parser.add_argument("--version", type=str, default="", help="Target version for PoC generation")
    parser.add_argument("--mode", type=str, default="ask", choices=["strict", "ask", "auto"], help="Governance mode for autonomous operations")
    parser.add_argument("--smart-scan", action="store_true", help="Use intelligent smart scan with file relationship analysis and finding correlation")
    parser.add_argument("--format", type=str, default=None, help="Output format for scan-report (html, md, sarif, json, txt, all)")
    parser.add_argument("--output", type=str, default=None, help="Output path for scan-report")
    parser.add_argument("--subcommand", type=str, default=None, help="Subcommand for marketplace/plugins")
    parser.add_argument("--query", type=str, default=None, help="Search query for marketplace")
    parser.add_argument("--verified", action="store_true", help="Show only verified plugins")
    parser.add_argument("--upgrade", action="store_true", help="Upgrade/force reinstall plugin")
    parser.add_argument("--check", action="store_true", help="Check for updates without applying")
    parser.add_argument("--apply", action="store_true", help="Apply update if available")
    parser.add_argument("--force", action="store_true", help="Force refresh (skip cache)")
    parser.add_argument("--yes", "-y", action="store_true", help="Auto-yes to prompts")
    parser.add_argument("--no-auto-report", action="store_false", dest="auto_report", help="Skip auto-generated HTML report after scan")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress phase-by-phase output; show only summary and report path (P3.2)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind address for API server")
    parser.add_argument("--port", type=int, default=8443, help="Port for API server")
    
    args, _ = parser.parse_known_args()

    # Set environment variable for smart scan mode (propagates to watchman/bot)
    if args.smart_scan:
        os.environ["ELENGENIX_SMART_SCAN"] = "1"

    # Set environment variable for quiet mode (P3.2: suppresses phase-by-phase output)
    if args.quiet:
        os.environ["ELENGENIX_QUIET"] = "1"
        # Suppress non-essential console output (errors/warnings still print via stderr logger)
        from rich.console import Console as _NoOutConsole
        class _SilentConsole(_NoOutConsole):
            def print(self, *a, **kw): pass
        try:
            import ui_components as _ui
            _ui.console = _SilentConsole()
        except Exception:
            pass

    # Welcome wizard on first run (before processing command)
    if args.command == "welcome":
        from tools.welcome_wizard import WelcomeWizard
        wizard = WelcomeWizard()
        wizard.run_setup()
        return
    
    # Auto-run welcome if first time (unless running specific commands)
    skip_welcome_commands = ["doctor", "configure", "update", "welcome", "cli", "cli-textual"]
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
        from tools.command_suggest import CommandSuggester
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
                # Show help with history context
                from tools.auto_detector import CommandSimplifier
                console.print(f"[grey70]Unknown command: {args.command}[/grey70]")
                console.print(CommandSimplifier.get_help_text())
                # Show recent history
                recent = history.get_recent_commands(hours=24, limit=5)
                if recent:
                    console.print("\n[dim]Recent commands:[/dim]")
                    for entry in recent:
                        console.print(f"  [red]elengenix {entry.command} {entry.args}[/red]")
                return
        else:
            # No suggestion found, show help
            from tools.auto_detector import CommandSimplifier
            console.print(f"[grey70]Unknown command: {args.command}[/grey70]")
            console.print(CommandSimplifier.get_help_text())
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

    # If no command or target is specified and it's "auto" (default), run the TUI
    if args.command == "auto" and not args.target:
        args.command = "tui"

    # ── D-handlers: short-circuit before auto-detect (D1+D2) ──
    if args.command == "list-tools":
        _cmd_list_tools()
        return
    if args.command == "examples":
        _cmd_examples()
        return
    # ── F-handler: prefetch — pre-download AI models (F1) ──
    if args.command == "prefetch":
        _cmd_prefetch()
        return

    # ── New: scan-report — generate Apple-level HTML/MD/SARIF reports from findings JSON ──
    if args.command == "scan-report":
        _cmd_scan_report(args)
        return

    # ── New: marketplace — plugin marketplace (search, install, list) ──
    if args.command == "marketplace":
        # Re-parse from sys.argv to handle subcommands naturally
        # Usage: elengenix marketplace [search|install|uninstall|list] [name] [--query ...]
        import sys as _sys
        m_args = _sys.argv[2:]  # skip "main.py marketplace"
        args.subcommand = m_args[0] if m_args and not m_args[0].startswith("-") else "list"
        if args.subcommand in ("install", "uninstall") and len(m_args) >= 2:
            args.name = m_args[1]
        elif args.subcommand == "search":
            args.query = " ".join(a for a in m_args[1:] if not a.startswith("-")) or ""
        _cmd_marketplace(args)
        return

    # ── New: plugins — manage loaded plugins (list, info, reload) ──
    if args.command == "plugins":
        # Re-parse from sys.argv: elengenix plugins [list|info|reload] [name]
        import sys as _sys
        p_args = _sys.argv[2:]
        args.subcommand = p_args[0] if p_args and not p_args[0].startswith("-") else "list"
        if args.subcommand in ("info", "reload") and len(p_args) >= 2:
            args.name = p_args[1]
        _cmd_plugins(args)
        return

    # Auto-detect mode (default) - Smart routing based on target
    # Auto-detect mode — skip for explicit commands
    explicit_commands = {"scan", "ai", "cli", "tui", "hunt", "recon", "sast", "cloud", "mobile", "soc", "bola", "waf"}
    if args.command == "auto" or (args.command and args.target and args.command not in explicit_commands):
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
            from agent import get_agent
            from bot_utils import send_telegram_notification
            from shutil import which

            # Silence INFO logs during scan
            logging.getLogger().setLevel(logging.WARNING)

            target = args.target or console.input("Enter target: ").strip()
            if not target: return
            if not require_authorized_scan_target(target):
                return

            env_models = [m.strip() for m in os.environ.get("ACTIVE_MODELS", "").split(",") if m.strip()]
            team_size = len(env_models)

            print()
            console.print(f"\n[bold #ffffff]  ELENGENIX AI SCAN 1.0.0[/bold #ffffff]")
            console.print(f"  Target: [red]{target}[/red]")
            if team_size >= 2:
                console.print(f"  Team: [red]{team_size} agents[/red]")
            print()

            # ── Phase 0: Elengenix Framework Pre-flight (runs FIRST, before AI agent) ──
            console.print("[bold #ffffff]Phase 0: Elengenix Framework Pre-flight[/bold #ffffff]")
            
            subdomain_hint = ""  # Initialize so preflight can extend it
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
                        asyncio.wait_for(run_elengenix_modules(target, preflight_dir, timeout=90), timeout=110)
                    )
                finally:
                    loop.close()
                if preflight_findings:
                    preflight_file = preflight_dir / "elengenix_findings.json"
                    preflight_file.write_text(json.dumps(preflight_findings, indent=2, default=str))
                    console.print(f"  [OK] Pre-flight: {len(preflight_findings)} findings saved to {preflight_file}")
                    # Inject preflight findings into the AI prompt as context
                    finding_summary = "\n".join(
                        f"  - [{f.get('severity', '?')}] {f.get('type', '?')}: {f.get('title', '?')[:80]}"
                        for f in preflight_findings[:20]
                    )
                    subdomain_hint += f"\nPre-flight Elengenix framework findings ({len(preflight_findings)} total):\n{finding_summary}\n"
                else:
                    console.print("  [dim]Pre-flight: 0 findings (target may be down or unreachable)[/dim]")
            except Exception as e:
                import traceback
                console.print(f"  [WARN] Pre-flight failed: {e}")

            # Phase 1: AI-driven reconnaissance
            console.print("[bold #ffffff]Phase 1: AI-Driven Reconnaissance[/bold #ffffff]")

            # Pre-seed subdomains via OTX (free, no API key needed)
            initial_subs = set()
            try:
                from tools.wayback_tool import fetch_otx_urls
                from urllib.parse import urlparse
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

            from agent import get_agent
            from bot_utils import send_telegram_notification
            from shutil import which
            agent = get_agent()

            # Check available tools for AI context
            tool_map = {
                "subfinder": which("subfinder"),
                "httpx": which("httpx"),
                "nuclei": which("nuclei"),
                "naabu": which("naabu"),
                "ffuf": which("ffuf"),
                "dalfox": which("dalfox"),
                "gau": which("gau"),
                "katana": which("katana"),
                "curl": which("curl"),
                "dig": which("dig"),
                "nmap": which("nmap"),
                "jq": which("jq"),
            }
            avail_tools = [name for name, path in tool_map.items() if path]
            tools_context = f"\nAvailable tools on system: {', '.join(sorted(avail_tools))}\n"

            def scan_callback(msg):
                import re
                try:
                    safe_msg = re.sub(r'\[/?[^\]]+\]', '', msg)
                    
                    if msg.startswith("### AI THINKING:"):
                        thought = msg.replace("### AI THINKING:", "").strip()
                        console.print(f"\n[THINKING] {thought[:150]}")
                    elif msg.startswith("[THINKING]"):
                        thought = msg.replace("[THINKING]", "").strip()
                        console.print(f"  >> {thought[:120]}...")
                    elif msg.startswith("[OK]") or msg.startswith("[FAIL]"):
                        parts = msg.split(" ", 2)
                        rest = parts[2] if len(parts) > 2 else ""
                        action_part = parts[1] if len(parts) > 1 else ""
                        if "shell" in action_part or "run_tool" in action_part:
                            cmd_str = rest.split(":", 1)[0].strip() if ":" in rest else rest[:80]
                            if cmd_str and cmd_str != "]":
                                console.print(f"  $ {cmd_str}")
                            res = rest.split(":", 1)[1].strip()[:200] if ":" in rest else ""
                            if res:
                                console.print(f"  -> {res[:150]}")
                        elif "search_web" in action_part:
                            query = rest.split(":", 1)[0].strip() if ":" in rest else rest[:80]
                            console.print(f"  [WEB] {query}")
                        elif "ask_user" in action_part:
                            console.print(f"  [ASK] {rest[:150]}")
                    elif msg.startswith(" Step"):
                        step_text = msg.strip()
                        console.print(f"  >> Step {step_text[:100]}")
                    elif msg.startswith("AI classified"):
                        pass
                    elif msg.startswith("###"):
                        console.print(f"\n{msg[:200]}")
                    elif msg.startswith("CVSS"):
                        console.print(f"{msg}")
                    elif msg.startswith("__PRIVILEGED__:"):
                        console.print(f"\n[PRIVILEGED] {msg.replace('__PRIVILEGED__:', '').strip()[:150]}")
                except Exception:
                    # Fallback - just print the raw safe message
                    try:
                        safe_msg = re.sub(r'\[/?[^\]]+\]', '', msg)
                        console.print(f"  {safe_msg[:200]}")
                    except:
                        console.print(f"  {msg[:200]}")

            subdomain_hint = ""
            if initial_subs:
                subdomain_hint = f"\nPre-discovered subdomains (via OTX):\n" + "\n".join(f"  {s}" for s in sorted(initial_subs)[:30]) + "\n"

            try:
                response = agent.process_universal(
                    f"Perform a full security reconnaissance and vulnerability assessment on {target}. "
                    f"Your mission:\n"
                    f"- Use shell commands directly to run any tools you need\n"
                    f"- You decide what tools to use and in what order (no fixed methodology)\n"
                    f"{subdomain_hint}"
                    f"{tools_context}"
                    f"TIPS:\n"
                    f"- For httpx, use: httpx -list subdomains.txt -silent -json (NOT -l)\n"
                    f"- For nuclei, use: nuclei -list live_hosts.txt -severity critical,high,medium\n"
                    f"- You can use pipes (|) and redirects (>) in your shell commands\n"
                    f"- If a tool is missing, ask the user with ask_user action\n"
                    f"- Run actual tools, report results honestly. If something fails, try another approach.\n"
                    f"- IMPORTANT: Write temp files to current directory (./subdomains.txt) NOT /tmp\n",
                    target=target, callback=scan_callback, mode="bug_bounty",
                    preflight_findings=preflight_findings,
                )
                if response:
                    # Strip any Rich tags from AI response before printing
                    import re
                    safe_response = re.sub(r'\[/?[^\]]+\]', '', response[:2000])
                    console.print(f"\nAI Analysis:")
                    console.print(f"  {safe_response[:2000]}")
                    report_file = Path(f"reports/scan_{target}_{int(time.time())}.md")
                    report_file.parent.mkdir(parents=True, exist_ok=True)
                    # Build report with preflight findings section if available
                    preflight_section = ""
                    if preflight_findings:
                        rows = "\n".join(
                            f"| {f.get('severity', '?')} | {f.get('type', '?')} | {f.get('title', '?')[:80]} |"
                            for f in preflight_findings
                        )
                        preflight_section = (
                            f"\n## Elengenix Framework Pre-flight Findings ({len(preflight_findings)})\n\n"
                            f"**Source**: 5 Elengenix pure-Python modules + PythonRecon\n"
                            f"(No third-party tools required)\n\n"
                            f"| Severity | Type | Title |\n"
                            f"|----------|------|-------|\n"
                            f"{rows}\n\n"
                            f"Full details: `{preflight_file}`\n"
                        )
                    # Detect if AI was useful vs. just "50 steps, 1 action"
                    ai_unhelpful = (
                        not response
                        or "reached 50 steps" in response
                        or "reached 1 steps" in response
                        or "All AI providers failed" in safe_response
                        or "[ELENGENIX_AI_UNAVAILABLE]" in response
                    )
                    if "[ELENGENIX_AI_UNAVAILABLE]" in response:
                        # P2.4: Prominent banner when AI is unavailable
                        console.print(Panel(
                            f"[bold yellow]AI PROVIDER UNAVAILABLE[/bold yellow]\n\n"
                            f"All configured AI providers (gemini/openai/nvidia) failed after consecutive errors.\n"
                            f"Showing {len(preflight_findings) if preflight_findings else 0} Elengenix preflight findings instead.\n\n"
                            f"[bold]Fix AI access:[/bold]\n"
                            f"  1. Check API keys in .env (GEMINI_API_KEY, OPENAI_API_KEY, etc.)\n"
                            f"  2. Verify provider quota: https://aistudio.google.com/apikey\n"
                            f"  3. Or reconfigure: python3 main.py configure\n",
                            border_style="yellow",
                            title="[bold red]AI Quota / Auth Error[/bold red]",
                        ))
                    ai_section_header = "## AI Analysis"
                    ai_section_body = response
                    if ai_unhelpful and preflight_findings:
                        # Generate auto-analysis from preflight findings
                        ai_section_header = "## AI Analysis (auto-generated from preflight — AI providers unavailable)"
                        sev_count: dict = {}
                        type_count: dict = {}
                        for f in preflight_findings:
                            sev = f.get("severity", "?")
                            sev_count[sev] = sev_count.get(sev, 0) + 1
                            t = f.get("type", "?")
                            type_count[t] = type_count.get(t, 0) + 1
                        sev_lines = "\n".join(f"- **{k}**: {v}" for k, v in sorted(sev_count.items(), key=lambda x: -x[1]))
                        type_lines = "\n".join(f"- {k}: {v}" for k, v in sorted(type_count.items(), key=lambda x: -x[1]))
                        # Highlight high-priority targets
                        hi = [f for f in preflight_findings if f.get("severity") in ("High", "Critical")]
                        hi_lines = "\n".join(
                            f"- **{f.get('severity')} {f.get('type')}**: {f.get('title', '?')[:80]}\n  URL: `{f.get('url', '?')}`"
                            for f in hi[:10]
                        ) or "- (none)"
                        # Suggest next steps
                        next_steps = []
                        if any(f.get("type") == "param_discovery" for f in preflight_findings):
                            next_steps.append("1. **Test the discovered parameters** for XSS, SQLi, command injection")
                        if any(f.get("type") == "endpoint" for f in preflight_findings):
                            next_steps.append("2. **Probe discovered endpoints** for authentication / access control issues")
                        if any(f.get("type") == "port" for f in preflight_findings):
                            next_steps.append("3. **Investigate non-standard open ports** for exposed services")
                        if any(f.get("type") == "waf" for f in preflight_findings):
                            next_steps.append("4. **Account for the detected WAF** when designing active attacks")
                        next_steps.append("5. **Re-run with a working AI provider** for deeper analysis")
                        ai_section_body = (
                            f"**Note**: All AI providers (gemini/openai/nvidia) returned errors during this scan.\n"
                            f"Auto-generated summary from {len(preflight_findings)} Elengenix framework findings:\n\n"
                            f"### Severity breakdown\n{sev_lines}\n\n"
                            f"### Type breakdown\n{type_lines}\n\n"
                            f"### High-priority targets ({len(hi)})\n{hi_lines}\n\n"
                            f"### Recommended next steps\n" + "\n".join(next_steps) + "\n\n"
                            f"### Fix AI provider access\n- Verify API keys in `.env` (GEMINI_API_KEY, OPENAI_API_KEY, etc.)\n"
                            f"- Check provider quota at https://aistudio.google.com/apikey\n"
                            f"- Or configure a different provider via `python3 main.py configure`\n"
                        )
                        console.print(f"\n[bold yellow]AI providers unavailable — generated auto-analysis from {len(preflight_findings)} preflight findings[/bold yellow]")
                    report_file.write_text(
                        f"# Scan Report: {target}\n"
                        f"**Date**: {datetime.now(timezone.utc).isoformat()}\n"
                        f"**Tool**: Elengenix 1.0.0\n"
                        f"{preflight_section}"
                        f"\n{ai_section_header}\n\n{ai_section_body}\n"
                    )
                    console.print(f"\nReport saved: {report_file}")
                    # Auto-generate HTML report if findings exist
                    if preflight_findings and preflight_file and getattr(args, 'auto_report', True):
                        try:
                            from tools.report_gen import ExecutiveSummary, FindingReport, export_report, ReportFormat
                            summary = ExecutiveSummary(
                                target=target,
                                scan_date=datetime.now(timezone.utc).isoformat(),
                                duration_seconds=0,
                                total_findings=len(preflight_findings),
                                tool_version="1.0.0",
                                risk_level="Unknown",
                            )
                            findings_reports = []
                            for f in preflight_findings:
                                findings_reports.append(FindingReport(
                                    id=f.get("id", str(hash(str(f)))),
                                    title=f.get("title", "Finding"),
                                    severity=f.get("severity", "Informational"),
                                    cvss=float(f.get("cvss", 0)),
                                    url=f.get("url", target),
                                    vuln_class=f.get("type", "unknown"),
                                    description=f.get("details", "")[:500],
                                    impact=f.get("impact", ""),
                                    remediation=f.get("remediation", ""),
                                    evidence=f.get("evidence", ""),
                                    cwe=f.get("cwe", []),
                                    cve=f.get("cve"),
                                ))
                            html_path = Path(f"reports/scan_{target}_{int(time.time())}.html")
                            html_path.parent.mkdir(parents=True, exist_ok=True)
                            export_report(summary, findings_reports, str(html_path), ReportFormat.HTML)
                            console.print(f"[green][OK] Report:[/green] {html_path}")
                        except Exception as rpt_err:
                            logger.debug(f"Auto-report skipped: {rpt_err}")
                    send_telegram_notification(f"Scan + AI analysis: {target}")
            except Exception as e:
                import traceback, re
                tb = traceback.format_exc()
                # Strip ALL Rich tags from error and traceback
                safe_err = re.sub(r'\[/?[^\]]+\]', '', str(e))
                safe_tb = re.sub(r'\[/?[^\]]+\]', '', tb)
                console.print(f"[bold red][FAIL] AI scan: {safe_err}[/bold red]")
                # Print first line of traceback only
                lines = safe_tb.split('\n')
                console.print(f"[dim]{lines[0][:200]}[/dim]")

        elif args.command == "universal":
            from cli_textual import main as cli_textual_main
            cli_textual_main()

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
            from cli_textual import main as cli_textual_main
            cli_textual_main()

        elif args.command in ("tui", "cli-textual", "clitest"):
            from cli_textual import main as cli_textual_main
            cli_textual_main()

        elif args.command == "cli-legacy":
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

            if not require_authorized_scan_target(args.target):
                return

            console.print(f"[bold]Elengenix Autonomous Mode[/bold]")
            console.print(f"Target: [red]{args.target}[/red]")
            console.print(f"Governance: [grey70]{mode}[/grey70]")
            console.print("")

            if mode == "auto":
                print_warning("Auto mode: AI will create tools and install deps without asking!")
                if not confirm("Continue?", default=False):
                    return

            agent = AutonomousAgent(governance_mode=mode)
            
            # Check for Team Aegis (multi-agent) mode
            active_models = os.environ.get("ACTIVE_MODELS", "").split(",")
            active_models = [m.strip() for m in active_models if m.strip()]
            
            if len(active_models) >= 2:
                console.print(f"[bold]Team Aegis Mode[/bold]: {len(active_models)} agents collaborating")
                result = agent.run_team_scan(args.target)
            else:
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

        elif args.command == "hunt":
            """Hybrid mode: AI Strategist + Specialist with full analysis pipeline."""
            from ui_components import show_section, print_info, print_success, print_error
            show_section("ELENGENIX HYBRID HUNT MODE")

            target = args.target or console.input("[red]Enter target[/red]: ").strip()
            if not target:
                return

            console.print(Panel.fit(
                "[bold red]HYBRID MODE[/bold red]\n"
                "[white]Strategist plans / Specialist executes / Full analysis pipeline[/white]\n"
                "[dim]Combines flexible shell execution with structured analysis[/dim]",
                border_style="red",
            ))

            if not require_authorized_scan_target(target):
                return

            from agent import get_agent

            agent = get_agent()

            def _hunt_callback(msg: str):
                safe = re.sub(r"\[/?[^\]]+\]", "", str(msg))
                console.print(f"  [dim]{safe[:250]}[/dim]")

            try:
                response = agent.process_hybrid(
                    f"Perform comprehensive security assessment on {target}. "
                    f"Use all available tools and techniques to find vulnerabilities.",
                    target=target,
                    callback=_hunt_callback,
                    mode="bug_bounty",
                )
                if response:
                    safe_resp = re.sub(r"\[/?[^\]]+\]", "", response[:3000])
                    print_success("Hybrid Mission Complete")
                    console.print(f"\n{safe_resp}\n")

                    # Save final report
                    safe_name = re.sub(r"[^a-zA-Z0-9.-]", "_", target)[:40]
                    report_path = Path("reports") / f"hunt_{safe_name}.md"
                    report_path.parent.mkdir(parents=True, exist_ok=True)
                    report_path.write_text(response)
                    print_info(f"Full report: {report_path}")
            except KeyboardInterrupt:
                print_info("Hybrid hunt interrupted by user")
            except Exception as e:
                print_error(f"Hybrid hunt error: {e}")

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
            all_findings = []
            try:
                from tools.sast_engine import SASTEngine
                engine = SASTEngine()
                results = engine.scan(target)
                all_findings.extend(results.get("findings", []))
            except Exception as e:
                print_info(f"SASTEngine skipped: {e}")
            # Also run multimodal agent code analysis (secret patterns, eval, SQLi, etc.)
            try:
                from tools.multimodal_agent import analyze_code, detect_language
                target_path = Path(target)
                if target_path.is_file():
                    paths = [target_path]
                else:
                    paths = list(target_path.rglob("*.py")) + list(target_path.rglob("*.js")) + \
                            list(target_path.rglob("*.ts")) + list(target_path.rglob("*.java")) + \
                            list(target_path.rglob("*.go")) + list(target_path.rglob("*.rb")) + \
                            list(target_path.rglob("*.php"))
                for p in paths[:50]:  # Limit to 50 files
                    try:
                        content = p.read_text(encoding="utf-8", errors="ignore")
                        code_findings = analyze_code(str(p), content)
                        for cf in code_findings:
                            all_findings.append({
                                "message": f"[multimodal] {cf.pattern_id}: {cf.message}",
                                "severity": "HIGH" if cf.severity == "High" else cf.severity.upper(),
                                "file": str(p),
                                "line": cf.line or 1,
                                "snippet": cf.code_snippet[:100] if cf.code_snippet else "",
                            })
                    except Exception:
                        pass
            except Exception as e:
                print_info(f"Multimodal analysis skipped: {e}")
            for finding in all_findings:
                sev = finding.get("severity", "info").upper()
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "grey70", "LOW": "dim"}.get(sev, "dim")
                msg = finding.get("message", "")
                f = finding.get("file", "")
                ln = finding.get("line", "")
                console.print(f"[{color}][{sev}][/{color}] {msg} [{f}:{ln}]")
            total = len(all_findings)
            print_success(f"SAST scan complete — {total} findings (SASTEngine + Multimodal)")
            if all_findings:
                html_path = Path(f"reports/sast_{target_path.name}_{int(time.time())}.html")
                html_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    from tools.report_gen import ExecutiveSummary, FindingReport, export_report, ReportFormat
                    from datetime import datetime, timezone
                    summary = ExecutiveSummary(
                        target=str(target_path),
                        scan_date=datetime.now(timezone.utc).isoformat(),
                        duration_seconds=0,
                        total_findings=len(all_findings),
                        tool_version="1.0.0",
                        risk_level="Unknown",
                    )
                    reports = []
                    for f in all_findings:
                        reports.append(FindingReport(
                            id=str(hash(str(f))),
                            title=f.get("message", "Finding")[:100],
                            severity=f.get("severity", "Informational"),
                            cvss=0,
                            url=f.get("file", target),
                            vuln_class="sast",
                            description=f.get("snippet", ""),
                            impact="",
                            remediation="",
                        ))
                    export_report(summary, reports, str(html_path), ReportFormat.HTML)
                    console.print(f"[green][OK] Report:[/green] {html_path}")
                except Exception:
                    pass

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

        elif args.command == "compliance":
            """Enterprise compliance assessment (PCI DSS, SOC2, ISO 27001, OWASP)."""
            from ui_components import show_section, print_info, print_success, print_error
            show_section("Enterprise Compliance Assessment")
            target = args.target or console.input("[red]Standard (pci_dss/soc2/iso27001/owasp)[/red]: ").strip() or "pci_dss"
            try:
                from tools.compliance_engine import ComplianceEngine
                engine = ComplianceEngine()
                # Check if target matches a standard
                std = engine.get_standard(target)
                if not std:
                    print_error(f"Unknown standard: {target}")
                    print_info(f"Available: {', '.join(s['name'] for s in engine.list_standards())}")
                    return
                print_info(f"Assessing against {std.name} {std.version} ({len(std.controls)} controls)")
                # Generate report with empty findings for overview
                assessment = engine.assess([], target)
                path = engine.generate_report(assessment, f"reports/compliance_{target}_{int(time.time())}.html", "html")
                print_success(f"Compliance report generated: {path}")
                # Print summary
                console.print(f"[bold white]  Score:[/bold white] {assessment['compliance_pct']}%")
                console.print(f"  [green]Passed:[/green] {assessment['passed']}  [red]Failed:[/red] {assessment['failed']}  [dim]Not tested:[/dim] {assessment['not_tested']}")
            except Exception as e:
                print_error(f"Compliance error: {e}")

        elif args.command == "soc":
            """SOC Analyzer — Security Log Intelligence."""
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

        elif args.command == "api":
            """Enterprise REST API server."""
            from ui_components import show_section, print_info, print_success
            show_section("Elengenix Enterprise API Server")
            host = getattr(args, "host", "0.0.0.0")
            port = getattr(args, "port", 8443)
            try:
                from tools.api_server import run_server
                print_success(f"Starting API server on {host}:{port}")
                print_info(f"  Dashboard: http://{host}:{port}/")
                print_info(f"  API Docs:  http://{host}:{port}/docs")
                run_server(host=host, port=port)
            except ImportError as e:
                from ui_components import print_error
                print_error(f"API server requires FastAPI: pip install fastapi uvicorn ({e})")
            except Exception as e:
                from ui_components import print_error
                print_error(f"API server error: {e}")

        elif args.command == "dashboard":
            from ui_components import show_section, print_info, print_success, print_error
            show_section("Elenginx Security Dashboard")
            target = args.target
            try:
                from tools.tui_dashboard import run_dashboard, run_minimal
                print_info("Launching Elenginx Security Dashboard...")
                try:
                    run_dashboard(target)
                except Exception:
                    run_minimal()
            except Exception as e:
                print_error(f"Dashboard error: {e}")
                # Fallback to minimal
                try:
                    from tools.tui_dashboard import run_minimal
                    run_minimal()
                except Exception:
                    pass

        elif args.command == "update":
            # New: use the Updater class to check for and apply updates
            _cmd_update(args)

        elif args.command == "memory":
            from ui_components import show_section, print_info, create_status_table
            
            try:
                from tools.vector_memory import get_vector_memory as vm_get
                
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
                
                # Memory management menu with questionary
                try:
                    import questionary
                    mem_choice = questionary.select(
                        "Select action:",
                        choices=[
                            "Search memories",
                            "List all targets",
                            "Clear target memory",
                            "Back",
                        ],
                    ).ask()
                except Exception:
                    # Fallback to numbered menu
                    from ui_components import prompt_choice
                    idx = prompt_choice(["Search memories", "List all targets", "Clear target memory", "Back"])
                    mem_choice = ["Search memories", "List all targets", "Clear target memory", "Back"][idx]
                
                if mem_choice == "Search memories":
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
                            
                elif mem_choice == "List all targets":
                    targets = vm.get_all_targets()
                    if targets:
                        console.print(f"\n[red]Known Targets ({len(targets)}):[/red]\n")
                        for t in targets[:20]:
                            console.print(f"  • {t}")
                        if len(targets) > 20:
                            print_info(f"... and {len(targets) - 20} more")
                    else:
                        print_info("No targets in memory")
                        
                elif mem_choice == "Clear target memory":
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
            if not require_authorized_scan_target(base_url):
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
            if not require_authorized_scan_target(target_url):
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
            if not require_authorized_scan_target(target):
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
            
            # Action selection with questionary
            try:
                import questionary
                action = questionary.select(
                    "Select action:",
                    choices=[
                        "List techniques",
                        "Generate payload",
                        "Plan attack",
                        "Back",
                    ],
                ).ask()
            except Exception:
                # Fallback to text input
                action = console.input(
                    "[red]Select action[/red] [list/generate/plan]: "
                ).strip().lower()
                action_map = {"list": "List techniques", "generate": "Generate payload", "plan": "Plan attack"}
                action = action_map.get(action, "Back")
            
            if action == "List techniques":
                category = console.input("[red]Filter by category[/red] [amsi/process/memory/sandbox/signature/all]: ").strip()
                if category == "all":
                    category = None
                techniques = engine.list_techniques(category=category)
                
                print_success(f"Found {len(techniques)} techniques:")
                for t in techniques:
                    risk_marker = "[H]" if t.detection_risk == "high" else "[M]" if t.detection_risk == "medium" else "[L]"
                    console.print(f"  {risk_marker} [{t.difficulty}] {t.name} ({t.category}) - {t.platform}")
                    
            elif action == "Generate payload":
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
                from ui_components import confirm
                if confirm("Save payload to file?", default=False):
                    timestamp = int(time.time())
                    out_path = Path(f"reports/evasion_{tech_name.replace(' ', '_').lower()}_{timestamp}.txt")
                    out_path.parent.mkdir(exist_ok=True)
                    out_path.write_text(result["generated_code"], encoding="utf-8")
                    print_success(f"Saved to: {out_path}")
                    
            elif action == "Plan attack":
                target_edr = console.input("[red]Target EDR[/red] (e.g., crowdstrike/sentinelone/defender): ").strip()
                objectives = console.input("[red]Objectives[/red] [persistence,privilege,escalation,evasion]: ").strip()
                obj_list = [o.strip() for o in objectives.split(",") if o.strip()]
                
                plan = engine.generate_red_team_plan(target_edr=target_edr or None, objectives=obj_list or None)
                console.print(format_edr_report(plan))

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
                    date=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
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
            from ui_components import print_info, print_success, print_error
            
            if not args.target:
                print_error("Usage: elengenix mission <target>")
                console.print("\n  Start autonomous scanning mission with:")
                console.print("    elengenix mission target.com")
                console.print("    elengenix mission target.com --pause-after 2")
                return
            
            target = args.target
            pause_after = 3  # Default: pause after 3 hours without findings
            if not require_authorized_scan_target(target):
                return
            
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

        elif args.command in ["quick", "deep", "bounty", "stealth", "web"]:
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
            
            # Re-dispatch by building new argv and re-entering main
            new_argv = [sys.argv[0], cmd] + cmd_args
            sys.argv = new_argv
            main()
            return

        # ── Command Registry fallback: Dispatch unknown commands ──
        else:
            # Auto-import command modules so their @command decorators register
            try:
                import commands.system
            except Exception:
                pass
            try:
                import commands.worldclass
            except Exception:
                pass
            from commands.registry import CommandRegistry
            _cmd_reg = CommandRegistry()
            _cmd_def = _cmd_reg.get(args.command)
            if _cmd_def:
                from ui_components import console as _console
                import asyncio as _asyncio
                try:
                    loop = _asyncio.new_event_loop()
                    _asyncio.set_event_loop(loop)
                    exit_code = loop.run_until_complete(_cmd_reg.dispatch(args.command, args))
                    loop.close()
                except Exception as e:
                    _console.print(f"[red][FAIL] {args.command}: {e}[/red]")
                return
            console.print(f"[FAIL] Unknown command: {args.command}")
            return
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

# ── D1: list-tools — show all 98 tools by category ──
def _cmd_list_tools():
    """Print the 98-tool catalog grouped by category.

    Tries the live ToolRegistry first (auto-registered base tools).
    ALWAYS also scans tools/*.py for module names + first-line docstring
    (covers the 90+ utility modules that aren't BaseTool subclasses).
    """
    all_tools = {}
    try:
        from tools.tool_registry import registry as _tool_registry
        all_tools = _tool_registry.list_available_tools() if hasattr(_tool_registry, 'list_available_tools') else {}
    except Exception as e:
        console.print(f"[dim]Registry unavailable: {e}[/dim]")

    # ALWAYS scan tools/*.py to find utility modules (not just BaseTool subclasses)
    import re
    from pathlib import Path
    tools_dir = Path(__file__).parent / "tools"
    # Heuristic category detection (matches docs/TOOL_CATALOG.md grouping)
    def _guess_cat(name: str) -> str:
        n = name.lower()
        if any(x in n for x in ['recon', 'finder', 'subdomain', 'wayback', 'dork', 'github_intel', 'param_miner', 'api_finder', 'api_schema', 'mobile_api']):
            return 'recon'
        if any(x in n for x in ['fuzz', 'injection', 'payload', 'mutation', 'race_condition', 'cors', 'ssrf', 'graphql', 'auth_tester', 'bola', 'object_id', 'logic', 'access_control']):
            return 'fuzz'
        if any(x in n for x in ['exploit', 'chain', 'template', 'poc', 'harness']):
            return 'exploit'
        if any(x in n for x in ['report', 'html', 'pdf', 'bounty', 'cvss', 'cve_database', 'finding_dedup', 'coverage', 'reporter']):
            return 'reporting'
        if any(x in n for x in ['ai_', 'agent_', 'llm', 'token_', 'memory_', 'vector_', 'user_', 'context_compressor', 'bounty_predictor']):
            return 'ai'
        if any(x in n for x in ['waf', 'evasion', 'dynamic_waf', 'edr_']):
            return 'waf'
        if any(x in n for x in ['telegram', 'bot', 'bridge', 'gateway']):
            return 'telegram'
        if any(x in n for x in ['governance', 'safe_exec', 'tool_registry', 'doctor', 'config_wizard', 'welcome_wizard', 'profile', 'session', 'history', 'overlay', 'dashboard', 'install', 'progress', 'wordlist', 'analysis_pipeline', 'multi_agent', 'swarm', 'autonomous', 'protocol', 'sast', 'cloud', 'soc', 'mobile', 'mission', 'research', 'vuln_', 'event_loop', 'base_', 'universal_', 'command_suggest', 'memory_persistence', 'skill_registry', 'executor', 'mission_state', 'history_manager', 'base_recon', 'base_scanner']):
            return 'infra'
        return 'utils'

    for py_file in tools_dir.glob("*.py"):
        if py_file.name == "__init__.py":
            continue
        if py_file.stem in all_tools:
            continue  # already in registry
        try:
            with open(py_file) as f:
                content = f.read(500)
            m = re.search(r'^"""(.+?)"""', content, re.DOTALL)
            if m:
                raw = m.group(1).strip()
                # Strip leading "tools/X.py — " pattern that some docstrings use
                raw = re.sub(r'^tools/\w+\.py\s*[—\-]\s*', '', raw)
                desc = raw.split('\n')[0]
            else:
                desc = "(no docstring)"
        except Exception:
            desc = "(read error)"
        all_tools[py_file.stem] = {
            "category": _guess_cat(py_file.stem),
            "description": desc,
            "available": True,
        }

    # Group by category
    by_cat = {}
    for name, info in all_tools.items():
        cat = info.get('category', 'unknown')
        by_cat.setdefault(cat, []).append((name, info.get('description', '')))

    console.print()
    console.print(f"[bold red]Elengenix Tool Catalog[/bold red] [dim]({len(all_tools)} tools registered)[/dim]")
    console.print()
    for cat in sorted(by_cat.keys()):
        tools = by_cat[cat]
        console.print(f"  [bold cyan]{cat.upper()}[/bold cyan] [dim]({len(tools)})[/dim]")
        for name, desc in sorted(tools):
            desc_short = desc[:60] + "..." if len(desc) > 60 else desc
            console.print(f"    [white]{name:30s}[/white] [dim]{desc_short}[/dim]")
        console.print()
    if not all_tools:
        console.print("  [yellow]No tools registered. Run: elengenix doctor[/yellow]")
    console.print(f"[dim]Full catalog: docs/TOOL_CATALOG.md[/dim]")


# ── D2: examples — show common usage patterns ──
def _cmd_examples():
    """Print common usage examples."""
    console.print()
    console.print("[bold red]Elengenix Common Usage Examples[/bold red]")
    console.print()
    examples = [
        ("[cyan]Quick scan[/cyan]", "elengenix scan example.com"),
        ("[cyan]Quiet scan (no phase output)[/cyan]", "elengenix scan example.com --quiet"),
        ("[cyan]Smart scan with correlation[/cyan]", "elengenix scan example.com --smart-scan"),
        ("[cyan]Full autonomous hunt[/cyan]", "elengenix autonomous example.com"),
        ("[cyan]WAF detection only[/cyan]", "elengenix waf example.com"),
        ("[cyan]BOLA / IDOR only[/cyan]", "elengenix bola example.com"),
        ("[cyan]Generate PoC for finding[/cyan]", "elengenix poc --framework django --version 4.2"),
        ("[cyan]Generate report from scan[/cyan]", "elengenix report example.com"),
        ("[cyan]Update CVE database[/cyan]", "elengenix cve-update"),
        ("[cyan]Health check[/cyan]", "elengenix doctor"),
        ("[cyan]Configure API keys[/cyan]", "elengenix configure"),
        ("[cyan]List all 98 tools[/cyan]", "elengenix list-tools"),
        ("[cyan]Show usage examples[/cyan]", "elengenix examples"),
        ("[cyan]Resume paused mission[/cyan]", "elengenix resume <mission-id>"),
        ("[cyan]Show scan history[/cyan]", "elengenix history list"),
        ("[cyan]Telegram gateway[/cyan]", "elengenix gateway"),
        ("[cyan]Interactive AI chat[/cyan]", "elengenix cli"),
    ]
    for desc, cmd in examples:
        console.print(f"  {desc}")
        console.print(f"    [white]{cmd}[/white]")
        console.print()
    console.print(f"[dim]Full docs: docs/TOOL_CATALOG.md, README.md[/dim]")


# ── F1: prefetch — pre-download AI models so first scan is fast ──
def _cmd_prefetch():
    """Pre-download heavy AI models (ChromaDB embedding model, etc.) so
    the first scan doesn't block on a 79MB download at 100KB/s.

    Safe to re-run — skips if already cached.
    """
    import os
    from pathlib import Path
    console.print()
    console.print("[bold red]Pre-fetching AI models...[/bold red]")
    console.print()

    # 1. ChromaDB embedding model (all-MiniLM-L6-v2, ~79MB)
    cache_dir = Path.home() / ".cache" / "chroma" / "onnx_models" / "all-MiniLM-L6-v2"
    onnx_file = cache_dir / "onnx.tar.gz"
    target_size = 79 * 1024 * 1024  # 79MB

    if onnx_file.exists() and onnx_file.stat().st_size >= target_size * 0.95:
        console.print(f"  [OK] ChromaDB embedding model: [dim]already cached ({onnx_file.stat().st_size/1024/1024:.1f}MB)[/dim]")
    else:
        console.print(f"  ChromaDB embedding model (~79MB)...", end="")
        try:
            # Trigger chromadb's lazy download
            import chromadb
            client = chromadb.PersistentClient(path="data/vector_memory")
            # Use a valid collection name (3-63 chars, alphanumeric + _.-)
            collection = client.get_or_create_collection("prefetch_test")
            # Quick smoke test (this triggers embedding model download)
            collection.add(documents=["prefetch test"], ids=["prefetch_1"])
            collection.query(query_texts=["prefetch"], n_results=1)
            try:
                client.delete_collection("prefetch_test")
            except Exception:
                pass
            console.print(f"\r  [OK] ChromaDB embedding model: [green]downloaded[/green]")
        except Exception as e:
            console.print(f"\r  [WARN] ChromaDB embedding: [yellow]{type(e).__name__}: {str(e)[:80]}[/yellow]")
            console.print(f"         Run scan first; model will download on demand")

    # 2. tiktoken (small, ~1MB)
    try:
        import importlib
        tiktoken_mod = importlib.import_module("tiktoken")
        tiktoken_mod.get_encoding("cl100k_base")
        console.print(f"  [OK] tiktoken: [dim]already cached[/dim]")
    except Exception as e:
        console.print(f"  [WARN] tiktoken: [yellow]{type(e).__name__}[/yellow]")

    console.print()
    console.print("[green]Pre-fetch complete. First scan will be faster.[/green]")
    console.print()


def _cmd_scan_report(args):
    """Generate Apple-level HTML/MD/SARIF report from findings JSON.

    Usage: elengenix scan-report <findings.json> [--format html|md|sarif|json|txt|all] [--output <path>]

    Example: elengenix scan-report reports/httpbin.org/findings.json --format all
    """
    import json
    from pathlib import Path
    from datetime import datetime, timezone
    from tools.report_gen import (
        FindingReport, ExecutiveSummary, ReportFormat, export_report
    )

    findings_file = args.target
    if not findings_file:
        console.print("[red]Usage:[/red] elengenix scan-report <findings.json> [--format html|md|sarif|json|txt|all]")
        return

    p = Path(findings_file)
    if not p.exists():
        console.print(f"[red]File not found:[/red] {findings_file}")
        return

    fmt = (getattr(args, "format", None) or "html").lower()
    out = getattr(args, "output", None) or f"reports/{p.stem}_report"

    console.print()
    console.print(f"[bold red]Elengenix Report Generator[/bold red]")
    console.print(f"  Source: [dim]{p}[/dim]")
    console.print(f"  Format: [cyan]{fmt}[/cyan]")
    console.print()

    try:
        data = json.loads(p.read_text())
    except Exception as e:
        console.print(f"[red]Failed to parse JSON:[/red] {e}")
        return

    # Normalize findings
    findings_raw = data if isinstance(data, list) else data.get("findings", [])
    if not findings_raw:
        console.print("[yellow]No findings found in file[/yellow]")
        return

    findings = []
    for f in findings_raw:
        findings.append(FindingReport(
            id=f.get("id", ""),
            title=f.get("title", "Untitled"),
            severity=f.get("severity", "Informational"),
            cvss=f.get("cvss", f.get("cvss_score", 0.0)),
            url=f.get("url", f.get("endpoint", "")),
            vuln_class=f.get("type", f.get("vuln_class", "unknown")),
            description=f.get("details", f.get("description", "")),
            impact=f.get("impact", "See details"),
            remediation=f.get("remediation", "See documentation"),
            evidence=f.get("evidence", ""),
            cwe=f.get("cwe", []),
            cve=f.get("cve"),
            confidence=f.get("confidence", 0.5),
        ))

    # Count by severity
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    # Risk score = max CVSS
    risk = max((f.cvss for f in findings), default=0.0)

    target = data.get("target", p.stem) if isinstance(data, dict) else p.stem
    summary = ExecutiveSummary(
        target=target,
        scan_date=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        duration_seconds=data.get("duration_s", 0) if isinstance(data, dict) else 0,
        total_findings=len(findings),
        critical=sev_counts["Critical"],
        high=sev_counts["High"],
        medium=sev_counts["Medium"],
        low=sev_counts["Low"],
        info=sev_counts["Informational"],
        ai_provider=os.environ.get("ACTIVE_MODELS", "Elengenix"),
        top_3_findings=sorted(findings, key=lambda x: -x.cvss)[:3],
        risk_score=risk,
        business_impact=f"Scan identified {len(findings)} findings with max CVSS {risk:.1f}. Risk level: {sev_counts['Critical']} critical, {sev_counts['High']} high." if findings else "No findings.",
    )

    # Generate requested formats
    formats = {
        "html": ReportFormat.HTML,
        "md": ReportFormat.MARKDOWN,
        "markdown": ReportFormat.MARKDOWN,
        "sarif": ReportFormat.SARIF,
        "json": ReportFormat.JSON,
        "txt": ReportFormat.TEXT,
        "text": ReportFormat.TEXT,
    }

    if fmt == "all":
        outputs = []
        for name, rf in formats.items():
            path = export_report(summary, findings, f"{out}.{name}", rf)
            outputs.append(path)
        console.print(f"[green][OK] Generated {len(outputs)} reports:[/green]")
        for op in outputs:
            console.print(f"  [cyan]{op}[/cyan] ({op.stat().st_size:,} bytes)")
    else:
        rf = formats.get(fmt)
        if not rf:
            console.print(f"[red]Unknown format:[/red] {fmt}. Use: html, md, sarif, json, txt, all")
            return
        path = export_report(summary, findings, f"{out}.{fmt}", rf)
        console.print(f"[green][OK] Report saved:[/green] {path} ({path.stat().st_size:,} bytes)")
        if rf == ReportFormat.HTML:
            console.print(f"  [dim]Open in browser: file://{path.absolute()}[/dim]")

    console.print()


# ── Marketplace + Update CLI handlers ──────────────────────────────────────


def _cmd_marketplace(args) -> None:
    """Plugin marketplace CLI: search, install, uninstall, list."""
    from tools.marketplace import Marketplace

    sub = args.subcommand or "list"
    m = Marketplace()

    if sub == "search":
        query = args.query or ""
        results = m.search(query=query, verified_only=args.verified)
        if not results:
            console.print(f"[yellow]No plugins found for '{query}'[/yellow]")
            return
        console.print(f"\n[red]Marketplace[/red] ({len(results)} plugin(s) for '{query}')\n")
        for entry in results:
            verified_mark = "[green]✓[/green] " if entry.verified else "   "
            console.print(
                f"  {verified_mark}[bold]{entry.name}[/bold] v{entry.version}  "
                f"[dim]({entry.downloads} downloads, {entry.stars} stars)[/dim]"
            )
            console.print(f"      {entry.description}")
            if entry.tags:
                console.print(f"      [dim]Tags: {', '.join(entry.tags)}[/dim]")
            console.print()
    elif sub == "install":
        name = getattr(args, "name", None) or args.target
        if not name:
            console.print("[red]Usage: marketplace install <name>[/red]")
            return
        ok, msg = m.install(name, upgrade=args.upgrade)
        if ok:
            console.print(f"[green][OK] {msg}[/green]")
        else:
            console.print(f"[red][FAIL] {msg}[/red]")
    elif sub == "uninstall":
        name = getattr(args, "name", None) or args.target
        if not name:
            console.print("[red]Usage: marketplace uninstall <name>[/red]")
            return
        ok, msg = m.uninstall(name)
        if ok:
            console.print(f"[green][OK] {msg}[/green]")
        else:
            console.print(f"[red][FAIL] {msg}[/red]")
    elif sub == "list":
        installed = m.list_installed()
        if not installed:
            console.print("[yellow]No plugins installed[/yellow]")
            console.print(f"[dim]Install dir: {m.install_dir}[/dim]")
            console.print(f"[dim]Search: python3 main.py marketplace search <query>[/dim]")
            return
        console.print(f"\n[red]Installed plugins[/red] ({len(installed)})\n")
        for p in installed:
            console.print(
                f"  [bold]{p['name']}[/bold] v{p['version']}  "
                f"[dim]by {p['author']}[/dim]"
            )
            console.print(f"      {p['description']}")
            console.print()
    else:
        console.print(f"[red]Unknown marketplace subcommand:[/red] {sub}")
        console.print("[dim]Use: search, install, uninstall, list[/dim]")


def _cmd_update(args) -> None:
    """Update check / apply CLI."""
    from tools.updater import Updater

    u = Updater()
    if args.check:
        console.print("[dim]Checking for updates...[/dim]")
        release = u.check_for_updates(use_cache=not args.force)
        if release is None:
            console.print(f"[green][OK] Elengenix {u.current_version} is up to date[/green]")
        else:
            console.print(f"\n[red]New version available![/red]\n")
            console.print(f"  Current:  [dim]{u.current_version}[/dim]")
            console.print(f"  Latest:   [bold]{release.version}[/bold] ({release.tag})")
            console.print(f"  Released: [dim]{release.published_at[:10] if release.published_at else 'unknown'}[/dim]")
            console.print(f"  URL:      [cyan]{release.url or u.stats().get('repo', '')}[/cyan]\n")
    elif args.apply:
        console.print("[dim]Checking for updates...[/dim]")
        release = u.check_for_updates(use_cache=False)
        if release is None:
            console.print(f"[green][OK] Elengenix {u.current_version} is up to date[/green]")
            return
        if not args.yes:
            response = input(f"Apply update to {release.version}? [y/N]: ").strip().lower()
            if response not in ("y", "yes"):
                console.print("[yellow]Update cancelled[/yellow]")
                return
        ok, msg = u.apply_update(release)
        if ok:
            console.print(f"[green][OK] {msg}[/green]")
        else:
            console.print(f"[red][FAIL] {msg}[/red]")
    else:
        # Default: just show status
        release = u.check_for_updates(use_cache=True)
        if release is None:
            console.print(f"[green][OK] Elengenix {u.current_version} (up to date)[/green]")
        else:
            console.print(f"[yellow]Update available:[/yellow] {release.version} (run with --apply)")


def _cmd_plugins(args) -> None:
    """Plugin management CLI: list, info, reload."""
    from tools.ecosystem import discover_and_load

    host = discover_and_load()

    if args.subcommand == "list":
        plugins = host.list_plugins()
        if not plugins:
            console.print("[yellow]No plugins loaded[/yellow]")
            return
        console.print(f"\n[red]Loaded plugins[/red] ({len(plugins)})\n")
        for p in plugins:
            state_color = {
                "active": "green",
                "failed": "red",
                "disabled": "yellow",
                "loading": "dim",
                "unloading": "dim",
                "discovered": "dim",
            }.get(p.state.value, "white")
            console.print(
                f"  [bold]{p.name}[/bold] v{p.manifest.version} "
                f"[{state_color}][{p.state.value}][/{state_color}] "
                f"[dim]({p.manifest.author or 'unknown'})[/dim]"
            )
            if p.manifest.description:
                console.print(f"      {p.manifest.description}")
            console.print(f"      [dim]tools={len(p.registered_tools)} "
                          f"cmds={len(p.registered_commands)} "
                          f"ai={len(p.registered_ai_providers)} "
                          f"hooks={len(p.registered_hooks)}[/dim]")
            if p.error:
                console.print(f"      [red]Error: {p.error}[/red]")
            console.print()
    elif args.subcommand == "info":
        name = getattr(args, "name", None) or args.target
        if not name:
            console.print("[red]Usage: plugins info <name>[/red]")
            return
        p = host.get_plugin(name)
        if not p:
            console.print(f"[red]Plugin not found:[/red] {name}")
            return
        console.print(f"\n[bold]{p.name}[/bold] v{p.manifest.version}\n")
        console.print(f"  Author:       {p.manifest.author or 'unknown'}")
        console.print(f"  Description:  {p.manifest.description or '(none)'}")
        console.print(f"  State:        {p.state.value}")
        console.print(f"  Path:         {p.path}")
        console.print(f"  SDK version:  {p.manifest.sdk_version}")
        console.print(f"  Capabilities: {[c.value for c in p.manifest.capabilities]}")
        if p.manifest.tags:
            console.print(f"  Tags:         {p.manifest.tags}")
        if p.registered_tools:
            console.print(f"\n  [bold]Tools ({len(p.registered_tools)}):[/bold]")
            for t in p.registered_tools:
                console.print(f"    - {t}")
        if p.registered_commands:
            console.print(f"\n  [bold]Commands ({len(p.registered_commands)}):[/bold]")
            for c in p.registered_commands:
                console.print(f"    - {c}")
        if p.registered_ai_providers:
            console.print(f"\n  [bold]AI Providers ({len(p.registered_ai_providers)}):[/bold]")
            for a in p.registered_ai_providers:
                console.print(f"    - {a}")
        if p.registered_hooks:
            console.print(f"\n  [bold]Finding Hooks ({len(p.registered_hooks)}):[/bold]")
            for h in p.registered_hooks:
                console.print(f"    - {h}")
    elif args.subcommand == "reload":
        name = getattr(args, "name", None) or args.target
        if not name:
            console.print("[red]Usage: plugins reload <name>[/red]")
            return
        result = host.reload(name)
        if result is None:
            console.print(f"[red]Plugin not found:[/red] {name}")
        else:
            console.print(f"[green][OK] Reloaded: {result.name}[/green]")
    else:
        console.print(f"[red]Unknown plugins subcommand:[/red] {args.subcommand}")
        console.print("[dim]Use: list, info, reload[/dim]")


if __name__ == "__main__":
    ensure_dependencies()
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)



