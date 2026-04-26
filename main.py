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
                        choices=["ai", "scan", "gateway", "configure", "update", "doctor", "arsenal", "memory", "menu"])
    parser.add_argument("target", nargs="?", help="Target domain or IP")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second")
    
    args, _ = parser.parse_known_args()

    # Interactive Menu
    if args.command == "menu":
        try:
            # Use clean menu from ui_components
            from ui_components import create_main_menu, format_menu_item, console
            menu_items = create_main_menu()
            
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
                    continue
            except ValueError:
                continue
            
            # Handle exit
            if choice_key == "exit":
                sys.exit(0)
            
            args.command = choice_key
            
        except KeyboardInterrupt: sys.exit(0)

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
