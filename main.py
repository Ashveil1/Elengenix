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
    banner = """
    [bold cyan]
     _____ _                               _      
    | ____| | ___ _ __   __ _  ___ _ __ (_)_  __
    |  _| | |/ _ \\ '_ \\ / _` |/ _ \\ '_ \\| \\ \\/ /
    | |___| |  __/ | | | (_| |  __/ | | | |>  < 
    |_____|_|\\___|_| |_|\\__, |\\___|_| |_|_/_/\\_\\
                        |___/                   
    [/bold cyan]
    [bold red]⚠️  FOR AUTHORIZED SECURITY TESTING ONLY[/bold red]
    [dim]The Ultimate AI-Powered Bug Bounty Framework v1.5.0[/dim]
    """
    console.print(banner)

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(description="Elengenix CLI", add_help=False)
    parser.add_argument("command", nargs="?", default="menu", 
                        choices=["ai", "scan", "gateway", "configure", "update", "doctor", "arsenal", "menu"])
    parser.add_argument("target", nargs="?", help="Target domain or IP")
    parser.add_argument("--rate-limit", type=int, default=5, help="Max requests per second")
    
    args, _ = parser.parse_known_args()

    # Interactive Menu
    if args.command == "menu":
        try:
            choice = questionary.select(
                "Hunter Station: Choose your operation",
                choices=[
                    "🤖 Chat with AI Partner (Intelligent Mode)",
                    "🚀 Run Advanced Omni-Scan (Automated)",
                    "⚔️  Open Tools Arsenal (Manual Select)",
                    "📱 Start Telegram Gateway (Remote Control)",
                    "🏥 Run System Doctor (Audit/Repair)",
                    "⚙️  Configure AI & Settings",
                    "🔄 Update Framework",
                    "❌ Exit"
                ]
            ).ask()
            if not choice or "Exit" in choice: sys.exit(0)
            
            mapping = {"AI Partner": "ai", "Omni-Scan": "scan", "Arsenal": "arsenal", 
                       "Telegram": "gateway", "Doctor": "doctor", "Configure": "configure", "Update": "update"}
            args.command = next((v for k, v in mapping.items() if k in choice), "menu")
        except KeyboardInterrupt: sys.exit(0)

    # Command Router
    try:
        if args.command == "scan":
            target = args.target or questionary.text("Enter Target (e.g., example.com):").ask()
            if not target: return
            if not validate_target(target):
                console.print("[bold red]❌ SECURITY ERROR: Invalid target format.[/bold red]")
                return
            
            from dependency_manager import check_and_install_dependencies
            from tools.omni_scan import run_omni_scan
            
            check_and_install_dependencies()
            console.print(f"[cyan]🎯 Initiating scan on: {target} (Rate: {args.rate_limit} req/s)[/cyan]")
            run_omni_scan(target, rate_limit=args.rate_limit)

        elif args.command == "ai":
            import cli
            cli.main()

        elif args.command == "gateway":
            bot_path = Path(__file__).parent / "bot.py"
            if not bot_path.exists():
                console.print("[bold red]❌ bot.py missing.[/bold red]")
                return
            console.print("[bold cyan]📱 Activating Telegram Gateway...[/bold cyan]")
            # 🛡️ Using subprocess for controlled execution
            subprocess.run([sys.executable, str(bot_path)])

        elif args.command == "doctor":
            from tools.doctor import check_health
            check_health()

        elif args.command == "configure":
            import wizard
            wizard.main()

        elif args.command == "arsenal":
            from tools_menu import show_tools_menu
            show_tools_menu()

        elif args.command == "update":
            console.print("[yellow][*] Checking for updates... Run: git pull && ./setup.sh[/yellow]")

    except KeyboardInterrupt:
        console.print("\n[yellow]⛔ Operation canceled by Hunter.[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.exception("Operational breakdown")
        console.print(f"\n[bold red]🚨 SYSTEM FAILURE: {e}[/bold red]")
        if questionary.confirm("Attempt emergency repair?", default=True).ask():
            from tools.doctor import check_health
            check_health(fix=True)

if __name__ == "__main__":
    ensure_dependencies()
    main()
