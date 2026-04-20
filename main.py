import sys
import subprocess
import os

# 🚀 Bulletproof Dependency Checker
def ensure_dependencies():
    required_libs = {
        "yaml": "pyyaml",
        "rich": "rich",
        "questionary": "questionary",
        "requests": "requests",
        "google.generativeai": "google-generativeai",
        "openai": "openai",
        "anthropic": "anthropic",
        "trafilatura": "trafilatura"
    }
    
    missing = []
    for module, package in required_libs.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"[*] Missing libraries detected: {', '.join(missing)}")
        print("[*] Attempting to install missing dependencies automatically...")
        try:
            cmd = [sys.executable, "-m", "pip", "install"] + missing + ["--break-system-packages"]
            subprocess.run(cmd, check=True)
            print("[*] Successfully installed dependencies. Restarting...\n")
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception:
            try:
                cmd = [sys.executable, "-m", "pip", "install"] + missing
                subprocess.run(cmd, check=True)
                os.execv(sys.executable, [sys.executable] + sys.argv)
            except Exception as e:
                print(f"[❌] Auto-installation failed: {e}")
                sys.exit(1)

ensure_dependencies()

import argparse
import yaml
import questionary
from rich.console import Console
from rich.panel import Panel

# Safety imports
try:
    from dependency_manager import check_and_install_dependencies
    from tools.doctor import check_health
    from tools_menu import show_tools_menu
    from tools.omni_scan import run_omni_scan
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from dependency_manager import check_and_install_dependencies
    from tools.doctor import check_health
    from tools_menu import show_tools_menu
    from tools.omni_scan import run_omni_scan

console = Console()

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
    [bold red]WARNING: FOR AUTHORIZED SECURITY TESTING ONLY.[/bold red]
    [dim]The Ultimate AI-Powered Bug Bounty Framework[/dim]
    """
    console.print(banner)

def main():
    show_banner()
    parser = argparse.ArgumentParser(description="Elengenix CLI", add_help=False)
    parser.add_argument("command", nargs="?", default="menu", choices=["ai", "scan", "gateway", "configure", "update", "doctor", "arsenal", "menu"])
    parser.add_argument("target", nargs="?", help="Target domain")
    
    args, unknown = parser.parse_known_args()

    if args.command == "menu":
        try:
            choice = questionary.select(
                "Welcome, Hunter! What would you like to do?",
                choices=[
                    "🤖 Chat with AI Partner (Unified Brain)",
                    "🚀 Run Advanced Omni-Scan (Everything)",
                    "⚔️  Open Tools Arsenal (Select by Number)",
                    "📱 Start Telegram Gateway",
                    "🏥 Run System Doctor (Check/Repair)",
                    "⚙️  Configure AI & Settings",
                    "🔄 Update Framework",
                    "❌ Exit"
                ]
            ).ask()
        except Exception:
            return

        if not choice or "Exit" in choice: return
        elif "AI Partner" in choice: args.command = "ai"
        elif "Omni-Scan" in choice: args.command = "scan"
        elif "Arsenal" in choice: args.command = "arsenal"
        elif "Telegram" in choice: args.command = "gateway"
        elif "Doctor" in choice: args.command = "doctor"
        elif "Configure" in choice: args.command = "configure"
        elif "Update" in choice: args.command = "update"

    if args.command == "doctor":
        check_health()
    elif args.command == "update":
        # (update logic here)
        pass
    elif args.command == "scan":
        target = args.target if args.target else questionary.text("Target:").ask()
        if target: run_omni_scan(target)
    elif args.command == "ai":
        import cli
        cli.main()
    elif args.command == "arsenal":
        show_tools_menu()
    elif args.command == "gateway":
        os.system(f"{sys.executable} {os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bot.py')}")
    elif args.command == "configure":
        import wizard
        wizard.main()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        console.print(f"\n[bold red]🚨 CRITICAL ERROR DETECTED: {e}[/bold red]")
        if questionary.confirm("Would you like Elengenix to attempt an Auto-Repair?", default=True).ask():
            check_health(fix=True)
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Happy Hunting![/yellow]")
        sys.exit(0)
