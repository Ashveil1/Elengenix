import argparse
import sys
import os
import yaml
import questionary
import subprocess
from rich.console import Console
from rich.panel import Panel
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
    [dim]The Ultimate AI-Powered Bug Bounty Framework[/dim]
    """
    console.print(banner)

def update_system():
    console.print("[bold cyan]🔄 Updating Elengenix & Security Tools...[/bold cyan]")
    try:
        subprocess.run("git pull", shell=True)
        subprocess.run("nuclei -update-templates", shell=True)
        console.print("[bold green]✅ Everything is up to date![/bold green]")
    except Exception as e:
        console.print(f"[bold red]❌ Update failed: {e}[/bold red]")

def main():
    show_banner()
    parser = argparse.ArgumentParser(description="Elengenix CLI", add_help=False)
    parser.add_argument("command", nargs="?", default="menu", choices=["ai", "scan", "gateway", "configure", "update", "doctor", "arsenal", "menu"])
    parser.add_argument("target", nargs="?", help="Target domain for 'scan' command")
    
    args, unknown = parser.parse_known_args()

    # Main Interactive Selector
    if args.command == "menu":
        choice = questionary.select(
            "Welcome, Hunter! What would you like to do?",
            choices=[
                "🤖 Chat with AI Partner (Unified Brain)",
                "🚀 Run Advanced Omni-Scan (Everything)",
                "⚔️  Open Tools Arsenal (Select by Number)",
                "📱 Start Telegram Gateway",
                "🏥 Run System Doctor (Check Health)",
                "⚙️  Configure AI & Settings",
                "🔄 Update Framework",
                "❌ Exit"
            ]
        ).ask()

        if not choice or "Exit" in choice: return
        elif "AI Partner" in choice: args.command = "ai"
        elif "Omni-Scan" in choice: args.command = "scan"
        elif "Arsenal" in choice: args.command = "arsenal"
        elif "Telegram" in choice: args.command = "gateway"
        elif "Doctor" in choice: args.command = "doctor"
        elif "Configure" in choice: args.command = "configure"
        elif "Update" in choice: args.command = "update"

    # Command Execution
    if args.command == "ai":
        import cli
        cli.main()
    elif args.command == "scan":
        target = args.target if args.target else questionary.text("Enter target domain:").ask()
        if target:
            check_and_install_dependencies()
            run_omni_scan(target)
    elif args.command == "arsenal":
        show_tools_menu()
    elif args.command == "doctor":
        check_health()
    elif args.command == "gateway":
        console.print("[bold yellow]📱 Starting Elengenix Gateway (Telegram Bot)...[/bold yellow]")
        # Running via system to avoid event loop conflicts
        os.system(f"{sys.executable} {os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bot.py')}")
    elif args.command == "update":
        update_system()
    elif args.command == "configure":
        import wizard
        wizard.main()

if __name__ == "__main__":
    main()
