import os
import shutil
import yaml
import requests
from rich.console import Console
from rich.table import Table

console = Console()

def check_health():
    """
    elengenix doctor - Comprehensive health check.
    """
    console.print("[bold cyan]🏥 Elengenix Doctor - System Health Check[/bold cyan]\n")
    
    # 1. Check Config
    config_table = Table(title="Configuration Status")
    config_table.add_column("Service", style="cyan")
    config_table.add_column("Status", style="magenta")
    
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    
    # Check AI
    active_ai = config["ai"]["active_provider"]
    ai_key = config["ai"]["providers"].get(active_ai, {}).get("api_key", "")
    config_table.add_row(f"AI Provider ({active_ai})", "✅ Configured" if ai_key and "YOUR" not in ai_key else "❌ Missing Key")
    
    # Check Telegram
    tg_token = config["telegram"]["token"]
    config_table.add_row("Telegram Bot", "✅ Configured" if tg_token and "YOUR" not in tg_token else "⚠️ Not Set")
    
    console.print(config_table)

    # 2. Check Security Tools
    tools_table = Table(title="Security Tools Status")
    tools_table.add_column("Tool", style="cyan")
    tools_table.add_column("Path", style="magenta")
    tools_table.add_column("Status", style="green")

    for tool in ["subfinder", "nuclei", "httpx", "katana", "waybackurls"]:
        path = shutil.which(tool)
        tools_table.add_row(tool, path if path else "Not Found", "✅ OK" if path else "❌ Missing")
    
    console.print(tools_table)
    
    if not shutil.which("nuclei"):
        console.print("\n[bold yellow]💡 Recommendation:[/bold yellow] Run 'elengenix update' to fix missing tools.")

if __name__ == "__main__":
    check_health()
