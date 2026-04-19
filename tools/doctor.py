import os
import shutil
import yaml
import subprocess
import questionary
from rich.console import Console
from rich.table import Table

console = Console()

def repair_system():
    """
    Attempts to fix missing tools and configurations.
    """
    console.print("[bold yellow]🛠️  Initiating Auto-Repair...[/bold yellow]")
    
    # Fix tools
    missing_tools = []
    tools_to_check = ["subfinder", "nuclei", "httpx", "katana", "waybackurls"]
    for tool in tools_to_check:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if missing_tools:
        console.print(f"[*] Missing tools found: {', '.join(missing_tools)}")
        if questionary.confirm("Do you want me to try reinstalling these tools?", default=True).ask():
            # Trigger setup logic for missing tools
            from dependency_manager import check_and_install_dependencies
            check_and_install_dependencies()
    
    # Fix Config
    config_path = "config.yaml"
    if not os.path.exists(config_path) or os.stat(config_path).st_size == 0:
        console.print("[!] Config file is missing or broken.")
        if questionary.confirm("Generate a new default config?", default=True).ask():
            from wizard import main as run_wizard
            run_wizard()

    console.print("[bold green]✅ Repair process finished.[/bold green]")

def check_health(fix=False):
    """
    Check system health. If fix=True, run repair.
    """
    if fix:
        repair_system()
        
    console.print("[bold cyan]🏥 Elengenix Doctor - System Health Check[/bold cyan]\n")
    
    # 1. Config Check
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f) or {}
    except:
        config = {}

    config_table = Table(title="Configuration")
    config_table.add_column("Service", style="cyan")
    config_table.add_row("Config File", "✅ Exists" if config else "❌ Broken/Missing")
    console.print(config_table)

    # 2. Tools Check
    tools_table = Table(title="Security Tools")
    tools_table.add_column("Tool", style="cyan")
    tools_table.add_column("Status", style="green")
    
    all_ok = True
    for tool in ["subfinder", "nuclei", "httpx", "katana", "waybackurls"]:
        status = "✅ OK" if shutil.which(tool) else "❌ Missing"
        if "Missing" in status: all_ok = False
        tools_table.add_row(tool, status)
    
    console.print(tools_table)

    if not all_ok:
        console.print("\n[bold red]⚠️  System is NOT healthy![/bold red]")
        if not fix and questionary.confirm("Would you like to run the Repair tool?").ask():
            repair_system()
            check_health(fix=False) # Re-check after repair
    else:
        console.print("\n[bold green]🌟 System is healthy and ready for battle![/bold green]")

if __name__ == "__main__":
    check_health()
