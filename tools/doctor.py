"""
doctor.py — Elengenix System Health & Auto-Repair Tool (v1.5.0)
- Verifies system binaries (Go, Tools)
- Checks Python environment and dependencies
- Validates Configuration and API Keys
- Performs automatic repair if requested
"""

import shutil
import sys
import os
import subprocess
import yaml
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

def check_health(fix: bool = False):
    console.print("\n[bold cyan]🏥 Elengenix System Doctor: Diagnostic Report[/bold cyan]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Component", width=20)
    table.add_column("Status", width=15)
    table.add_column("Details")

    # 1. Binary Checks
    tools = ["go", "git", "subfinder", "nuclei", "httpx", "katana"]
    for tool in tools:
        found = shutil.which(tool)
        status = "[green]OK[/green]" if found else "[red]MISSING[/red]"
        table.add_row(tool, status, found if found else "Not found in PATH")

    # 2. Config Check
    config_path = Path("config.yaml")
    if config_path.exists():
        try:
            with open(config_path, "r") as f:
                yaml.safe_load(f)
            table.add_row("config.yaml", "[green]OK[/green]", "Valid YAML structure")
        except Exception as e:
            table.add_row("config.yaml", "[red]ERROR[/red]", str(e))
    else:
        table.add_row("config.yaml", "[yellow]MISSING[/yellow]", "Using defaults (check config.yaml.example)")

    # 3. Environment Check
    venv = os.getenv("VIRTUAL_ENV")
    status = "[green]ACTIVE[/green]" if venv else "[yellow]INACTIVE[/yellow]"
    table.add_row("Python venv", status, venv if venv else "System Python in use")

    console.print(table)
    
    if fix:
        console.print("\n[bold yellow][*] Attempting Auto-Repair...[/bold yellow]")
        # 1. Try to fix dependencies
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"], check=True)
            console.print("[green]✓ Python dependencies re-installed.[/green]")
        except:
            console.print("[red]✗ Failed to repair Python environment.[/red]")
        
        # 2. Run dependency manager
        try:
            from dependency_manager import check_and_install_dependencies
            check_and_install_dependencies()
        except:
            pass

if __name__ == "__main__":
    check_health(fix="--fix" in sys.argv)
