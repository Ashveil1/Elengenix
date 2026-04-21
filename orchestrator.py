import os
import re
from rich.console import Console
from rich.panel import Panel
from tools.base_recon import run_subdomain_enum
from tools.base_scanner import run_nuclei_scan
from tools.js_analyzer import analyze_js
from tools.param_miner import mine_parameters
from bot_utils import send_telegram_notification, send_document

console = Console()

def validate_target(target: str) -> bool:
    """Strictly validates target input to prevent command injection."""
    if not target: return False
    # Only allow domain characters and basic URL structure
    pattern = r'^[a-zA-Z0-9.-]+(/[a-zA-Z0-9.-]*)*$'
    if not re.match(pattern, target.replace("http://", "").replace("https://", "")):
        return False
    return True

def run_standard_scan(target, report_dir_base="reports"):
    """Standard Non-AI Pipeline with Input Validation."""
    if not validate_target(target):
        console.print(f"[bold red]Error: Invalid target format '{target}'[/bold red]")
        return None

    report_dir = f"{report_dir_base}/{target.replace('.', '_').replace('/', '_')}"
    os.makedirs(report_dir, exist_ok=True)

    msg = f"Scan Started: `{target}`\nMode: `Standard Pipeline`"
    send_telegram_notification(msg)
    console.print(Panel(f"Starting Standard Scan on: {target}", border_style="cyan"))

    # Recon
    live_targets_file = run_subdomain_enum(target, report_dir)
    
    # Scanning (Standard Pipeline continues...)
    # ...
    return live_targets_file
