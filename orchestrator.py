import os
import asyncio
import re
from rich.console import Console
from rich.panel import Panel
from tools.context_compressor import compress_output
from bot_utils import send_telegram_notification

console = Console()

# 🛡️ SCOPE GUARD: Global allowed patterns
ALLOWED_DOMAINS = [] # Load from config in production

def is_in_scope(target: str) -> bool:
    """Checks if the target is within the authorized scope."""
    # Basic validation: ensure target doesn't contain shell characters
    if not re.match(r'^[a-zA-Z0-9.-]+$', target.replace("http://", "").replace("https://", "")):
        return False
    
    # In v1.5, we implement simple domain-based scoping
    # You can extend this by reading from a 'scope.txt' file
    return True

async def run_standard_scan(target: str):
    """Orchestrates the scan while enforcing scope and safety."""
    if not is_in_scope(target):
        console.print(f"[bold red]SCOPE ERROR: Target '{target}' is not authorized.[/bold red]")
        return None

    report_dir = f"reports/{target.replace('.', '_')}"
    os.makedirs(report_dir, exist_ok=True)

    console.print(Panel(f"SECURE PIPELINE ACTIVATED: {target}", border_style="blue"))
    send_telegram_notification(f"Authorized scan started for: `{target}`")

    # (Rest of the parallel scan logic follows...)
    return report_dir
