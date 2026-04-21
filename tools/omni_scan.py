import os
import sys
import subprocess
import shutil
import shlex
import re
from rich.console import Console
from rich.panel import Panel

# Path standardization
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path: sys.path.append(project_root)

from tools.base_recon import run_subdomain_enum
from bot_utils import send_telegram_notification

console = Console()

def sanitize_target(target: str) -> str:
    """
    Prevents command injection by allowing only valid domain/URL patterns.
    """
    # Remove protocol if present for validation
    clean_target = re.sub(r'^https?://', '', target)
    # Regex for valid domain name
    pattern = re.compile(r'^[a-zA-Z0-9.-]+$')
    if not pattern.match(clean_target):
        raise ValueError(f"Invalid target format: {target}")
    return target

def run_omni_scan(target):
    try:
        safe_target = sanitize_target(target)
    except ValueError as e:
        console.print(f"[bold red]Security Error: {e}[/bold red]")
        return

    report_dir = f"reports/{safe_target.replace('.', '_')}"
    os.makedirs(report_dir, exist_ok=True)

    console.print(Panel(f"ELENGENIX FULL-SCALE MISSION: {safe_target}", border_style="red"))
    send_telegram_notification(f"Deep hunting initiated on: {safe_target}")

    # 1. Recon (Using safe subprocess list)
    all_urls_file = os.path.join(report_dir, "discovered_urls.txt")
    
    if shutil.which("katana"):
        console.print("[*] Launching Katana Deep Crawl...")
        # 🛡️ SECURITY: No shell=True. Using list arguments.
        subprocess.run(["katana", "-u", safe_target, "-o", all_urls_file, "-silent"], capture_output=True)

    if shutil.which("nuclei"):
        console.print("[*] Launching Nuclei Multi-Vulnerability Scan...")
        results_file = os.path.join(report_dir, "findings.txt")
        subprocess.run(["nuclei", "-l", all_urls_file, "-o", results_file, "-as", "-silent"], capture_output=True)

    console.print(Panel("MISSION COMPLETED. EVIDENCE STORED IN REPORTS.", border_style="green"))
    send_telegram_notification(f"Scan finished for {safe_target}. Finalizing reports.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_omni_scan(sys.argv[1])
