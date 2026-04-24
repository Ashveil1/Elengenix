"""
omni_scan.py — Elengenix Full-Scale Mission Orchestrator (v1.5.0)
- Deep Recon (Katana + Wayback)
- Automated Vulnerability Scan (Nuclei)
- Safe Argument Handling and Rate Limiting
"""

import os
import sys
import subprocess
import shutil
import re
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

# Path standardization
current_dir = Path(__file__).parent.absolute()
project_root = current_dir.parent
if str(project_root) not in sys.path: sys.path.append(str(project_root))

from bot_utils import send_telegram_notification

console = Console()

def sanitize_target(target: str) -> str:
    """Rigorous domain/URL validation."""
    clean_target = re.sub(r'^https?://', '', target).split('/')[0]
    pattern = re.compile(r'^[a-zA-Z0-9.-]+$')
    if not pattern.match(clean_target):
        raise ValueError(f"Dangerous or invalid target format: {target}")
    return clean_target

def run_omni_scan(target: str, rate_limit: int = 5):
    """
    Executes a comprehensive attack chain.
    """
    try:
        domain = sanitize_target(target)
    except ValueError as e:
        console.print(f"[bold red]❌ {e}[/bold red]")
        return

    report_dir = project_root / "reports" / domain.replace('.', '_')
    report_dir.mkdir(parents=True, exist_ok=True)
    
    discovery_file = report_dir / "all_urls.txt"
    findings_file = report_dir / "nuclei_findings.txt"

    console.print(Panel(f"DEPLOYING OMNI-SCAN: {domain}", border_style="red", title="High-Intensity Mission"))
    send_telegram_notification(f"🔥 *Omni-Scan Active:* Hunting on `{domain}` (RL: {rate_limit})")

    # 1. Deep Discovery (Katana)
    if shutil.which("katana"):
        console.print(f"[*] Crawling {domain}...")
        subprocess.run([
            "katana", "-u", f"https://{domain}", "-o", str(discovery_file), 
            "-silent", "-concurrency", str(rate_limit * 2)
        ], check=False)
    
    # 2. Historical Discovery (Wayback)
    if shutil.which("waybackurls"):
        console.print("[*] Fetching historical data...")
        with open(discovery_file, "a") as f:
            subprocess.run(["waybackurls", domain], stdout=f, check=False)

    # 3. Vulnerability Injection (Nuclei)
    if shutil.which("nuclei") and discovery_file.exists():
        console.print("[*] Launching multi-vector Nuclei scan...")
        subprocess.run([
            "nuclei", "-l", str(discovery_file), "-o", str(findings_file),
            "-silent", "-as", "-rl", str(rate_limit * 10)
        ], check=False)

    console.print(f"\n[bold green]✅ Mission Accomplished.[/bold green]")
    console.print(f"📁 Reports: {report_dir.relative_to(project_root)}")
    send_telegram_notification(f"🏁 *Omni-Scan Complete:* Results stored for `{domain}`")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Default rate limit if called directly
        run_omni_scan(sys.argv[1], rate_limit=5)
