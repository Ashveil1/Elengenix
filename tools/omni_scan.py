import os
import sys
import subprocess
from rich.console import Console
from rich.panel import Panel

# Standardizing paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path: sys.path.append(project_root)

from tools.base_recon import run_subdomain_enum
from tools.base_scanner import run_nuclei_scan
from tools.api_finder import find_api_docs
from tools.js_analyzer import analyze_js
from tools.param_miner import mine_parameters
from tools.dork_miner import run_smart_dorking
from tools.memory_manager import save_learning
from bot_utils import send_telegram_notification, send_document

console = Console()

def run_omni_scan(target):
    report_dir = f"reports/{target.replace('.', '_')}"
    os.makedirs(report_dir, exist_ok=True)

    console.print(Panel(f"[bold red]💀 ELENGENIX DEEP-HUNT MODE ACTIVATED: {target}[/bold red]", border_style="red"))
    send_telegram_notification(f"*DEEP-HUNT STARTED:* `{target}`\nI will not stop until everything is found.")

    # 1. Google Dorking (Finding Exposed Files)
    dorks = run_smart_dorking(target)

    # 2. Advanced Crawling with Katana (Finding EVERY hidden link)
    console.print("[bold cyan]Step 2: Deep Crawling (Katana)...[/bold cyan]")
    all_urls_file = f"{report_dir}/all_urls.txt"
    try:
        # Katana will find every link, even in JS and deep folders
        subprocess.run(f"katana -u {target} -o {all_urls_file} -silent -nc", shell=True)
    except:
        with open(all_urls_file, "w") as f: f.write(target)

    # 3. Massive Nuclei Scan (All templates, all severities)
    console.print("[bold cyan]Step 3: Massive Vulnerability Scan (Nuclei)...[/bold cyan]")
    # รันแบบจัดเต็ม -as (automatic scan)
    subprocess.run(f"nuclei -l {all_urls_file} -o {report_dir}/nuclei_results.txt -as -silent", shell=True)

    # 4. AI Code Audit & Logic Check
    with open(all_urls_file, "r") as f:
        found_urls = [line.strip() for line in f.readlines()[:20]] # Check top 20 links
    
    for url in found_urls:
        console.print(f"[bold blue]AI Auditing Code:[/bold blue] {url}")
        # Analyze JS and Params
        js = analyze_js(url)
        params = mine_parameters(url)
        
        # Save any finding to Long-term memory
        if js or params:
            save_learning(target, f"URL {url} has interesting JS/Params")

    # 5. Final Report
    console.print(Panel("[bold green]MISSION ACCOMPLISHED: Report Generated.[/bold green]", border_style="green"))
    send_telegram_notification(f"*DEEP-HUNT COMPLETE:* `{target}`\nEverything found is in your report.")
