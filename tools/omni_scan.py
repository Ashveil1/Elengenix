import os
import sys
from rich.console import Console
from rich.panel import Panel

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.base_recon import run_subdomain_enum
from tools.base_scanner import run_nuclei_scan
from tools.api_finder import find_api_docs
from tools.js_analyzer import analyze_js
from tools.param_miner import mine_parameters
from tools.dork_miner import run_smart_dorking
from tools.diff_engine import get_new_items
from tools.reporter import generate_bug_report
from bot_utils import send_telegram_notification, send_document

console = Console()

def run_omni_scan(target):
    """
    Omni-Scan: The complete bug hunting pipeline.
    Dorking -> Recon -> API -> Nuclei -> JS -> Params -> Diff -> Report
    """
    report_dir = f"reports/{target.replace('.', '_')}"
    if not os.path.exists(report_dir): os.makedirs(report_dir)
    history_dir = "data/history"
    if not os.path.exists(history_dir): os.makedirs(history_dir)

    console.print(Panel(f"[bold green]🔥 ELENGENIX OMNI-SCAN INITIATED: {target}[/bold green]", border_style="red"))
    send_telegram_notification(f"🛸 *OMNI-SCAN STARTED:* `{target}`\nI am unleashing all weapons.")

    # 1. Smart Dorking
    console.print("[bold cyan]Step 1: Smart Google Dorking...[/bold cyan]")
    dorks = run_smart_dorking(target)
    if dorks:
        send_telegram_notification(f"🕵️ *Dorking:* Found {len(dorks)} potential files for `{target}`")

    # 2. Recon (Subdomains + Live Check)
    console.print("[bold cyan]Step 2: Subdomain Recon & Live Check...[/bold cyan]")
    live_targets_file = run_subdomain_enum(target, report_dir)
    if "Error" in live_targets_file:
        console.print("[red]❌ Recon Failed. Stopping Omni-Scan.[/red]")
        return

    with open(live_targets_file, 'r') as f:
        targets = [line.strip().split()[0] for line in f.readlines()]
    console.print(f"[green]✅ Found {len(targets)} live hosts.[/green]")

    # 3. API Discovery
    console.print("[bold cyan]Step 3: API Discovery (Swagger/Docs)...[/bold cyan]")
    for host in targets[:10]: # Check first 10 for speed
        api_docs = find_api_docs(host)
        if api_docs:
            console.print(f"[yellow]🔌 API Docs Found: {api_docs}[/yellow]")
            send_telegram_notification(f"🔌 *API Docs Found:* `{host}`\n{', '.join(api_docs)}")

    # 4. Vulnerability Scan
    console.print("[bold cyan]Step 4: Nuclei Vulnerability Scan...[/bold cyan]")
    scan_results = run_nuclei_scan(live_targets_file, report_dir)

    # 5. Deep Analysis (JS & Params)
    console.print("[bold cyan]Step 5: JS Secret Analysis & Param Mining...[/bold cyan]")
    for host in targets[:5]:
        if not host.startswith("http"): host = f"http://{host}"
        
        # JS
        js_findings = analyze_js(host)
        if js_findings and "error" not in js_findings:
            console.print(f"[yellow]🔑 Secrets found on {host}[/yellow]")
        
        # Params
        params = mine_parameters(host)
        if params and "error" not in params:
            console.print(f"[green]🎯 Params found on {host}: {params}[/green]")

    # 6. Diffing
    history_file = f"{history_dir}/{target}_subs_history.txt"
    new_assets = get_new_items(targets, history_file)
    if new_assets:
        send_telegram_notification(f"🌟 *New Assets Found:* {len(new_assets)} new subdomains discovered.")

    # 7. Final Report
    final_report = f"{report_dir}/omni_report.md"
    generate_bug_report(target, [], final_report)
    console.print(Panel(f"[bold green]✨ OMNI-SCAN COMPLETE![/bold green]\nReport: {final_report}", border_style="green"))
    send_telegram_notification(f"🏁 *OMNI-SCAN COMPLETE for:* `{target}`")
    send_document(final_report, caption=f"📄 Complete Omni-Report: {target}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_omni_scan(sys.argv[1])
    else:
        print("Usage: python3 omni_scan.py <target>")
