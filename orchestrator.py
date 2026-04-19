import os
from rich.console import Console
from rich.panel import Panel
from tools.base_recon import run_subdomain_enum
from tools.base_scanner import run_nuclei_scan
from tools.js_analyzer import analyze_js
from tools.param_miner import mine_parameters
from bot_utils import send_telegram_notification, send_document

console = Console()

def run_standard_scan(target, report_dir_base="reports"):
    """
    Standard Non-AI Pipeline: Works for both CLI and Telegram.
    """
    report_dir = f"{report_dir_base}/{target.replace('.', '_')}"
    if not os.path.exists(report_dir): os.makedirs(report_dir)

    # Status Update
    msg = f"🚀 *Scan Started for:* `{target}`\nMode: `Standard Pipeline`"
    send_telegram_notification(msg)
    console.print(Panel(f"🚀 Starting Standard Scan on: {target}", border_style="cyan"))

    # 1. Recon
    live_targets_file = run_subdomain_enum(target, report_dir)
    if "Error" in live_targets_file:
        send_telegram_notification(f"❌ *Recon Failed for:* `{target}`")
        return None

    # 2. Nuclei Scan
    scan_results = run_nuclei_scan(live_targets_file, report_dir)
    
    # 3. Deep Analysis (JS & Params)
    with open(live_targets_file, 'r') as f:
        targets = [line.strip().split()[0] for line in f.readlines()[:5]]

    for url in targets:
        if not url.startswith("http"): url = f"http://{url}"
        
        # JS Analysis
        js_findings = analyze_js(url)
        if js_findings and "error" not in js_findings:
            finding_msg = f"🔑 *Secrets Found on:* `{url}`\n"
            for k, v in js_findings.items(): finding_msg += f"- {k}: `{', '.join(v[:3])}`\n"
            send_telegram_notification(finding_msg)
            console.print(f"[bold yellow]🔥 HIT! Secrets on {url}[/bold yellow]")

        # Param Mining
        params = mine_parameters(url)
        if params and "error" not in params:
            param_msg = f"🎯 *Params Found on:* `{url}`\n- `{', '.join(params)}`"
            send_telegram_notification(param_msg)
            console.print(f"[bold green]🎯 HIT! Params on {url}[/bold green]")

    # Final Report
    send_telegram_notification(f"✨ *Scan Complete for:* `{target}`")
    if os.path.exists(scan_results):
        send_document(scan_results, caption=f"📄 Nuclei Report: {target}")
    
    return scan_results
