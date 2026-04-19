import os
import sys
from rich.console import Console
from rich.panel import Panel

# Path Hack to ensure imports work correctly
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

# Standardize imports
try:
    from tools.base_recon import run_subdomain_enum
    from tools.base_scanner import run_nuclei_scan
    from tools.api_finder import find_api_docs
    from tools.js_analyzer import analyze_js
    from tools.param_miner import mine_parameters
    from tools.dork_miner import run_smart_dorking
    from tools.diff_engine import get_new_items
    from tools.reporter import generate_bug_report
    from tools.html_reporter import generate_html_report # New!
    from bot_utils import send_telegram_notification, send_document
except ImportError:
    from base_recon import run_subdomain_enum
    from base_scanner import run_nuclei_scan
    from api_finder import find_api_docs
    from js_analyzer import analyze_js
    from param_miner import mine_parameters
    from dork_miner import run_smart_dorking
    from diff_engine import get_new_items
    from reporter import generate_bug_report
    from html_reporter import generate_html_report # New!
    from bot_utils import send_telegram_notification, send_document

console = Console()

def run_omni_scan(target):
    report_dir = f"reports/{target.replace('.', '_')}"
    if not os.path.exists(report_dir): os.makedirs(report_dir)
    history_dir = "data/history"
    if not os.path.exists(history_dir): os.makedirs(history_dir)

    console.print(Panel(f"[bold green]🔥 ELENGENIX OMNI-SCAN INITIATED: {target}[/bold green]", border_style="red"))
    send_telegram_notification(f"🛸 *OMNI-SCAN STARTED:* `{target}`")

    # (Pipeline execution logic...)
    # 1. Dorking
    dorks = run_smart_dorking(target)
    
    # 2. Recon
    live_targets_file = run_subdomain_enum(target, report_dir)
    if "Error" in live_targets_file: return

    # 3. Vuln Scan
    scan_results = run_nuclei_scan(live_targets_file, report_dir)

    # 4. Final Reporting (Markdown + HTML)
    findings = [] # In real use, parse results from nuclei_results.txt
    
    # Generate Markdown
    md_report = f"{report_dir}/professional_report.md"
    generate_bug_report(target, findings, md_report)
    
    # Generate HTML Dashboard
    html_report = f"{report_dir}/dashboard.html"
    generate_html_report(target, findings, html_report)

    console.print(Panel(f"[bold green]✨ OMNI-SCAN COMPLETE![/bold green]\nDashboard: {html_report}", border_style="green"))
    
    # Send everything to Telegram
    send_telegram_notification(f"🏁 *OMNI-SCAN COMPLETE for:* `{target}`\nI've sent you the Dashboard and Markdown report.")
    send_document(md_report, caption=f"📄 Markdown Report: {target}")
    send_document(html_report, caption=f"📊 HTML Dashboard: {target}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_omni_scan(sys.argv[1])
