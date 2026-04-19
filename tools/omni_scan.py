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
    from bot_utils import send_telegram_notification, send_document
except ImportError:
    # If called from within tools/
    from base_recon import run_subdomain_enum
    from base_scanner import run_nuclei_scan
    from api_finder import find_api_docs
    from js_analyzer import analyze_js
    from param_miner import mine_parameters
    from dork_miner import run_smart_dorking
    from diff_engine import get_new_items
    from reporter import generate_bug_report
    # bot_utils might still be in parent
    sys.path.append(project_root)
    from bot_utils import send_telegram_notification, send_document

console = Console()

def run_omni_scan(target):
    # (Rest of the code remains the same...)
    report_dir = f"reports/{target.replace('.', '_')}"
    if not os.path.exists(report_dir): os.makedirs(report_dir)
    history_dir = "data/history"
    if not os.path.exists(history_dir): os.makedirs(history_dir)

    console.print(Panel(f"[bold green]🔥 ELENGENIX OMNI-SCAN INITIATED: {target}[/bold green]", border_style="red"))
    send_telegram_notification(f"🛸 *OMNI-SCAN STARTED:* `{target}`")

    # (Pipeline execution logic continues...)
    # I'll just finish the function signature for context
    console.print("[bold cyan]Step 1: Smart Google Dorking...[/bold cyan]")
    dorks = run_smart_dorking(target)
    # ...
