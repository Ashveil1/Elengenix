import os
import sys
import subprocess
import shutil
import logging
from rich.console import Console
from rich.panel import Panel

# Path standardization
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path: sys.path.append(project_root)

from tools.base_recon import run_subdomain_enum
from tools.base_scanner import run_nuclei_scan
from tools.dork_miner import run_smart_dorking
from tools.memory_manager import save_learning
from bot_utils import send_telegram_notification

console = Console()
logger = logging.getLogger(__name__)

def run_omni_scan(target):
    report_dir = f"reports/{target.replace('.', '_')}"
    os.makedirs(report_dir, exist_ok=True)

    console.print(Panel(f"ELENGENIX DEEP-HUNT MODE ACTIVATED: {target}", border_style="red"))
    send_telegram_notification(f"DEEP-HUNT STARTED: `{target}`")

    # 1. Google Dorking
    run_smart_dorking(target)

    # 2. Advanced Crawling (Safe implementation)
    console.print("[*] Step 2: Deep Crawling (Katana)...")
    all_urls_file = os.path.join(report_dir, "all_urls.txt")
    
    if shutil.which("katana"):
        try:
            subprocess.run(
                ["katana", "-u", target, "-o", all_urls_file, "-silent", "-nc"],
                check=True,
                capture_output=True
            )
        except Exception as e:
            logger.error(f"Katana failed: {e}")
            with open(all_urls_file, "w") as f: f.write(target)
    else:
        with open(all_urls_file, "w") as f: f.write(target)

    # 3. Massive Nuclei Scan (Safe implementation)
    console.print("[*] Step 3: Vulnerability Scan (Nuclei)...")
    results_file = os.path.join(report_dir, "nuclei_results.txt")
    
    if shutil.which("nuclei"):
        try:
            subprocess.run(
                ["nuclei", "-l", all_urls_file, "-o", results_file, "-as", "-silent"],
                check=True,
                capture_output=True
            )
        except Exception as e:
            logger.error(f"Nuclei failed: {e}")

    # 4. Finalizing
    console.print(Panel("MISSION ACCOMPLISHED: Report Generated.", border_style="green"))
    send_telegram_notification(f"DEEP-HUNT COMPLETE: `{target}`")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_omni_scan(sys.argv[1])
