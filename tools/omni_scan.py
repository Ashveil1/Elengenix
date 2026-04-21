import os
import sys
import subprocess
import shutil
from rich.console import Console
from rich.panel import Panel

# Path standardization
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path: sys.path.append(project_root)

from tools.base_recon import run_subdomain_enum
from tools.js_analyzer import analyze_js
from tools.param_miner import mine_parameters
from tools.dork_miner import run_smart_dorking
from tools.memory_manager import save_learning
from bot_utils import send_telegram_notification, send_document

console = Console()

def run_omni_scan(target):
    report_dir = f"reports/{target.replace('.', '_')}"
    os.makedirs(report_dir, exist_ok=True)

    console.print(Panel(f"ELENGENIX FULL-SCALE ATTACK: {target}", border_style="red"))
    send_telegram_notification(f"🔥 *HUNTING STARTED:* `{target}`\nI am unleashing the full arsenal.")

    # 1. Professional Recon (Subfinder + Wayback + Httpx)
    live_targets_file = run_subdomain_enum(target, report_dir)

    # 2. Deep Crawler (Katana)
    console.print("[*] Step 2: Extracting every possible URL (Katana)...")
    all_urls_file = os.path.join(report_dir, "all_discovered_urls.txt")
    if shutil.which("katana"):
        subprocess.run(["katana", "-u", target, "-o", all_urls_file, "-silent", "-nc"], capture_output=True)
    else:
        # Fallback to recon results
        shutil.copy(live_targets_file, all_urls_file)

    # 3. THE HEART: Aggressive Nuclei Scan (Automatic Scan Mode)
    console.print("[*] Step 3: Unleashing Nuclei Automatic Scan (Finding REAL Bugs)...")
    results_file = os.path.join(report_dir, "nuclei_vulnerabilities.txt")
    
    if shutil.which("nuclei"):
        # 🔥 -as (Automatic Scan) is the key to find real vulnerabilities based on tech stack
        subprocess.run(["nuclei", "-l", all_urls_file, "-o", results_file, "-as", "-silent"], check=False)
        
        # Notify Telegram for each Critical/High finding
        if os.path.exists(results_file):
            with open(results_file, "r") as f:
                findings = f.readlines()
                for finding in findings:
                    if any(sev in finding.lower() for sev in ["critical", "high"]):
                        send_telegram_notification(f"🚨 *VULNERABILITY FOUND:* \n`{finding[:500]}`")

    # 4. Final Reporting
    console.print(Panel("✨ HUNT COMPLETE. Check reports/ folder.", border_style="green"))
    send_telegram_notification(f"🏁 *HUNT FINISHED:* `{target}`")
    if os.path.exists(results_file):
        send_document(results_file, caption=f"📄 Full Vulnerability Report: {target}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_omni_scan(sys.argv[1])
