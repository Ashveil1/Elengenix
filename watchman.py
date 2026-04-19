import time
import os
import yaml
from orchestrator import run_standard_scan
from bot_utils import send_telegram_notification
from agent_brain import ElengenixAgent

def start_watching(target_list_path):
    """
    Background Watcher: Periodically checks targets and 
    messages the user PROACTIVELY if something is found.
    """
    agent = ElengenixAgent()
    send_telegram_notification("🛡️ *Watchman Mode:* Activated. I am now monitoring your targets 24/7.")

    while True:
        if not os.path.exists(target_list_path):
            print(f"Waiting for targets in {target_list_path}...")
            time.sleep(60)
            continue

        with open(target_list_path, "r") as f:
            targets = [line.strip() for line in f.readlines() if line.strip()]

        for target in targets:
            print(f"[*] Proactive Check: {target}")
            # In a real scenario, we'd compare results with previous scans
            # For this demo, we'll let the AI decide if it needs to notify you
            
            query = f"Monitor the target {target}. Check if there are any new vulnerabilities or changes."
            agent.process_query(query) # This will trigger proactive TG messages

        # Wait for 1 hour (or any interval) before next proactive check
        time.sleep(3600)

if __name__ == "__main__":
    # You can put targets in a file and let the Watchman do the work
    start_watching("targets_to_watch.txt")
