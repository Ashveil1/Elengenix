"""
watchman.py — Elengenix 24/7 Target Monitoring Daemon (v1.5.0)
- Automated Periodic Scanning with State Tracking
- SHA256 Result Fingerprinting (Token Optimization)
- Smart AI Analysis on Change Detection
- Graceful Shutdown and Persistence
"""

import time
import os
import json
import logging
import signal
import sys
import hashlib
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from orchestrator import run_standard_scan
from bot_utils import send_telegram_notification
from agent import get_agent

# ── Logging Setup ─────────────────────────────────────────────────────────────
LOG_DIR = Path("data")
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "watchman.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("elengenix.watchman")

# ── State Management ──────────────────────────────────────────────────────────
STATE_FILE = LOG_DIR / "watchman_state.json"

def load_state() -> Dict[str, Any]:
    """Loads previous monitoring state from disk."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"State file corrupted, starting fresh: {e}")
    return {}

def save_state(state: Dict[str, Any]):
    """Persists current state to JSON."""
    try:
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to persist state: {e}")

def get_results_fingerprint(report_dir: str) -> str:
    """Generates a SHA256 hash of found URLs and findings to detect changes."""
    # We look for common output files in the report directory
    fingerprint_data = ""
    report_path = Path(report_dir)
    
    # Files that indicate a change in attack surface or vulnerabilities
    interesting_files = ["discovered_urls.txt", "findings.txt", "nmap_scan.txt"]
    
    for filename in interesting_files:
        f = report_path / filename
        if f.exists():
            # Only use the last modified time and size for a quick hash, 
            # or read content for a deep hash. Let's do a fast content sample.
            try:
                fingerprint_data += f.read_text(encoding="utf-8")[:5000] 
            except: pass
            
    if not fingerprint_data:
        return "none"
        
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()

# ── Main Watcher Logic ───────────────────────────────────────────────────────
async def start_watching(target_list_path: str = "targets_to_watch.txt", interval_hours: int = 1):
    logger.info("👁️ Watchman Activated. 24/7 Monitoring Initialized.")
    send_telegram_notification("👁️ *Watchman Mode:* Activated. Continuous monitoring is now online.")

    # Initialize AI Agent (v1.5.0 Factory)
    try:
        agent = get_agent()
    except Exception as e:
        logger.error(f"Failed to init AI agent: {e}. Running in scan-only mode.")
        agent = None

    state = load_state()
    interval_seconds = interval_hours * 3600

    # 🛑 Signal Handling
    def shutdown_handler(sig, frame):
        logger.info("🛑 Watchman shutting down. Finalizing state...")
        save_state(state)
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    while True:
        try:
            target_file = Path(target_list_path)
            if not target_file.exists():
                logger.warning(f"Target list missing: {target_list_path}. Sleeping for {interval_hours}h.")
                await asyncio.sleep(interval_seconds)
                continue

            targets = [line.strip() for line in target_file.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
            logger.info(f"Monitor Loop: Processing {len(targets)} targets.")

            for target in targets:
                logger.info(f"🔍 Monitoring Target: {target}")
                
                target_state = state.get(target, {})
                last_hash = target_state.get("last_hash")

                # 1. Execute Scan (Async-Safe)
                try:
                    report_dir = await run_standard_scan(target)
                    if not report_dir:
                        logger.warning(f"Scan skipped or failed for {target}")
                        continue

                    current_hash = get_results_fingerprint(report_dir)
                    
                    if current_hash == last_hash:
                        logger.info(f"✅ No changes detected for {target}. Token usage optimized.")
                        state[target] = {"last_hash": current_hash, "last_check": datetime.now().isoformat()}
                        save_state(state)
                        continue

                    logger.info(f"⚠️ NEW DATA DETECTED for {target}. Invoking AI analysis...")
                except Exception as e:
                    logger.error(f"Pipeline error for {target}: {e}")
                    continue

                # 2. AI Intelligence Round
                if agent:
                    try:
                        query = (
                            f"Analyze the latest scan results for {target} at {report_dir}. "
                            "Identify NEW changes, critical vulnerabilities, or increased risk. "
                            "Provide a concise summary for a professional security alert."
                        )
                        analysis = agent.process_query(query, target=target)
                        
                        if analysis:
                            send_telegram_notification(f"🚨 *WATCHMAN ALERT: {target}*\n\n{analysis[:3500]}")
                            logger.info(f"Alert dispatched for {target}")

                        state[target] = {
                            "last_hash": current_hash,
                            "last_check": datetime.now().isoformat(),
                            "status": "alert_sent"
                        }
                    except Exception as e:
                        logger.error(f"AI Reasoning failed for {target}: {e}")

                save_state(state)

            logger.info(f"💤 Loop finished. Sleeping for {interval_hours} hour(s).")
            await asyncio.sleep(interval_seconds)

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Daemon Loop Crash: {e}. Recovering in 5 mins...")
            await asyncio.sleep(300)

    save_state(state)
    logger.info("Watchman Terminated.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Elengenix Watchman Monitoring Daemon")
    parser.add_argument("--targets", default="targets_to_watch.txt", help="File containing domains to monitor")
    parser.add_argument("--interval", type=int, default=1, help="Interval in hours")
    args = parser.parse_args()
    
    asyncio.run(start_watching(args.targets, args.interval))
