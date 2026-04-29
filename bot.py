"""
Elengenix - Telegram Bot (v1.5.0)
- High-Security Implementation
- Rate Limiting & Domain Validation
- Robust Async Execution & Race Condition Prevention
- Production-Grade Logging and Error Handling
"""

import logging
import yaml
import os
import asyncio
import re
import stat
import time
from collections import defaultdict, deque
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from telegram import Update
from telegram.ext import (
 ApplicationBuilder,
 ContextTypes,
 CommandHandler,
 MessageHandler,
 filters,
)
from agent_brain import ElengenixAgent

# Logging Setup 
logging.basicConfig(
 format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
 level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Config Security Check 
CONFIG_PATH = Path(__file__).parent / "config.yaml"

def check_config_security(path: Path):
    """Check file permissions (chmod 600) for security."""
    if not path.exists(): return
    mode = path.stat().st_mode
    # Warn if readable by others (Group or World)
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        logger.warning(f" {path.name} has loose permissions: {oct(mode)}")
        logger.warning(" Run: chmod 600 config.yaml to protect your secrets")

# Load Config 
try:
    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)
        check_config_security(CONFIG_PATH)
except Exception as e:
    logger.error(f"Config error: {e}")
    raise SystemExit(1)

# Rate Limiting Setup 
# Max 3 commands per 60 seconds per user
RATE_LIMIT = 3
RATE_WINDOW = 60
user_requests = defaultdict(deque)

def check_rate_limit(user_id: int) -> bool:
    now = time.time()
    while user_requests[user_id] and user_requests[user_id][0] < now - RATE_WINDOW:
        user_requests[user_id].popleft()
    if len(user_requests[user_id]) >= RATE_LIMIT:
        return False
    user_requests[user_id].append(now)
    return True

# Domain Validation 
def is_valid_domain(target: str) -> bool:
    """Strictly validate domain format to prevent injection and internal scans."""
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
    # Standard domain regex
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    if not re.match(pattern, clean_target):
        return False
    # Block local/private address space
    if clean_target.lower() in ['localhost', '127.0.0.1'] or clean_target.endswith('.local'):
        return False
    return True

# Global State 
executor = ThreadPoolExecutor(max_workers=4)
try:
    agent = ElengenixAgent()
    logger.info("Elengenix AI Agent loaded.")
except Exception as e:
    logger.warning(f"AI Agent failed to load: {e} (Continuing in tool-only mode)")
    agent = None

# Helpers 
async def run_in_thread(func, *args):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(executor, func, *args)

async def safe_reply(update: Update, text: str, parse_mode: str = "Markdown"):
    """Failsafe reply helper."""
    try:
        if update.message:
            await update.message.reply_text(text, parse_mode=parse_mode)
        else:
            # For cases where message object might be missing (callback context)
            await update.effective_chat.send_message(text, parse_mode=parse_mode)
    except Exception:
        await update.effective_chat.send_message(text, parse_mode=None)

# Command Handlers 

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome = (
        " *Elengenix Hunter Bot v1.5.0*\n\n"
        "Professional Bug Bounty Automation Hub.\n\n"
        " *Commands:*\n"
        " `/scan <domain>` — Optimized Recon & Scan\n"
        " `/ask <query>` — Persistent AI Agent\n"
        " `/status` — Check System Health\n"
        " `/bounty` — Discover bug bounty programs\n"
        " `/mission <target>` — Start autonomous mission\n"
        " `/pause <mission_id>` — Pause mission\n"
        " `/resume <mission_id>` — Resume mission\n"
        " `/findings <mission_id>` — View findings\n"
        " `/programs` — List top programs\n"
    )
    await safe_reply(update, welcome)

async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    import shutil
    tools = ["subfinder", "httpx", "nuclei", "katana"]
    lines = [" *System Health Checklist:*\n"]
    for tool in tools:
        found = shutil.which(tool) is not None
        lines.append(f"{'' if found else ''} `{tool}`")
    lines.append(f"\n AI Agent: {' Online' if agent else ' Offline'}")
    await safe_reply(update, "\n".join(lines))

async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not check_rate_limit(user_id):
        await safe_reply(update, "⏳ *Rate Limit:* Please wait a moment before next scan.")
        return

    if not context.args:
        await safe_reply(update, " Usage: `/scan example.com`")
        return

    target = context.args[0].strip()
    if not is_valid_domain(target):
        await safe_reply(update, " *Security Error:* Invalid domain or unauthorized scope.")
        return

    await safe_reply(update, f" *Scan Initiated:* `{target}`\nRunning parallel recon and analysis...")

    try:
        from orchestrator import run_standard_scan
        # ⏱ 10-Minute Timeout Protection
        result = await asyncio.wait_for(
            run_in_thread(run_standard_scan, target),
            timeout=600
        )
        if result:
            await safe_reply(update, f" *Scan Complete:* `{target}`\nReports saved to cloud/local storage.")
        else:
            await safe_reply(update, f" Scan finished for `{target}` with no critical findings.")
    except asyncio.TimeoutError:
        await safe_reply(update, "⏱ *Timeout:* Scan exceeded 10 minutes. Check local logs.")
    except Exception as e:
        logger.error(f"Scan error: {e}")
        await safe_reply(update, f" *System Error:* `{str(e)[:100]}`")

async def cmd_ask(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not agent:
        await safe_reply(update, " AI Agent is currently offline.")
        return

    query = " ".join(context.args).strip()
    if not query:
        await safe_reply(update, " Usage: `/ask find vulnerabilities on example.com`")
        return

    chat_id = update.effective_chat.id
    await safe_reply(update, " *Sentinel is analyzing technical vectors...*")

    # Race-Condition Safe Callback
    def bot_callback(msg: str):
        asyncio.create_task(context.bot.send_message(chat_id=chat_id, text=f" {msg}", parse_mode="Markdown"))

    try:
        response = await run_in_thread(agent.process_query, query, bot_callback)
        if response:
            await safe_reply(update, f" *Agent Findings:*\n\n{response[:3800]}")
    except Exception as e:
        logger.error(f"AI error: {e}")
        await safe_reply(update, f" *AI Error:* `{str(e)[:100]}`")

async def cmd_bounty(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start autonomous bounty hunt."""
    from tools.bounty_intelligence import BountyIntelligence
    import os

    api_key = os.environ.get("HACKERONE_API_KEY")
    api_user = os.environ.get("HACKERONE_API_USER")

    intel = BountyIntelligence(api_key=api_key, api_username=api_user)

    await safe_reply(update, "*Discovering bug bounty programs...*")

    try:
        if api_key:
            programs = await run_in_thread(intel.discover_programs_api, 500, 10)
        else:
            programs = await run_in_thread(intel.discover_programs_public, 10)

        if not programs:
            await safe_reply(update, "No programs found")
            return

        ranked = await run_in_thread(intel.rank_programs, programs)
        top = ranked[0]

        message = (
            f"*Top Recommendation*\n\n"
            f"Program: *{top.name}*\n"
            f"Reward: {top.bounty_range}\n"
            f"URL: {top.url}\n"
            f"Score: {top.score_total:.1f}/100\n\n"
            f"Start scan with: `/mission {top.url}`"
        )
        await safe_reply(update, message)

    except Exception as e:
        logger.error(f"Bounty discovery error: {e}")
        await safe_reply(update, f"Error: {str(e)[:100]}")

async def cmd_mission(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start autonomous scanning mission."""
    from tools.smart_scanner import SmartScanner

    if not context.args:
        await safe_reply(update, "Usage: `/mission <target>")
        return

    target = context.args[0].strip()
    if not is_valid_domain(target):
        await safe_reply(update, "Invalid domain")
        return

    await safe_reply(update, f"*Starting mission for* `{target}`")

    try:
        scanner = SmartScanner(target=target, auto_pause=True, pause_after_hours=3)
        results = await run_in_thread(scanner.run)

        message = (
            f"*Mission {results['mission_id']}*\n\n"
            f"Status: {results['status']}\n"
            f"Findings: {len(results.get('findings', []))}\n"
            f"Tokens: {results['tokens_used']:,}\n"
            f"Duration: {results['duration_seconds']:.0f}s"
        )
        await safe_reply(update, message)

        if results['status'] == 'paused':
            await safe_reply(update, f"Resume with: `/resume {results['mission_id']}`")

    except Exception as e:
        logger.error(f"Mission error: {e}")
        await safe_reply(update, f"Error: {str(e)[:100]}")

async def cmd_mission_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check mission status."""
    from tools.smart_scanner import SmartScanner

    if not context.args:
        await safe_reply(update, "Usage: `/status <mission_id>`")
        return

    mission_id = context.args[0].strip()

    try:
        scanner = SmartScanner.load(mission_id)
        if not scanner:
            await safe_reply(update, f"Mission not found: `{mission_id}`")
            return

        status = scanner.get_status()
        from tools.telegram_bridge import TelegramBridge
        bridge = TelegramBridge()
        await bridge.notify_mission_status(mission_id, status)

    except Exception as e:
        logger.error(f"Status error: {e}")
        await safe_reply(update, f"Error: {str(e)[:100]}")

async def cmd_pause(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Pause a running mission."""
    from tools.smart_scanner import SmartScanner

    if not context.args:
        await safe_reply(update, "Usage: `/pause <mission_id>`")
        return

    mission_id = context.args[0].strip()

    try:
        scanner = SmartScanner.load(mission_id)
        if not scanner:
            await safe_reply(update, f"Mission not found: `{mission_id}`")
            return

        scanner.pause()
        await safe_reply(update, f"Mission `{mission_id}` paused")

    except Exception as e:
        logger.error(f"Pause error: {e}")
        await safe_reply(update, f"Error: {str(e)[:100]}")

async def cmd_resume(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Resume a paused mission."""
    from tools.smart_scanner import SmartScanner

    if not context.args:
        await safe_reply(update, "Usage: `/resume <mission_id>`")
        return

    mission_id = context.args[0].strip()

    try:
        scanner = SmartScanner.load(mission_id)
        if not scanner:
            await safe_reply(update, f"Mission not found: `{mission_id}`")
            return

        await safe_reply(update, f"Resuming mission `{mission_id}`")
        results = await run_in_thread(scanner.resume)

        message = (
            f"Mission resumed\n\n"
            f"Status: {results['status']}\n"
            f"Findings: {len(results.get('findings', []))}"
        )
        await safe_reply(update, message)

    except Exception as e:
        logger.error(f"Resume error: {e}")
        await safe_reply(update, f"Error: {str(e)[:100]}")

async def cmd_findings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """View mission findings."""
    from tools.smart_scanner import SmartScanner

    if not context.args:
        await safe_reply(update, "Usage: `/findings <mission_id>`")
        return

    mission_id = context.args[0].strip()

    try:
        scanner = SmartScanner.load(mission_id)
        if not scanner:
            await safe_reply(update, f"Mission not found: `{mission_id}`")
            return

        from tools.telegram_bridge import TelegramBridge
        bridge = TelegramBridge()
        await bridge.notify_findings_list(mission_id, scanner.findings)

    except Exception as e:
        logger.error(f"Findings error: {e}")
        await safe_reply(update, f"Error: {str(e)[:100]}")

async def cmd_programs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """List top bug bounty programs."""
    from tools.bounty_intelligence import BountyIntelligence
    import os

    api_key = os.environ.get("HACKERONE_API_KEY")
    api_user = os.environ.get("HACKERONE_API_USER")

    intel = BountyIntelligence(api_key=api_key, api_username=api_user)

    await safe_reply(update, "*Fetching programs...*")

    try:
        if api_key:
            programs = await run_in_thread(intel.discover_programs_api, 500, 5)
        else:
            programs = await run_in_thread(intel.discover_programs_public, 5)

        if not programs:
            await safe_reply(update, "No programs found")
            return

        ranked = await run_in_thread(intel.rank_programs, programs)

        from tools.telegram_bridge import TelegramBridge
        bridge = TelegramBridge()
        await bridge.notify_programs_list([p.__dict__ for p in ranked])

    except Exception as e:
        logger.error(f"Programs error: {e}")
        await safe_reply(update, f"Error: {str(e)[:100]}")

# Main 
def main():
    # Environment Variable Support (10/10 Standard)
    token = os.getenv("TELEGRAM_BOT_TOKEN") or config.get("telegram", {}).get("token") or config.get("telegram", {}).get("bot_token")
    
    if not token or "YOUR" in str(token):
        logger.error("Missing TELEGRAM_BOT_TOKEN in ENV or config.yaml")
        return

    app = ApplicationBuilder().token(token).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("ask", cmd_ask))
    app.add_handler(CommandHandler("bounty", cmd_bounty))
    app.add_handler(CommandHandler("mission", cmd_mission))
    app.add_handler(CommandHandler("pause", cmd_pause))
    app.add_handler(CommandHandler("resume", cmd_resume))
    app.add_handler(CommandHandler("findings", cmd_findings))
    app.add_handler(CommandHandler("programs", cmd_programs))

    logger.info(" Elengenix Bot is now operational (v1.5.0)")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
 main()
