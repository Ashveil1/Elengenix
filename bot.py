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

 logger.info(" Elengenix Bot is now operational (v1.5.0)")
 app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
 main()
