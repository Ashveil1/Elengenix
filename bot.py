"""
Elengenix - Telegram Bot (Fixed)
Based on original by Ashveil1 (MIT License)
Fixes:
  - asyncio.get_event_loop() deprecated -> Use asyncio.get_running_loop()
  - Added /scan command
  - Added error handling for config load
  - Added /status command to check tools
  - Prevent bot crash on agent error
  - Improved /help documentation
"""

import logging
import yaml
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor

from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    ContextTypes,
    CommandHandler,
    MessageHandler,
    filters,
)
from agent_brain import ElengenixAgent

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ── Load Config ───────────────────────────────────────────────
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

try:
    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    logger.error("config.yaml not found - Please configure before running the bot")
    raise SystemExit(1)
except yaml.YAMLError as e:
    logger.error(f"config.yaml syntax error: {e}")
    raise SystemExit(1)

# ── Initialize Agent ──────────────────────────────────────────
try:
    agent = ElengenixAgent()
    logger.info("ElengenixAgent loaded successfully")
except Exception as e:
    logger.warning(f"Failed to load Agent: {e} - AI mode will be disabled")
    agent = None

executor = ThreadPoolExecutor(max_workers=4)


# ── Helpers ───────────────────────────────────────────────────
async def run_in_thread(func, *args):
    """Run blocking functions in thread pool correctly."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(executor, func, *args)


async def safe_reply(update: Update, text: str, parse_mode: str = "Markdown"):
    """Reply to message with fallback if Markdown fails."""
    try:
        await update.message.reply_text(text, parse_mode=parse_mode)
    except Exception:
        await update.message.reply_text(text, parse_mode=None)


# ── Commands ──────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/start - Show welcome message"""
    welcome = (
        "🛡️ *Elengenix AI Bug Hunter*\n\n"
        "Welcome to the automated bug bounty framework.\n\n"
        "📋 *Available Commands:*\n"
        "🔍 `/scan <domain>` — Scan target\n"
        "🤖 `/ask <query>` — Query AI Agent\n"
        "📊 `/status` — Check tool status\n"
        "❓ `/help` — Show usage instructions\n"
    )
    await safe_reply(update, welcome)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/help - Detailed usage instructions"""
    help_text = (
        "📖 *Elengenix Usage Guide*\n\n"
        "*🔍 Scan Target:*\n"
        "`/scan example.com`\n"
        "-> Runs Recon -> Nuclei -> JS Analysis -> Param Mining\n\n"
        "*🤖 Query AI Agent:*\n"
        "`/ask find XSS on example.com`\n"
        "-> AI plans and executes tools automatically\n\n"
        "*📊 Check Status:*\n"
        "`/status`\n"
        "-> Verify availability of core security tools\n\n"
        "⚠️ *AUTHORIZED TESTING ONLY*"
    )
    await safe_reply(update, help_text)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/status - Check health of all tools"""
    import shutil

    tools = ["subfinder", "httpx", "nuclei", "katana", "waybackurls"]
    lines = ["📊 *Tool Status:*\n"]

    for tool in tools:
        found = shutil.which(tool) is not None
        icon = "✅" if found else "❌"
        lines.append(f"{icon} `{tool}`")

    if agent is not None:
        lines.append("\n🤖 AI Agent: ✅ Ready")
    else:
        lines.append("\n🤖 AI Agent: ❌ Offline (Check config.yaml)")

    await safe_reply(update, "\n".join(lines))


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/scan <domain> - Execute standard scan pipeline"""
    if not context.args:
        await safe_reply(
            update,
            "⚠️ Please provide a domain\nExample: `/scan example.com`"
        )
        return

    target = context.args[0].strip()

    forbidden = [";", "&", "|", "`", "$", "(", ")", ">", "<", "\n"]
    if any(c in target for c in forbidden):
        await safe_reply(update, "❌ Domain contains prohibited characters")
        return

    await safe_reply(update, f"🚀 *Scanning:* `{target}`\nThis may take some time...")

    try:
        from orchestrator import run_standard_scan
        result = await run_in_thread(run_standard_scan, target)

        if result:
            await safe_reply(update, f"✅ *Scan Complete:* `{target}`\nReports have been generated.")
        else:
            await safe_reply(update, f"⚠️ Scan for `{target}` finished with no findings.")

    except Exception as e:
        logger.error(f"Scan error: {e}")
        await safe_reply(update, f"❌ Error: `{str(e)[:200]}`")


async def cmd_ask(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/ask <query> - Interaction with AI Agent"""
    if agent is None:
        await safe_reply(
            update,
            "❌ AI Agent not ready\nPlease check API Key in config.yaml"
        )
        return

    query = " ".join(context.args).strip()
    if not query:
        await safe_reply(update, "🤖 Please provide a query\nExample: `/ask find subdomains of example.com`")
        return

    await safe_reply(update, "🤔 *Sentinel is thinking...*")
    loop = asyncio.get_running_loop()

    def callback(msg: str):
        asyncio.run_coroutine_threadsafe(safe_reply(update, msg), loop)

    try:
        response = await run_in_thread(agent.process_query, query, callback)

        if response:
            if len(response) > 3800:
                response = response[:3800] + "\n\n_...output truncated, check reports_"
            await safe_reply(update, f"🤖 *Sentinel:*\n\n{response}")
        else:
            await safe_reply(update, "⚠️ AI returned no response - Please try again")

    except Exception as e:
        logger.error(f"Ask error: {e}")
        await safe_reply(update, f"❌ AI Error: `{str(e)[:200]}`")


async def handle_unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle messages that are not commands"""
    await safe_reply(
        update,
        "❓ Unknown command\nType /help for usage"
    )


# ── Main ──────────────────────────────────────────────────────
def main():
    token = config.get("telegram", {}).get("bot_token", "")

    if not token or token in ("YOUR_BOT_TOKEN_HERE", ""):
        logger.error("Telegram bot_token not found in config.yaml")
        raise SystemExit(1)

    app = ApplicationBuilder().token(token).build()

    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("help",   cmd_help))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("scan",   cmd_scan))
    app.add_handler(CommandHandler("ask",    cmd_ask))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_unknown))

    logger.info("🛡️ Elengenix Bot is running...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
