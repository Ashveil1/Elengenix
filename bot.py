"""
Elengenix - Telegram Bot (Fixed)
Based on original by Ashveil1 (MIT License)
Fixes:
  - asyncio.get_event_loop() deprecated → ใช้ asyncio.get_running_loop()
  - เพิ่ม /scan command ที่อยู่ใน README แต่หายไปจากโค้ด
  - เพิ่ม error handling รอบ config load
  - เพิ่ม /status command ตรวจ tools
  - ป้องกัน bot crash เมื่อ agent error
  - เพิ่ม /help ที่ละเอียดขึ้น
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
    logger.error("ไม่พบ config.yaml — กรุณาตั้งค่าก่อนรัน bot")
    raise SystemExit(1)
except yaml.YAMLError as e:
    logger.error(f"config.yaml มี syntax ผิด: {e}")
    raise SystemExit(1)

# ── Initialize Agent ──────────────────────────────────────────
try:
    agent = ElengenixAgent()
    logger.info("ElengenixAgent โหลดสำเร็จ")
except Exception as e:
    logger.warning(f"โหลด Agent ไม่สำเร็จ: {e} — โหมด AI จะไม่ทำงาน")
    agent = None

# ThreadPoolExecutor สำหรับรัน blocking tasks
executor = ThreadPoolExecutor(max_workers=4)


# ── Helper ────────────────────────────────────────────────────
async def run_in_thread(func, *args):
    """รัน blocking function ใน thread pool อย่างถูกต้อง
    แก้: ไม่ใช้ asyncio.get_event_loop() ที่ deprecated แล้ว
    ใช้ asyncio.get_running_loop() แทน (Python 3.10+)
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(executor, func, *args)


async def safe_reply(update: Update, text: str, parse_mode: str = "Markdown"):
    """ส่งข้อความกลับ พร้อม fallback ถ้า Markdown parse ไม่ได้"""
    try:
        await update.message.reply_text(text, parse_mode=parse_mode)
    except Exception:
        # fallback เป็น plain text ถ้า Markdown มีปัญหา
        await update.message.reply_text(text, parse_mode=None)


# ── Commands ──────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/start — แสดงหน้าต้อนรับ"""
    welcome = (
        "*Elengenix AI Bug Hunter*\n\n"
        "ยินดีต้อนรับสู่ระบบ Bug Bounty อัตโนมัติ\n\n"
        "*คำสั่งที่ใช้ได้:*\n"
        "🔍 `/scan <domain>` — สแกนเป้าหมาย\n"
        "🤖 `/ask <query>` — ถาม AI Agent\n"
        "📊 `/status` — ตรวจสอบ tools\n"
        "❓ `/help` — แสดงวิธีใช้\n"
    )
    await safe_reply(update, welcome)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/help — แสดงวิธีใช้ละเอียด"""
    help_text = (
        "*วิธีใช้ Elengenix*\n\n"
        "*🔍 สแกนเป้าหมาย:*\n"
        "`/scan example.com`\n"
        "→ รัน Recon → Nuclei → JS Analysis → Param Mining\n\n"
        "*🤖 ถาม AI Agent:*\n"
        "`/ask find XSS on example.com`\n"
        "→ AI จะวางแผนและรัน tools ให้อัตโนมัติ\n\n"
        "*📊 ตรวจสอบ tools:*\n"
        "`/status`\n"
        "→ ดูว่า subfinder, nuclei, httpx พร้อมหรือเปล่า\n\n"
        "*ใช้เฉพาะกับ domain ที่ได้รับอนุญาตเท่านั้น*"
    )
    await safe_reply(update, help_text)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/status — ตรวจสอบสถานะ tools ทั้งหมด (command นี้หายไปจากต้นฉบับ)"""
    import shutil

    tools = ["subfinder", "httpx", "nuclei", "katana", "waybackurls"]
    lines = ["📊 *สถานะ Tools:*\n"]

    for tool in tools:
        found = shutil.which(tool) is not None
        icon = "✅" if found else "❌"
        lines.append(f"{icon} `{tool}`")

    # ตรวจ AI
    if agent is not None:
        lines.append("\n🤖 AI Agent: ✅ พร้อมใช้งาน")
    else:
        lines.append("\n🤖 AI Agent: ❌ ไม่พร้อม (ตรวจสอบ config.yaml)")

    await safe_reply(update, "\n".join(lines))


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/scan <domain> — รัน standard scan pipeline
    แก้: command นี้อยู่ใน README แต่หายไปจากโค้ดต้นฉบับทั้งหมด
    """
    if not context.args:
        await safe_reply(
            update,
            "กรุณาระบุ domain\nตัวอย่าง: `/scan example.com`"
        )
        return

    target = context.args[0].strip()

    # ตรวจ input เบื้องต้น — ป้องกัน injection
    forbidden = [";", "&", "|", "`", "$", "(", ")", ">", "<", "\n"]
    if any(c in target for c in forbidden):
        await safe_reply(update, "❌ Domain มีอักขระที่ไม่อนุญาต")
        return

    await safe_reply(update, f"*กำลังสแกน:* `{target}`\nอาจใช้เวลาสักครู่...")

    try:
        from orchestrator import run_standard_scan

        def do_scan():
            return run_standard_scan(target)

        result = await run_in_thread(do_scan)

        if result:
            await safe_reply(update, f"*สแกนเสร็จสิ้น:* `{target}`\nรายงานถูกส่งไปแล้ว")
        else:
            await safe_reply(update, f"สแกน `{target}` เสร็จแต่ไม่พบ findings")

    except Exception as e:
        logger.error(f"scan error: {e}")
        await safe_reply(update, f"❌ เกิดข้อผิดพลาด: `{str(e)[:200]}`")


async def cmd_ask(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/ask <query> — ถาม AI Agent"""
    if agent is None:
        await safe_reply(
            update,
            "❌ AI Agent ไม่พร้อม\nกรุณาตรวจสอบ API Key ใน config.yaml"
        )
        return

    query = " ".join(context.args).strip()
    if not query:
        await safe_reply(update, "🤖 กรุณาระบุคำถาม\nตัวอย่าง: `/ask find subdomains of example.com`")
        return

    await safe_reply(update, "*Sentinel กำลังคิด...*")

    # callback สำหรับส่ง status update ระหว่าง agent ทำงาน
    # แก้: ใช้ asyncio.get_running_loop() แทน get_event_loop()
    loop = asyncio.get_running_loop()

    def callback(msg: str):
        """ส่งข้อความ update จาก agent thread กลับมายัง Telegram"""
        asyncio.run_coroutine_threadsafe(
            safe_reply(update, msg),
            loop
        )

    try:
        def do_ask():
            return agent.process_query(query, callback)

        response = await run_in_thread(do_ask)

        if response:
            # ตัดข้อความถ้ายาวเกิน Telegram limit (4096 chars)
            if len(response) > 3800:
                response = response[:3800] + "\n\n_...ข้อความยาวเกินไป ดูรายละเอียดใน report_"
            await safe_reply(update, f"🤖 *Sentinel:*\n\n{response}")
        else:
            await safe_reply(update, "AI ไม่มีคำตอบ — ลองใหม่อีกครั้ง")

    except Exception as e:
        logger.error(f"ask error: {e}")
        await safe_reply(update, f"❌ AI เกิดข้อผิดพลาด: `{str(e)[:200]}`")


async def handle_unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """รับข้อความที่ไม่ใช่ command"""
    await safe_reply(
        update,
        "❓ ไม่รู้จักคำสั่งนี้\nพิมพ์ /help เพื่อดูคำสั่งทั้งหมด"
    )


# ── Main ──────────────────────────────────────────────────────
def main():
    token = config.get("telegram", {}).get("bot_token", "")

    if not token or token in ("YOUR_BOT_TOKEN_HERE", ""):
        logger.error("❌ ไม่พบ Telegram bot_token ใน config.yaml")
        raise SystemExit(1)

    app = ApplicationBuilder().token(token).build()

    # ลงทะเบียน handlers
    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("help",   cmd_help))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("scan",   cmd_scan))
    app.add_handler(CommandHandler("ask",    cmd_ask))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_unknown))

    logger.info("🛡️ Elengenix Bot กำลังรัน...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
