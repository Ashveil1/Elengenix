import logging
import yaml
import os
import asyncio
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler
from agent_brain import ElengenixAgent

# Setup logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

# Load Config
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

# Initialize Agent Brain
agent = ElengenixAgent()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = "🛡️ *Elengenix Unified Bot Ready*\\n\\n🚀 `/scan <domain>` - Run Standard Scan\\n🤖 `/ask <query>` - Chat with AI Agent"
    await update.message.reply_text(welcome_text, parse_mode="Markdown")

async def ai_ask(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = " ".join(context.args)
    if not query:
        await update.message.reply_text("🤖 I'm listening. How can I help with your bug hunt?")
        return

    await update.message.reply_text("🤔 *Sentinel is thinking...*", parse_mode="Markdown")

    def callback(msg):
        # Helper to send status updates from within the Agent Brain
        loop = asyncio.get_event_loop()
        asyncio.run_coroutine_threadsafe(update.message.reply_text(msg, parse_mode="Markdown"), loop)

    # Process via Unified Brain
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(None, agent.process_query, query, callback)
    
    await update.message.reply_text(f"🤖 *Sentinel Response:*\\n\\n{response}", parse_mode="Markdown")

if __name__ == '__main__':
    token = config["telegram"]["token"]
    if token == "YOUR_TELEGRAM_BOT_TOKEN":
        print("❌ Error: Please set your Telegram Token in config.yaml")
    else:
        application = ApplicationBuilder().token(token).build()
        application.add_handler(CommandHandler('start', start))
        application.add_handler(CommandHandler('ask', ai_ask))
        print("🛡️ Elengenix Unified Bot is running...")
        application.run_polling()
