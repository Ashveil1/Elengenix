"""
bot_utils.py — Elengenix Telegram Utilities (v1.5.0)
- Secure Message Escaping (MarkdownV2)
- Path Traversal Protection for Document Delivery
- Robust Retry Logic & Rate Limit Handling
- Standardized Config Loading
"""

import requests
import yaml
import os
import logging
import html
import time
from pathlib import Path
from typing import Optional, Set
from requests.exceptions import RequestException, Timeout

# Logging Setup 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Config Loader 
def get_config() -> dict:
 """Robust configuration loader with environment variable priority."""
 base_dir = Path(__file__).parent.absolute()
 config_path = base_dir / "config.yaml"
 
 config_data = {}
 if config_path.exists():
 try:
 with open(config_path, "r") as f:
 full_yaml = yaml.safe_load(f)
 config_data = full_yaml if full_yaml else {}
 except Exception as e:
 logger.error(f"Failed to read config.yaml: {e}")

 telegram_cfg = config_data.get("telegram", {})
 
 return {
 "telegram": {
 # Priority: ENV > config(token) > config(bot_token)
 "token": (
 os.getenv("TELEGRAM_BOT_TOKEN") or 
 telegram_cfg.get("token") or 
 telegram_cfg.get("bot_token")
 ),
 "chat_id": os.getenv("TELEGRAM_CHAT_ID") or telegram_cfg.get("chat_id")
 }
 }

# Message Sender 
def send_telegram_notification(
 message: str, 
 max_retries: int = 3, 
 parse_mode: str = "MarkdownV2"
) -> bool:
 """
 Sends a secure message to Telegram with retry logic and proper escaping.
 """
 config = get_config()
 token = config["telegram"]["token"]
 chat_id = config["telegram"]["chat_id"]

 if not token or not chat_id or "YOUR" in str(token):
 return False

 # SECURITY: Proper Escaping based on parse_mode
 if parse_mode == "MarkdownV2":
 escape_chars = r'_*[]()~`>#+-=|{}.!'
 safe_message = ''.join(f'\\{c}' if c in escape_chars else c for c in message)
 else:
 # For HTML: escape only critical tags to allow our formatting to work
 safe_message = message.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

 url = f"https://api.telegram.org/bot{token}/sendMessage"
 payload = {
 "chat_id": chat_id,
 "text": safe_message,
 "parse_mode": parse_mode
 }

 for attempt in range(max_retries):
 try:
 response = requests.post(url, json=payload, timeout=10)
 response.raise_for_status()
 return True
 except Timeout:
 logger.warning(f"Telegram timeout (Attempt {attempt+1}/{max_retries})")
 except RequestException as e:
 if response.status_code == 429: # Rate Limited
 retry_after = int(response.headers.get("Retry-After", 5))
 logger.warning(f"Telegram Rate Limited. Waiting {retry_after}s")
 time.sleep(retry_after)
 continue
 logger.error(f"Telegram API error: {e}")
 break
 except Exception as e:
 logger.error(f"Unexpected Telegram error: {e}")
 break
 time.sleep(2 ** attempt) # Exponential backoff
 return False

# Document Sender 
def send_document(
 file_path: str, 
 caption: str = "", 
 allowed_extensions: Optional[Set[str]] = None
) -> bool:
 """
 Sends a file to Telegram with Path Traversal protection.
 """
 # SECURITY: Validate file path (Prevent Path Traversal)
 try:
 file_path_obj = Path(file_path).resolve()
 # Only allow sending files from the project root or reports folder
 base_dir = Path(__file__).parent.parent.resolve()
 
 if not str(file_path_obj).startswith(str(base_dir)):
 logger.error(f"Access Denied: Path traversal attempt blocked: {file_path}")
 return False

 if not file_path_obj.exists():
 logger.error(f"File not found: {file_path}")
 return False

 if allowed_extensions and file_path_obj.suffix.lower() not in allowed_extensions:
 logger.error(f"Forbidden extension: {file_path_obj.suffix}")
 return False

 except Exception as e:
 logger.error(f"Path validation error: {e}")
 return False

 # SECURITY: Escape caption
 safe_caption = html.escape(caption)
 
 config = get_config()
 token = config["telegram"]["token"]
 chat_id = config["telegram"]["chat_id"]
 
 if not token or not chat_id: return False

 url = f"https://api.telegram.org/bot{token}/sendDocument"
 try:
 with open(file_path_obj, "rb") as f:
 files = {"document": (file_path_obj.name, f, "application/octet-stream")}
 data = {"chat_id": chat_id, "caption": safe_caption, "parse_mode": "HTML"}
 response = requests.post(url, data=data, files=files, timeout=30)
 response.raise_for_status()
 return True
 except Exception as e:
 logger.error(f"Failed to deliver document {file_path_obj.name}: {e}")
 return False
