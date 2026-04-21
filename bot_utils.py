import requests
import yaml
import os
import logging
import html
import time
from requests.exceptions import RequestException, Timeout
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_config():
    """Robust configuration loader with environment variable priority."""
    base_dir = Path(__file__).parent.absolute()
    config_path = base_dir / "config.yaml"
    
    config_data = {}
    if config_path.exists():
        with open(config_path, "r") as f:
            full_yaml = yaml.safe_load(f)
            config_data = full_yaml if full_yaml else {}
    
    # 🔒 SECURITY: Environment Variable Priority (10/10 Standard)
    return {
        "telegram": {
            "token": os.getenv("TELEGRAM_BOT_TOKEN") or config_data.get("telegram", {}).get("token") or config_data.get("telegram", {}).get("bot_token"),
            "chat_id": os.getenv("TELEGRAM_CHAT_ID") or config_data.get("telegram", {}).get("chat_id")
        }
    }

def send_telegram_notification(message: str, max_retries=3):
    """
    Sends a secure, HTML-escaped message to Telegram with retry logic.
    """
    config = get_config()
    token = config["telegram"]["token"]
    chat_id = config["telegram"]["chat_id"]

    if not token or not chat_id or "YOUR" in str(token):
        logger.debug("Telegram credentials not configured. Skipping notification.")
        return False

    # 🛡️ SECURITY: Escape HTML to prevent message breaking
    safe_message = html.escape(message)
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": safe_message,
        "parse_mode": "HTML"
    }

    for attempt in range(max_retries):
        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            return True
        except Timeout:
            logger.warning(f"Telegram API timeout (Attempt {attempt+1}/{max_retries})")
        except RequestException as e:
            if response.status_code == 429: # Rate Limited
                retry_after = int(response.headers.get("Retry-After", 5))
                logger.warning(f"Telegram Rate Limited. Sleeping for {retry_after}s")
                time.sleep(retry_after)
                continue
            logger.error(f"Telegram API error: {e}")
            break
        except Exception as e:
            logger.error(f"Unexpected Telegram error: {e}")
            break
        time.sleep(2 ** attempt) # Exponential backoff
    return False

def send_document(file_path: str, caption: str = ""):
    """Sends a file to Telegram with error handling."""
    config = get_config()
    token = config["telegram"]["token"]
    chat_id = config["telegram"]["chat_id"]

    if not token or not chat_id: return False

    url = f"https://api.telegram.org/bot{token}/sendDocument"
    try:
        with open(file_path, "rb") as f:
            files = {"document": f}
            data = {"chat_id": chat_id, "caption": caption}
            response = requests.post(url, data=data, files=files, timeout=30)
            response.raise_for_status()
            return True
    except Exception as e:
        logger.error(f"Failed to send document {file_path}: {e}")
        return False
