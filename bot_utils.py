import requests
import yaml
import os
import logging

logger = logging.getLogger(__name__)

def get_config():
    """Helper to get absolute path to config.yaml."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "config.yaml")
    
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(base_dir), "config.yaml")
        
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Config file not found at {config_path}")
        return None
    except yaml.YAMLError as e:
        logger.error(f"Syntax error in config.yaml: {e}")
        return None

def send_telegram_notification(message):
    """Sends a message to the configured Telegram chat."""
    config = get_config()
    if not config: return

    try:
        token = config.get("telegram", {}).get("token") or config.get("telegram", {}).get("bot_token")
        chat_id = config.get("telegram", {}).get("chat_id")

        if not token or "YOUR" in token: return

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
        response = requests.post(url, data=data, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.warning(f"Telegram notification failed: {e}")

def send_document(file_path, caption=""):
    """Sends a file to Telegram."""
    config = get_config()
    if not config: return

    try:
        token = config.get("telegram", {}).get("token") or config.get("telegram", {}).get("bot_token")
        chat_id = config.get("telegram", {}).get("chat_id")

        if not token or "YOUR" in token: return

        url = f"https://api.telegram.org/bot{token}/sendDocument"
        with open(file_path, "rb") as f:
            files = {"document": f}
            data = {"chat_id": chat_id, "caption": caption}
            response = requests.post(url, data=data, files=files, timeout=30)
            response.raise_for_status()
    except (requests.exceptions.RequestException, IOError) as e:
        logger.warning(f"Telegram document delivery failed: {e}")
