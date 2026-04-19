import requests
import yaml
import os

def get_config():
    """
    Helper to get the absolute path to config.yaml.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "config.yaml")
    
    if not os.path.exists(config_path):
        # Try one level up (if called from tools/)
        config_path = os.path.join(os.path.dirname(base_dir), "config.yaml")
        
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def send_telegram_notification(message):
    """
    Sends a message to the configured Telegram chat.
    """
    try:
        config = get_config()
        token = config["telegram"]["token"]
        chat_id = config["telegram"]["chat_id"]

        if token == "YOUR_TELEGRAM_BOT_TOKEN" or not token:
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
        requests.post(url, data=data)
    except:
        pass

def send_document(file_path, caption=""):
    """
    Sends a file to Telegram.
    """
    try:
        config = get_config()
        token = config["telegram"]["token"]
        chat_id = config["telegram"]["chat_id"]

        url = f"https://api.telegram.org/bot{token}/sendDocument"
        with open(file_path, "rb") as f:
            files = {"document": f}
            data = {"chat_id": chat_id, "caption": caption}
            requests.post(url, data=data, files=files)
    except:
        pass
