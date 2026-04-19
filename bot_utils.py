import requests
import yaml
import os

def send_telegram_notification(message):
    """
    Sends a message to the configured Telegram chat.
    """
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        
        token = config["telegram"]["token"]
        chat_id = config["telegram"]["chat_id"]

        if token == "YOUR_TELEGRAM_BOT_TOKEN" or not token:
            print("[!] Telegram token not configured. Skipping notification.")
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
        
        response = requests.post(url, data=data)
        return response.json()
    except Exception as e:
        print(f"[!] Failed to send Telegram notification: {e}")
        return None

def send_document(file_path, caption=""):
    """
    Sends a file (like a scan report) to Telegram.
    """
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        
        token = config["telegram"]["token"]
        chat_id = config["telegram"]["chat_id"]

        url = f"https://api.telegram.org/bot{token}/sendDocument"
        with open(file_path, "rb") as f:
            files = {"document": f}
            data = {"chat_id": chat_id, "caption": caption}
            response = requests.post(url, data=data, files=files)
        return response.json()
    except Exception as e:
        print(f"[!] Failed to send Telegram document: {e}")
        return None
