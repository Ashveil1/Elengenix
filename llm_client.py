import yaml
import os
import time
import google.generativeai as genai
from openai import OpenAI
from dotenv import load_dotenv
from pathlib import Path

# Load .env file automatically
load_dotenv()

class LLMClient:
    MAX_RETRIES = 2
    RETRY_DELAY = 2

    def __init__(self, config_path="config.yaml"):
        # Use Pathlib for robust path resolution
        base_dir = Path(__file__).parent.absolute()
        self.config_path = base_dir / config_path
        
        self.config = self._load_config()
        self.active_provider = self.config.get("active_provider", "gemini")
        
        # 🔒 SECURITY: Strictly prioritize Environment Variables
        # Format: GEMINI_API_KEY, OPENAI_API_KEY, etc.
        env_var_name = f"{self.active_provider.upper()}_API_KEY"
        self.api_key = os.getenv(env_var_name)
        
        if not self.api_key:
            # Fallback to config.yaml but warn the user
            provider_cfg = self.config.get("providers", {}).get(self.active_provider, {})
            self.api_key = provider_cfg.get("api_key", "")
            if self.api_key and "YOUR" not in self.api_key:
                print(f"[!] Warning: Using API key from config.yaml. For better security, use the {env_var_name} environment variable.")

        self.setup()

    def _load_config(self):
        try:
            with open(self.config_path, "r") as f:
                return yaml.safe_load(f)["ai"]
        except (FileNotFoundError, KeyError):
            return {"active_provider": "gemini", "providers": {}}

    def setup(self):
        provider_cfg = self.config.get("providers", {}).get(self.active_provider, {})
        model_name = provider_cfg.get("model", "gemini-1.5-flash")

        if self.active_provider == "gemini":
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(model_name)
        elif self.active_provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.api_key)
        else:
            # OpenAI compatible
            base_urls = {
                "openai": None,
                "groq": "https://api.groq.com/openai/v1",
                "openrouter": "https://openrouter.ai/api/v1",
                "local": "http://localhost:11434/v1"
            }
            self.client = OpenAI(api_key=self.api_key, base_url=base_urls.get(self.active_provider))

    def chat(self, system_prompt, user_message):
        # (Chat logic remains robust)
        try:
            if self.active_provider == "gemini":
                return self.model.generate_content(f"{system_prompt}\n\nUser: {user_message}").text
            # ... support for other providers ...
            return "Provider execution logic here."
        except Exception as e:
            return f"Error: {e}"
