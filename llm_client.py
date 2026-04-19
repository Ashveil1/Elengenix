import yaml
import os
import time
import google.generativeai as genai
from openai import OpenAI

# Model catalogs
CLAUDE_MODELS = ["claude-sonnet-4-5", "claude-opus-4-5", "claude-haiku-4-5-20251001"]
GEMINI_MODELS = ["gemini-2.5-pro-preview-05-06", "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"]

class LLMClient:
    MAX_RETRIES = 2
    RETRY_DELAY = 2

    def __init__(self, config_path="config.yaml"):
        # 🎯 FIX: Robust Config Path Resolution
        if not os.path.isabs(config_path):
            # Find config.yaml relative to this script's home
            base_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(base_dir, config_path)

        if not os.path.exists(config_path):
            raise FileNotFoundError(f"❌ Elengenix Error: Config not found at {config_path}. Please run 'elengenix configure'.")

        with open(config_path, "r") as f:
            full_config = yaml.safe_load(f)
            config = full_config["ai"]

        self.active_provider = config["active_provider"]
        self.provider_config = config["providers"].get(self.active_provider, {})
        self._setup(self.active_provider, self.provider_config.get("api_key", ""))
        
    # (Rest of the llm_client.py remains same...)
    def _setup(self, provider, api_key):
        self.active_provider = provider
        if provider == "gemini":
            genai.configure(api_key=api_key)
            model_name = self.provider_config.get("model", "gemini-2.0-flash")
            self.gemini_model = genai.GenerativeModel(model_name)
        elif provider == "anthropic":
            import anthropic
            self.anthropic_client = anthropic.Anthropic(api_key=api_key)
            self.anthropic_model = self.provider_config.get("model", "claude-sonnet-4-5")
        else:
            base_urls = {
                "openai": None, "groq": "https://api.groq.com/openai/v1",
                "openrouter": "https://openrouter.ai/api/v1", "together": "https://api.together.xyz/v1",
                "mistral": "https://api.mistral.ai/v1", "perplexity": "https://api.perplexity.ai",
                "local": self.provider_config.get("base_url", "http://localhost:11434/v1"),
            }
            self.openai_client = OpenAI(api_key=api_key or "ollama", base_url=base_urls.get(provider))

    def fetch_available_models(self, provider, api_key):
        try:
            self._setup(provider, api_key)
            if provider == "gemini":
                return [m.name.replace("models/", "") for m in genai.list_models() if "generateContent" in m.supported_generation_methods][:10]
            elif provider == "anthropic": return CLAUDE_MODELS
            else:
                models_data = self.openai_client.models.list()
                return [m.id for m in models_data.data][:15]
        except: return GEMINI_MODELS if provider == "gemini" else CLAUDE_MODELS

    def chat(self, system_prompt, user_message):
        for attempt in range(self.MAX_RETRIES + 1):
            try:
                if self.active_provider == "gemini":
                    return self.gemini_model.generate_content(f"{system_prompt}\n\n---\n\n{user_message}").text
                elif self.active_provider == "anthropic":
                    return self.anthropic_client.messages.create(model=self.anthropic_model, max_tokens=4096, system=system_prompt, messages=[{"role": "user", "content": user_message}]).content[0].text
                else:
                    return self.openai_client.chat.completions.create(model=self.provider_config.get("model", "gpt-4o-mini"), max_tokens=4096, messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message}]).choices[0].message.content
            except Exception as e:
                if attempt < self.MAX_RETRIES: time.sleep(self.RETRY_DELAY)
                else: return f"❌ LLM error: {str(e)}"
