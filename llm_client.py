import yaml
import os
import google.generativeai as genai
from openai import OpenAI

class LLMClient:
    def __init__(self, config_path="config.yaml"):
        # Support running from different directories
        if not os.path.exists(config_path):
            config_path = os.path.join(os.path.dirname(__file__), "..", config_path)
            
        with open(config_path, "r") as f:
            self.full_config = yaml.safe_load(f)["ai"]
        
        self.active_provider = self.full_config["active_provider"]
        self.provider_config = self.full_config["providers"].get(self.active_provider, {})
        self.setup()

    def setup(self, provider=None, api_key=None):
        target_provider = provider or self.active_provider
        target_key = api_key or self.provider_config.get("api_key", "")
        
        base_urls = {
            "openai": None,
            "groq": "https://api.groq.com/openai/v1",
            "together": "https://api.together.xyz/v1",
            "mistral": "https://api.mistral.ai/v1",
            "openrouter": "https://openrouter.ai/api/v1",
            "monster": "https://api.monsterapi.ai/v1",
            "perplexity": "https://api.perplexity.ai",
            "local": self.provider_config.get("base_url", "http://localhost:11434/v1")
        }
        
        if target_provider == "gemini":
            genai.configure(api_key=target_key)
            model_name = self.provider_config.get("model", "gemini-1.5-pro")
            self.model = genai.GenerativeModel(model_name)
        elif target_provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic(api_key=target_key)
        else:
            self.client = OpenAI(api_key=target_key, base_url=base_urls.get(target_provider))

    def fetch_available_models(self, provider, api_key):
        """
        Dynamically fetches the latest models from the provider's API.
        """
        try:
            self.setup(provider, api_key)
            if provider == "gemini":
                # Gemini list_models
                models = [m.name.replace("models/", "") for m in genai.list_models() if "generateContent" in m.supported_generation_methods]
                return models[:10]
            elif provider == "anthropic":
                return ["claude-3-5-sonnet-20240620", "claude-3-opus-20240229", "claude-3-haiku-20240307"]
            else:
                # OpenAI Compatible
                models_data = self.client.models.list()
                # Sort by created date if available or just return IDs
                return [m.id for m in models_data.data if "gpt" in m.id or "llama" in m.id or "claude" in m.id or "mixtral" in m.id or "/" in m.id][:15]
        except Exception as e:
            print(f"⚠️ Could not fetch dynamic models: {e}")
            return []

    def chat(self, system_prompt, user_message):
        # (Existing chat logic remains the same)
        try:
            if self.active_provider == "gemini":
                full_prompt = f"{system_prompt}\n\nUser: {user_message}"
                response = self.model.generate_content(full_prompt)
                return response.text
            elif self.active_provider == "anthropic":
                response = self.client.messages.create(
                    model=self.provider_config.get("model"),
                    max_tokens=2048,
                    system=system_prompt,
                    messages=[{"role": "user", "content": user_message}]
                )
                return response.content[0].text
            else:
                response = self.client.chat.completions.create(
                    model=self.provider_config["model"],
                    messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message}]
                )
                return response.choices[0].message.content
        except Exception as e:
            return f"❌ Error: {str(e)}"
