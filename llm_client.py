import yaml
import os
import asyncio
import google.generativeai as genai
from openai import AsyncOpenAI # 🚀 Full Async Client
from dotenv import load_dotenv
from pathlib import Path

# Load .env file automatically
load_dotenv()

class LLMClient:
    """
    High-efficiency LLM Client with native async support for all providers.
    """
    def __init__(self, config_path="config.yaml"):
        base_dir = Path(__file__).parent.absolute()
        self.config_path = base_dir / config_path
        
        self.config = self._load_ai_config()
        self.active_provider = self.config.get("active_provider", "gemini")
        
        # Priority: Environment Variable > config.yaml
        self.api_key = os.getenv(f"{self.active_provider.upper()}_API_KEY") or \
                       self.config.get("providers", {}).get(self.active_provider, {}).get("api_key", "")

        if not self.api_key or "YOUR" in str(self.api_key):
            raise ValueError(f"API Key for {self.active_provider} is missing.")

        self.setup()

    def _load_ai_config(self):
        try:
            with open(self.config_path, "r") as f:
                full_config = yaml.safe_load(f)
                return full_config.get("ai", {})
        except Exception:
            return {"active_provider": "gemini", "providers": {}}

    def setup(self):
        provider_cfg = self.config.get("providers", {}).get(self.active_provider, {})
        self.model_name = provider_cfg.get("model", "gemini-1.5-flash")

        if self.active_provider == "gemini":
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(self.model_name)
        else:
            # OpenAI compatible providers (Groq, OpenRouter, etc.)
            base_urls = {
                "openai": None,
                "groq": "https://api.groq.com/openai/v1",
                "openrouter": "https://openrouter.ai/api/v1",
                "local": "http://localhost:11434/v1"
            }
            # 🚀 Native Async OpenAI Client
            self.async_client = AsyncOpenAI(
                api_key=self.api_key, 
                base_url=base_urls.get(self.active_provider)
            )

    async def chat_async(self, system_prompt: str, user_message: str):
        try:
            if self.active_provider == "gemini":
                response = await self.model.generate_content_async(f"{system_prompt}\n\nUser: {user_message}")
                return response.text
            
            else:
                # 🚀 Full Non-blocking Async Call
                response = await self.async_client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    timeout=60.0
                )
                return response.choices[0].message.content

        except Exception as e:
            # Structured logging would go here
            return f"LLM Execution Error: {str(e)}"

    def chat(self, system_prompt: str, user_message: str):
        """Synchronous bridge for CLI."""
        return asyncio.run(self.chat_async(system_prompt, user_message))
