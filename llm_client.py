"""
llm_client.py — Elengenix Upgraded LLM Client
- Gemini เป็น default (ตาม config)
- อัปเดต Claude model names ให้ถูกต้อง
- Error handling ดีขึ้น
- Retry 2 ครั้งถ้า API ล้ม
- รองรับ Termux (ไม่มี dependency หนัก)
"""

import os
import time
import yaml
import google.generativeai as genai
from openai import OpenAI


# ─────────────────────────────────────────────
# Model Catalog (อัปเดตแล้ว 2025-2026)
# ─────────────────────────────────────────────
CLAUDE_MODELS = [
    "claude-sonnet-4-5",
    "claude-opus-4-5",
    "claude-haiku-4-5-20251001",
]

GEMINI_MODELS = [
    "gemini-2.5-pro-preview-05-06",
    "gemini-2.0-flash",
    "gemini-1.5-pro",
    "gemini-1.5-flash",
]


class LLMClient:
    MAX_RETRIES = 2
    RETRY_DELAY = 2  # seconds

    def __init__(self, config_path: str = "config.yaml"):
        # รองรับ run จาก directory ต่างๆ
        if not os.path.exists(config_path):
            config_path = os.path.join(os.path.dirname(__file__), config_path)

        with open(config_path, "r") as f:
            config = yaml.safe_load(f)["ai"]

        self.active_provider = config["active_provider"]
        self.provider_config = config["providers"].get(self.active_provider, {})
        self._setup(self.active_provider, self.provider_config.get("api_key", ""))

    # ─────────────────────────────────────────────
    # Setup per provider
    # ─────────────────────────────────────────────
    def _setup(self, provider: str, api_key: str) -> None:
        self.active_provider = provider

        if provider == "gemini":
            genai.configure(api_key=api_key)
            model_name = self.provider_config.get("model", "gemini-2.0-flash")
            self.gemini_model = genai.GenerativeModel(
                model_name=model_name,
                generation_config=genai.GenerationConfig(
                    temperature=0.4,       # ลด hallucination
                    max_output_tokens=4096,
                )
            )

        elif provider == "anthropic":
            import anthropic
            self.anthropic_client = anthropic.Anthropic(api_key=api_key)
            self.anthropic_model = self.provider_config.get("model", "claude-sonnet-4-5")

        else:
            # OpenAI-compatible: openai, groq, openrouter, local (ollama)
            base_urls = {
                "openai":      None,
                "groq":        "https://api.groq.com/openai/v1",
                "openrouter":  "https://openrouter.ai/api/v1",
                "together":    "https://api.together.xyz/v1",
                "mistral":     "https://api.mistral.ai/v1",
                "perplexity":  "https://api.perplexity.ai",
                "local":       self.provider_config.get("base_url", "http://localhost:11434/v1"),
            }
            self.openai_client = OpenAI(
                api_key=api_key or "ollama",
                base_url=base_urls.get(provider)
            )

    # ─────────────────────────────────────────────
    # Fetch available models dynamically
    # ─────────────────────────────────────────────
    def fetch_available_models(self, provider: str, api_key: str) -> list[str]:
        try:
            self._setup(provider, api_key)

            if provider == "gemini":
                return [
                    m.name.replace("models/", "")
                    for m in genai.list_models()
                    if "generateContent" in m.supported_generation_methods
                ][:10]

            elif provider == "anthropic":
                return CLAUDE_MODELS

            else:
                models_data = self.openai_client.models.list()
                return [m.id for m in models_data.data][:15]

        except Exception as e:
            print(f"⚠️ Could not fetch models: {e}")
            return GEMINI_MODELS if provider == "gemini" else CLAUDE_MODELS

    # ─────────────────────────────────────────────
    # Main Chat Method
    # ─────────────────────────────────────────────
    def chat(self, system_prompt: str, user_message: str) -> str:
        for attempt in range(self.MAX_RETRIES + 1):
            try:
                return self._call_api(system_prompt, user_message)
            except Exception as e:
                if attempt < self.MAX_RETRIES:
                    print(f"⚠️ LLM error (attempt {attempt+1}): {e}. Retrying in {self.RETRY_DELAY}s...")
                    time.sleep(self.RETRY_DELAY)
                else:
                    return f"❌ LLM failed after {self.MAX_RETRIES+1} attempts: {str(e)}"

    def _call_api(self, system_prompt: str, user_message: str) -> str:
        if self.active_provider == "gemini":
            full_prompt = f"{system_prompt}\n\n---\n\n{user_message}"
            response = self.gemini_model.generate_content(full_prompt)
            return response.text

        elif self.active_provider == "anthropic":
            response = self.anthropic_client.messages.create(
                model=self.anthropic_model,
                max_tokens=4096,
                system=system_prompt,
                messages=[{"role": "user", "content": user_message}]
            )
            return response.content[0].text

        else:
            response = self.openai_client.chat.completions.create(
                model=self.provider_config.get("model", "gpt-4o-mini"),
                max_tokens=4096,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_message},
                ]
            )
            return response.choices[0].message.content
