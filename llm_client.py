"""
llm_client.py — Elengenix High-Resilience LLM Interface (v2.0.1)
- Native Anthropic, Gemini, Cohere, Hugging Face, Replicate Support
- OpenAI-compatible API for Groq, OpenRouter, Mistral, DeepSeek, Perplexity, Azure OpenAI
- Automatic Retries and Exponential Backoff
- Token Usage Tracking and Prompt Sanitization
- Optional nest_asyncio for nested event loops
"""

import yaml
import os
import asyncio
import logging
import re
import threading
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, Any, Union
from openai import AsyncOpenAI, AsyncAzureOpenAI

# Optional python-dotenv for environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, skip

# Optional tenacity for retry logic
try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
except ImportError:
    # Fallback decorator if tenacity not installed
    def retry(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    stop_after_attempt = lambda x: None
    wait_exponential = lambda **kwargs: None
    retry_if_exception_type = lambda x: None

# Optional: Initialize nest_asyncio to allow nested event loops (Telegram Bot compatibility)
try:
    import nest_asyncio
    nest_asyncio.apply()
except ImportError:
    pass  # nest_asyncio not installed, skip

# Setup structured logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("elengenix.llm")

@dataclass
class LLMResponse:
 content: str
 prompt_tokens: int = 0
 completion_tokens: int = 0
 total_tokens: int = 0
 model: str = ""
 provider: str = ""

class LLMClient:
    _shared_loop = None
    _loop_thread = None
    _loop_lock = threading.Lock()

    @classmethod
    def _get_shared_loop(cls):
        with cls._loop_lock:
            if cls._shared_loop is None:
                cls._shared_loop = asyncio.new_event_loop()
                def run_loop(loop):
                    asyncio.set_event_loop(loop)
                    loop.run_forever()
                cls._loop_thread = threading.Thread(target=run_loop, args=(cls._shared_loop,), daemon=True)
                cls._loop_thread.start()
            return cls._shared_loop

    def __init__(self, config_path: str = "config.yaml"):
        base_dir = Path(__file__).parent.absolute()
        self.config_path = base_dir / config_path
        
        self.config = self._load_ai_config()
        self.active_provider = self.config.get("active_provider", "gemini").lower()
        
        # Priority: Environment Variables
        self.api_key = os.getenv(f"{self.active_provider.upper()}_API_KEY") or \
            self.config.get("providers", {}).get(self.active_provider, {}).get("api_key", "")

        if not self._validate_api_key(self.api_key, self.active_provider):
            raise ValueError(f"Valid API Key for {self.active_provider} is required.")

        self.setup()

    def _load_ai_config(self) -> Dict[str, Any]:
        try:
            with open(self.config_path, "r") as f:
                full_config = yaml.safe_load(f)
                return full_config.get("ai", {})
        except Exception:
            return {"active_provider": "gemini", "providers": {}}

    def _validate_api_key(self, key: str, provider: str) -> bool:
        """Strict API key validation to prevent configuration errors."""
        if not key or "YOUR" in str(key).upper():
            return False
        return True

    def _sanitize_text(self, text: str, max_len: int = 32000) -> str:
        """Shields against prompt injection markers and manages length."""
        if len(text) > max_len:
            text = text[:max_len] + "... [Truncated]"
        
        # Block potential multi-role injection attempts
        forbidden = ["### SYSTEM:", "### USER:", "### ASSISTANT:"]
        for marker in forbidden:
            text = text.replace(marker, f"[{marker}]")
        return text

    def setup(self):
        provider_cfg = self.config.get("providers", {}).get(self.active_provider, {})
        self.model_name = provider_cfg.get("model", "gemini-1.5-flash")

        if self.active_provider == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self.gemini_model = genai.GenerativeModel(self.model_name)
        elif self.active_provider == "anthropic":
            import anthropic
            self.anthropic_client = anthropic.AsyncAnthropic(api_key=self.api_key)
        elif self.active_provider == "cohere":
            import cohere
            self.cohere_client = cohere.AsyncClient(api_key=self.api_key)
        elif self.active_provider == "huggingface":
            from huggingface_hub import AsyncInferenceClient
            self.hf_client = AsyncInferenceClient(model=self.model_name, token=self.api_key)
        elif self.active_provider == "replicate":
            import replicate
            self.replicate_client = replicate.AsyncClient(api_token=self.api_key)
        elif self.active_provider == "azure":
            # Azure OpenAI
            self.async_client = AsyncAzureOpenAI(
                api_key=self.api_key,
                api_version=provider_cfg.get("api_version", "2024-02-15-preview"),
                azure_endpoint=provider_cfg.get("azure_endpoint", os.getenv("AZURE_OPENAI_ENDPOINT"))
            )
        else:
            # OpenAI compatible (OpenAI, Groq, OpenRouter, Mistral, DeepSeek, Perplexity, Together AI)
            base_urls = {
                "openai": None,
                "groq": "https://api.groq.com/openai/v1",
                "openrouter": "https://openrouter.ai/api/v1",
                "local": "http://localhost:11434/v1",
                "mistral": "https://api.mistral.ai/v1",
                "deepseek": "https://api.deepseek.com/v1",
                "perplexity": "https://api.perplexity.ai",
                "together": "https://api.together.xyz/v1"
            }
            self.async_client = AsyncOpenAI(
                api_key=self.api_key, 
                base_url=base_urls.get(self.active_provider)
            )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=20),
        retry=retry_if_exception_type((Exception)), # Refine to specific network errors in production
        reraise=True
    )
    async def chat_async(self, system_prompt: str, user_message: str) -> LLMResponse:
        """ High-Performance Async LLM Call with integrated resilience."""
        safe_system = self._sanitize_text(system_prompt, max_len=8000)
        safe_user = self._sanitize_text(user_message)

        try:
            if self.active_provider == "gemini":
                # Combining prompts for Gemini's structure
                full_content = f"{safe_system}\n\nUser: {safe_user}"
                response = await self.gemini_model.generate_content_async(full_content)
                usage = getattr(response, "usage_metadata", None)
                return LLMResponse(
                    content=response.text,
                    prompt_tokens=getattr(usage, "prompt_token_count", 0),
                    completion_tokens=getattr(usage, "candidates_token_count", 0),
                    total_tokens=getattr(usage, "total_token_count", 0),
                    model=self.model_name,
                    provider="gemini"
                )

            elif self.active_provider == "anthropic":
                response = await self.anthropic_client.messages.create(
                    model=self.model_name,
                    max_tokens=4096,
                    system=safe_system,
                    messages=[{"role": "user", "content": safe_user}]
                )
                return LLMResponse(
                    content=response.content[0].text,
                    prompt_tokens=response.usage.input_tokens,
                    completion_tokens=response.usage.output_tokens,
                    total_tokens=response.usage.input_tokens + response.usage.output_tokens,
                    model=self.model_name,
                    provider="anthropic"
                )

            elif self.active_provider == "cohere":
                response = await self.cohere_client.chat(
                    model=self.model_name,
                    message=safe_user,
                    preamble=safe_system,
                    max_tokens=4096
                )
                return LLMResponse(
                    content=response.text,
                    prompt_tokens=response.meta.billed_units.input_tokens,
                    completion_tokens=response.meta.billed_units.output_tokens,
                    total_tokens=response.meta.billed_units.input_tokens + response.meta.billed_units.output_tokens,
                    model=self.model_name,
                    provider="cohere"
                )

            elif self.active_provider == "huggingface":
                # Hugging Face Inference API
                prompt = f"{safe_system}\n\n{safe_user}"
                response = await self.hf_client.text_generation(
                    prompt=prompt,
                    max_new_tokens=4096,
                    do_sample=False
                )
                return LLMResponse(
                    content=response,
                    prompt_tokens=0,  # HF doesn't provide token counts
                    completion_tokens=0,
                    total_tokens=0,
                    model=self.model_name,
                    provider="huggingface"
                )

            elif self.active_provider == "replicate":
                # Replicate - run model
                import replicate
                output = await replicate.async_run(
                    f"{self.model_name}",
                    input={
                        "prompt": f"{safe_system}\n\n{safe_user}",
                        "max_tokens": 4096
                    },
                    api_token=self.api_key
                )
                return LLMResponse(
                    content=str(output),
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=0,
                    model=self.model_name,
                    provider="replicate"
                )

            else:
                # OpenAI Compatible (OpenAI, Groq, OpenRouter, Mistral, DeepSeek, Perplexity, Together AI, Azure)
                response = await self.async_client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": safe_system},
                        {"role": "user", "content": safe_user}
                    ],
                    timeout=60.0
                )
                usage = response.usage
                return LLMResponse(
                    content=response.choices[0].message.content,
                    prompt_tokens=usage.prompt_tokens,
                    completion_tokens=usage.completion_tokens,
                    total_tokens=usage.total_tokens,
                    model=response.model,
                    provider=self.active_provider
                )

        except Exception as e:
            logger.error(f"LLM failure on {self.active_provider}: {e}")
            raise

    def chat(self, system_prompt: str, user_message: str) -> str:
        """Synchronous wrapper for chat_async using a persistent background loop.
        
        This prevents 'got Future attached to a different loop' errors when using gRPC 
        clients (like Gemini/Anthropic) by ensuring all async execution happens on a 
        single shared event loop, instead of creating/destroying loops with asyncio.run().
        """
        loop = self._get_shared_loop()
        future = asyncio.run_coroutine_threadsafe(self.chat_async(system_prompt, user_message), loop)
        try:
            response = future.result(timeout=120)
            return response.content
        except Exception as e:
            logger.error(f"Error in synchronous chat execution: {e}")
            raise
