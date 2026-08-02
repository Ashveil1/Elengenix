"""tools/ai_config.py

Single Source of Truth for AI provider configuration.

Priority order (high → low):
  1. Constructor params (provider=, model=, api_key=, base_url=)
  2. config.yaml providers.{name}.*  ← single source of truth
  3. .env  {PROVIDER}_API_KEY, {PROVIDER}_MODEL
  4. PROVIDER_CONFIGS hardcoded defaults (in universal_ai_client.py)

This module:
  - Loads config.yaml ONCE (cached, thread-safe)
  - Returns typed dicts for each provider (api_key, base_url, model)
  - Parses active_models from config.yaml into clean list of (provider, model)
  - Exposes helper functions used by UniversalAIClient + AIClientManager + TeamAegis
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from elengenix.paths import find_env, find_config

logger = logging.getLogger("elengenix.ai_config")

# Load .env once at import (best-effort, safe if missing)
try:
    from dotenv import load_dotenv

    _env = find_env()
    if _env:
        load_dotenv(_env, override=False)
except ImportError:
    pass


# ── config.yaml loader (cached) ─────────────────────────────────
_CONFIG_CACHE: Dict[str, Any] = {}
_CONFIG_LOCK = threading.Lock()


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load config.yaml once and cache. Thread-safe.

    Returns full dict, or empty dict on parse error.
    """
    global _CONFIG_CACHE
    if _CONFIG_CACHE:
        return _CONFIG_CACHE
    with _CONFIG_LOCK:
        if _CONFIG_CACHE:  # double-check
            return _CONFIG_CACHE
        path = config_path or find_config()
        if not path or not path.exists():
            logger.debug(f"config.yaml not found at {path}")
            _CONFIG_CACHE = {}
            return _CONFIG_CACHE
        try:
            import yaml  # type: ignore

            with open(path) as f:
                _CONFIG_CACHE = yaml.safe_load(f) or {}
        except ImportError:
            logger.warning("PyYAML not installed — config.yaml ignored. Run: pip install pyyaml")
            _CONFIG_CACHE = {}
        except Exception as e:
            logger.warning(f"Failed to parse config.yaml: {e}")
            _CONFIG_CACHE = {}
        return _CONFIG_CACHE


def reset_config_cache() -> None:
    """Clear cache (for testing)."""
    global _CONFIG_CACHE
    with _CONFIG_LOCK:
        _CONFIG_CACHE = {}


# ── Public API ──────────────────────────────────────────────────


def get_ai_section() -> Dict[str, Any]:
    """Return the `ai:` section of config.yaml, or {} if missing."""
    cfg = load_config()
    return cfg.get("ai", {}) or {}


def get_active_provider() -> str:
    """Return the configured active provider name (e.g. 'nvidia').

    Falls back to ACTIVE_AI_PROVIDER env var, then 'auto'.
    """
    ai = get_ai_section()
    cfg_provider = (ai.get("active_provider") or "").strip().lower()
    if cfg_provider:
        return cfg_provider
    env_provider = os.getenv("ACTIVE_AI_PROVIDER", "").strip().lower()
    if env_provider and env_provider != "custom":  # 'custom' is a sentinel, ignore
        return env_provider
    return "auto"


def get_provider_config(provider: str) -> Dict[str, Any]:
    """Return config for a specific provider from config.yaml.

    Returns dict with keys: base_url, model, env_key (optional).
    Empty dict if provider not in config.
    """
    ai = get_ai_section()
    providers = ai.get("providers", {}) or {}
    return dict(providers.get(provider, {}) or {})


# Providers that are usable without an API key (local servers, probed for
# reachability separately by UniversalAIClient.is_available).
_KEY_FREE_PROVIDERS = {"ollama"}


def any_provider_configured() -> bool:
    """Return True if at least one AI provider is genuinely usable.

    A provider counts as configured when it has a real credential: either a
    non-empty API key in the environment, or a provider section in
    config.yaml that contains a resolvable api_key (literal key or env_key
    pointing to a set env var). Prevents providers from appearing "READY"
    merely because the project repo ships a config.yaml with model names.
    """
    # Explicit provider key in env wins fast.
    for name in _KNOWN_PROVIDER_PREFIXES:
        env_key = _default_env_key_for(name)
        if env_key and os.getenv(env_key, "").strip():
            return True
    # CUSTOM_API_BASE_URL + CUSTOM_API_KEY pair.
    if os.getenv("CUSTOM_API_KEY", "").strip() or os.getenv(
        "CUSTOM_API_BASE", ""
    ).strip():
        return True
    # Active provider explicitly set to a key-free local provider.
    active = get_active_provider()
    if active in _KEY_FREE_PROVIDERS and os.getenv("OLLAMA_BASE_URL"):
        return True
    return False


def resolve_provider_settings(
    provider: str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve final (base_url, model, api_key) for a provider.

    Priority (high → low):
      1. Constructor params (passed in)
      2. config.yaml providers.{name}.*
      3. .env  {PROVIDER}_API_KEY, {PROVIDER}_MODEL, {PROVIDER}_BASE_URL
      4. PROVIDER_CONFIGS hardcoded defaults (caller merges)

    Returns dict with keys: provider, base_url, model, api_key, source
    (source describes where each value came from, for debugging).
    """
    provider_lower = provider.lower() if provider else "auto"
    pc = get_provider_config(provider_lower)

    # base_url — strip trailing slashes so endpoints join cleanly
    sources: Dict[str, str] = {}
    if base_url:
        final_base_url = base_url.rstrip("/")
        sources["base_url"] = "param"
    elif pc.get("base_url"):
        final_base_url = pc["base_url"].rstrip("/")
        sources["base_url"] = "config.yaml"
    else:
        env_base = os.getenv(f"{provider_lower.upper()}_BASE_URL")
        if env_base:
            final_base_url = env_base.rstrip("/")
            sources["base_url"] = "env"
        else:
            final_base_url = ""
            sources["base_url"] = "default"

    # model
    if model:
        final_model = model
        sources["model"] = "param"
    elif pc.get("model"):
        final_model = pc["model"]
        sources["model"] = "config.yaml"
    else:
        env_model = os.getenv(f"{provider_lower.upper()}_MODEL")
        if env_model:
            final_model = env_model
            sources["model"] = "env"
        else:
            final_model = ""
            sources["model"] = "default"

    # api_key — config.yaml ONLY (explicit, auditable single source of truth).
    # This avoids the "which credential actually got used?" ambiguity that
    # makes environments hard to reproduce across machines/CI.
    if api_key:
        final_api_key = api_key
        sources["api_key"] = "param"
    else:
        cfg_key = pc.get("api_key")
        if isinstance(cfg_key, str) and cfg_key.strip():
            # literal key embedded in config.yaml (discouraged but allowed)
            final_api_key = cfg_key
            sources["api_key"] = "config.yaml (literal)"
            logger.warning(
                "Hardcoded api_key in config.yaml — use .env or rotate regularly."
            )
        else:
            final_api_key = ""
            sources["api_key"] = "none"

    return {
        "provider": provider_lower,
        "base_url": final_base_url,
        "model": final_model,
        "api_key": final_api_key,
        "sources": sources,
    }


def parse_active_models() -> List[Tuple[str, str]]:
    """Parse `active_models` from config.yaml into list of (provider, model) tuples.

    Accepts two formats:
      A) ["meta/llama-3.3-70b-instruct", "gpt-4o-mini"]      ← legacy / active_provider implied
      B) ["nvidia/meta/llama-3.3-70b-instruct", "openai/gpt-4o-mini"]  ← explicit

    Format A is converted using active_provider from config.yaml.
    Format B is split on first '/' only (NVIDIA model names contain '/').

    Returns clean list, may be empty.
    """
    ai = get_ai_section()
    raw = ai.get("active_models", []) or []
    active_provider = get_active_provider()
    out: List[Tuple[str, str]] = []
    for entry in raw:
        if not isinstance(entry, str):
            continue
        # Format B: "provider/model_with_slashes" — first '/' is the split point
        if "/" in entry:
            # Heuristic: known provider names are short (<= 12 chars, no slash)
            # If first segment matches a known provider, use Format B
            first, rest = entry.split("/", 1)
            if first.lower() in _KNOWN_PROVIDER_PREFIXES:
                out.append((first.lower(), rest))
                continue
            # Else treat as Format A: provider = active_provider, full = model
        # Format A
        out.append((active_provider, entry))
    return out


def get_provider_order() -> List[str]:
    """Return the provider priority order for AIClientManager.

    Order:
      1. active_provider from config.yaml
      2. ACTIVE_AI_PROVIDER from env (if not "custom" sentinel)
      3. All known providers (fallback chain)
    """
    ai = get_ai_section()
    active = get_active_provider()
    if active == "auto":
        active = "nvidia"  # sensible default for the current deployment
    # Build a list with active first, then remaining known providers
    all_providers = list(_KNOWN_PROVIDER_PREFIXES)
    if active in all_providers:
        all_providers.remove(active)
    return [active] + all_providers


# ── Internal helpers ────────────────────────────────────────────

_KNOWN_PROVIDER_PREFIXES = {
    "openai",
    "gemini",
    "anthropic",
    "groq",
    "nvidia",
    "deepseek",
    "mistral",
    "openrouter",
    "together",
    "perplexity",
    "opencode",
    "ollama",
}


def _default_env_key_for(provider: str) -> Optional[str]:
    """Default env var name for a provider's API key.

    Kept in sync with PROVIDER_CONFIGS in universal_ai_client.py
    """
    return {
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "groq": "GROQ_API_KEY",
        "nvidia": "NVIDIA_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "mistral": "MISTRAL_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "together": "TOGETHER_API_KEY",
        "perplexity": "PERPLEXITY_API_KEY",
        "opencode": "OPENCODE_API_KEY",
        "ollama": None,
        "custom": "CUSTOM_API_KEY",
    }.get(provider)


def describe_provider_setup() -> Dict[str, Any]:
    """Describe which AI provider will be used and whether its key is set.

    Additive helper for the CLI/UX layer (`elengenix configure`, interactive
    chat startup, TUI status line). Purely read-only — it never mutates env
    or config, and never performs hidden fallback selection.

    Returns a dict with keys:
      - providers : list of per-provider dicts (name, env_key, key_set,
        key_source, reachable, active)
      - active    : the provider name that will actually be used (or "")
      - model     : resolved model for the active provider (or "")
      - key_set   : bool — does the active provider have a credential?
      - key_source: where the credential comes from
          ("env:NAME", "config.yaml", "param", "env", "key-free",
          "none (not set)")
      - ok        : bool — True when some provider is genuinely usable.

    `reachable` is a socket-level TCP connect to the provider's host
    (no HTTP request, no key sent), so it is safe to call offline — on
    failure it simply reports "offline".
    """
    active = get_active_provider()
    providers: List[Dict[str, Any]] = []
    for name in sorted(_KNOWN_PROVIDER_PREFIXES):
        pc = get_provider_config(name) or {}
        env_name = _default_env_key_for(name)
        key_val, key_source = "", "none (not set)"
        if env_name and os.getenv(env_name, "").strip():
            key_val, key_source = os.getenv(env_name, "").strip(), f"env:{env_name}"
        elif isinstance(pc.get("api_key"), str) and pc.get("api_key", "").strip():
            key_val, key_source = pc["api_key"].strip(), "config.yaml"
        if name in _KEY_FREE_PROVIDERS:
            base_hint = os.getenv("OLLAMA_BASE_URL", "").strip() or str(
                pc.get("base_url", "") or ""
            ).strip()
            key_set = bool(base_hint)
            key_source = "key-free" if key_set else "none (not set)"
        else:
            key_set = bool(key_val)
        providers.append(
            {
                "name": name,
                "env_key": env_name or "",
                "key_set": key_set,
                "key_source": key_source,
                "reachable": None,  # filled below for active provider only
                "active": name == active,
            }
        )

    ok = any_provider_configured()

    # Model for the active provider
    resolved = resolve_provider_settings(active) if active else {}
    active_model = str(resolved.get("model") or "")

    # Socket-level reachability probe for the active provider only
    active_reachable: Optional[bool] = None
    base_url = ""
    if active:
        base_url = str(resolved.get("base_url") or "")
        if not base_url:
            pc = get_provider_config(active) or {}
            base_url = str(pc.get("base_url") or "")
        if not base_url and active == "ollama":
            base_url = os.getenv("OLLAMA_BASE_URL", "")
    if base_url:
        try:
            from urllib.parse import urlparse
            import socket

            u = urlparse(base_url if "://" in base_url else f"https://{base_url}")
            host = u.hostname or ""
            port = u.port or (443 if u.scheme == "https" else 80)
            if host:
                with socket.create_connection((host, port), timeout=2.0):
                    active_reachable = True
        except Exception:
            active_reachable = False
    for p in providers:
        if p["name"] == active:
            p["reachable"] = active_reachable

    # Active provider convenience view
    active_info = next((p for p in providers if p["name"] == active), None)
    key_set = active_info["key_set"] if active_info else False
    key_source = active_info["key_source"] if active_info else "none (not set)"

    return {
        "providers": providers,
        "active": active if active != "auto" else "",
        "model": active_model,
        "key_set": key_set,
        "key_source": key_source,
        "ok": ok,
    }

