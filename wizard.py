"""
wizard.py -- Elengenix AI Provider Configuration Wizard (v2.0.0)

Interactive wizard for selecting and configuring AI providers.
Supports multi-provider setup with model selection and API key validation.

Usage:
    python wizard.py

Dependencies:
    - pyyaml
    - questionary
    - rich
"""

import yaml
import questionary
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional
from rich.console import Console

logger = logging.getLogger("elengenix.wizard")
console = Console()

# ---------------------------------------------------------------------------
# Supported AI Providers
# ---------------------------------------------------------------------------

PROVIDERS = [
    "gemini", "openai", "anthropic", "groq", "openrouter",
    "together", "mistral", "deepseek", "perplexity", "local", "skip"
]

# Preset model lists per provider (used as defaults when dynamic fetch is unavailable)
DEFAULT_MODELS: Dict[str, List[str]] = {
    "gemini":      ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"],
    "openai":      ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
    "anthropic":   ["claude-3-5-sonnet-latest", "claude-3-haiku-20240307", "claude-3-opus-20240229"],
    "groq":        ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
    "openrouter":  ["meta-llama/llama-3.1-70b-instruct", "anthropic/claude-3-haiku", "auto"],
    "together":    ["meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo", "mistralai/Mixtral-8x7B-Instruct-v0.1"],
    "mistral":     ["mistral-large-latest", "mistral-small-latest", "open-mixtral-8x7b"],
    "deepseek":    ["deepseek-chat", "deepseek-coder"],
    "perplexity":  ["llama-3.1-sonar-large-128k-online", "llama-3.1-sonar-small-128k-online"],
    "local":       ["llama3.2", "llama3.1:8b", "mistral:7b", "codellama:7b"],
}


def _load_config(config_path: str) -> dict:
    """Load and return the YAML configuration file."""
    path = Path(config_path)
    if not path.exists():
        logger.error("Configuration file not found: %s", config_path)
        console.print(f"[red][FAIL] Configuration file not found: {config_path}[/red]")
        console.print("[dim]Run ./setup.sh or copy config.yaml.example to config.yaml[/dim]")
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        logger.error("Failed to parse %s: %s", config_path, exc)
        console.print(f"[red][FAIL] Config parse error: {exc}[/red]")
        return {}


def _save_config(config: dict, config_path: str) -> bool:
    """Write configuration back to YAML file."""
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        return True
    except Exception as exc:
        logger.error("Failed to save config: %s", exc)
        console.print(f"[red][FAIL] Could not save configuration: {exc}[/red]")
        return False


def _get_models_for_provider(provider: str) -> List[str]:
    """Return the list of available models for a given provider.

    Uses preset defaults. Dynamic model fetching can be added in a future
    version once all provider SDKs support it consistently.
    """
    return DEFAULT_MODELS.get(provider, ["auto"])


def _save_key_to_env(provider: str, api_key: str) -> None:
    """Append or update the API key in the .env file for secure storage."""
    env_key = f"{provider.upper()}_API_KEY"
    env_path = Path(".env")

    lines: List[str] = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()

    # Remove any existing entry for this provider
    lines = [line for line in lines if not line.startswith(f"{env_key}=")]
    lines.append(f"{env_key}={api_key}")

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("API key for %s saved to .env", provider)


# ---------------------------------------------------------------------------
# Main Wizard Flow
# ---------------------------------------------------------------------------

def main() -> None:
    """Run the interactive AI provider configuration wizard."""
    config_path = "config.yaml"
    config = _load_config(config_path)
    if not config:
        return

    # Ensure required config sections exist
    config.setdefault("ai", {})
    config["ai"].setdefault("providers", {})

    console.print("\n[bold red]AI Provider Configuration Wizard[/bold red]\n")

    # Step 1: Select provider
    provider = questionary.select(
        "Select your AI Provider:",
        choices=PROVIDERS
    ).ask()

    if not provider or provider == "skip":
        console.print("[dim]Configuration skipped[/dim]")
        return

    # Step 2: Enter API key (stored in .env, not config.yaml)
    if provider != "local":
        api_key = questionary.password(f"Enter API Key for {provider}:").ask()
        if not api_key:
            console.print("[yellow][WARN] No API key provided. Skipping.[/yellow]")
            return
        _save_key_to_env(provider, api_key)
    else:
        console.print("[dim]Local provider selected -- no API key required[/dim]")

    # Step 3: Select model from preset list
    models = _get_models_for_provider(provider)
    choices = models + ["Custom (enter manually)"]

    model = questionary.select(
        f"Select model for {provider}:",
        choices=choices
    ).ask()

    if model == "Custom (enter manually)":
        model = questionary.text("Enter model identifier:").ask()
        if not model:
            console.print("[yellow][WARN] No model provided. Using default.[/yellow]")
            model = models[0] if models else "auto"

    # Step 4: Save provider and model to config.yaml (API key stays in .env)
    config["ai"]["active_provider"] = provider
    if provider not in config["ai"]["providers"]:
        config["ai"]["providers"][provider] = {}

    config["ai"]["providers"][provider]["model"] = model
    # Note: API keys are stored in .env, not in config.yaml

    if _save_config(config, config_path):
        console.print(f"\n[bold white][OK] {provider.upper()} configured with model: {model}[/bold white]")
        console.print("[dim]API key saved to .env (not stored in config.yaml)[/dim]")
    else:
        console.print("[bold red][FAIL] Configuration could not be saved[/bold red]")


if __name__ == "__main__":
    main()
