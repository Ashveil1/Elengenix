import yaml
import questionary
import os
from rich.console import Console
from llm_client import LLMClient

console = Console()

PROVIDERS = [
    "gemini", "openai", "anthropic", "groq", "openrouter", 
    "together", "mistral", "monster", "perplexity", "local", "skip"
]

def main():
    config_path = "config.yaml"
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    console.print("[bold cyan]🤖 AI Engine Multi-Provider Wizard[/bold cyan]")
    
    provider = questionary.select(
        "Select your AI Provider:",
        choices=PROVIDERS
    ).ask()

    if provider != "skip":
        # 1. Ask for API Key first (to fetch models)
        api_key = questionary.password(f"Enter API Key for {provider}:").ask()
        
        # 2. Fetch Models Dynamically
        with console.status(f"[bold yellow]Fetching latest models from {provider}...[/bold yellow]"):
            client = LLMClient()
            dynamic_models = client.fetch_available_models(provider, api_key)
        
        # 3. Select Model
        choices = dynamic_models + ["Custom (Enter Manually)"]
        model = questionary.select(
            f"Select model for {provider}:", 
            choices=choices
        ).ask()
        
        if model == "Custom (Enter Manually)":
            model = questionary.text("Enter Model Name (e.g., gpt-5-preview):").ask()
        
        # Save to config
        config["ai"]["active_provider"] = provider
        if provider not in config["ai"]["providers"]: 
            config["ai"]["providers"][provider] = {}
        
        config["ai"]["providers"][provider]["model"] = model
        config["ai"]["providers"][provider]["api_key"] = api_key
        
        with open(config_path, "w") as f:
            yaml.dump(config, f)
        
        console.print(f"[bold green]✅ {provider.upper()} configured with model: {model}[/bold green]")

if __name__ == "__main__":
    main()
