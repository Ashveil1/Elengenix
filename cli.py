import os
import yaml
import questionary
from llm_client import LLMClient
from knowledge_loader import load_knowledge_base
from rich.console import Console
from rich.markdown import Markdown

console = Console()

def select_model_config():
    """
    Interactive menu to select provider and model, 
    matching OpenClaw-like behavior but with more options.
    """
    # 1. Select Provider
    provider = questionary.select(
        "Select your AI Provider:",
        choices=[
            "gemini",
            "openai",
            "anthropic",
            "groq",
            "local (Ollama/LM Studio)",
            "Other (Enter Manually)"
        ]
    ).ask()

    if provider == "Other (Enter Manually)":
        provider = questionary.text("Enter Provider Name:").ask()

    # 2. Select or Enter Model
    model_choices = {
        "gemini": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-1.0-pro"],
        "openai": ["gpt-4-turbo", "gpt-4", "gpt-3.5-turbo", "o1-preview"],
        "anthropic": ["claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"],
        "groq": ["llama3-70b-8192", "llama3-8b-8192", "mixtral-8x7b-32768", "gemma-7b-it"],
        "local (Ollama/LM Studio)": ["llama3", "mistral", "codellama", "phi3"]
    }

    choices = model_choices.get(provider, []) + ["Custom (Enter Manually)"]
    
    model = questionary.select(
        f"Select {provider} model:",
        choices=choices
    ).ask()

    if model == "Custom (Enter Manually)":
        model = questionary.text("Enter Model Name (e.g., gpt-4o):").ask()

    # 3. Enter API Key if not in config
    api_key = questionary.password(f"Enter API Key for {provider} (leave blank to use config.yaml):").ask()

    return provider, model, api_key

def main():
    console.print("[bold cyan]🛡️ Elengenix - AI Bug Bounty Framework[/bold cyan]")
    
    # Selection Menu
    provider, model, api_key = select_model_config()

    # Load Base System Prompt
    with open("prompts/system_prompt.txt", "r") as f:
        system_prompt = f.read()
    
    # 🧠 Load Knowledge Base (Training Data)
    knowledge = load_knowledge_base()
    system_prompt += knowledge

    # 🛠️ Add Tool Knowledge
    tools_info = "\n\n### AVAILABLE BASE TOOLS:\n"
    if os.path.exists("tools"):
        for tool_file in os.listdir("tools"):
            if tool_file.endswith(".py"):
                tools_info += f"- {tool_file}: Specialized tool for bug hunting.\n"
    
    system_prompt += tools_info

    # Initialize Client with temporary overrides
    client = LLMClient()
    client.active_provider = provider
    client.provider_config = {
        "model": model,
        "api_key": api_key if api_key else client.full_config["providers"].get(provider, {}).get("api_key", "")
    }
    client.setup()

    console.print(f"\n[bold green]✅ Sentinel Initialized with {provider}/{model}[/bold green]\n")
    console.print("[dim]Type '/exit' to quit. Ask me anything about bug bounty![/dim]\n")

    while True:
        user_input = input("👤 Hunter: ")
        if user_input.lower() == "/exit":
            break
        
        with console.status(f"[bold yellow]Sentinel is thinking ({model})...[/bold yellow]"):
            response = client.chat(system_prompt, user_input)
        
        console.print(Markdown(f"🤖 **Sentinel:**\n{response}"))

if __name__ == "__main__":
    main()
