import os
from pathlib import Path

def _load_env():
    """
    Load .env from the first location found:
    1. Same directory as this file (standalone mode)
    2. Parent directory   (nested inside another project)
    3. System environment only (no .env file needed)
    """
    try:
        from dotenv import load_dotenv
        this_dir = Path(__file__).resolve().parent
        for candidate in [this_dir / ".env", this_dir.parent / ".env"]:
            if candidate.exists():
                load_dotenv(candidate)
                return
    except ImportError:
        pass  # python-dotenv not installed — rely on system env vars

_load_env()

# API Keys — read after .env is loaded
GEMINI_API_KEY   = os.getenv("GEMINI_API_KEY")
OPENAI_API_KEY   = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
NVIDIA_API_KEY   = os.getenv("NVIDIA_API_KEY")
CUSTOM_API_KEY   = os.getenv("CUSTOM_API_KEY")
CUSTOM_API_BASE  = os.getenv("CUSTOM_API_BASE")

# Active providers for slots (AI1 is default Strategist/Fallback, AI2 Specialist, AI3 Chat)
AI1_PROVIDER = os.getenv("AI1_PROVIDER", "")
AI2_PROVIDER = os.getenv("AI2_PROVIDER", "")
AI3_PROVIDER = os.getenv("AI3_PROVIDER", "")

def save_to_env(key: str, value: str):
    """Save or update a key-value pair in the .env file."""
    this_dir = Path(__file__).resolve().parent
    env_file = this_dir / ".env"
    if not env_file.exists():
        env_file = this_dir.parent / ".env"
        
    lines = []
    if env_file.exists():
        lines = env_file.read_text().splitlines()
        
    updated = False
    for i, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[i] = f"{key}={value}"
            updated = True
            break
            
    if not updated:
        lines.append(f"{key}={value}")
        
    env_file.write_text("\n".join(lines) + "\n")
    # Also update current os.environ so changes take effect immediately
    os.environ[key] = value
