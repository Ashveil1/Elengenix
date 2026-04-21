"""
cli.py — Elengenix AI Partner Mode (v1.5.0)
- Secure Interactive CLI with Input Sanitization
- Usage Logging & Rate Limiting
- Non-blocking input with timeout support
- Robust Error Handling and Thread-safe Callbacks
"""

import os
import sys
import time
import select
import logging
import threading
from pathlib import Path
from collections import deque
from typing import Optional, Callable

from rich.console import Console
from rich.markdown import Markdown
from rich.live import Live
from rich.panel import Panel

from agent import get_agent
from bot_utils import send_telegram_notification

# ── Logging Setup ───────────────────────────────────────────
LOG_FILE = Path("data/elengenix_cli.log")
LOG_FILE.parent.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        # StreamHandler is omitted here to keep CLI clean, using Rich for UI
    ]
)
logger = logging.getLogger("elengenix.cli")

console = Console()

# ── Rate Limiting Configuration ──────────────────────────────
RATE_LIMIT = 5  # Max queries
RATE_WINDOW = 60  # per minute
user_requests = deque()

def check_rate_limit() -> bool:
    """Returns True if within limit, False otherwise."""
    now = time.time()
    while user_requests and user_requests[0] < now - RATE_WINDOW:
        user_requests.popleft()
    if len(user_requests) >= RATE_LIMIT:
        return False
    user_requests.append(now)
    return True

# ── Security & Sanitization ──────────────────────────────────
def sanitize_input(text: str, max_length: int = 2000) -> str:
    """Sanitize and truncate user input for safety."""
    text = text.strip()
    if len(text) > max_length:
        logger.warning(f"Input truncated from {len(text)} to {max_length}")
        text = text[:max_length]
    
    # Block potentially harmful patterns in a CLI context
    dangerous = ["__import__", "eval(", "exec(", "os.system"]
    for pattern in dangerous:
        if pattern in text.lower():
            logger.warning(f"Dangerous pattern blocked: {pattern}")
            console.print(f"[bold red]⚠️ Security Alert: Patterns like '{pattern}' are restricted.[/bold red]")
            return ""
    return text

def get_secure_input(prompt: str, timeout: int = 300) -> Optional[str]:
    """Retrieves user input with a timeout (Unix-friendly)."""
    console.print(prompt, end="")
    if sys.platform != "win32":
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        if ready:
            return sys.stdin.readline().rstrip('\n')
        return None
    else:
        # Fallback for Windows
        try:
            return input()
        except EOFError:
            return None

# ── UI Helpers ───────────────────────────────────────────────
def create_callback(console_obj: Console) -> Callable[[str], None]:
    """Factory for agent thought updates."""
    def callback(msg: str):
        console_obj.print(f"[dim]⚡ {msg}[/dim]")
    return callback

# ── Main Entry Point ─────────────────────────────────────────
def main():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]🛡️ ELENGENIX AI PARTNER MODE (v1.5.0)[/bold cyan]\n"
        "[dim]Enter '/exit' to quit | Secure Session Active[/dim]",
        border_style="cyan"
    ))

    try:
        agent = get_agent()
    except Exception as e:
        logger.error(f"Agent Init Failed: {e}")
        console.print(f"[bold red]❌ Failed to initialize Agent: {e}[/bold red]")
        return

    callback = create_callback(console)

    while True:
        try:
            raw_input = get_secure_input("\n[bold green]👤 Hunter:[/bold green] ", timeout=600)
            
            if raw_input is None:
                console.print("\n[yellow]⏱️ Session timed out due to inactivity.[/yellow]")
                break
                
            if raw_input.lower() in ["/exit", "exit", "quit"]:
                console.print("[bold yellow]👋 Mission Paused. See you soon, Hunter.[/bold yellow]")
                break

            user_query = sanitize_input(raw_input)
            if not user_query:
                continue

            if not check_rate_limit():
                console.print("[bold yellow]⏳ Rate Limit reached. Please wait a minute.[/bold yellow]")
                continue

            logger.info(f"Query: {user_query[:100]}...")

            # 🔄 Execution with Threaded Timeout
            result_container = {"response": None, "error": None}
            def run_agent():
                try:
                    result_container["response"] = agent.process_query(user_query, callback=callback)
                except Exception as ex:
                    result_container["error"] = ex

            with console.status("[bold cyan]Agent is processing mission parameters...[/bold cyan]", spinner="dots"):
                agent_thread = threading.Thread(target=run_agent)
                agent_thread.start()
                agent_thread.join(timeout=300) # 5-minute hard limit per query

            if agent_thread.is_alive():
                logger.error("Query timed out after 300s")
                console.print("[bold red]⏱️ Agent response timed out. Mission aborted.[/bold red]")
                continue

            if result_container["error"]:
                raise result_container["error"]

            response = result_container["response"]
            logger.info(f"Agent finished query successfully.")

            # Render Result
            console.print("\n" + "─" * 50)
            console.print(Markdown(response if response else "Agent returned no findings."))
            console.print("─" * 50)

        except KeyboardInterrupt:
            console.print("\n[bold yellow]⚠️ Interrupted by user. Exiting...[/bold yellow]")
            break
        except Exception as e:
            logger.error(f"Unexpected CLI error: {e}", exc_info=True)
            console.print(f"[bold red]❌ System Error: {str(e)[:200]}[/bold red]")

if __name__ == "__main__":
    main()
