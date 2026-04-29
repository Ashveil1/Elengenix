"""
cli.py — Elengenix AI Partner Mode (v2.0.0)
- Universal Agent Mode: Flexible like Claude Code / Gemini CLI
- Bug Bounty Specialist Mode: Deep security expertise
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

# Logging Setup 
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

# Rate Limiting Configuration 
RATE_LIMIT = 5 # Max queries
RATE_WINDOW = 60 # per minute
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

# Security & Sanitization 
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
 console.print(f"[bold red] Security Alert: Patterns like '{pattern}' are restricted.[/bold red]")
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

# UI Helpers 
def create_callback(console_obj: Console, use_live_display: bool = False) -> Callable[[str], None]:
 """Factory for agent thought updates."""
 def callback(msg: str):
 if use_live_display:
 # Use activity logger for live display
 from live_display import display_in_chat_mode
 if "Running" in msg or "Executing" in msg:
 display_in_chat_mode(msg, "action")
 elif "success" in msg.lower() or "complete" in msg.lower():
 display_in_chat_mode(msg, "result")
 else:
 display_in_chat_mode(msg, "thought")
 else:
 # Simple console output
 if "Running" in msg or "Executing" in msg:
 console_obj.print(f"[cyan]→ {msg}[/cyan]")
 elif "success" in msg.lower() or "complete" in msg.lower():
 console_obj.print(f"[green] {msg}[/green]")
 elif "error" in msg.lower() or "fail" in msg.lower():
 console_obj.print(f"[red] {msg}[/red]")
 else:
 console_obj.print(f"[dim]• {msg}[/dim]")
 return callback

# Main Entry Point 
def select_agent_mode() -> str:
 """Let user choose between Universal Agent and Bug Bounty Specialist."""
 from ui_components import console
 
 console.print("\n[bold cyan]Select Agent Mode[/bold cyan]\n")
 console.print(" 1. Universal Agent (Flexible - Like Claude Code)")
 console.print(" 2. Bug Bounty Specialist (Security Focused)")
 console.print(" 3. Auto Detect (Choose based on query)")
 console.print()
 
 choice = console.input("[cyan]Mode[/cyan] [dim](1-3)[/dim]: ").strip()
 
 if choice == "1":
 return "universal"
 elif choice == "2":
 return "bug_bounty"
 else:
 return "auto"

def main(mode: str = None, target: str = None):
 import os
 
 # Detect if running in tmux
 in_tmux = os.environ.get("TMUX") is not None
 tmux_pane = os.environ.get("ELENGENIX_PANE", "unknown")
 
 # Check if tmux is available and offer split-screen mode
 if not in_tmux:
 try:
 import tmux_manager
 tmux_mgr = tmux_manager.get_tmux_manager()
 if tmux_mgr.is_available():
 console.print("\n[dim]Tmux detected! Split-screen mode available.[/dim]")
 use_tmux = console.input("[cyan]Use split-screen mode?[/cyan] [dim](y/N)[/dim]: ").strip().lower()
 if use_tmux in ('y', 'yes'):
 console.print("[dim]Launching split-screen mode...[/dim]")
 if tmux_manager.launch_tmux_mode():
 return # Exit normal CLI, tmux will handle the session
 else:
 console.print("[yellow]Failed to launch tmux mode, continuing with normal mode...[/yellow]\n")
 else:
 console.print("[dim]Continuing with normal mode...[/dim]\n")
 except Exception as e:
 pass # Tmux not available or error, continue normally
 
 console.clear()
 
 # Select mode if not provided
 if not mode:
 mode = select_agent_mode()
 
 mode_display = {
 "universal": "Universal Agent",
 "bug_bounty": "Bug Bounty Specialist",
 "auto": "Adaptive Agent"
 }.get(mode, "AI Partner")
 
 # Show banner (simpler in tmux)
 if in_tmux:
 console.print(f"[bold cyan]{mode_display}[/bold cyan] [dim](tmux mode)[/dim]\n")
 else:
 console.print(Panel.fit(
 f"[bold cyan]{mode_display} MODE (v2.0.0)[/bold cyan]\n"
 f"[dim]Enter '/exit' to quit | '/mode' to switch | '/target <domain>' to set target[/dim]",
 border_style="cyan"
 ))

 try:
 agent = get_agent()
 except Exception as e:
 logger.error(f"Agent Init Failed: {e}")
 console.print(f"[bold red] Failed to initialize Agent: {e}[/bold red]")
 return

 # Create callback with tmux-aware display
 callback = create_callback(console, use_live_display=in_tmux)

 while True:
 try:
 raw_input = get_secure_input("\n[cyan]You[/cyan]: ", timeout=600)
 
 if raw_input is None:
 console.print("\n[dim]Session timed out due to inactivity[/dim]")
 break
 
 if raw_input.lower() in ["/exit", "exit", "quit"]:
 console.print("[dim]Session ended[/dim]")
 break
 
 if raw_input.lower() == "/help":
 console.print("\n[bold cyan]Available Commands:[/bold cyan]\n")
 console.print(" /exit - End session")
 console.print(" /mode - Switch agent mode")
 console.print(" /target - Set target domain")
 console.print(" /help - Show this help")
 if in_tmux:
 console.print("\n[bold cyan]Tmux Shortcuts:[/bold cyan]\n")
 console.print(" Ctrl+B ← - Focus left pane (chat)")
 console.print(" Ctrl+B → - Focus right pane (logs)")
 console.print(" Ctrl+B % - Split window vertically")
 console.print(' Ctrl+B " - Split window horizontally')
 console.print(" Ctrl+B x - Close current pane")
 console.print()
 continue
 
 if raw_input.lower() == "/mode":
 mode = select_agent_mode()
 console.print(f"[green]Switched to {mode} mode[/green]")
 continue
 
 if raw_input.lower().startswith("/target "):
 target = raw_input[8:].strip()
 console.print(f"[green]Target set to: {target}[/green]")
 continue

 user_query = sanitize_input(raw_input)
 if not user_query:
 continue

 if not check_rate_limit():
 console.print("[yellow]Rate Limit reached. Please wait a minute.[/yellow]")
 continue

 logger.info(f"Query: {user_query[:100]}...")

 # Execution with Threaded Timeout
 result_container = {"response": None, "error": None}
 def run_agent():
 try:
 # Choose processing method based on mode
 if mode == "universal" or (mode == "auto" and not target and 
 not any(kw in user_query.lower() for kw in ["scan", "vuln", "exploit", "pentest", "target", "domain"])):
 # Use Universal Agent Mode
 result_container["response"] = agent.process_universal(
 user_query, 
 callback=callback,
 target=target or "",
 mode=mode
 )
 else:
 # Use Bug Bounty Specialist Mode
 result_container["response"] = agent.process_query(
 user_query, 
 callback=callback,
 target=target
 )
 except Exception as ex:
 result_container["error"] = ex

 with console.status("[cyan]Agent is thinking...[/cyan]", spinner="dots"):
 agent_thread = threading.Thread(target=run_agent)
 agent_thread.start()
 agent_thread.join(timeout=300) # 5-minute hard limit per query

 if agent_thread.is_alive():
 logger.error("Query timed out after 300s")
 console.print("[red]Agent response timed out[/red]")
 continue

 if result_container["error"]:
 raise result_container["error"]

 response = result_container["response"]
 logger.info(f"Agent finished query successfully.")

 # Render Result
 console.print("\n[dim] Response [/dim]\n")
 console.print(Markdown(response if response else "No response from agent."))
 console.print("\n[dim][/dim]")

 except KeyboardInterrupt:
 console.print("\n[dim]Interrupted by user. Exiting...[/dim]")
 break
 except Exception as e:
 logger.error(f"Unexpected CLI error: {e}", exc_info=True)
 console.print(f"[red]Error: {str(e)[:200]}[/red]")

if __name__ == "__main__":
 main()
