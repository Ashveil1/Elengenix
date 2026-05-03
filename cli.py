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
    ]
)
logger = logging.getLogger("elengenix.cli")

console = Console()

# Rate Limiting Configuration 
RATE_LIMIT = 5
RATE_WINDOW = 60
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

def sanitize_input(text: str, max_length: int = 2000) -> str:
    """Sanitize and truncate user input for safety."""
    text = text.strip()
    if len(text) > max_length:
        logger.warning(f"Input truncated from {len(text)} to {max_length}")
        text = text[:max_length]
    
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
        try:
            return input()
        except EOFError:
            return None

def create_callback(console_obj: Console, use_live_display: bool = False) -> Callable[[str], None]:
    """Factory for agent thought updates - minimal output."""
    def callback(msg: str):
        # Only show important actions and results, skip thinking
        msg_lower = msg.lower()
        
        # Skip thinking/thought messages
        if any(skip in msg_lower for skip in ["step", "thinking", "reasoning", "i will", "i need to", "plan"]):
            return
            
        if use_live_display:
            from live_display import display_in_chat_mode
            if "→" in msg or ":" in msg[:30]:
                display_in_chat_mode(msg, "action")
            elif "success" in msg_lower or "complete" in msg_lower or "done" in msg_lower:
                display_in_chat_mode(msg, "result")
        else:
            # Show only actions and errors, skip verbose thoughts
            if "→" in msg or ":" in msg[:30]:
                console_obj.print(f"[cyan]→ {msg[:100]}[/cyan]")
            elif "error" in msg_lower or "fail" in msg_lower:
                console_obj.print(f"[red] {msg[:100]}[/red]")
    return callback

def select_agent_mode() -> str:
    """Auto-detect mode to save tokens and merge capabilities."""
    return "auto"

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style as PTStyle

def get_bottom_toolbar(target_state: str, mode_state: str):
    """Generate dynamic bottom toolbar matching Gemini CLI style."""
    t_disp = target_state if target_state else "no target"
    # Use spacing to simulate column layout
    return HTML(f' <b>workspace</b> (~/Elengenix)      <b>target</b> ({t_disp})      <b>mode</b> ({mode_state})      <b>status</b> (Ready) ')

def main(mode: str = "auto", target: str = None):
    import os
    
    in_tmux = os.environ.get("TMUX") is not None
    
    console.clear()
    mode = "auto"
    
    if in_tmux:
        console.print(f"[bold cyan]Elengenix Core[/bold cyan] [dim](tmux mode)[/dim]\n")
    else:
        # Show Gemini-style startup banner
        from ui_components import show_main_banner
        show_main_banner()
        console.print("  [dim]Signed in with secure profile[/dim]")
        console.print("  [dim]Plan: Elengenix Professional Edition[/dim]\n\n")
        console.print("                                                                [dim]? for shortcuts[/dim]")
        console.print("[dim]────────────────────────────────────────────────────────────────────────────────[/dim]")
        console.print(" [dim]Shift+Tab to accept edits[/dim]")

    try:
        agent = get_agent()
    except Exception as e:
        logger.error(f"Agent Init Failed: {e}")
        console.print(f"[bold red] Failed to initialize Agent: {e}[/bold red]")
        return

    callback = create_callback(console, use_live_display=in_tmux)

    # Prompt Toolkit Setup
    from prompt_toolkit.completion import Completer, Completion

    class SlashCommandCompleter(Completer):
        def __init__(self, commands):
            self.commands = commands

        def get_completions(self, document, complete_event):
            text = document.text_before_cursor.lstrip()
            if not text.startswith('/'):
                return
                
            word = text.split(' ')[0].lower()
            for cmd in self.commands:
                if cmd.startswith(word):
                    yield Completion(cmd, start_position=-len(word))

    commands = ['/clear', '/quit', '/exit', '/help', '/mode', '/target', '/thinking', '/stats', '/resume', '/compress', '/directory']
    completer = SlashCommandCompleter(commands)
    
    style = PTStyle.from_dict({
        'bottom-toolbar': 'bg:#222222 #aaaaaa',
    })
    from prompt_toolkit.filters import Always
    from prompt_toolkit.key_binding import KeyBindings

    kb = KeyBindings()

    @kb.add('backspace')
    def _(event):
        # Delete character and force completion menu to pop back up
        event.app.current_buffer.delete_before_cursor(count=1)
        event.app.current_buffer.start_completion(select_first=False)

    @kb.add('escape')
    def _(event):
        """Handle ESC to abort current session gracefully."""
        # Raise KeyboardInterrupt to be caught by the outer loop
        raise KeyboardInterrupt

    session = PromptSession(
        completer=completer,
        style=style,
        key_bindings=kb,
        complete_while_typing=Always()
    )

    while True:
        try:
            with patch_stdout():
                raw_input = session.prompt(
                    HTML('\n<b><ansired>Σlengenix</ansired></b> <ansiwhite>❯</ansiwhite> '),
                    bottom_toolbar=lambda: get_bottom_toolbar(target, mode),
                )

            if not raw_input.strip():
                continue

            if raw_input.lower() in ["/exit", "exit", "quit", "/quit"]:
                # Print exit summary like Gemini
                console.print("[dim]▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀[/dim]")
                console.print("╭──────────────────────────────────────────────────────────────────────────────╮")
                console.print("│                                                                              │")
                console.print("│  Agent powering down. Goodbye!                                               │")
                console.print("│                                                                              │")
                console.print("│  Interaction Summary                                                         │")
                console.print("│  Session ID:                 elengenix-auto-session                          │")
                console.print("│                                                                              │")
                console.print("│  To resume this session: elengenix cli --resume                              │")
                console.print("╰──────────────────────────────────────────────────────────────────────────────╯")
                break
                
            if raw_input.lower() == "/clear":
                console.clear()
                show_main_banner()
                continue

            if raw_input.lower() == "/help":
                console.print("\n[bold cyan]Available Commands:[/bold cyan]")
                console.print(" /clear       Clear the screen")
                console.print(" /quit        Exit the cli")
                console.print(" /mode        Switch agent mode")
                console.print(" /target      Set target domain")
                console.print(" /thinking    Toggle AI thinking (enable/disable/auto)")
                console.print(" /help        Show this help")
                if in_tmux:
                    console.print("\n[bold cyan]Tmux Shortcuts:[/bold cyan]")
                    console.print(" Ctrl+B ← - Focus left pane (chat)")
                    console.print(" Ctrl+B → - Focus right pane (logs)")
                continue

            if raw_input.lower() == "/mode":
                console.print("[green]Mode is locked to Auto for maximum efficiency.[/green]")
                continue

            if raw_input.lower().startswith("/target"):
                parts = raw_input.split(" ", 1)
                if len(parts) > 1:
                    target = parts[1].strip()
                    console.print(f"[green]Target set to: {target}[/green]")
                else:
                    target = None
                    console.print("[dim]Target cleared.[/dim]")
                continue

            if raw_input.lower().startswith("/thinking"):
                parts = raw_input.lower().split(" ", 1)
                valid_modes = ["auto", "nemotron", "enable", "disable", "none"]
                if len(parts) > 1 and parts[1].strip() in valid_modes:
                    mode_val = parts[1].strip()
                    os.environ["NVIDIA_PARAM_MODE"] = mode_val
                    
                    # Update .env file as well
                    env_file = Path(".env")
                    if env_file.exists():
                        lines = env_file.read_text(encoding="utf-8").splitlines()
                        updated = False
                        for i, line in enumerate(lines):
                            if line.startswith("NVIDIA_PARAM_MODE="):
                                lines[i] = f"NVIDIA_PARAM_MODE={mode_val}"
                                updated = True
                                break
                        if not updated:
                            lines.append(f"NVIDIA_PARAM_MODE={mode_val}")
                        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    
                    console.print(f"[green]AI Thinking Mode updated to: {mode_val}[/green]")
                else:
                    current = os.getenv("NVIDIA_PARAM_MODE", "auto")
                    console.print(f"\n[bold]Current AI Thinking Mode:[/bold] {current}")
                    console.print("Usage: /thinking <mode>")
                    console.print("Valid modes: enable, disable, auto, nemotron, none")
                continue

            if raw_input.lower().startswith("/memory"):
                from tools.memory_profile import show_memory_summary
                console.print(f"\n[bold magenta]🧠 Personal AI Memory Profile[/bold magenta]")
                summary = show_memory_summary()
                console.print(summary)
                continue
            user_query = sanitize_input(raw_input)
            if not user_query:
                continue

            if not check_rate_limit():
                console.print("[yellow]Rate Limit reached. Please wait a minute.[/yellow]")
                continue

            logger.info(f"Query: {user_query[:100]}...")

            result_container = {"response": None, "error": None}
            def run_agent():
                try:
                    result_container["response"] = agent.process_universal(
                        user_query,
                        callback=callback,
                        target=target,
                        mode="auto",
                    )
                except Exception as ex:
                    result_container["error"] = ex

            with console.status("[cyan]Agent is processing...[/cyan]", spinner="dots"):
                agent_thread = threading.Thread(target=run_agent)
                agent_thread.daemon = True
                agent_thread.start()
                
                # Check for KeyboardInterrupt while waiting
                while agent_thread.is_alive():
                    agent_thread.join(timeout=1.0)

            if result_container["error"]:
                raise result_container["error"]

            response = result_container["response"]
            logger.info(f"Agent finished query successfully.")

            console.print("\n[dim]────────────────────────────────────────────────────────────────────────────────[/dim]")
            console.print(Markdown(response if response else "No response from agent."))
            console.print("[dim]────────────────────────────────────────────────────────────────────────────────[/dim]\n")

        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted by user. Type /quit to exit.[/dim]")
        except EOFError:
            break
        except Exception as e:
            logger.error(f"Unexpected CLI error: {e}")
            error_msg = str(e).lower()
            if "api key" in error_msg or "provider" in error_msg:
                console.print(f"\n[bold yellow]⚠ AI Provider Issue:[/bold yellow] Please check your API keys or quota.\n[dim]Details: {str(e)[:150]}[/dim]")
            elif "quota" in error_msg or "rate limit" in error_msg:
                console.print(f"\n[bold yellow]⚠ Quota Exceeded:[/bold yellow] You may have reached your AI usage limits.\n[dim]Details: {str(e)[:150]}[/dim]")
            else:
                console.print(f"\n[bold yellow]⚠ Notice:[/bold yellow] {str(e)[:150]}")

if __name__ == "__main__":
    main()
