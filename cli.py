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
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*google.generativeai.*")
from pathlib import Path
from typing import List, Optional
from collections import deque
from typing import Optional, Callable

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from agent import get_agent
from bot_utils import send_telegram_notification
from ui_components import console, show_main_banner

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

# Rate Limiting Configuration 
RATE_LIMIT = 5
RATE_WINDOW = 60
user_requests = deque()

def check_rate_limit() -> bool:
    """Returns True if within global limit for human inputs."""
    import os
    rate_limit = int(os.getenv("ELENGENIX_RATE_LIMIT", "40"))
    rate_window = 60
    
    now = time.time()
    while user_requests and user_requests[0] < now - rate_window:
        user_requests.popleft()
    if len(user_requests) >= rate_limit:
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

def get_bottom_toolbar(target_state: str, mode_state: str, model_name: str = "default", thinking_on: bool = False):
    """Generate dynamic bottom toolbar with status indicators."""
    t_disp = target_state if target_state else "no target"
    
    # Status indicators
    research_status = "ON" if mode_state == "research" else "off"
    mode_display = "scan" if mode_state == "scan" else "normal"  # Show scan or normal
    think_status = "ON" if thinking_on else "off"
    
    # Team/Model display
    active_models = os.environ.get("ACTIVE_MODELS", "").split(",")
    active_models = [m.strip() for m in active_models if m.strip()]
    active_provider = os.environ.get("ACTIVE_AI_PROVIDER", "")
    
    if len(active_models) >= 2:
        model_display = f"team({len(active_models)})"
    elif active_provider:
        model_display = active_provider
    elif model_name != "default":
        model_display = model_name
    else:
        model_display = "model"
    
    # Use prompt_toolkit HTML format
    return HTML(
        f' <b>workspace</b> (~/Elengenix)    '
        f'<b>target</b> ({t_disp})    '
        f'<b>ctrl+r</b>:research[<b>{research_status}</b>]    '
        f'<b>ctrl+m</b>:<b>{mode_display}</b>    '
        f'<b>ctrl+t</b>:think[<b>{think_status}</b>]    '
        f'<b>ctrl+p</b>:<b>{model_display}</b>    '
        f'<b>status</b> (Ready)'
    )


def show_mode_selector(console: Console) -> str:
    """Interactive mode selector menu."""
    modes = [
        ("auto", "Auto-detect (AI chooses mode)", "AI automatically classifies your intent"),
        ("research", "Research Mode", "Web search for current information, news, sports"),
        ("security_chat", "Security Chat", "Ask security questions, get expert advice"),
        ("scan", "Scan Mode", "Active security testing with tools (requires target)"),
        ("casual", "Casual Chat", "General conversation, greetings, chit-chat"),
    ]
    
    print("\n========== Mode Selector ==========")
    for i, (key, name, desc) in enumerate(modes, 1):
        print(f"  {i}. {name:<20} - {desc}")
    print("  0. Cancel (or just press Enter)")
    print("====================================")
    
    try:
        choice = input("Select (0-5): ").strip()
        if not choice:  # Empty = cancel
            print("Cancelled.")
            return None
        if choice.isdigit():
            idx = int(choice)
            if idx == 0:
                print("Cancelled.")
                return None
            if 1 <= idx <= len(modes):
                selected = modes[idx-1][0]
                print(f"Selected: {selected}")
                return selected
        print("Invalid choice.")
    except (EOFError, KeyboardInterrupt):
        print("Cancelled.")
    return None


def show_model_selector(console: Console, manager) -> Optional[tuple[str, List[str]]]:
    """Advanced interactive model selector with ultra-stable overlay feel."""
    import questionary
    
    def print_centered_box(title: str, subtitle: str, width: int = 60):
        """Stable centered box using string manipulation (no complex ANSI)."""
        import os
        os.system('clear' if os.name == 'posix' else 'cls')
        
        terminal_width = 80
        padding = (terminal_width - width) // 2
        pad_str = " " * padding
        
        # Draw Box with pure text (avoids terminal proxy color glitches)
        print("\n" * 2)
        print(f"{pad_str}╭─{'─' * (width-4)}─╮")
        print(f"{pad_str}│ {title.center(width-4)} │")
        print(f"{pad_str}╰─{'─' * (width-4)}─╯")
        print(f"{pad_str}  {subtitle.center(width-4)}  ")
        print("\n")

    try:
        import os
        
        # Load current team from environment
        active_models_str = os.environ.get("ACTIVE_MODELS", "")
        current_team = []
        for m in active_models_str.split(","):
            m = m.strip()
            if m:
                if "/" in m:
                    prov, mod = m.split("/", 1)
                    current_team.append({"provider": prov, "model": mod})
                else:
                    # Legacy fallback
                    prov = os.environ.get("ACTIVE_AI_PROVIDER", "auto")
                    current_team.append({"provider": prov, "model": m})
        
        # Pad to 3
        while len(current_team) < 3:
            current_team.append(None)
        
        roles = ["Strategist", "Recon Lead", "Exploit Analyst"]
        
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            print_centered_box("TEAM AEGIS BUILDER", "Build your multi-agent security team")
            
            print("  Current Team Roster:")
            for i in range(3):
                agent = current_team[i]
                if agent:
                    print(f"  [{i+1}] {roles[i]:<15}: {agent['provider'].upper()} / {agent['model']}")
                else:
                    print(f"  [{i+1}] {roles[i]:<15}: (Empty)")
            print("")
            
            # Build menu options
            options = []
            for i in range(3):
                options.append(f"Assign Agent {i+1} ({roles[i]})")
            
            options.append(questionary.Separator())
            options.append("Remove an Agent")
            options.append("Done / Save Team")
            options.append("Cancel")
            
            choice = questionary.select(
                "    Options:",
                choices=options,
                style=questionary.Style([
                    ('qmark', 'fg:#ff0000 bold'),
                    ('pointer', 'fg:#ff0000 bold'),
                    ('highlighted', 'fg:#ffffff bg:#880000 bold'),
                    ('selected', 'fg:#ff0000'),
                ])
            ).ask()
            
            if choice == "Cancel" or not choice:
                return None
                
            if choice == "Done / Save Team":
                # Filter out empty slots
                final_team = [agent for agent in current_team if agent]
                if not final_team:
                    print("  Cannot save an empty team.")
                    time.sleep(1)
                    continue
                return final_team
                
            if choice == "Remove an Agent":
                remove_choices = []
                for i in range(3):
                    if current_team[i]:
                        remove_choices.append(f"Agent {i+1} ({current_team[i]['model']})")
                
                if not remove_choices:
                    print("  No agents to remove.")
                    time.sleep(1)
                    continue
                    
                remove_choices.append("Back")
                to_remove = questionary.select("Select agent to remove:", choices=remove_choices).ask()
                
                if to_remove and to_remove != "Back":
                    idx = int(to_remove.split(" ")[1]) - 1
                    current_team[idx] = None
                continue
                
            if choice.startswith("Assign Agent"):
                agent_idx = int(choice.split(" ")[2]) - 1
                
                # Step 1: Select Provider
                providers_status = manager.get_all_providers_status()
                provider_choices = []
                for p in providers_status:
                    status_label = " [ACTIVE]" if p["active"] else " [READY]" if p["available"] else " [KEY MISSING]"
                    provider_choices.append({"name": f"{p['provider'].upper():<12} {status_label}", "value": p["provider"]})
                
                provider_choices.append(questionary.Separator())
                provider_choices.append({"name": "Back", "value": None})
                
                selected_provider = questionary.select("    Choose Provider:", choices=provider_choices).ask()
                if not selected_provider:
                    continue
                    
                # Step 2: Select Model
                client = manager.clients.get(selected_provider)
                if not client:
                    from tools.universal_ai_client import UniversalAIClient
                    client = UniversalAIClient(provider=selected_provider)
                    if not client.is_available():
                        print(f"\n  Error: {selected_provider} API key missing!")
                        time.sleep(2)
                        continue
                
                print(f"\n  Fetching models for {selected_provider}...")
                available_models = client.fetch_available_models()
                if not available_models:
                    available_models = [client.model]
                
                selected_model = questionary.select(
                    f"    Choose Model for Agent {agent_idx+1}:", 
                    choices=available_models
                ).ask()
                
                if not selected_model:
                    continue
                    
                # Step 3: Set RPM
                env_key = f"RPM_{selected_provider.upper()}_{selected_model.upper()}"
                current_rpm = os.environ.get(env_key, "40")
                rpm_input = questionary.text(
                    f"    Set RPM for {selected_model} (Current: {current_rpm}):",
                    default=current_rpm
                ).ask()
                
                try:
                    rpm_val = int(rpm_input) if rpm_input else int(current_rpm)
                except ValueError:
                    rpm_val = 40
                
                # Update team
                current_team[agent_idx] = {
                    "provider": selected_provider,
                    "model": selected_model,
                    "rpm": str(rpm_val)
                }

    except (EOFError, KeyboardInterrupt):
        return None
    except Exception as e:
        print(f"  Team Builder Error: {e}")
        time.sleep(2)
        return None


def show_help_panel(console: Console):
    """Show keyboard shortcuts help panel."""
    print("\n┌─ Keyboard Shortcuts ────────────────────────────────────┐")
    print("│  Ctrl+R  - Toggle Research mode [ON/off] (forces web search)")
    print("│  Ctrl+B  - Toggle Scan mode [on/OFF] (security testing)")
    print("│  Ctrl+T  - Toggle Thinking mode [on/OFF] (show AI reasoning)")
    print("│  Ctrl+P  - Open model selector (Gemini models)")
    print("│  Ctrl+G  - Show this help panel")
    print("│  Escape  - Cancel current operation")
    print("│  ?       - Show slash commands")
    print("│  /quit   - Exit Elengenix")
    print("│  /help   - Show available commands")
    print("└─────────────────────────────────────────────────────────┘")

def main(mode: str = "auto", target: str = None):
    import os
    
    in_tmux = os.environ.get("TMUX") is not None
    
    console.clear()
    mode = "auto"
    
    if in_tmux:
        console.print(f"[bold cyan]Elengenix Core[/bold cyan] [dim](tmux mode)[/dim]\n")
    else:
        # Spacing for clean start (Banner already shown by main.py)
        console.print("  [dim]Signed in with secure profile[/dim]")
        console.print("  [dim]Plan: Elengenix Professional Edition[/dim]")
        print("         ctrl+r:research[ON/off]  ctrl+b:mode[on/OFF]  ctrl+t:think[on/OFF]  ctrl+p:model")
        print("────────────────────────────────────────────────────────────────────────────────")
        print(" Shift+Tab to accept edits")

    try:
        agent = get_agent()
    except Exception as e:
        logger.error(f"Agent Init Failed: {e}")
        console.print(f"[bold red] Failed to initialize Agent: {e}[/bold red]")
        return

    # Silence verbose tool/discovery logs during startup for a cleaner UI
    logging.getLogger("elengenix.agent").setLevel(logging.WARNING)
    logging.getLogger("elengenix.brain").setLevel(logging.WARNING)
    
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
    
    # State variables for mode, model, and thinking (using mutable containers for cross-scope access)
    mode_state = [mode]  # Index 0 holds current mode
    model_state = ["default"]  # Index 0 holds current model
    thinking_state = [False]  # Index 0 holds thinking mode ON/OFF
    mode_changed = [False]
    model_changed = [False]

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
    
    @kb.add('c-r')  # Ctrl+R = Toggle Research Mode ON/OFF
    def _(event):
        """Toggle research mode (forces web search for queries)."""
        event.app.exit()
        if mode_state[0] == "research":
            mode_state[0] = "auto"
            print("→ Research mode: OFF (auto-detect)")
        else:
            mode_state[0] = "research"
            print("→ Research mode: ON (forces web search)")
        mode_changed[0] = True
    
    @kb.add('c-b')  # Ctrl+B = Toggle Scan <-> Normal
    def _(event):
        """Toggle between Scan mode and Normal mode."""
        event.app.exit()
        if mode_state[0] == "scan":
            mode_state[0] = "auto"  # Normal = auto/casual/security_chat combined
            print("→ Mode: NORMAL (chat + security advice)")
        else:
            mode_state[0] = "scan"
            print("→ Mode: SCAN (security testing)")
        mode_changed[0] = True
    
    @kb.add('c-t')  # Ctrl+T = Toggle Thinking Mode ON/OFF
    def _(event):
        """Toggle AI thinking mode (shows reasoning)."""
        event.app.exit()
        import os
        current = os.environ.get("NVIDIA_PARAM_MODE", "auto")
        if current in ["enable", "nemotron"]:
            os.environ["NVIDIA_PARAM_MODE"] = "disable"
            thinking_state[0] = False
            print("→ Thinking mode: OFF")
        else:
            os.environ["NVIDIA_PARAM_MODE"] = "enable"
            thinking_state[0] = True
            print("→ Thinking mode: ON")
    
    @kb.add('c-p')  # Ctrl+P for Model selector  
    def _(event):
        """Open model selector menu using run_in_terminal for stability."""
        from prompt_toolkit.application import run_in_terminal
        
        def run_selector():
            result = show_model_selector(console, agent.client)
            if result:
                final_team = result
                
                # The primary model (Strategist) is always the first one
                primary = final_team[0]
                provider_name = primary["provider"]
                model_name = primary["model"]
                
                # Dynamically update the backend agent client
                if provider_name in agent.client.clients:
                    agent.client.active_client = agent.client.clients[provider_name]
                    agent.client.active_client.model = model_name
                else:
                    from tools.universal_ai_client import UniversalAIClient
                    new_client = UniversalAIClient(provider=provider_name, model=model_name)
                    agent.client.clients[provider_name] = new_client
                    agent.client.active_client = new_client
                
                # Store primary model as string, but keep list in state if needed
                model_state[0] = model_name
                
                # Build the cross-provider ACTIVE_MODELS string
                models_str = []
                for agent_dict in final_team:
                    models_str.append(f"{agent_dict['provider']}/{agent_dict['model']}")
                
                os.environ["ACTIVE_AI_PROVIDER"] = provider_name
                os.environ["ACTIVE_MODELS"] = ",".join(models_str)
                model_changed[0] = True
                
                # Save RPMs and ACTIVE_MODELS to .env
                from tools.config_wizard import ConfigWizard
                wizard = ConfigWizard()
                wizard._save_env_var("ACTIVE_AI_PROVIDER", provider_name)
                wizard._save_env_var("ACTIVE_MODELS", os.environ["ACTIVE_MODELS"])
                
                for agent_dict in final_team:
                    env_key = f"RPM_{agent_dict['provider'].upper()}_{agent_dict['model'].upper()}"
                    rpm_val = agent_dict["rpm"]
                    os.environ[env_key] = rpm_val
                    wizard._save_env_var(env_key, rpm_val)
                
                print(f"→ Team Aegis configuration saved!")
                print(f"→ Team size: {len(final_team)} agents")
                for i, agent_dict in enumerate(final_team):
                    print(f"  [{i+1}] {agent_dict['provider'].upper()} / {agent_dict['model']} ({agent_dict['rpm']} RPM)")
            
            # Return cleanly to the prompt without redrawing the massive banner

        run_in_terminal(run_selector)
    
    @kb.add('c-g')  # Ctrl+G for Help
    def _(event):
        """Show help panel."""
        event.app.exit()
        show_help_panel(console)

    session = PromptSession(
        completer=completer,
        style=style,
        key_bindings=kb,
        complete_while_typing=Always()
    )

    while True:
        # Reset change flags
        mode_changed[0] = False
        model_changed[0] = False
        
        try:
            # Sticky Bottom Toolbar using prompt_toolkit
            toolbar_html = get_bottom_toolbar(target, mode_state[0], model_state[0], thinking_state[0])
            
            with patch_stdout():
                raw_input = session.prompt(
                    HTML('<ansired>Σlengenix</ansired> <ansigray>❯</ansigray> '),
                    bottom_toolbar=toolbar_html,
                    style=style,
                )
            
            if raw_input is None:
                continue
            
            raw_input = raw_input.strip()
            
            if not raw_input:
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
                print("\nAvailable Commands:")
                print(" /clear       Clear the screen")
                print(" /quit        Exit the cli")
                print(" /mode        Switch agent mode")
                print(" /target      Set target domain")
                print(" /thinking    Toggle AI thinking (enable/disable/auto)")
                print(" /help        Show this help")
                print("\nKeyboard Shortcuts:")
                print(" Ctrl+R       Toggle Research [ON/off] - forces web search")
                print(" Ctrl+B       Toggle Scan [on/OFF] - security testing")
                print(" Ctrl+T       Toggle Thinking [on/OFF] - show AI reasoning")
                print(" Ctrl+P       Open model selector (Gemini models)")
                print(" Ctrl+G       Show keyboard shortcuts help")
                print(" Escape       Cancel current operation")
                if in_tmux:
                    print("\nTmux Shortcuts:")
                    print(" Ctrl+B ← - Focus left pane (chat)")
                    print(" Ctrl+B → - Focus right pane (logs)")
                continue

            if raw_input.lower() == "/mode":
                selected = show_mode_selector(console)
                if selected:
                    mode_state[0] = selected
                    print(f"Mode set to: {selected}")
                continue

            if raw_input.lower().startswith("/target"):
                parts = raw_input.split(" ", 1)
                if len(parts) > 1:
                    target = parts[1].strip()
                    print(f"Target set to: {target}")
                else:
                    target = None
                    print("Target cleared.")
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
                    
                    print(f"AI Thinking Mode updated to: {mode_val}")
                else:
                    current = os.getenv("NVIDIA_PARAM_MODE", "auto")
                    print(f"\nCurrent AI Thinking Mode: {current}")
                    print("Usage: /thinking <mode>")
                    print("Valid modes: enable, disable, auto, nemotron, none")
                continue

            if raw_input.lower().startswith("/memory"):
                from tools.memory_profile import show_memory_summary
                print("\nPersonal AI Memory Profile")
                summary = show_memory_summary()
                print(summary)
                continue
            user_query = sanitize_input(raw_input)
            if not user_query:
                continue

            if not check_rate_limit():
                print("Rate Limit reached. Please wait a minute.")
                continue

            logger.info(f"Query: {user_query[:100]}...")

            try:
                result_container = {"response": None, "error": None}
                def run_agent():
                    try:
                        # Check for Team Aegis (multi-agent) mode
                        active_models = os.environ.get("ACTIVE_MODELS", "").split(",")
                        active_models = [m.strip() for m in active_models if m.strip()]
                        
                        if len(active_models) >= 2 and target and mode_state[0] in ("scan", "bug_bounty"):
                            # Team Aegis: Multi-agent collaboration
                            print("Team Aegis engaged! Multiple agents collaborating...")
                            result_container["response"] = agent.process_team_scan(
                                user_query,
                                model_names=active_models,
                                target=target,
                                callback=callback,
                            )
                        else:
                            result_container["response"] = agent.process_universal(
                                user_query,
                                callback=callback,
                                target=target,
                                mode=mode_state[0],
                            )
                    except Exception as ex:
                        import traceback
                        traceback.print_exc()
                        result_container["error"] = ex

                print("Agent is thinking...")
                agent_thread = threading.Thread(target=run_agent)
                agent_thread.daemon = True
                agent_thread.start()
                
                # Check for ESC or Ctrl+C while waiting
                try:
                    import select
                    while agent_thread.is_alive():
                        # Non-blocking check for ESC key (hex 1b)
                        if sys.platform != "win32":
                            dr, dw, de = select.select([sys.stdin], [], [], 0.1)
                            if dr:
                                char = sys.stdin.read(1)
                                if char == '\x1b': # ESC
                                    console.print("\n[dim]→ Thinking stopped by ESC.[/dim]")
                                    break
                        else:
                            agent_thread.join(timeout=0.1)
                except KeyboardInterrupt:
                    console.print("\n[dim]→ Thinking aborted by user.[/dim]")
                    # Continue to prompt
                
                # If thread is still alive, we interrupted the wait
                if agent_thread.is_alive():
                    continue

                if result_container["error"]:
                    print(f"Error: {result_container['error']}")
                    continue

                response = result_container["response"]
                if not response:
                    print("No response from agent (API key issue?)")
                    continue
                    
                logger.info(f"Agent finished query successfully.")
                print("-" * 80)
                print(response)
                print("-" * 80)
            except Exception as e:
                import traceback
                traceback.print_exc()

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
