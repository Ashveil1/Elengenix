"""
tools/doctor.py — System Health Check & Auto-Repair (v2.0.0)
- Checks Python version, config, all security tools
- Checks AI provider connectivity
- Auto-repair mode: installs missing tools via setup.sh hint
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import yaml
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger("elengenix.doctor")

SECURITY_TOOLS: List[str] = [
    "subfinder", "nuclei", "httpx", "katana",
    "waybackurls", "nmap", "ffuf", "gau",
    "naabu", "arjun", "dalfox", "trufflehog"
]

PYTHON_MIN = (3, 10)


def _check_python() -> Tuple[bool, str]:
    v = sys.version_info
    ok = (v.major, v.minor) >= PYTHON_MIN
    return ok, f"{v.major}.{v.minor}.{v.micro}"


def _check_config() -> Tuple[bool, str]:
    """Validate configuration: checks config.yaml, .env file, and environment variables."""
    config_path = Path("config.yaml")
    if not config_path.exists():
        return False, "config.yaml not found"
    try:
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f)
        if not cfg or "ai" not in cfg:
            return False, "config.yaml missing 'ai' section"
        provider = cfg["ai"].get("active_provider", "")

        # Priority check: ENV var > .env file > config.yaml
        env_key_name = f"{provider.upper()}_API_KEY"
        api_key = os.getenv(env_key_name, "")

        # Fallback: check .env file directly if env var is empty
        if not api_key:
            env_path = Path(".env")
            if env_path.exists():
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith(f"{env_key_name}="):
                        api_key = line.split("=", 1)[1].strip()
                        break

        # Fallback: check config.yaml (not recommended, but supported)
        if not api_key:
            api_key = cfg["ai"].get("providers", {}).get(provider, {}).get("api_key", "")

        if not api_key or "YOUR" in str(api_key).upper() or api_key.startswith("sk-..."):
            return False, (
                f"API key for '{provider}' not set. "
                f"Set {env_key_name} in .env or as an environment variable"
            )
        return True, f"OK (provider: {provider})"
    except Exception as e:
        return False, f"Parse error: {e}"


def _check_tool(tool: str) -> Tuple[bool, str]:
    path = shutil.which(tool)
    if path:
        return True, path
    return False, "Not found"


def check_health(interactive: bool = True) -> bool:
    """
    Full system health check.
    If interactive=True, prompts the user to fix issues dynamically.
    Returns True if system is healthy.
    """
    from ui_components import console, print_error, print_success, print_warning, confirm
    import questionary
    
    console.print("\n[bold red]System Health Check[/bold red] [dim]v2.0.0[/dim]\n")
    all_ok = True

    # ── Python Version ─────────────────────────────────────────────────────────
    py_ok, py_ver = _check_python()
    console.print("[bold red]Python Runtime[/bold red]")
    status = "[bold white]OK[/bold white]" if py_ok else "[bold red]FAIL[/bold red]"
    detail = py_ver + (f" (need >={PYTHON_MIN[0]}.{PYTHON_MIN[1]})" if not py_ok else "")
    console.print(f"  Version: {status} {detail}")
    if not py_ok:
        all_ok = False
    console.print()

    # ── Config ─────────────────────────────────────────────────────────────────
    cfg_ok, cfg_msg = _check_config()
    console.print("[bold red]Configuration[/bold red]")
    status = "[bold white]OK[/bold white]" if cfg_ok else "[bold red]FAIL[/bold red]"
    console.print(f"  config.yaml: {status} {cfg_msg}")
    if not cfg_ok:
        all_ok = False
        if interactive and confirm("API Keys not configured. Run configuration wizard now?", default=True):
            console.print("\n[grey70]Launching Configuration Wizard...[/grey70]")
            try:
                import wizard
                wizard.main()
                # Re-check config after wizard
                cfg_ok, cfg_msg = _check_config()
                if cfg_ok:
                    all_ok = True
                    console.print(f"  [bold white]New config:[/bold white] {cfg_msg}")
            except Exception as e:
                logger.error(f"Wizard failed: {e}")
    console.print()

    # ── Security Tools ─────────────────────────────────────────────────────────
    console.print("[bold red]Security Tools[/bold red]")
    
    missing: List[str] = []
    for tool in SECURITY_TOOLS:
        ok, info = _check_tool(tool)
        status = "[bold white]OK[/bold white]" if ok else "[bold red]Missing[/bold red]"
        console.print(f"  {tool}: {status}")
        if not ok:
            missing.append(tool)
            all_ok = False
    console.print()

    if missing:
        print_error(f"Missing tools: {', '.join(missing)}")
        if interactive:
            try:
                while True:
                    choice = questionary.select(
                        "Missing security tools detected. What would you like to do?",
                        choices=[
                            "Install ALL missing tools (Recommended)",
                            "Select specific tools to install",
                            "Skip for now"
                        ]
                    ).ask()
                    
                    if choice == "Install ALL missing tools (Recommended)":
                        import dependency_manager
                        dependency_manager.check_and_install_dependencies()
                        break
                    elif choice == "Select specific tools to install":
                        selected = questionary.checkbox(
                            "Select tools to install (Press Space to select, Enter to confirm):",
                            choices=missing
                        ).ask()
                        if not selected:
                            console.print("[grey70]No tools selected. Returning to menu...[/grey70]")
                            continue  # Loop back to the main menu
                        
                        import dependency_manager
                        for tool in selected:
                            if tool in dependency_manager.TOOLS:
                                console.print(f"[*] Installing {tool}...")
                                dependency_manager.run_with_streaming(dependency_manager.TOOLS[tool])
                        break
                    else:
                        console.print("[dim]Skipping tool installation.[/dim]")
                        break
            except ImportError:
                print_warning("questionary module missing. Run setup.sh to install core dependencies.")
            except Exception as e:
                logger.error(f"Error during tool installation prompt: {e}")

    # ── Final Verdict ──────────────────────────────────────────────────────────
    console.print()
    if all_ok:
        print_success("System is healthy and ready for use")
    else:
        print_warning("System still has some unresolved issues. Run 'elengenix doctor' again later.")
    console.print()

    return all_ok


if __name__ == "__main__":
    import sys
    import os
    # Ensure the root directory is in sys.path so we can import root modules like ui_components
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    check_health(interactive="--no-interactive" not in sys.argv)
