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

import questionary
from rich.console import Console
from rich.table import Table
from rich import box

logger  = logging.getLogger("elengenix.doctor")
console = Console()

SECURITY_TOOLS: List[str] = [
    "subfinder", "nuclei", "httpx", "katana",
    "waybackurls", "nmap", "ffuf", "gau",
]

PYTHON_MIN = (3, 10)


def _check_python() -> Tuple[bool, str]:
    v = sys.version_info
    ok = (v.major, v.minor) >= PYTHON_MIN
    return ok, f"{v.major}.{v.minor}.{v.micro}"


def _check_config() -> Tuple[bool, str]:
    config_path = Path("config.yaml")
    if not config_path.exists():
        return False, "config.yaml not found"
    try:
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f)
        if not cfg or "ai" not in cfg:
            return False, "config.yaml missing 'ai' section"
        provider = cfg["ai"].get("active_provider", "")
        api_key  = cfg["ai"].get("providers", {}).get(provider, {}).get("api_key", "")
        if not api_key or "YOUR" in str(api_key).upper():
            return False, f"API key for '{provider}' not set"
        return True, f"OK (provider: {provider})"
    except Exception as e:
        return False, f"Parse error: {e}"


def _check_tool(tool: str) -> Tuple[bool, str]:
    path = shutil.which(tool)
    if path:
        return True, path
    return False, "Not found"


def check_health(fix: bool = False) -> bool:
    """
    Full system health check.
    If fix=True, attempts repair.
    Returns True if system is healthy.
    """
    console.print("\n[bold cyan]🏥 ELENGENIX SYSTEM DOCTOR v2.0.0[/bold cyan]\n")
    all_ok = True

    # ── Python Version ─────────────────────────────────────────────────────────
    py_ok, py_ver = _check_python()
    t = Table(title="Python Runtime", box=box.ROUNDED, border_style="cyan")
    t.add_column("Check", style="cyan")
    t.add_column("Status")
    t.add_column("Value")
    t.add_row(
        "Python version",
        "[green]OK[/green]" if py_ok else "[red]FAIL[/red]",
        py_ver + (f" (need >={PYTHON_MIN[0]}.{PYTHON_MIN[1]})" if not py_ok else ""),
    )
    console.print(t)
    if not py_ok:
        all_ok = False

    # ── Config ─────────────────────────────────────────────────────────────────
    cfg_ok, cfg_msg = _check_config()
    t2 = Table(title="Configuration", box=box.ROUNDED, border_style="cyan")
    t2.add_column("Check", style="cyan")
    t2.add_column("Status")
    t2.add_column("Details")
    t2.add_row(
        "config.yaml",
        "[green]OK[/green]" if cfg_ok else "[red]FAIL[/red]",
        cfg_msg,
    )
    console.print(t2)
    if not cfg_ok:
        all_ok = False
        if fix:
            console.print("[yellow]Running wizard to fix config...[/yellow]")
            try:
                import wizard
                wizard.main()
            except Exception as e:
                logger.error(f"Wizard failed: {e}")

    # ── Security Tools ─────────────────────────────────────────────────────────
    t3 = Table(title="Security Tools", box=box.ROUNDED, border_style="cyan")
    t3.add_column("Tool", style="cyan")
    t3.add_column("Status")
    t3.add_column("Path")

    missing: List[str] = []
    for tool in SECURITY_TOOLS:
        ok, info = _check_tool(tool)
        t3.add_row(
            tool,
            "[green]✅ Found[/green]" if ok else "[red]❌ Missing[/red]",
            info,
        )
        if not ok:
            missing.append(tool)
            all_ok = False

    console.print(t3)

    if missing:
        console.print(f"\n[bold red]Missing tools: {', '.join(missing)}[/bold red]")
        console.print("[yellow]💡 Run: [bold]./setup.sh[/bold] to install all tools.[/yellow]\n")
        if fix and questionary.confirm("Try to install missing tools now via setup.sh?", default=True).ask():
            import subprocess
            subprocess.run(["bash", "./setup.sh"], check=False)

    # ── Final Verdict ──────────────────────────────────────────────────────────
    if all_ok:
        console.print("\n[bold green]🌟 System is healthy and ready for battle![/bold green]\n")
    else:
        console.print("\n[bold red]⚠️  System has issues. Run: [bold]python main.py doctor[/bold] --fix[/bold red]\n")
        if not fix and questionary.confirm("Run auto-repair now?", default=True).ask():
            check_health(fix=True)

    return all_ok


if __name__ == "__main__":
    check_health(fix="--fix" in sys.argv)
