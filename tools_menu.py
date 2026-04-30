"""
tools_menu.py — Elengenix Production-Hardened Arsenal Menu (v1.5.0)
- Secure Subprocess Management (shell=False)
- Strict Target Validation and Sanitization
- Rich-Optimized Interactive CLI
- Timeout and Signal Awareness
"""

import sys
import os
import subprocess
import logging
import re
from pathlib import Path
from typing import List, Dict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Import shared UI utilities (used by _run_tool and show_tools_menu)
from ui_components import print_error, print_warning, console as ui_console

# ── Setup ───────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("elengenix.arsenal")
console = ui_console

# ── Security Configuration ───────────────────────────────────
FORBIDDEN_CHARS = set(";|&`$()><\\'\" \t\n\r")

def _validate_target(target: str) -> bool:
    """Rigorous domain/IP validation to prevent injection."""
    if not target or not target.strip(): return False
    target = target.strip()
    
    if any(c in target for c in FORBIDDEN_CHARS) or ".." in target:
        return False
    
    if len(target) > 253: return False
    
    domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    
    return bool(re.match(domain_pattern, target) or re.match(ip_pattern, target))

# ── Tool Registry ─────────────────────────────────────────────
TOOLS: List[Dict[str, str]] = [
    {"name": "OMNI-SCAN (Full Chaos)", "file": "omni_scan.py", "desc": "End-to-end hunting: Dorking -> Recon -> API -> Nuclei"},
    {"name": "Recon & Discovery", "file": "base_recon.py", "desc": "Subdomain enumeration + HTTP probes (Subfinder/httpx)"},
    {"name": "Vulnerability Scanner", "file": "base_scanner.py", "desc": "Targeted Nuclei scan with custom templates"},
    {"name": "API Hunter", "file": "api_finder.py", "desc": "Discover Swagger, OpenAPI, and hidden API routes"},
    {"name": "JS Secrets Analyzer", "file": "js_analyzer.py", "desc": "Extract tokens and paths from JS files"},
    {"name": "Hidden Param Miner", "file": "param_miner.py", "desc": "Fuzz URL parameters for hidden vulnerabilities"},
    {"name": "Smart Google Dorking", "file": "dork_miner.py", "desc": "Search for exposed files and logs via Google"},
    {"name": "AI Web Research", "file": "research_tool.py", "desc": "Autonomous technical research on specific vectors"},
]

def _run_tool(tool_file: str, target: str) -> int:
    """Executes a tool securely with isolation and timeout."""
    # Robust Path Resolution
    base_dir = Path(__file__).parent.absolute()
    script_path = base_dir / "tools" / tool_file

    if not script_path.is_file():
        print_error(f"Tool missing: {script_path.relative_to(base_dir.parent)}")
        return 1

    try:
        from ui_components import console
        console.print(f"[dim]Running with 10min timeout. Press Ctrl+C to cancel.[/dim]\n")
        
        # Use current sys.executable to maintain virtual environment
        result = subprocess.run(
            [sys.executable, str(script_path), target],
            shell=False,
            check=False,
            timeout=600,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        return result.returncode
        
    except subprocess.TimeoutExpired:
        print_error("Process timed out after 10 minutes")
        return 124
    except KeyboardInterrupt:
        console.print("\n[dim]Operation suspended by user[/dim]")
        return 130
    except Exception as e:
        logger.error(f"Execution Error ({tool_file}): {e}")
        return 1

def show_tools_menu():
    """Main Interactive Arsenal Loop."""
    from ui_components import show_arsenal_banner, create_tools_table, prompt_target, print_error, console
    
    while True:
        console.clear()
        show_arsenal_banner()

        table = create_tools_table(TOOLS)
        console.print(table)
        console.print("\n[dim]Enter 0 to return to Main Menu[/dim]")

        try:
            choice = input("Select Vector [0-{}]: ".format(len(TOOLS))).strip()
            if choice == "0": return
            if not choice.isdigit() or not (1 <= int(choice) <= len(TOOLS)):
                console.print("[red] Invalid selection.[/red]\n")
                continue

            selected = TOOLS[int(choice) - 1]
            console.print(f"\n[bold red]{selected['name']}[/bold red]")
            target = prompt_target()
            
            if not _validate_target(target):
                print_error("Security Violation: Target format not allowed")
                console.input("\n[dim]Press Enter to continue...[/dim]")
                continue

            console.print(f"\n[red]Deploying {selected['name']} on {target}...[/red]\n")
            _run_tool(selected["file"], target)
            
            from ui_components import confirm
            if not confirm("\nRun another mission?", default=True):
                break

        except (KeyboardInterrupt, EOFError):
            break

if __name__ == "__main__":
    show_tools_menu()
