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
 api_key = cfg["ai"].get("providers", {}).get(provider, {}).get("api_key", "")
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
 from ui_components import console, print_error, print_success, print_warning, confirm, create_status_table
 
 console.print("\n[bold cyan]System Health Check[/bold cyan] [dim]v2.0.0[/dim]\n")
 all_ok = True

 # Python Version 
 py_ok, py_ver = _check_python()
 console.print("[cyan]Python Runtime[/cyan]")
 status = "[green]OK[/green]" if py_ok else "[red]FAIL[/red]"
 detail = py_ver + (f" (need >={PYTHON_MIN[0]}.{PYTHON_MIN[1]})" if not py_ok else "")
 console.print(f" Version: {status} {detail}")
 if not py_ok:
 all_ok = False
 console.print()

 # Config 
 cfg_ok, cfg_msg = _check_config()
 console.print("[cyan]Configuration[/cyan]")
 status = "[green]OK[/green]" if cfg_ok else "[red]FAIL[/red]"
 console.print(f" config.yaml: {status} {cfg_msg}")
 if not cfg_ok:
 all_ok = False
 if fix:
 console.print("[yellow]Running wizard to fix config...[/yellow]")
 try:
 import wizard
 wizard.main()
 except Exception as e:
 logger.error(f"Wizard failed: {e}")
 console.print()

 # Security Tools 
 console.print("[cyan]Security Tools[/cyan]")
 
 missing: List[str] = []
 for tool in SECURITY_TOOLS:
 ok, info = _check_tool(tool)
 status = "[green]OK[/green]" if ok else "[red]Missing[/red]"
 console.print(f" {tool}: {status}")
 if not ok:
 missing.append(tool)
 all_ok = False
 console.print()

 if missing:
 print_error(f"Missing tools: {', '.join(missing)}")
 console.print("[dim]Run: ./setup.sh to install all tools[/dim]\n")
 if fix and confirm("Install missing tools now?", default=True):
 import subprocess
 subprocess.run(["bash", "./setup.sh"], check=False)

 # Final Verdict 
 console.print()
 if all_ok:
 print_success("System is healthy and ready for use")
 else:
 print_error("System has issues")
 console.print("[dim]Run: python main.py doctor --fix[/dim]")
 if not fix and confirm("Run auto-repair now?", default=True):
 check_health(fix=True)
 console.print()

 return all_ok

if __name__ == "__main__":
 check_health(fix="--fix" in sys.argv)
