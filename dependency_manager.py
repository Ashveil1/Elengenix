"""
dependency_manager.py — Elengenix Resilient Tool Installer (v1.5.0)
- Prerequisite Verification (Go & Git)
- Streaming Subprocess Output (Memory efficient)
- Post-install Verification & PATH Guidance
- Machine-readable output for CI/CD
"""

import subprocess
import shutil
import questionary
import logging
import sys
import os
import time
from pathlib import Path
from typing import List, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

# ── Setup ───────────────────────────────────────────────────
console = Console()
logger = logging.getLogger("elengenix.installer")

# Standard security tool commands (List format for shell=False)
TOOLS = {
    "subfinder": ["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    "nuclei": ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
    "httpx": ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    "katana": ["go", "install", "-v", "github.com/projectdiscovery/katana/cmd/katana@latest"],
    "waybackurls": ["go", "install", "github.com/tomnomnom/waybackurls@latest"]
}

# ── Helpers ──────────────────────────────────────────────────
def check_prerequisites() -> bool:
    """Ensure Go and Git are installed before proceeding."""
    reqs = {"go": "Go is required to compile tools (https://go.dev/)", "git": "Git is required for cloning tools"}
    missing = [k for k, v in reqs.items() if not shutil.which(k)]
    if missing:
        console.print("[bold red]❌ Missing Prerequisites:[/bold red]")
        for m in missing: console.print(f"  - {m}: {reqs[m]}")
        return False
    return True

def run_with_streaming(cmd: List[str], timeout: int = 600) -> bool:
    """Run command with streaming output to prevent memory bloat (Ideal for 4GB RAM)."""
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Stream output line by line
        for line in process.stdout:
            # Only log interesting lines or dim them to keep UI clean
            if "installing" in line.lower() or "downloading" in line.lower():
                console.print(f"    [dim]{line.strip()}[/dim]")
        
        process.wait(timeout=timeout)
        return process.returncode == 0
    except subprocess.TimeoutExpired:
        process.kill()
        logger.error(f"Installation timed out after {timeout}s")
        return False
    except Exception as e:
        logger.error(f"Execution error: {e}")
        return False

def verify_and_advise(tool: str) -> bool:
    """Check if tool is in PATH or provide advice on how to add it."""
    if shutil.which(tool): return True

    # Check common Go bin locations
    go_bin = Path(os.environ.get("GOPATH", Path.home() / "go")) / "bin"
    if (go_bin / tool).exists() or (go_bin / f"{tool}.exe").exists():
        console.print(f"[yellow]⚠️  {tool} installed but not in PATH.[/yellow]")
        console.print(f"   Action: Add [bold]{go_bin}[/bold] to your system PATH.")
        return True
    return False

# ── Main Logic ───────────────────────────────────────────────
def check_and_install_dependencies(check_only: bool = False, max_retries: int = 1):
    if not check_prerequisites():
        return False

    missing_tools = [t for t in TOOLS if not shutil.which(t)]
    
    if not missing_tools:
        if not check_only: console.print("[bold green]✅ All security tools are present and verified.[/bold green]")
        return True

    if check_only:
        console.print(f"[bold red]❌ Missing Tools: {', '.join(missing_tools)}[/bold red]")
        return False

    console.print(f"[bold yellow]Security Tools Missing: {', '.join(missing_tools)}[/bold yellow]")
    
    for tool in missing_tools:
        # Handle questionary None result (Ctrl+C)
        try:
            choice = questionary.confirm(f"Install '{tool}' now?", default=True).ask()
            if choice is None or not choice:
                console.print(f"[dim]⏭️ Skipped {tool}[/dim]")
                continue
        except KeyboardInterrupt:
            break

        success = False
        for attempt in range(max_retries + 1):
            console.print(f"[*] Installing {tool} (Attempt {attempt+1}/{max_retries+1})...")
            
            if run_with_streaming(TOOLS[tool]):
                if verify_and_advise(tool):
                    console.print(f"[bold green]✓ {tool} successfully integrated.[/bold green]")
                    success = True
                    break
            
            if attempt < max_retries:
                console.print("[dim]Retry in 3s...[/dim]")
                time.sleep(3)

        if not success:
            console.print(f"[bold red]❌ Failed to install {tool} automatically.[/bold red]")
            console.print(f"   Manual command: [dim]{' '.join(TOOLS[tool])}[/dim]")

    return True

if __name__ == "__main__":
    # Support for CI/CD via --check-only flag
    if "--check-only" in sys.argv:
        sys.exit(0 if check_and_install_dependencies(check_only=True) else 1)
    else:
        check_and_install_dependencies()
