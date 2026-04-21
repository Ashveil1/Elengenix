import subprocess
import shutil
import questionary
import logging
import sys
from rich.console import Console

console = Console()
logger = logging.getLogger(__name__)

# Security: Define commands as lists for shell=False execution
TOOLS = {
    "subfinder": ["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    "nuclei": ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
    "httpx": ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    "katana": ["go", "install", "-v", "github.com/projectdiscovery/katana/cmd/katana@latest"],
    "waybackurls": ["go", "install", "github.com/tomnomnom/waybackurls@latest"]
}

def check_and_install_dependencies(check_only=False):
    """
    Checks for required security binaries. 
    If not found and not in check_only mode, prompts for installation.
    """
    missing_tools = [tool for tool in TOOLS if not shutil.which(tool)]
    
    if not missing_tools:
        if not check_only:
            console.print("[bold green][System Health] All core security tools are present.[/bold green]")
        return True

    if check_only:
        console.print(f"[bold red][System Health] Missing tools: {', '.join(missing_tools)}[/bold red]")
        return False

    console.print(f"[bold yellow]Security Warning: The following tools are missing: {', '.join(missing_tools)}[/bold yellow]")
    console.print("Elengenix requires these for full reconnaissance and vulnerability scanning.")
    
    for tool in missing_tools:
        install = questionary.confirm(f"Install '{tool}' now?", default=True).ask()
        if install:
            console.print(f"[*] Executing install command for {tool}...")
            try:
                # 🛡️ SECURITY: shell=False is enforced. No command injection possible.
                subprocess.run(TOOLS[tool], check=True, capture_output=True)
                console.print(f"[bold green]Successfully installed {tool}.[/bold green]")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install {tool}: {e}")
                console.print(f"[bold red]Installation failed. Run manually: {' '.join(TOOLS[tool])}[/bold red]")
    
    return True

if __name__ == "__main__":
    if "--check-only" in sys.argv:
        sys.exit(0 if check_and_install_dependencies(check_only=True) else 1)
    else:
        check_and_install_dependencies()
