import subprocess
import shutil
import questionary
import logging
import sys
from rich.console import Console

console = Console()
logger = logging.getLogger(__name__)

# Standard security tool commands in list format for safety
TOOLS = {
    "subfinder": ["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    "nuclei": ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
    "httpx": ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    "katana": ["go", "install", "-v", "github.com/projectdiscovery/katana/cmd/katana@latest"],
    "waybackurls": ["go", "install", "github.com/tomnomnom/waybackurls@latest"]
}

def check_and_install_dependencies(check_only=False):
    """
    Check if required tools are installed. 
    If not check_only, ask the user to install them.
    """
    missing_tools = []
    for tool in TOOLS:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if not missing_tools:
        if not check_only:
            console.print("[bold green]System Health: All core security tools are present.[/bold green]")
        return True

    if check_only:
        console.print(f"[bold red]System Health: Missing tools -> {', '.join(missing_tools)}[/bold red]")
        return False

    console.print(f"[bold yellow]Attention: Missing security tools -> {', '.join(missing_tools)}[/bold yellow]")
    
    for tool in missing_tools:
        install = questionary.confirm(
            f"Would you like to install '{tool}' using Go?",
            default=True
        ).ask()
        
        if install:
            console.print(f"[*] Installing {tool} (this may take a few minutes)...")
            try:
                # 🛡️ SECURITY: shell=False with list-based arguments
                subprocess.run(TOOLS[tool], check=True, capture_output=True)
                console.print(f"[bold green]Successfully installed {tool}.[/bold green]")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install {tool}: {e}")
                console.print(f"[bold red]Installation failed. Please run manually: {' '.join(TOOLS[tool])}[/bold red]")
        else:
            console.print(f"[dim]Skipping {tool}. Proceeding with caution.[/dim]")
    
    return True

if __name__ == "__main__":
    # Allow running as a standalone check tool
    if "--check-only" in sys.argv:
        sys.exit(0 if check_and_install_dependencies(check_only=True) else 1)
    else:
        check_and_install_dependencies()
