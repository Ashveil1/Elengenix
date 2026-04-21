import subprocess
import shutil
import questionary
import logging
from rich.console import Console

console = Console()
logger = logging.getLogger(__name__)

# Standard security tool commands (split into list for subprocess safety)
TOOLS = {
    "subfinder": ["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    "nuclei": ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
    "httpx": ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    "katana": ["go", "install", "-v", "github.com/projectdiscovery/katana/cmd/katana@latest"],
    "waybackurls": ["go", "install", "github.com/tomnomnom/waybackurls@latest"]
}

def check_and_install_dependencies():
    """
    Check if required tools are installed. If not, ask the user to install them.
    Security: shell=False is enforced.
    """
    missing_tools = []
    for tool in TOOLS:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if not missing_tools:
        console.print("[bold green]All core security tools are installed.[/bold green]")
        return True

    console.print(f"[bold yellow]Missing tools detected: {', '.join(missing_tools)}[/bold yellow]")
    
    for tool in missing_tools:
        install = questionary.confirm(
            f"Tool '{tool}' is missing. Install now?",
            default=True
        ).ask()
        
        if install:
            console.print(f"[bold blue]Installing {tool}...[/bold blue]")
            try:
                # 🛡️ SECURITY: shell=False with list arguments
                subprocess.run(TOOLS[tool], check=True, capture_output=True)
                console.print(f"[bold green]Successfully installed {tool}.[/bold green]")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install {tool}: {e}")
                console.print(f"[bold red]Failed to install {tool}. Please try: {' '.join(TOOLS[tool])}[/bold red]")
        else:
            console.print(f"Skipping {tool}. Some features may be limited.")
    
    return True
