import subprocess
import shutil
import questionary
from rich.console import Console

console = Console()

TOOLS = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest"
}

def check_and_install_dependencies():
    """
    Check if required tools are installed. If not, ask the user to install them.
    """
    missing_tools = []
    for tool in TOOLS:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if not missing_tools:
        console.print("[bold green]✅ All core tools are installed![/bold green]")
        return True

    console.print(f"[bold yellow]⚠️ Missing tools detected: {', '.join(missing_tools)}[/bold yellow]")
    
    for tool in missing_tools:
        install = questionary.confirm(
            f"Tool '{tool}' is missing. It is used for specialized bug hunting. Do you want to install it now?",
            default=True
        ).ask()
        
        if install:
            console.print(f"[bold blue]⏳ Installing {tool}... (This may take a minute)[/bold blue]")
            try:
                # Assuming Go is installed since these are Go tools
                subprocess.run(TOOLS[tool], shell=True, check=True)
                console.print(f"[bold green]✅ Successfully installed {tool}![/bold green]")
            except Exception as e:
                console.print(f"[bold red]❌ Failed to install {tool}: {e}[/bold red]")
        else:
            console.print(f"[dim]Skipping {tool}. Some features might not work.[/dim]")
    
    return True
