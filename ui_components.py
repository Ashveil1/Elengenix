"""
ui_components.py — Modern Professional UI Components (v1.0.0)
- Clean, minimal design with minimal emojis
- Professional color scheme
- Consistent styling across all modules
- Rich console components
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.style import Style
from rich.box import Box, ROUNDED, SIMPLE_HEAD, MINIMAL_DOUBLE_HEAD
from typing import List, Dict, Optional, Any

console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
# COLOR SCHEME — Professional dark theme
# ═══════════════════════════════════════════════════════════════════════════════

COLORS = {
    "primary": "cyan",        # Main brand color
    "secondary": "blue",      # Secondary actions
    "success": "green",       # Success states
    "warning": "yellow",      # Warnings
    "error": "red",           # Errors
    "info": "cyan",           # Info text
    "text": "white",          # Normal text
    "muted": "dim",           # Muted/secondary text
    "accent": "magenta",      # Highlights
}

# ═══════════════════════════════════════════════════════════════════════════════
# STYLES
# ═══════════════════════════════════════════════════════════════════════════════

STYLES = {
    "title": Style(color="cyan", bold=True),
    "subtitle": Style(color="blue", dim=True),
    "success": Style(color="green", bold=True),
    "error": Style(color="red", bold=True),
    "warning": Style(color="yellow"),
    "info": Style(color="cyan", dim=True),
    "command": Style(color="cyan", bgcolor="black"),
}

# ═══════════════════════════════════════════════════════════════════════════════
# BANNERS
# ═══════════════════════════════════════════════════════════════════════════════

def show_main_banner():
    """Clean main banner with minimal styling."""
    banner = """
    [bold cyan]ELENGENIX[/bold cyan] [dim]v2.0.0[/dim]
    [dim]Universal AI Agent • Bug Bounty Specialist[/dim]
    """
    console.print(Panel(
        banner,
        border_style="cyan",
        box=MINIMAL_DOUBLE_HEAD,
        padding=(1, 2)
    ))

def show_cli_banner(mode: str = "agent"):
    """CLI mode banner."""
    mode_names = {
        "universal": "Universal Agent",
        "bug_bounty": "Bug Bounty Specialist", 
        "auto": "Adaptive Agent",
        "agent": "AI Partner"
    }
    mode_text = mode_names.get(mode, "AI Partner")
    
    console.print(Panel(
        f"[bold cyan]{mode_text}[/bold cyan] [dim]v2.0.0[/dim]\n"
        f"[dim]Type /help for commands | /exit to quit[/dim]",
        border_style="cyan",
        box=ROUNDED,
        padding=(0, 2)
    ))

def show_arsenal_banner():
    """Tools arsenal banner."""
    console.print(Panel(
        "[bold cyan]Security Arsenal[/bold cyan] [dim]v2.0.0[/dim]\n"
        "[dim]Select a tool to begin[/dim]",
        border_style="cyan",
        box=ROUNDED,
        padding=(0, 2)
    ))

# ═══════════════════════════════════════════════════════════════════════════════
# MENUS
# ═══════════════════════════════════════════════════════════════════════════════

def create_main_menu() -> List[tuple]:
    """Create main menu items without emojis."""
    return [
        ("AI Partner", "Chat with AI (Intelligent Mode, auto tmux)", "ai"),
        ("Universal Agent", "Flexible agent mode (Claude Code style)", "universal"),
        ("Omni-Scan", "Full automated scan", "scan"),
        ("Arsenal", "Manual tool selection", "arsenal"),
        ("Telegram", "Start Telegram bot", "gateway"),
        ("Memory", "View AI memory & history", "memory"),
        ("Doctor", "System health check", "doctor"),
        ("Settings", "Configure AI & options", "configure"),
        ("Update", "Update framework", "update"),
        ("Exit", "Quit application", "exit"),
    ]

def create_arsenal_menu() -> List[Dict[str, str]]:
    """Create arsenal menu items."""
    return [
        {"name": "Omni-Scan", "desc": "End-to-end: Recon → Vuln Scan → Report", "file": "omni_scan.py"},
        {"name": "Recon", "desc": "Subdomain enumeration + HTTP probes", "file": "base_recon.py"},
        {"name": "Vuln Scanner", "desc": "Nuclei CVE and misconfiguration scan", "file": "base_scanner.py"},
        {"name": "API Hunter", "desc": "Discover Swagger, OpenAPI, API routes", "file": "api_finder.py"},
        {"name": "JS Analyzer", "desc": "Extract secrets from JS files", "file": "js_analyzer.py"},
        {"name": "Param Miner", "desc": "Fuzz URL parameters", "file": "param_miner.py"},
        {"name": "Google Dorking", "desc": "Search exposed files via Google", "file": "dork_miner.py"},
        {"name": "AI Research", "desc": "Autonomous web research", "file": "research_tool.py"},
    ]

def format_menu_item(number: int, title: str, description: str) -> str:
    """Format a menu item cleanly."""
    return f"[cyan]{number:2}.[/cyan] [bold]{title}[/bold]  [dim]{description}[/dim]"

# ═══════════════════════════════════════════════════════════════════════════════
# TABLES
# ═══════════════════════════════════════════════════════════════════════════════

def create_status_table(title: str) -> Table:
    """Create a clean status table."""
    table = Table(
        title=title,
        box=ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True
    )
    return table

def create_tools_table(tools: List[Dict[str, str]]) -> Table:
    """Create arsenal tools table."""
    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=ROUNDED,
        border_style="cyan",
        show_lines=True
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Tool", style="cyan", width=20)
    table.add_column("Description", style="white")
    
    for idx, tool in enumerate(tools, 1):
        table.add_row(
            str(idx),
            tool["name"],
            tool["desc"]
        )
    
    return table

def create_doctor_table(checks: List[Dict[str, Any]]) -> Table:
    """Create doctor check results table."""
    table = Table(
        box=ROUNDED,
        border_style="cyan",
        show_lines=False,
        padding=(0, 1)
    )
    table.add_column("Check", style="cyan")
    table.add_column("Status", width=10)
    table.add_column("Details", style="white")
    
    for check in checks:
        status = check.get("status", "unknown")
        status_style = {
            "ok": "[green]OK[/green]",
            "fail": "[red]FAIL[/red]",
            "warn": "[yellow]WARN[/yellow]",
            "info": "[dim]INFO[/dim]"
        }.get(status, status)
        
        table.add_row(
            check.get("name", ""),
            status_style,
            check.get("details", "")
        )
    
    return table

# ═══════════════════════════════════════════════════════════════════════════════
# MESSAGES
# ═══════════════════════════════════════════════════════════════════════════════

def print_success(message: str):
    """Print success message."""
    console.print(f"[green]{message}[/green]")

def print_error(message: str):
    """Print error message."""
    console.print(f"[red]{message}[/red]")

def print_warning(message: str):
    """Print warning message."""
    console.print(f"[yellow]{message}[/yellow]")

def print_info(message: str):
    """Print info message."""
    console.print(f"[dim]{message}[/dim]")

def print_command(command: str):
    """Print command in highlighted style."""
    console.print(f"[black on cyan] {command} [/black on cyan]")

# ═══════════════════════════════════════════════════════════════════════════════
# PROGRESS & STATUS
# ═══════════════════════════════════════════════════════════════════════════════

def show_spinner(message: str):
    """Return status context manager."""
    return console.status(f"[cyan]{message}[/cyan]", spinner="dots")

def show_section(title: str):
    """Show section divider."""
    console.print(f"\n[bold cyan]━━━ {title} ━━━[/bold cyan]\n")

# ═══════════════════════════════════════════════════════════════════════════════
# INPUT PROMPTS
# ═══════════════════════════════════════════════════════════════════════════════

def prompt_target() -> str:
    """Clean target input prompt."""
    return console.input("[cyan]Target[/cyan] [dim](domain/IP)[/dim]: ")

def prompt_choice(options: List[str]) -> int:
    """Show numbered options and get choice."""
    for i, opt in enumerate(options, 1):
        console.print(f"  {i}. {opt}")
    
    while True:
        choice = console.input("\n[cyan]Select[/cyan] [dim](number)[/dim]: ")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return idx
        except ValueError:
            pass
        console.print("[red]Invalid selection[/red]")

def confirm(message: str, default: bool = False) -> bool:
    """Clean confirmation prompt."""
    default_text = "Y/n" if default else "y/N"
    response = console.input(f"[cyan]{message}[/cyan] [dim]({default_text})[/dim]: ").lower().strip()
    
    if not response:
        return default
    return response in ("y", "yes")

# ═══════════════════════════════════════════════════════════════════════════════
# RESULT DISPLAYS
# ═══════════════════════════════════════════════════════════════════════════════

def show_scan_summary(findings: Dict[str, Any]):
    """Show scan results summary."""
    console.print("\n[bold cyan]Scan Results[/bold cyan]\n")
    
    critical = findings.get("critical", 0)
    high = findings.get("high", 0)
    medium = findings.get("medium", 0)
    low = findings.get("low", 0)
    
    if critical > 0:
        console.print(f"  [red]Critical: {critical}[/red]")
    if high > 0:
        console.print(f"  [yellow]High: {high}[/yellow]")
    if medium > 0:
        console.print(f"  [blue]Medium: {medium}[/blue]")
    if low > 0:
        console.print(f"  [dim]Low: {low}[/dim]")
    
    if not any([critical, high, medium, low]):
        console.print("  [dim]No findings[/dim]")
    
    console.print()

def show_memory_stats(stats: Dict[str, Any]):
    """Show memory system stats."""
    console.print("\n[bold cyan]Memory Statistics[/bold cyan]\n")
    
    status = stats.get("status", "unknown")
    total = stats.get("total_memories", 0)
    targets = stats.get("unique_targets", 0)
    
    console.print(f"  Status: [cyan]{status}[/cyan]")
    console.print(f"  Total memories: {total}")
    console.print(f"  Unique targets: {targets}")
    
    if stats.get("targets"):
        console.print(f"\n  [dim]Recent targets:[/dim]")
        for t in stats["targets"][:10]:
            console.print(f"    • {t}")
    
    console.print()

# ═══════════════════════════════════════════════════════════════════════════════
# CLEAN EXPORT — Functions for external use
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = [
    # Banners
    "show_main_banner", "show_cli_banner", "show_arsenal_banner",
    # Menus
    "create_main_menu", "create_arsenal_menu", "format_menu_item",
    # Tables
    "create_status_table", "create_tools_table", "create_doctor_table",
    # Messages
    "print_success", "print_error", "print_warning", "print_info", "print_command",
    # Progress
    "show_spinner", "show_section",
    # Input
    "prompt_target", "prompt_choice", "confirm",
    # Results
    "show_scan_summary", "show_memory_stats",
    # Console
    "console", "COLORS", "STYLES"
]
