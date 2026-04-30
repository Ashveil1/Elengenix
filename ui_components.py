"""
ui_components.py -- Elengenix Professional UI Component Library (v2.0.0)

Centralized UI components for the entire Elengenix framework.
Provides consistent styling, color scheme, and reusable display
elements across all modules.

Design Principles:
    - No emoji characters in any output
    - Professional text-only markers: [OK], [FAIL], [WARN], [INFO]
    - Consistent cyan/blue color scheme with green/red for status
    - All components use Rich library for terminal rendering

Usage:
    from ui_components import console, print_success, print_error
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.style import Style
from rich.box import Box, ROUNDED, SIMPLE_HEAD, MINIMAL_DOUBLE_HEAD, HEAVY
from typing import List, Dict, Optional, Any

# ---------------------------------------------------------------------------
# Shared Console Instance
# All modules should import this instead of creating their own Console()
# ---------------------------------------------------------------------------

console = Console()


# ---------------------------------------------------------------------------
# COLOR SCHEME -- Professional dark theme
# ---------------------------------------------------------------------------

COLORS = {
    "primary":   "cyan",       # Main brand color
    "secondary": "blue",       # Secondary actions
    "success":   "green",      # Success states
    "warning":   "yellow",     # Warnings
    "error":     "red",        # Errors
    "info":      "cyan",       # Informational text
    "text":      "white",      # Normal text
    "muted":     "dim",        # Muted/secondary text
    "accent":    "magenta",    # Highlights and accents
}


# ---------------------------------------------------------------------------
# STYLES -- Reusable Rich Style objects
# ---------------------------------------------------------------------------

STYLES = {
    "title":     Style(color="cyan", bold=True),
    "subtitle":  Style(color="blue", dim=True),
    "success":   Style(color="green", bold=True),
    "error":     Style(color="red", bold=True),
    "warning":   Style(color="yellow"),
    "info":      Style(color="cyan", dim=True),
    "command":   Style(color="cyan", bgcolor="black"),
}

# Standard text markers (no emoji)
MARKERS = {
    "ok":    "[OK]",
    "fail":  "[FAIL]",
    "warn":  "[WARN]",
    "info":  "[INFO]",
    "run":   "[RUN]",
    "skip":  "[SKIP]",
}


# ---------------------------------------------------------------------------
# BANNERS
# ---------------------------------------------------------------------------

def show_main_banner():
    """Display the main application banner.

    Used at startup in main.py. Renders a centered, bordered panel
    with the application name, version, and tagline.
    """
    banner = (
        "\n"
        "  [bold cyan]ELENGENIX[/bold cyan] [dim]v2.0.0[/dim]\n"
        "  [dim]Universal AI Agent  |  Bug Bounty Specialist[/dim]\n"
    )
    console.print(Panel(
        banner,
        border_style="cyan",
        box=MINIMAL_DOUBLE_HEAD,
        padding=(1, 2)
    ))


def show_cli_banner(mode: str = "agent"):
    """Display the CLI mode banner.

    Args:
        mode: One of 'universal', 'bug_bounty', 'auto', or 'agent'.
    """
    mode_names = {
        "universal":  "Universal Agent",
        "bug_bounty": "Bug Bounty Specialist",
        "auto":       "Adaptive Agent",
        "agent":      "AI Partner"
    }
    mode_text = mode_names.get(mode, "AI Partner")

    console.print(Panel(
        f"[bold cyan]{mode_text}[/bold cyan] [dim]v2.0.0[/dim]\n"
        f"[dim]Type /help for commands  |  /exit to quit[/dim]",
        border_style="cyan",
        box=ROUNDED,
        padding=(0, 2)
    ))


def show_arsenal_banner():
    """Display the Security Arsenal banner."""
    console.print(Panel(
        "[bold cyan]Security Arsenal[/bold cyan] [dim]v2.0.0[/dim]\n"
        "[dim]Select a tool to begin[/dim]",
        border_style="cyan",
        box=ROUNDED,
        padding=(0, 2)
    ))


# ---------------------------------------------------------------------------
# MENUS
# ---------------------------------------------------------------------------

def create_main_menu() -> List[tuple]:
    """Create main menu items.

    Returns:
        List of (title, description, command_key) tuples.
    """
    return [
        ("AI Partner",       "Interactive AI chat with auto tmux support",  "ai"),
        ("Universal Agent",  "Flexible agent mode (Claude Code style)",     "universal"),
        ("Omni-Scan",        "Full automated security scan",               "scan"),
        ("Arsenal",          "Manual tool selection",                       "arsenal"),
        ("Telegram",         "Start Telegram bot gateway",                 "gateway"),
        ("Memory",           "View AI memory and history",                 "memory"),
        ("Doctor",           "System health check",                        "doctor"),
        ("Settings",         "Configure AI providers and options",         "configure"),
        ("Update",           "Update framework",                           "update"),
        ("Exit",             "Quit application",                           "exit"),
    ]


def create_arsenal_menu() -> List[Dict[str, str]]:
    """Create arsenal tool menu items.

    Returns:
        List of dicts with 'name', 'desc', and 'file' keys.
    """
    return [
        {"name": "Omni-Scan",       "desc": "End-to-end: Recon -> Vuln Scan -> Report",   "file": "omni_scan.py"},
        {"name": "Recon",           "desc": "Subdomain enumeration + HTTP probes",         "file": "base_recon.py"},
        {"name": "Vuln Scanner",    "desc": "Nuclei CVE and misconfiguration scan",        "file": "base_scanner.py"},
        {"name": "API Hunter",      "desc": "Discover Swagger, OpenAPI, API routes",       "file": "api_finder.py"},
        {"name": "JS Analyzer",     "desc": "Extract secrets from JS files",               "file": "js_analyzer.py"},
        {"name": "Param Miner",     "desc": "Fuzz URL parameters",                        "file": "param_miner.py"},
        {"name": "Google Dorking",  "desc": "Search exposed files via Google",             "file": "dork_miner.py"},
        {"name": "AI Research",     "desc": "Autonomous web research",                    "file": "research_tool.py"},
    ]


def format_menu_item(number: int, title: str, description: str) -> str:
    """Format a single menu item with consistent styling.

    Args:
        number: Item number (displayed left-aligned).
        title: Item title (bold).
        description: Item description (dimmed).
    """
    return f"[cyan]{number:2}.[/cyan] [bold]{title}[/bold]  [dim]{description}[/dim]"


# ---------------------------------------------------------------------------
# TABLES
# ---------------------------------------------------------------------------

def create_status_table(title: str) -> Table:
    """Create a bordered status table with the standard color scheme.

    Args:
        title: Table title displayed above the header row.
    """
    table = Table(
        title=title,
        box=ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True
    )
    return table


def create_tools_table(tools: List[Dict[str, str]]) -> Table:
    """Create a table listing available security tools.

    Args:
        tools: List of tool dicts with 'name' and 'desc' keys.
    """
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
        table.add_row(str(idx), tool["name"], tool["desc"])

    return table


def create_doctor_table(checks: List[Dict[str, Any]]) -> Table:
    """Create a table for displaying doctor health check results.

    Args:
        checks: List of dicts with 'name', 'status', and 'details' keys.
               Status values: 'ok', 'fail', 'warn', 'info'.
    """
    table = Table(
        box=ROUNDED,
        border_style="cyan",
        show_lines=False,
        padding=(0, 1)
    )
    table.add_column("Check", style="cyan")
    table.add_column("Status", width=10)
    table.add_column("Details", style="white")

    status_display = {
        "ok":   "[green]OK[/green]",
        "fail": "[red]FAIL[/red]",
        "warn": "[yellow]WARN[/yellow]",
        "info": "[dim]INFO[/dim]",
    }

    for check in checks:
        status = check.get("status", "unknown")
        styled_status = status_display.get(status, status)
        table.add_row(
            check.get("name", ""),
            styled_status,
            check.get("details", "")
        )

    return table


# ---------------------------------------------------------------------------
# MESSAGE UTILITIES
# ---------------------------------------------------------------------------

def print_success(message: str):
    """Print a success message with [OK] marker."""
    console.print(f"[green][OK] {message}[/green]")


def print_error(message: str):
    """Print an error message with [FAIL] marker."""
    console.print(f"[red][FAIL] {message}[/red]")


def print_warning(message: str):
    """Print a warning message with [WARN] marker."""
    console.print(f"[yellow][WARN] {message}[/yellow]")


def print_info(message: str):
    """Print an informational message (dimmed)."""
    console.print(f"[dim]{message}[/dim]")


def print_command(command: str):
    """Print a command in highlighted style (for copy-paste guidance)."""
    console.print(f"[black on cyan] {command} [/black on cyan]")


# ---------------------------------------------------------------------------
# PROGRESS AND STATUS
# ---------------------------------------------------------------------------

def show_spinner(message: str):
    """Return a Rich status context manager with a spinning indicator.

    Usage:
        with show_spinner("Loading..."):
            do_work()
    """
    return console.status(f"[cyan]{message}[/cyan]", spinner="dots")


def show_section(title: str):
    """Print a section divider with a bold title.

    Args:
        title: Section heading text.
    """
    console.print(f"\n[bold cyan]{title}[/bold cyan]\n")


# ---------------------------------------------------------------------------
# INPUT PROMPTS
# ---------------------------------------------------------------------------

def prompt_target() -> str:
    """Prompt the user to enter a target domain or IP address."""
    return console.input("[cyan]Target[/cyan] [dim](domain/IP)[/dim]: ")


def prompt_choice(options: List[str]) -> int:
    """Display numbered options and return the selected index (0-based).

    Args:
        options: List of option strings to display.

    Returns:
        Zero-based index of the selected option.
    """
    for i, opt in enumerate(options, 1):
        console.print(f" {i}. {opt}")

    while True:
        choice = console.input("\n[cyan]Select[/cyan] [dim](number)[/dim]: ")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return idx
        except ValueError:
            console.print("[red]Invalid selection[/red]")


def confirm(message: str, default: bool = False) -> bool:
    """Display a yes/no confirmation prompt.

    Args:
        message: Prompt text.
        default: Default value when user presses Enter without input.

    Returns:
        True if user confirmed, False otherwise.
    """
    default_text = "Y/n" if default else "y/N"
    response = console.input(
        f"[cyan]{message}[/cyan] [dim]({default_text})[/dim]: "
    ).lower().strip()

    if not response:
        return default
    return response in ("y", "yes")


# ---------------------------------------------------------------------------
# RESULT DISPLAYS
# ---------------------------------------------------------------------------

def show_scan_summary(findings: Dict[str, Any]):
    """Display scan results grouped by severity.

    Args:
        findings: Dict with 'critical', 'high', 'medium', 'low' counts.
    """
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
    """Display AI memory system statistics.

    Args:
        stats: Dict with 'status', 'total_memories', 'unique_targets',
               and optional 'targets' list.
    """
    console.print("\n[bold cyan]Memory Statistics[/bold cyan]\n")

    status = stats.get("status", "unknown")
    total = stats.get("total_memories", 0)
    targets = stats.get("unique_targets", 0)

    console.print(f"  Status:          [cyan]{status}[/cyan]")
    console.print(f"  Total memories:  {total}")
    console.print(f"  Unique targets:  {targets}")

    if stats.get("targets"):
        console.print(f"\n  [dim]Recent targets:[/dim]")
        for t in stats["targets"][:10]:
            console.print(f"    - {t}")

    console.print()


# ---------------------------------------------------------------------------
# PUBLIC API -- Exported symbols for 'from ui_components import *'
# ---------------------------------------------------------------------------

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
    # Shared objects
    "console", "COLORS", "STYLES", "MARKERS",
]
