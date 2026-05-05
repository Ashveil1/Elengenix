"""
ui_components.py -- Elengenix Professional UI Component Library (v2.0.0)

Centralized UI components for the entire Elengenix framework.
Provides consistent styling, color scheme, and reusable display
elements across all modules.

Design Principles:
    - No emoji characters in any output
    - Professional text-only markers: [OK], [FAIL], [WARN], [INFO]
    - Consistent red/blue color scheme with green/red for status
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

# Force color support to ensure premium aesthetics in all terminal modes
console = Console(force_terminal=True, color_system="auto")


# ---------------------------------------------------------------------------
# COLOR SCHEME -- Professional dark theme
# ---------------------------------------------------------------------------

COLORS = {
    "primary":   "red",              # Bronze / Gold (Main brand)
    "secondary": "grey70",         # Aegean Sea Blue (Secondary actions)
    "success":   "white",  # Olive (Success states)
    "warning":   "grey70",        # Terracotta (Warnings)
    "error":     "red",         # Spartan Red (Errors)
    "info":      "grey70",         # Lapis Lazuli (Informational text)
    "text":      "white",              # Marble (Normal text)
    "muted":     "dim",                # Muted/secondary text
    "accent":    "red",              # Highlights and accents
}


# ---------------------------------------------------------------------------
# STYLES -- Reusable Rich Style objects
# ---------------------------------------------------------------------------

STYLES = {
    "title":     Style(color="red", bold=True),
    "subtitle":  Style(color="grey70", dim=True),
    "success":   Style(color="white", bold=True),
    "error":     Style(color="red", bold=True),
    "warning":   Style(color="grey70"),
    "info":      Style(color="grey70", dim=True),
    "command":   Style(color="red", bgcolor="black"),
}

# Standard text markers (no emoji, Greek-inspired or professional symbols)
MARKERS = {
    "ok":    "[✔]",
    "fail":  "[✘]",
    "warn":  "[!]",
    "info":  "[i]",
    "run":   "[►]",
    "skip":  "[»]",
}


# ---------------------------------------------------------------------------
# BANNERS
# ---------------------------------------------------------------------------

def show_main_banner():
    """Display the majestic application banner.

    Used at startup in main.py. Renders a centered, bordered panel
    with the application name, version, and tagline using a Greek aesthetic.
    """
    from rich.align import Align
    
    banner = (
        "\n"
        "[bold red] ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗[/bold red]\n"
        "[bold red] ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝[/bold red]\n"
        "[bold red] █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ [/bold red]\n"
        "[bold red] ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ [/bold red]\n"
        "[bold red] ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗[/bold red]\n"
        "[bold red] ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝[/bold red]\n"
        "[dim grey70] ─────────────────────────────────────────────────────────────────────────── [/dim grey70]\n"
        "[bold white]                   Universal AI & Bug Bounty Agent                   [/bold white]\n"
        "[dim grey70]                        Aegis Protocol Active                        [/dim grey70]\n\n"
        "                               [bold red]v2.0.0[/bold red]                                \n"
    )
    console.print(Panel(
        Align.center(banner),
        border_style="red",
        box=ROUNDED,
        padding=(0, 2),
        title="[bold red] System Online [/bold red]",
        title_align="center"
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
        f"[bold red]❖ {mode_text} ❖[/bold red]\n"
        f"[dim]Type /help for commands  |  /exit to quit[/dim]",
        border_style="red",
        box=ROUNDED,
        padding=(0, 2),
        subtitle="[dim]v2.0.0[/dim]",
        subtitle_align="right"
    ))


def show_arsenal_banner():
    """Display the Security Arsenal banner."""
    console.print(Panel(
        "[bold red]Security Arsenal[/bold red] [dim]v2.0.0[/dim]\n"
        "[dim]Select a tool to begin[/dim]",
        border_style="red",
        box=ROUNDED,
        padding=(0, 2)
    ))


# ---------------------------------------------------------------------------
# MENUS
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# MENU CATEGORIES
# ---------------------------------------------------------------------------

MENU_CATEGORIES = [
    {
        "title": "AI & Agent",
        "items": [
            ("AI Partner",      "Interactive AI assistant (chat mode)",             "ai"),
            ("Universal Agent", "Autonomous agent — executes tasks end-to-end",    "universal"),
            ("Autonomous",      "Fully autonomous scan with AI decision-making",   "autonomous"),
        ]
    },
    {
        "title": "Reconnaissance",
        "items": [
            ("Recon",           "Subdomain + asset discovery & correlation",        "recon"),
            ("Omni-Scan",       "Full pipeline: Recon -> Vuln -> Report",           "scan"),
            ("Bounty Intel",    "Bug bounty program analysis & predictor",         "bounty"),
        ]
    },
    {
        "title": "Exploitation & Testing",
        "items": [
            ("BOLA / IDOR",     "Broken access control & IDOR differential tests", "bola"),
            ("WAF / XSS",       "WAF detection, bypass & XSS mutation engine",     "waf"),
            ("Evasion",         "EDR/AV evasion framework (authorized use only)",  "evasion"),
            ("Research / PoC",  "CVE research + Proof-of-Concept generator",       "research"),
        ]
    },
    {
        "title": "Analysis & Intelligence",
        "items": [
            ("SAST",            "Static analysis — Python, JS, Go, Java, PHP",     "sast"),
            ("Cloud",           "Cloud/Terraform/IaC security review",             "cloud"),
            ("Mobile / API",    "Mobile API traffic analysis & fuzzing",           "mobile"),
            ("SOC Analyzer",    "Security log & threat intelligence analysis",      "soc"),
        ]
    },
    {
        "title": "Reports & Memory",
        "items": [
            ("Report",          "Generate HTML/PDF security report",               "report"),
            ("Memory",          "View & manage AI semantic memory",               "memory"),
            ("History",         "Browse past scan sessions & findings",            "history"),
            ("Dashboard",       "Launch live web dashboard (browser UI)",          "dashboard"),
        ]
    },
    {
        "title": "System",
        "items": [
            ("Doctor",          "System health check — tools & API keys",          "doctor"),
            ("Configure",       "Set up AI providers, Telegram, HackerOne",        "configure"),
            ("Arsenal",         "Legacy manual tool picker",                        "arsenal"),
            ("Telegram",        "Start Telegram bot gateway",                      "gateway"),
            ("Update",          "Update framework via git pull",                   "update"),
        ]
    },
]


def create_main_menu() -> List[tuple]:
    """Flatten MENU_CATEGORIES into a numbered list for the interactive prompt.

    Returns:
        List of (title, description, command_key) tuples.
    """
    flat: List[tuple] = []
    for cat in MENU_CATEGORIES:
        flat.extend(cat["items"])
    flat.append(("Exit", "Quit application", "exit"))
    return flat


def show_categorized_menu():
    """Render the main menu grouped by category using a rich Table."""
    from rich.box import MINIMAL_DOUBLE_HEAD

    table = Table(
        show_header=False,
        box=ROUNDED,
        border_style="red",
        padding=(0, 1),
        show_lines=False,
        expand=True,
    )
    table.add_column("Num",  style="red",   width=4,  justify="right")
    table.add_column("Name", style="bold",  width=18)
    table.add_column("Desc", style="dim",   min_width=30)

    item_num = 1
    for cat in MENU_CATEGORIES:
        table.add_row("", f"[bold red]{cat['title'].upper()}[/bold red]", "", style="")
        for title, desc, _ in cat["items"]:
            table.add_row(f"{item_num}.", title, desc)
            item_num += 1

    # Exit row
    table.add_row("", "[bold red]SYSTEM[/bold red]", "")
    table.add_row(f"{item_num}.", "Exit", "Quit application")

    console.print(Panel(
        table,
        title="[bold red] ELENGENIX — MAIN MENU [/bold red]",
        border_style="red",
        box=ROUNDED,
        padding=(0, 1),
    ))
    console.print(f"[dim]   Enter number or type a command  |  Ctrl+C to quit[/dim]\n")


def create_arsenal_menu() -> List[Dict[str, str]]:
    """Create arsenal tool menu items.

    Returns:
        List of dicts with 'name', 'desc', and 'file' keys.
    """
    return [
        {"name": "OMNI-SCAN",       "desc": "Full pipeline: Dorking -> Recon -> Vuln -> Report",   "file": "omni_scan.py"},
        {"name": "Recon",           "desc": "Subdomain enumeration + HTTP probes",                  "file": "base_recon.py"},
        {"name": "Vuln Scanner",    "desc": "Nuclei CVE and misconfiguration scan",                 "file": "base_scanner.py"},
        {"name": "API Hunter",      "desc": "Discover Swagger, OpenAPI, hidden API routes",         "file": "api_finder.py"},
        {"name": "JS Analyzer",     "desc": "Extract secrets & paths from JS files",               "file": "js_analyzer.py"},
        {"name": "Param Miner",     "desc": "Fuzz URL parameters for hidden vulns",                "file": "param_miner.py"},
        {"name": "Google Dorking",  "desc": "Search exposed files & logs via Google",              "file": "dork_miner.py"},
        {"name": "AI Research",     "desc": "Autonomous web research on specific vectors",          "file": "research_tool.py"},
        {"name": "Cloud Scanner",   "desc": "Terraform / IaC / AWS configuration review",          "file": "cloud_scanner.py"},
        {"name": "SAST Engine",     "desc": "Static analysis for Python, JS, Java, Go, PHP",       "file": "sast_engine.py"},
        {"name": "Mobile API",      "desc": "Analyze mobile API traffic, Burp export, fuzzing",    "file": "mobile_api_tester.py"},
        {"name": "SOC Analyzer",    "desc": "Security log, SIEM & threat intel analysis",           "file": "soc_analyzer.py"},
        {"name": "Protocol Probe",  "desc": "Deep analysis: MQTT, Modbus, gRPC, IoT/ICS",         "file": "protocol_analyzer.py"},
    ]


def format_menu_item(number: int, title: str, description: str) -> str:
    """Format a single menu item with consistent styling.

    Args:
        number: Item number (displayed left-aligned).
        title: Item title (bold).
        description: Item description (dimmed).
    """
    return f"[red]{number:2}.[/red] [bold]{title}[/bold]  [dim]{description}[/dim]"


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
        border_style="red",
        header_style="bold red",
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
        header_style="bold red",
        box=ROUNDED,
        border_style="red",
        show_lines=True
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Tool", style="red", width=20)
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
        border_style="red",
        show_lines=False,
        padding=(0, 1)
    )
    table.add_column("Check", style="red")
    table.add_column("Status", width=10)
    table.add_column("Details", style="white")

    status_display = {
        "ok":   "[white]OK[/white]",
        "fail": "[red]FAIL[/red]",
        "warn": "[grey70]WARN[/grey70]",
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
    """Print a success message with [✔] marker."""
    console.print(f"[white]{MARKERS['ok']} {message}[/white]")


def print_error(message: str):
    """Print an error message with [✘] marker."""
    console.print(f"[red]{MARKERS['fail']} {message}[/red]")


def print_warning(message: str):
    """Print a warning message with [!] marker."""
    console.print(f"[grey70]{MARKERS['warn']} {message}[/grey70]")


def print_info(message: str):
    """Print an informational message with [i] marker."""
    console.print(f"[grey70]{MARKERS['info']} {message}[/grey70]")


def print_command(command: str):
    """Print a command in highlighted style (for copy-paste guidance)."""
    console.print(f"[black on red] {command} [/black on red]")


# ---------------------------------------------------------------------------
# PROGRESS AND STATUS
# ---------------------------------------------------------------------------

def show_spinner(message: str):
    """Return a Rich status context manager with a spinning indicator.

    Usage:
        with show_spinner("Loading..."):
            do_work()
    """
    return console.status(f"[red]{message}[/red]", spinner="dots")


def show_section(title: str):
    """Print a section divider with a bold title and Greek-style border.

    Args:
        title: Section heading text.
    """
    console.print()
    console.print(f"[bold red] ❖ {title.upper()} ❖ [/bold red]")
    console.print(f"[dim red] ────────{'─' * len(title)}──────── [/dim red]")


# ---------------------------------------------------------------------------
# INPUT PROMPTS
# ---------------------------------------------------------------------------

def prompt_target() -> str:
    """Prompt the user to enter a target domain or IP address."""
    return console.input("[red]Target[/red] [dim](domain/IP)[/dim]: ")


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
        choice = console.input("\n[red]Select[/red] [dim](number)[/dim]: ")
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
        f"[red]{message}[/red] [dim]({default_text})[/dim]: "
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
    console.print("\n[bold red]Scan Results[/bold red]\n")

    critical = findings.get("critical", 0)
    high = findings.get("high", 0)
    medium = findings.get("medium", 0)
    low = findings.get("low", 0)

    if critical > 0:
        console.print(f"  [red]Critical: {critical}[/red]")
    if high > 0:
        console.print(f"  [grey70]High: {high}[/grey70]")
    if medium > 0:
        console.print(f"  [grey70]Medium: {medium}[/grey70]")
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
    console.print("\n[bold red]Memory Statistics[/bold red]\n")

    status = stats.get("status", "unknown")
    total = stats.get("total_memories", 0)
    targets = stats.get("unique_targets", 0)

    console.print(f"  Status:          [red]{status}[/red]")
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
    "show_categorized_menu", "MENU_CATEGORIES",
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
