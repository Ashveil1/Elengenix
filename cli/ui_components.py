"""
ui_components.py - Elengenix Professional UI Component Library

Centralized UI components for the entire Elengenix framework.
Provides consistent styling, Monochrome Black & White color scheme, and reusable
display elements across all modules.

Design Principles:
    - No emoji characters in any output
    - Professional text-only markers: [OK], [FAIL], [WARN], [INFO]
    - Monochrome Black & White color palette
    - Card-style panels, progress bars, and metric displays
    - All components use Rich library for terminal rendering

Usage:
    from cli.ui_components import console, print_success, print_error
"""

import time
from typing import Any, Dict, List, Optional

from rich.box import ASCII, MINIMAL
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.style import Style
from rich.table import Table

# ---------------------------------------------------------------------------
# Shared Console Instance
# All modules should import this instead of creating their own Console()
# ---------------------------------------------------------------------------

console = Console(
    force_terminal=True,
    color_system="truecolor",
)
console.width = max(100, console.width or 120)


# ---------------------------------------------------------------------------
# MONOCHROME COLOR SCHEME - Black & White Minimalist
# ---------------------------------------------------------------------------

COLORS = {
    "primary": "#ffffff",  # White
    "secondary": "#888888",  # Gray
    "accent": "#ffffff",  # White
    "success": "#ffffff",  # White
    "warning": "#ffffff",  # White
    "error": "#ffffff",  # White
    "info": "#ffffff",  # White
    "text": "#ffffff",  # White
    "muted": "#555555",  # Dim gray
    "high": "#ffffff",  # White
    "medium": "#cccccc",  # Light gray
    "low": "#81C784",  # Green (Low severity)
    "border": "#ffffff",  # Crimson (Panel borders)
    "bg_dark": "#1A1A1A",  # Dark background
    "bg_card": "#242424",  # Card background
    "gradient_1": "#ffffff",  # Gradient start
    "gradient_2": "#ffffff",  # Gradient end
}


# ---------------------------------------------------------------------------
# STYLES - Reusable Rich Style objects
# ---------------------------------------------------------------------------

STYLES = {
    "title": Style(color="#ffffff", bold=True),
    "subtitle": Style(color="#737373", dim=True),
    "success": Style(color="#ffffff", bold=True),
    "error": Style(color="#ffffff", bold=True),
    "warning": Style(color="#888888", bold=True),
    "info": Style(color="#ffffff", dim=True),
    "command": Style(color="#ffffff", bgcolor="#ffffff"),
    "high": Style(color="#ffffff", bold=True),
    "medium": Style(color="#888888", bold=True),
    "low": Style(color="#81C784", bold=True),
    "accent": Style(color="#ffffff", bold=True),
    "heading": Style(color="#ffffff", bold=True, underline=False),
}


# ---------------------------------------------------------------------------
# MARKERS - Professional text-only markers
# ---------------------------------------------------------------------------

MARKERS = {
    "ok": "[OK]",
    "fail": "[FAIL]",
    "warn": "[WARN]",
    "info": "[INFO]",
    "run": "[RUN]",
    "skip": "[SKIP]",
    "arrow": "[->]",
}


# ---------------------------------------------------------------------------
# BANNERS
# ---------------------------------------------------------------------------


def show_main_banner():
    """Display the main application banner styled to match the TUI."""
    console.print()

    ascii_art = [
        "███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗",
        "██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝",
        "█████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ ",
        "██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ ",
        "███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗",
        "╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝",
    ]

    for line in ascii_art:
        console.print(f"  [bold #ffffff]{line}[/bold #ffffff]")
    console.print("           [dim #ffffff]Universal AI & Bug Bounty Agent[/dim #ffffff]")
    console.print("           [dim]Type /help for commands[/dim]")
    console.print()


def show_cli_banner(mode: str = "agent"):
    """Display the CLI mode banner with vibrant styling.

    Args:
        mode: One of 'universal', 'bug_bounty', 'auto', or 'agent'.
    """
    mode_info = {
        "universal": ("Universal Agent", "[bold #ffffff]READY[/bold #ffffff]", "#ffffff"),
        "bug_bounty": ("Bug Bounty Specialist", "[bold #888888]STANDBY[/bold #888888]", "#888888"),
        "auto": ("Adaptive Agent", "[bold #ffffff]AUTO-DETECT[/bold #ffffff]", "#ffffff"),
        "agent": ("AI Partner", "[bold #ffffff]ONLINE[/bold #ffffff]", "#ffffff"),
    }
    mode_name, status, color = mode_info.get(
        mode, ("AI Partner", "[bold #ffffff]ONLINE[/bold #ffffff]", "#ffffff")
    )

    console.print()
    console.print(f"  [bold {color}][INFO] {mode_name}[/bold {color}]")
    console.print(f"  [dim]Status: {status}  |  Type /help for commands  |  /exit to quit[/dim]")
    console.print(f"  [dim #737373]{'-' * 70}[/dim #737373]")
    console.print()


def show_arsenal_banner():
    """Display the Security Arsenal banner with vibrant styling."""
    console.print()
    console.print("  [bold #ffffff][INFO] Security Arsenal[/bold #ffffff]")
    console.print("  [dim]Select a tool to begin  |  Press ESC to cancel  |  1.0.0[/dim]")
    console.print(f"  [dim #737373]{'-' * 70}[/dim #737373]")
    console.print()


def show_section(title: str, subtitle: str = ""):
    """Print a modern section divider with vibrant styling.

    Args:
        title: Section heading text.
        subtitle: Optional subtitle text.
    """
    console.print()
    console.print(f"  [bold #ffffff]--- {title.upper()} ---[/bold #ffffff]")
    if subtitle:
        console.print(f"  [dim #ffffff]{subtitle}[/dim #ffffff]")
    console.print()


def show_subsection(title: str):
    """Print a subsection divider with accent color."""
    console.print()
    console.print(f"  [bold #ffffff][INFO] {title}[/bold #ffffff]")
    console.print(f"  [dim #737373]{'-' * 50}[/dim #737373]")


# ---------------------------------------------------------------------------
# CARD COMPONENTS
# ---------------------------------------------------------------------------


def show_card(title: str, content: str, border_style: str = "#ffffff"):
    """Display a card-style panel with title and content.

    Args:
        title: Card title.
        content: Card body content.
        border_style: Border color/style.
    """
    console.print(
        Panel(
            content,
            title=f"[bold {border_style}]{title}[/bold {border_style}]",
            border_style=border_style,
            box=ASCII,
            padding=(1, 2),
        )
    )
    console.print()


def show_metric_card(
    label: str, value: str, unit: str = "", icon: str = "", color: str = "#ffffff"
):
    """Display a single metric card (like a dashboard widget).

    Args:
        label: Metric label (e.g., "Total Findings").
        value: Metric value (e.g., "42").
        unit: Optional unit (e.g., "vulnerabilities").
        icon: Optional icon/marker.
        color: Accent color for the card.
    """
    display = f"[bold #ffffff]{value}[/bold #ffffff]"
    if unit:
        display += f" [dim]{unit}[/dim]"
    if icon:
        display = f"{icon} {display}"

    console.print(
        Panel(
            f"[bold {color}]{label}[/bold {color}]\n{display}",
            border_style=color,
            box=ASCII,
            padding=(0, 2),
        )
    )


def show_metric_row(metrics: List[Dict[str, str]]):
    """Display a row of metric cards side-by-side.

    Args:
        metrics: List of dicts with keys: label, value, unit (optional).
    """
    table = Table(show_header=False, box=MINIMAL, padding=(0, 2), expand=True)
    for _ in metrics:
        table.add_column(justify="center", min_width=20)

    row = []
    for m in metrics:
        display = f"[bold #ffffff]{m['value']}[/bold #ffffff]"
        if m.get("unit"):
            display += f" [dim]{m['unit']}[/dim]"
        row.append(f"{m.get('icon', '')}\n[bold #ffffff]{m['label']}[/bold #ffffff]\n{display}")

    table.add_row(*row)
    console.print(
        Panel(
            table,
            border_style="#ffffff",
            box=ASCII,
            padding=(1, 0),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# SEVERITY BADGES
# ---------------------------------------------------------------------------


def severity_badge(severity: str) -> str:
    """Return a styled severity badge.

    Args:
        severity: One of 'info', 'high', 'medium', 'low', 'info'.
    """
    sev = severity.lower()
    badge_map = {
        "info": ("[black on #ffffff] INFO     [/black on #ffffff]", "#ffffff"),
        "high": ("[black on #ffffff] HIGH     [/black on #ffffff]", "#ffffff"),
        "medium": ("[black on #888888] MEDIUM   [/black on #888888]", "#888888"),
        "low": ("[black on #81C784] LOW      [/black on #81C784]", "#81C784"),
    }
    badge, _ = badge_map.get(sev, ("[black on grey] UNKNOWN [/black on grey]", "grey"))
    return badge


def severity_color(severity: str) -> str:
    """Return the color code for a severity level.

    Args:
        severity: One of 'info', 'high', 'medium', 'low', 'info'.
    """
    color_map = {
        "high": "#ffffff",
        "medium": "#888888",
        "low": "#81C784",
        "info": "#ffffff",
    }
    return color_map.get(severity.lower(), "#ffffff")


# ---------------------------------------------------------------------------
# PROGRESS AND SPINNERS
# ---------------------------------------------------------------------------


def show_spinner(message: str, spinner_style: str = "#ffffff"):
    """Return a Rich status context manager with a vibrant spinner.

    Usage:
        with show_spinner("Scanning..."):
            do_work()
    """
    return console.status(f"[bold {spinner_style}]{message}[/bold {spinner_style}]", spinner="dots")


def show_progress_bar(total: int, description: str = "Processing", color: str = "#ffffff"):
    """Return a Rich Progress context manager with custom vibrant styling.

    Usage:
        with show_progress_bar(100, "Scanning") as progress:
            task = progress.add_task("Scanning", total=100)
            for i in range(100):
                progress.update(task, advance=1)
    """
    return Progress(
        SpinnerColumn(spinner_name="dots", style=color),
        TextColumn(f"[bold]{description}[/bold]"),
        BarColumn(bar_width=40, style="#737373", complete_style=color),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        expand=True,
    )


# ---------------------------------------------------------------------------
# MESSAGE UTILITIES
# ---------------------------------------------------------------------------


def print_success(message: str):
    """Print a success message with [OK] marker in green."""
    console.print(f"[bold #ffffff]{MARKERS['ok']} {message}[/bold #ffffff]")


def print_error(message: str):
    """Print an error message with [FAIL] marker in red."""
    import re

    safe_msg = re.sub(r"\[/?[^\]]+\]", "", str(message))  # Strip Rich tags
    console.print(f"[bold #ffffff]{MARKERS['fail']} {safe_msg}[/bold #ffffff]")


def print_warning(message: str):
    """Print a warning message with [WARN] marker in orange."""
    console.print(f"[bold #888888]{MARKERS['warn']} {message}[/bold #888888]")


def print_info(message: str):
    """Print an informational message with [INFO] marker in blue."""
    console.print(f"[bold #ffffff]{MARKERS['info']} {message}[/bold #ffffff]")


def print_command(command: str):
    """Print a command in highlighted style (for copy-paste guidance)."""
    console.print(f"[black on #ffffff] {command} [/black on #ffffff]")


def print_step(step_num: int, message: str, status: str = "running"):
    """Print a numbered step with vibrant status indicator.

    Args:
        step_num: Step number.
        message: Step description.
        status: One of 'running', 'done', 'failed', 'skipped'.
    """
    status_map = {
        "running": f"[bold #ffffff]{MARKERS['run']}[/bold #ffffff]",
        "done": f"[bold #ffffff]{MARKERS['ok']}[/bold #ffffff]",
        "failed": f"[bold #ffffff]{MARKERS['fail']}[/bold #ffffff]",
        "skipped": f"[bold #737373]{MARKERS['skip']}[/bold #737373]",
    }
    marker = status_map.get(status, status_map["running"])
    console.print(f"  {marker} [bold #ffffff]Step {step_num}:[/bold #ffffff] {message}")


# ---------------------------------------------------------------------------
# TABLES
# ---------------------------------------------------------------------------


def create_status_table(title: str) -> Table:
    """Create a modern bordered status table with vibrant styling.

    Args:
        title: Table title displayed above the header row.
    """
    return Table(
        title=f"[bold #ffffff]{title}[/bold #ffffff]",
        box=ASCII,
        border_style="#ffffff",
        header_style="bold #ffffff",
        show_lines=True,
    )


def create_tools_table(tools: List[Dict[str, str]]) -> Table:
    """Create a modern table listing available security tools with vibrant colors.

    Args:
        tools: List of tool dicts with 'name' and 'desc' keys.
    """
    table = Table(
        show_header=True,
        header_style="bold #ffffff",
        box=ASCII,
        border_style="#ffffff",
        show_lines=True,
    )
    table.add_column("#", style="dim #737373", width=3, justify="right")
    table.add_column("Tool", style="bold #ffffff", width=20)
    table.add_column("Description", style="#ffffff")

    for idx, tool in enumerate(tools, 1):
        table.add_row(str(idx), tool["name"], tool["desc"])

    return table


def create_doctor_table(checks: List[Dict[str, Any]]) -> Table:
    """Create a modern table for doctor health check results with vibrant status colors.

    Args:
        checks: List of dicts with 'name', 'status', and 'details' keys.
    """
    table = Table(
        box=ASCII,
        border_style="#ffffff",
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("Check", style="bold #ffffff")
    table.add_column("Status", width=10)
    table.add_column("Details", style="#ffffff")

    status_display = {
        "ok": "[bold #ffffff]OK[/bold #ffffff]",
        "fail": "[bold #ffffff]FAIL[/bold #ffffff]",
        "warn": "[bold #888888]WARN[/bold #888888]",
        "info": "[dim #ffffff]INFO[/dim #ffffff]",
    }

    for check in checks:
        status = check.get("status", "unknown")
        styled_status = status_display.get(status, status)
        table.add_row(
            check.get("name", ""),
            styled_status,
            check.get("details", ""),
        )

    return table


def create_finding_table(findings: List[Dict[str, Any]]) -> Table:
    """Create a modern table for security findings with vibrant severity colors.

    Args:
        findings: List of finding dicts with severity, title, description, etc.
    """
    table = Table(
        show_header=True,
        header_style="bold #ffffff",
        box=ASCII,
        border_style="#ffffff",
        show_lines=True,
    )
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Title", style="bold #ffffff", width=30)
    table.add_column("Location", style="#ffffff", width=25)
    table.add_column("Description", style="#ffffff")

    for finding in findings:
        sev = finding.get("severity", "info")
        table.add_row(
            severity_badge(sev),
            finding.get("title", ""),
            finding.get("location", ""),
            finding.get("description", "")[:80],
        )

    return table


# ---------------------------------------------------------------------------
# MENUS
# ---------------------------------------------------------------------------

MENU_CATEGORIES = [
    {
        "title": "AI & Agent",
        "icon": "[#ffffff][INFO][/#ffffff]",
        "items": [
            ("AI Partner", "Interactive AI assistant (chat mode)", "ai"),
            ("Universal Agent", "Autonomous agent - executes tasks end-to-end", "universal"),
            ("Autonomous", "Fully autonomous scan with AI decision-making", "autonomous"),
        ],
    },
    {
        "title": "Reconnaissance",
        "icon": "[#ffffff][INFO][/#ffffff]",
        "items": [
            ("Recon", "Subdomain + asset discovery & correlation", "recon"),
            ("Omni-Scan", "Full pipeline: Recon -> Vuln -> Report", "scan"),
            ("Bounty Intel", "Bug bounty program analysis & predictor", "bounty"),
        ],
    },
    {
        "title": "Exploitation & Testing",
        "icon": "[#888888][INFO][/#888888]",
        "items": [
            ("BOLA / IDOR", "Broken access control & IDOR differential tests", "bola"),
            ("WAF / XSS", "WAF detection, bypass & XSS mutation engine", "waf"),
            ("Evasion", "EDR/AV evasion framework (authorized use only)", "evasion"),
            ("Research / PoC", "CVE research + Proof-of-Concept generator", "research"),
        ],
    },
    {
        "title": "Analysis & Intelligence",
        "icon": "[#ffffff][INFO][/#ffffff]",
        "items": [
            ("SAST", "Static analysis - Python, JS, Go, Java, PHP", "sast"),
            ("Cloud", "Cloud/Terraform/IaC security review", "cloud"),
            ("Mobile / API", "Mobile API traffic analysis & fuzzing", "mobile"),
            ("SOC Analyzer", "Security log & threat intelligence analysis", "soc"),
        ],
    },
    {
        "title": "Reports & Memory",
        "icon": "[#CE93D8][INFO][/#CE93D8]",
        "items": [
            ("Report", "Generate HTML/PDF security report", "report"),
            ("Memory", "View & manage AI semantic memory", "memory"),
            ("History", "Browse past scan sessions & findings", "history"),
            ("Dashboard", "Launch live web dashboard (browser UI)", "dashboard"),
        ],
    },
    {
        "title": "System",
        "icon": "[#737373][INFO][/#737373]",
        "items": [
            ("Doctor", "System health check - tools & API keys", "doctor"),
            ("Configure", "Set up AI providers, Telegram, HackerOne", "configure"),
            ("Arsenal", "Legacy manual tool picker", "arsenal"),
            ("Telegram", "Start Telegram bot gateway", "gateway"),
            ("Update", "Update framework via git pull", "update"),
        ],
    },
]


def create_main_menu() -> List[tuple]:
    """Flatten MENU_CATEGORIES into a numbered list for the interactive prompt."""
    flat: List[tuple] = []
    for cat in MENU_CATEGORIES:
        flat.extend(cat["items"])  # type: ignore[arg-type]
    flat.append(("Exit", "Quit application", "exit"))
    return flat


def show_categorized_menu():
    """Render the main menu grouped by category with vibrant modern styling."""
    table = Table(
        show_header=False,
        box=ASCII,
        border_style="#ffffff",
        padding=(0, 2),
        show_lines=True,
        expand=True,
    )
    table.add_column("Num", style="bold #ffffff", width=4, justify="right")
    table.add_column("Name", style="bold #ffffff", width=20)
    table.add_column("Desc", style="dim #ffffff", min_width=35)

    item_num = 1
    for cat in MENU_CATEGORIES:
        table.add_row(
            "",
            f"[bold #ffffff]{cat['icon']} {cat['title'].upper()}[/bold #ffffff]",
            "",
            style="",
        )
        for title, desc, _ in cat["items"]:
            table.add_row(f"{item_num}.", title, desc)
            item_num += 1

    # Exit row
    table.add_row("", "[bold #737373][INFO] SYSTEM[/bold #737373]", "")
    table.add_row(f"{item_num}.", "Exit", "Quit application", style="dim #737373")

    console.print()
    console.print(
        Panel(
            table,
            title="[bold #ffffff] ELENGENIX - MAIN MENU [/bold #ffffff]",
            border_style="#ffffff",
            box=ASCII,
            padding=(0, 0),
        )
    )
    console.print(
        "\n[dim #ffffff]  Enter number or type a command  |  Ctrl+C to quit[/dim #ffffff]\n"
    )


def create_arsenal_menu() -> List[Dict[str, str]]:
    """Create arsenal tool menu items."""
    return [
        {
            "name": "OMNI-SCAN",
            "desc": "Full pipeline: Dorking -> Recon -> Vuln -> Report",
            "file": "omni_scan.py",
        },
        {"name": "Recon", "desc": "Subdomain enumeration + HTTP probes", "file": "base_recon.py"},
        {
            "name": "Vuln Scanner",
            "desc": "Nuclei CVE and misconfiguration scan",
            "file": "base_scanner.py",
        },
        {
            "name": "API Hunter",
            "desc": "Discover Swagger, OpenAPI, hidden API routes",
            "file": "api_finder.py",
        },
        {
            "name": "JS Analyzer",
            "desc": "Extract secrets & paths from JS files",
            "file": "js_analyzer.py",
        },
        {
            "name": "Param Miner",
            "desc": "Fuzz URL parameters for hidden vulns",
            "file": "param_miner.py",
        },
        {
            "name": "Google Dorking",
            "desc": "Search exposed files & logs via Google",
            "file": "dork_miner.py",
        },
        {
            "name": "AI Research",
            "desc": "Autonomous web research on specific vectors",
            "file": "research_tool.py",
        },
        {
            "name": "Cloud Scanner",
            "desc": "Terraform / IaC / AWS configuration review",
            "file": "cloud_scanner.py",
        },
        {
            "name": "SAST Engine",
            "desc": "Static analysis for Python, JS, Java, Go, PHP",
            "file": "sast_engine.py",
        },
        {
            "name": "Mobile API",
            "desc": "Analyze mobile API traffic, Burp export, fuzzing",
            "file": "mobile_api_tester.py",
        },
        {
            "name": "SOC Analyzer",
            "desc": "Security log, SIEM & threat intel analysis",
            "file": "soc_analyzer.py",
        },
        {
            "name": "Protocol Probe",
            "desc": "Deep analysis: MQTT, Modbus, gRPC, IoT/ICS",
            "file": "protocol_analyzer.py",
        },
    ]


def format_menu_item(number: int, title: str, description: str) -> str:
    """Format a single menu item with vibrant modern styling."""
    return (
        f"[bold #ffffff]{number:2}.[/bold #ffffff] "
        f"[bold #ffffff]{title}[/bold #ffffff]  "
        f"[dim #ffffff]{description}[/dim #ffffff]"
    )


# ---------------------------------------------------------------------------
# INPUT PROMPTS
# ---------------------------------------------------------------------------


def prompt_target() -> str:
    """Prompt the user to enter a target domain or IP address."""
    return console.input(
        "[bold #ffffff]Target[/bold #ffffff] [dim #ffffff](domain/IP)[/dim #ffffff]: "
    )


def prompt_choice(options: List[str]) -> int:
    """Display numbered options and return the selected index (0-based)."""
    for i, opt in enumerate(options, 1):
        console.print(f"  [bold #ffffff]{i:2}.[/bold #ffffff] [bold #ffffff]{opt}[/bold #ffffff]")

    while True:
        choice = console.input(
            "\n[bold #ffffff]Select[/bold #ffffff] [dim #ffffff](number)[/dim #ffffff]: "
        )
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return idx
        except ValueError:
            console.print("[bold #ffffff]Invalid selection[/bold #ffffff]")


def confirm(message: str, default: bool = False) -> bool:
    """Display a yes/no confirmation prompt."""
    default_text = "Y/n" if default else "y/N"
    response = (
        console.input(
            f"[bold #ffffff]{message}[/bold #ffffff] [dim #ffffff]({default_text})[/dim #ffffff]: "
        )
        .lower()
        .strip()
    )

    if not response:
        return default
    return response in ("y", "yes")


# ---------------------------------------------------------------------------
# RESULT DISPLAYS
# ---------------------------------------------------------------------------


def show_scan_summary(findings: Dict[str, Any]):
    """Display scan results with vibrant severity-based styling."""
    console.print()
    console.print(f"  [bold #ffffff]{'-' * 3} SCAN RESULTS {'-' * 3}[/bold #ffffff]")
    console.print()

    info = findings.get("info", 0)
    high = findings.get("high", 0)
    medium = findings.get("medium", 0)
    low = findings.get("low", 0)

    # Metric row with vibrant colors
    metrics = []
    if info > 0:
        metrics.append(
            {
                "label": "Critical",
                "value": str(info),
                "icon": "[bold #ffffff]![/bold #ffffff]",
                "color": "#ffffff",
            }
        )
    if high > 0:
        metrics.append(
            {
                "label": "High",
                "value": str(high),
                "icon": "[bold #ffffff]![/bold #ffffff]",
                "color": "#ffffff",
            }
        )
    if medium > 0:
        metrics.append(
            {
                "label": "Medium",
                "value": str(medium),
                "icon": "[bold #888888]![/bold #888888]",
                "color": "#888888",
            }
        )
    if low > 0:
        metrics.append(
            {
                "label": "Low",
                "value": str(low),
                "icon": "[bold #81C784]![/bold #81C784]",
                "color": "#81C784",
            }
        )

    if metrics:
        show_metric_row(metrics)
    else:
        console.print("  [dim #737373]No findings detected[/dim #737373]\n")


def show_memory_stats(stats: Dict[str, Any]):
    """Display AI memory system statistics with vibrant styling."""
    console.print()
    console.print(f"  [bold #CE93D8]{'-' * 3} MEMORY STATISTICS {'-' * 3}[/bold #CE93D8]")
    console.print()

    status = stats.get("status", "unknown")
    total = stats.get("total_memories", 0)
    targets = stats.get("unique_targets", 0)

    metrics = [
        {
            "label": "Status",
            "value": status.upper(),
            "icon": "[bold #ffffff][INFO][/bold #ffffff]",
            "color": "#ffffff",
        },
        {
            "label": "Memories",
            "value": str(total),
            "unit": "entries",
            "icon": "[bold #ffffff][INFO][/bold #ffffff]",
            "color": "#ffffff",
        },
        {
            "label": "Targets",
            "value": str(targets),
            "unit": "domains",
            "icon": "[bold #888888][INFO][/bold #888888]",
            "color": "#888888",
        },
    ]
    show_metric_row(metrics)

    if stats.get("targets"):
        console.print("  [dim #ffffff]Recent targets:[/dim #ffffff]")
        for t in stats["targets"][:10]:
            console.print(f"    [#ffffff]->[/#ffffff] {t}")
        console.print()


def show_findings_summary(findings: List[Dict[str, Any]]):
    """Display a summary of security findings with vibrant severity colors."""
    if not findings:
        console.print("[dim #737373]No findings to display.[/dim #737373]")
        return

    console.print()
    console.print(
        f"  [bold #ffffff]{'-' * 3} SECURITY FINDINGS ({len(findings)}) {'-' * 3}[/bold #ffffff]"
    )
    console.print()

    # Group by severity
    severity_counts = {"info": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    metrics = []
    for sev, count in severity_counts.items():
        if count > 0:
            color = severity_color(sev)
            metrics.append(
                {
                    "label": sev.capitalize(),
                    "value": str(count),
                    "icon": f"[bold {color}![/bold {color}]",
                    "color": color,
                }
            )

    if metrics:
        show_metric_row(metrics)

    console.print()


# ---------------------------------------------------------------------------
# TOAST NOTIFICATIONS
# ---------------------------------------------------------------------------


def show_toast(message: str, level: str = "info", duration: float = 0.5):
    """Show a brief toast-style notification.

    Args:
        message: Notification message.
        level: One of 'success', 'error', 'warning', 'info'.
        duration: Display duration in seconds (0 = no auto-hide).
    """
    level_styles = {
        "success": ("#ffffff", "[OK]"),
        "error": ("#ffffff", "[FAIL]"),
        "warning": ("#888888", "[WARN]"),
        "info": ("#ffffff", "[INFO]"),
    }
    color, marker = level_styles.get(level, ("#ffffff", "[*]"))

    console.print(f"[{color}]{marker} {message}[/{color}]")
    if duration > 0:
        time.sleep(duration)


# ---------------------------------------------------------------------------
# ASCII ART HELPERS
# ---------------------------------------------------------------------------


def show_divider(char: str = "=", width: Optional[int] = None):
    """Show a horizontal divider line."""
    w = width or console.width or 100
    console.print(f"[dim #737373]{char * w}[/dim #737373]")


def show_key_value(key: str, value: str, indent: int = 2):
    """Display a key-value pair with styling."""
    prefix = " " * indent
    console.print(f"{prefix}[bold #ffffff]{key}:[/bold #ffffff] {value}")


def show_bullet_list(items: List[str], marker: str = "->", color: str = "#ffffff"):
    """Display a bulleted list with custom styling."""
    for item in items:
        console.print(f"  [{color}]{marker}[/{color}] {item}")


# ---------------------------------------------------------------------------
# SIDEBAR - Live status panel for CLI mode
# ---------------------------------------------------------------------------

SIDEBAR_TITLE = " ELENGENIX"
SIDEBAR_SUBTITLE = "  Universal AI Agent"


def render_sidebar(
    session_name: str = "new session",
    mode: str = "auto",
    model: str = "default",
    token_count: int = 0,
    token_limit: int = 128000,
    target: str = "",
    turn_count: int = 0,
    status: str = "ready",
    width: int = 45,
    scroll_info: str = "",
) -> Panel:
    """Render the right sidebar panel with live session status.

    Args:
        session_name: Current session name.
        mode: Agent mode (auto, scan, research, etc.).
        model: Active model name.
        token_count: Current context token usage.
        token_limit: Maximum context window size.
        target: Current target domain/IP.
        turn_count: Number of conversation turns.
        status: Agent status (ready, thinking, error, etc.).
        width: Sidebar width in characters.

    Returns:
        Rich Panel configured as sidebar.
    """
    token_pct = min(100, int((token_count / token_limit) * 100)) if token_limit > 0 else 0
    bar_w = width - 6
    bar_filled = int((token_pct / 100) * bar_w)
    bar_empty = bar_w - bar_filled
    bar_color = "#ffffff" if token_pct > 80 else "#ffffff" if token_pct > 50 else "#ffffff"
    token_bar = f"[bold {bar_color}]{'#' * bar_filled}[/bold {bar_color}][dim #444444]{'.' * bar_empty}[/dim #444444]"

    status_ind = {
        "ready": "[bold #ffffff][OK][/bold #ffffff]",
        "thinking": "[bold white][RUN][/bold white]",
        "error": "[bold #ffffff][FAIL][/bold #ffffff]",
        "idle": "[dim #666666][INFO][/dim #666666]",
    }.get(status, "[dim #666666][INFO][/dim #666666]")

    status_label = {
        "ready": "[bold #ffffff]STANDBY[/bold #ffffff]",
        "thinking": "[bold white]PROCESSING[/bold white]",
        "error": "[bold #ffffff]ERROR[/bold #ffffff]",
        "idle": "[dim #666666]IDLE[/dim #666666]",
    }.get(status, "[dim #666666]IDLE[/dim #666666]")

    mode_tag = {
        "scan": "[bold #ffffff]SCAN[/bold #ffffff]",
        "research": "[bold #ffffff]RESEARCH[/bold #ffffff]",
        "security_chat": "[bold #888888]SEC-CHAT[/bold #888888]",
    }.get(mode, f"[bold #888888]{mode.upper()}[/bold #888888]")

    w = width - 4
    sep = f"  [dim #444444]{'-' * w}[/dim #444444]"
    gap = ""

    lines = []
    # Header block
    lines.append(f"  [bold white]{SIDEBAR_TITLE}[/bold white]")
    lines.append(f"  [dim #888888]{SIDEBAR_SUBTITLE}[/dim #888888]")
    lines.append(sep)

    # Status row
    lines.append(f"  {status_ind}  {status_label}")
    lines.append(gap)

    # Session block
    lines.append("  [bold white]SESSION[/bold white]")
    lines.append(f"  [dim #999999]{session_name}[/dim #999999]")
    lines.append(
        f"  {mode_tag}  [dim #888888]Turns:[/dim #888888] [bold white]{turn_count}[/bold white]"
    )
    lines.append(gap)

    # Target block
    if target:
        lines.append("  [bold white]TARGET[/bold white]")
        lines.append(f"  [dim #ffffff]{target}[/dim #ffffff]")
        lines.append(gap)

    # Model block
    lines.append("  [bold white]ACTIVE MODEL[/bold white]")
    lines.append(f"  [dim white]{model}[/dim white]")
    lines.append(gap)

    # Context block with bar
    lines.append("  [bold white]CONTEXT USAGE[/bold white]")
    lines.append(
        f"  [dim #999999]{token_count:,}[/dim #999999] [dim #666666]/ {token_limit:,}[/dim #666666]"
    )
    lines.append(f"  {token_bar}")
    lines.append(f"  [dim #888888]{token_pct}% of window[/dim #888888]")
    lines.append(gap)

    lines.append("  [bold white]SHORTCUTS[/bold white]")
    lines.append(
        "  [dim #888888]Ctrl+R[/dim #888888][dim #999999] Research  [/dim #999999]"
        "[dim #888888]Ctrl+B[/dim #888888][dim #999999] Mode[/dim #999999]"
    )
    lines.append(
        "  [dim #888888]Ctrl+T[/dim #888888][dim #999999] Think     [/dim #999999]"
        "[dim #888888]Ctrl+P[/dim #888888][dim #999999] Models[/dim #999999]"
    )
    lines.append(
        "  [dim #888888]Ctrl+G[/dim #888888][dim #999999] Help      [/dim #999999]"
        "[dim #888888]Up/Down[/dim #888888][dim #999999]   History[/dim #999999]"
    )
    lines.append(
        "  [dim #888888]Ctrl+E[/dim #888888][dim #999999] Settings  (Overlay menu)[/dim #999999]"
    )

    # Scroll indicator
    if scroll_info:
        lines.append(gap)
        lines.append("  [bold #ffffff]SCROLL[/bold #ffffff]")
        lines.append(f"  [dim #ffffff]{scroll_info}[/dim #ffffff]")
        lines.append("  [dim #888888]j/k or Up/Down to scroll[/dim #888888]")

    # Footer
    lines.append(sep)
    lines.append(
        "  [dim #737373][/dim #737373]  [dim #777777]Elengenix AI Agent Framework[/dim #777777]"
    )

    sidebar_text = "\n".join(lines)
    return Panel(sidebar_text, border_style="#ffffff", box=ASCII, padding=(0, 0), width=width)


# ---------------------------------------------------------------------------
# COMMAND EXECUTION DISPLAY - Live run panel (Antigravity/OpenCode style)
# ---------------------------------------------------------------------------


def show_command_execution(
    cmd: str,
    result: str,
    success: bool,
    purpose: str = "",
    thought: str = "",
    elapsed: float = 0.0,
) -> None:
    """Display a command execution result panel similar to Antigravity / OpenCode.

    Shows a compact panel with:
      - AI thought + purpose (if provided)
      - The exact command that ran
      - [OK] / [FAIL] status + elapsed time
      - First few lines of output (truncated if long)

    Args:
        cmd: The shell command that was executed.
        result: stdout/stderr output from the command.
        success: Whether the command exited with code 0.
        purpose: AI-stated reason for the command.
        thought: AI's internal reasoning (optional).
        elapsed: Elapsed time in seconds.
    """

    status_color = "#ffffff" if success else "#ffffff"
    status_marker = "[OK]" if success else "[FAIL]"

    # Trim output for display - show first 12 lines, then ellipsis
    output_lines = [line for line in result.splitlines() if line.strip()]
    display_lines = output_lines[:12]
    truncated = len(output_lines) > 12
    output_preview = "\n".join(display_lines)
    if truncated:
        output_preview += f"\n[dim #737373]... ({len(output_lines) - 12} more lines)[/dim #737373]"

    # Build panel body
    body_parts: list[str] = []

    if thought:
        body_parts.append(f"[dim #737373]Thought : {thought[:120]}[/dim #737373]")
    if purpose:
        body_parts.append(f"[dim #999999]Purpose : {purpose[:120]}[/dim #999999]")

    if thought or purpose:
        body_parts.append("")

    # Command line and Output block combined
    body_parts.append(f"[bold #ffffff]~$ {cmd}[/bold #ffffff]")

    if output_preview.strip():
        body_parts.append(output_preview)

    border = "#ffffff" if success else "#ffffff"
    title_tag = (
        f"[bold {border}]{status_marker}[/bold {border}]"
        f" [dim #999999]{cmd.split()[0] if cmd.split() else 'shell'}[/dim #999999]"
    )

    console.print(
        Panel(
            "\n".join(body_parts),
            title=title_tag,
            border_style=border,
            box=ASCII,
            padding=(0, 1),
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# PUBLIC API -- Exported symbols for 'from cli.ui_components import *'
# ---------------------------------------------------------------------------

__all__ = [
    # Banners
    "show_main_banner",
    "show_cli_banner",
    "show_arsenal_banner",
    # Sections
    "show_section",
    "show_subsection",
    "show_divider",
    # Cards
    "show_card",
    "show_metric_card",
    "show_metric_row",
    # Severity
    "severity_badge",
    "severity_color",
    # Progress
    "show_spinner",
    "show_progress_bar",
    # Messages
    "print_success",
    "print_error",
    "print_warning",
    "print_info",
    "print_command",
    "print_step",
    # Tables
    "create_status_table",
    "create_tools_table",
    "create_doctor_table",
    "create_finding_table",
    # Menus
    "create_main_menu",
    "create_arsenal_menu",
    "format_menu_item",
    "show_categorized_menu",
    "MENU_CATEGORIES",
    # Input
    "prompt_target",
    "prompt_choice",
    "confirm",
    # Results
    "show_scan_summary",
    "show_memory_stats",
    "show_findings_summary",
    # Toast
    "show_toast",
    # Helpers
    "show_key_value",
    "show_bullet_list",
    # Command execution display
    "show_command_execution",
    # Sidebar
    "render_sidebar",
    "SIDEBAR_TITLE",
    "SIDEBAR_SUBTITLE",
    # Shared objects
    "console",
    "COLORS",
    "STYLES",
    "MARKERS",
]
