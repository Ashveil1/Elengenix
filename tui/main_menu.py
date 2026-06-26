"""tui/main_menu.py - Interactive Main Menu System for Elengenix TUI.

Provides:
    * :class:`MainMenu` - Interactive main menu with all features
    * :func:`run_main_menu` - Run the main menu

Features:
    - Interactive selection with questionary
    - Beautiful visual design
    - All features accessible from menus
    - Sub-menus for each category
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.align import Align
from rich.box import HEAVY, ROUNDED, SIMPLE
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger("elengenix.tui.main_menu")


# ── Menu Items ──────────────────────────────────────────────────────────────

MENU_ITEMS = {
    "scan": {
        "title": "Scan Target",
        "description": "Run security scan on a target",
        "icon": "[SCAN]",
        "action": "scan",
    },
    "recon": {
        "title": "Reconnaissance",
        "description": "DNS, HTTP, port discovery",
        "icon": "[RECON]",
        "action": "recon",
    },
    "tools": {
        "title": "Security Tools",
        "description": "Access individual scanners",
        "icon": "[TOOLS]",
        "action": "tools",
    },
    "reports": {
        "title": "View Reports",
        "description": "Browse past scan reports",
        "icon": "[RPT]",
        "action": "reports",
    },
    "memory": {
        "title": "AI Memory",
        "description": "Search and manage AI memory",
        "icon": "[MEM]",
        "action": "memory",
    },
    "settings": {
        "title": "Settings",
        "description": "Theme, providers, configuration",
        "icon": "[SET]",
        "action": "settings",
    },
    "help": {
        "title": "Help",
        "description": "Commands and shortcuts",
        "icon": "[?]",
        "action": "help",
    },
    "exit": {
        "title": "Exit",
        "description": "Exit Elengenix",
        "icon": "[X]",
        "action": "exit",
    },
}


# ── Scan Menu ───────────────────────────────────────────────────────────────

SCAN_OPTIONS = [
    {"label": "Quick Scan", "description": "Fast vulnerability scan", "args": {"mode": "quick"}},
    {
        "label": "Full Scan",
        "description": "Comprehensive security assessment",
        "args": {"mode": "full"},
    },
    {"label": "Custom Scan", "description": "Choose specific scanners", "args": {"mode": "custom"}},
    {"label": "Back", "description": "Return to main menu", "args": {}},
]


# ── Tools Menu ──────────────────────────────────────────────────────────────

TOOL_CATEGORIES = {
    "Reconnaissance": [
        {
            "name": "Python Recon",
            "module": "python_recon",
            "description": "HTTP probe and directory discovery",
        },
        {"name": "API Finder", "module": "api_finder", "description": "Discover API endpoints"},
    ],
    "Vulnerability Scanning": [
        {
            "name": "SSRF Scanner",
            "module": "ssrf_scanner",
            "description": "Server-Side Request Forgery",
        },
        {
            "name": "SSTI Scanner",
            "module": "ssti_scanner",
            "description": "Server-Side Template Injection",
        },
        {"name": "XXE Scanner", "module": "xxe_scanner", "description": "XML External Entity"},
        {
            "name": "Deserialization",
            "module": "deserialization_scanner",
            "description": "Insecure deserialization",
        },
        {
            "name": "GraphQL Scanner",
            "module": "graphql_scanner",
            "description": "GraphQL vulnerabilities",
        },
    ],
    "API Security": [
        {"name": "CORS Checker", "module": "cors_checker", "description": "CORS misconfiguration"},
        {"name": "JWT Tester", "module": "jwt_tester", "description": "JWT vulnerabilities"},
        {
            "name": "API Schema Diff",
            "module": "api_schema_diff",
            "description": "Schema drift detection",
        },
    ],
    "Business Logic": [
        {
            "name": "Logic Flaw Engine",
            "module": "logic_flaw_engine",
            "description": "Business logic vulnerabilities",
        },
        {
            "name": "Race Condition Tester",
            "module": "race_condition_tester",
            "description": "Race conditions",
        },
    ],
    "Supply Chain": [
        {
            "name": "Supply Chain Analyzer",
            "module": "supply_chain_analyzer",
            "description": "Dependency vulnerabilities",
        },
    ],
}


# ── Settings Menu ───────────────────────────────────────────────────────────

SETTINGS_OPTIONS = [
    {"label": "Theme", "description": "Change color theme"},
    {"label": "AI Provider", "description": "Configure AI provider"},
    {"label": "Scan Options", "description": "Default scan settings"},
    {"label": "Export Settings", "description": "Report export options"},
    {"label": "Back", "description": "Return to main menu"},
]


# ── Main Menu Functions ─────────────────────────────────────────────────────


def render_main_menu(
    primary: str = "#ff2222",
    text_color: str = "#ffffff",
    muted: str = "#888888",
) -> Panel:
    """Render the main menu as a Rich Panel.

    Args:
        primary: Primary theme color.
        text_color: Main text color.
        muted: Muted text color.

    Returns:
        Rich Panel with main menu.
    """
    table = Table(
        show_header=True,
        header_style=f"bold {primary}",
        box=SIMPLE,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("#", width=4, justify="right")
    table.add_column("Option", width=20)
    table.add_column("Description", style=muted)

    for i, (key, item) in enumerate(MENU_ITEMS.items(), 1):
        table.add_row(
            str(i),
            f"[bold]{item['title']}[/bold]",
            item["description"],
        )

    return Panel(
        table,
        title=f"[bold {primary}]ELENGENIX MAIN MENU[/bold {primary}]",
        border_style=primary,
        box=ROUNDED,
        padding=(0, 1),
    )


def render_scan_menu(
    primary: str = "#ff2222",
    text_color: str = "#ffffff",
    muted: str = "#888888",
) -> Panel:
    """Render the scan menu as a Rich Panel.

    Args:
        primary: Primary theme color.
        text_color: Main text color.
        muted: Muted text color.

    Returns:
        Rich Panel with scan menu.
    """
    table = Table(
        show_header=True,
        header_style=f"bold {primary}",
        box=SIMPLE,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("#", width=4, justify="right")
    table.add_column("Scan Type", width=20)
    table.add_column("Description", style=muted)

    for i, option in enumerate(SCAN_OPTIONS, 1):
        table.add_row(
            str(i),
            f"[bold]{option['label']}[/bold]",
            option["description"],
        )

    return Panel(
        table,
        title=f"[bold {primary}]SCAN TARGET[/bold {primary}]",
        border_style=primary,
        box=ROUNDED,
        padding=(0, 1),
    )


def render_tools_menu(
    primary: str = "#ff2222",
    text_color: str = "#ffffff",
    muted: str = "#888888",
) -> Panel:
    """Render the tools menu as a Rich Panel.

    Args:
        primary: Primary theme color.
        text_color: Main text color.
        muted: Muted text color.

    Returns:
        Rich Panel with tools menu.
    """
    table = Table(
        show_header=True,
        header_style=f"bold {primary}",
        box=SIMPLE,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("Category", width=20, style=f"bold {primary}")
    table.add_column("Tool", width=20)
    table.add_column("Description", style=muted)

    for category, tools in TOOL_CATEGORIES.items():
        for i, tool in enumerate(tools):
            table.add_row(
                category if i == 0 else "",
                tool["name"],
                tool["description"],
            )

    return Panel(
        table,
        title=f"[bold {primary}]SECURITY TOOLS[/bold {primary}]",
        border_style=primary,
        box=ROUNDED,
        padding=(0, 1),
    )


def render_settings_menu(
    primary: str = "#ff2222",
    text_color: str = "#ffffff",
    muted: str = "#888888",
) -> Panel:
    """Render the settings menu as a Rich Panel.

    Args:
        primary: Primary theme color.
        text_color: Main text color.
        muted: Muted text color.

    Returns:
        Rich Panel with settings menu.
    """
    table = Table(
        show_header=True,
        header_style=f"bold {primary}",
        box=SIMPLE,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("#", width=4, justify="right")
    table.add_column("Setting", width=20)
    table.add_column("Description", style=muted)

    for i, option in enumerate(SETTINGS_OPTIONS, 1):
        table.add_row(
            str(i),
            f"[bold]{option['label']}[/bold]",
            option["description"],
        )

    return Panel(
        table,
        title=f"[bold {primary}]SETTINGS[/bold {primary}]",
        border_style=primary,
        box=ROUNDED,
        padding=(0, 1),
    )


# ── Menu Runner ─────────────────────────────────────────────────────────────


def run_main_menu() -> None:
    """Run the interactive main menu."""
    try:
        import questionary
    except ImportError:
        print("questionary not installed. Install with: pip install questionary")
        return

    while True:
        # Clear screen
        os.system("clear" if os.name != "nt" else "cls")

        # Print banner
        from tui.welcome import ascii_logo

        logo = ascii_logo()
        print(logo)
        print()

        # Get user choice
        choices = [item["title"] for item in MENU_ITEMS.values()]
        choice = questionary.select(
            "Select an option:",
            choices=choices,
        ).ask()

        if choice is None:
            break

        # Find action
        action = None
        for key, item in MENU_ITEMS.items():
            if item["title"] == choice:
                action = item["action"]
                break

        if action == "exit":
            break
        elif action == "scan":
            run_scan_menu()
        elif action == "tools":
            run_tools_menu()
        elif action == "settings":
            run_settings_menu()
        elif action == "memory":
            run_memory_menu()
        elif action == "help":
            run_help_menu()
        elif action == "recon":
            run_recon_menu()
        elif action == "reports":
            run_reports_menu()


def run_scan_menu() -> None:
    """Run the scan menu."""
    try:
        import questionary
    except ImportError:
        print("questionary not installed")
        return

    # Get target
    target = questionary.text("Enter target domain/IP:").ask()
    if not target:
        return

    # Get scan type
    scan_type = questionary.select(
        "Select scan type:",
        choices=[opt["label"] for opt in SCAN_OPTIONS],
    ).ask()

    if scan_type == "Back":
        return

    # Find scan mode
    mode = "full"
    for opt in SCAN_OPTIONS:
        if opt["label"] == scan_type:
            mode = opt["args"].get("mode", "full")
            break

    # Run scan
    print(f"\nStarting {scan_type} on {target}...")
    os.system(f"python3 main.py scan {target}")


def run_tools_menu() -> None:
    """Run the tools menu."""
    try:
        import questionary
    except ImportError:
        print("questionary not installed")
        return

    # Flatten tools
    all_tools = []
    for category, tools in TOOL_CATEGORIES.items():
        for tool in tools:
            all_tools.append(f"{tool['name']} - {tool['description']}")

    # Add back option
    all_tools.append("Back")

    choice = questionary.select(
        "Select a tool:",
        choices=all_tools,
    ).ask()

    if choice == "Back" or choice is None:
        return

    # Find tool module
    for category, tools in TOOL_CATEGORIES.items():
        for tool in tools:
            if f"{tool['name']} - {tool['description']}" == choice:
                print(f"\nRunning {tool['name']}...")
                # Here you would run the actual tool
                print(f"Tool {tool['module']} would be executed here")
                break


def run_settings_menu() -> None:
    """Run the settings menu."""
    try:
        import questionary
    except ImportError:
        print("questionary not installed")
        return

    while True:
        choice = questionary.select(
            "Select setting:",
            choices=[opt["label"] for opt in SETTINGS_OPTIONS],
        ).ask()

        if choice == "Back" or choice is None:
            break

        if choice == "Theme":
            run_theme_selector()
        elif choice == "AI Provider":
            print("Configure AI provider...")
        elif choice == "Scan Options":
            print("Configure scan options...")


def run_theme_selector() -> None:
    """Run the theme selector."""
    try:
        import questionary
    except ImportError:
        print("questionary not installed")
        return

    from tui.themes import THEMES

    theme_names = list(THEMES.keys())
    choice = questionary.select(
        "Select theme:",
        choices=theme_names,
    ).ask()

    if choice:
        print(f"Theme changed to: {choice}")


def run_memory_menu() -> None:
    """Run the memory menu."""
    try:
        import questionary
    except ImportError:
        print("questionary not installed")
        return

    while True:
        choice = questionary.select(
            "Select action:",
            choices=[
                "Search memories",
                "List all targets",
                "Clear target memory",
                "Back",
            ],
        ).ask()

        if choice == "Back" or choice is None:
            break

        if choice == "Search memories":
            query = questionary.text("Enter search query:").ask()
            if query:
                from tools.vector_memory import recall

                results = recall(query, n_results=5)
                print(f"\nFound {len(results)} memories:")
                for r in results:
                    print(f"  - {r.get('content', '')[:80]}...")
        elif choice == "List all targets":
            print("Listing targets...")
        elif choice == "Clear target memory":
            target = questionary.text("Enter target to clear:").ask()
            if target:
                print(f"Clearing memory for {target}...")


def run_recon_menu() -> None:
    """Run the recon menu."""
    try:
        import questionary
    except ImportError:
        print("questionary not installed")
        return

    target = questionary.text("Enter target domain:").ask()
    if target:
        print(f"\nStarting reconnaissance on {target}...")
        os.system(f"python3 main.py recon {target}")


def run_reports_menu() -> None:
    """Run the reports menu."""
    try:
        import questionary
    except ImportError:
        print("questionary not installed")
        return

    reports_dir = Path("reports")
    if not reports_dir.exists():
        print("No reports found.")
        return

    reports = list(reports_dir.glob("*.html")) + list(reports_dir.glob("*.md"))
    if not reports:
        print("No reports found.")
        return

    choices = [r.name for r in reports] + ["Back"]
    choice = questionary.select(
        "Select a report:",
        choices=choices,
    ).ask()

    if choice and choice != "Back":
        print(f"Opening {choice}...")


def run_help_menu() -> None:
    """Run the help menu."""
    print(
        """
╔══════════════════════════════════════════════════════════════╗
║                    ELENGENIX HELP                           ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  COMMANDS:                                                   ║
║    elengenix scan <target>     - Run security scan          ║
║    elengenix recon <target>    - Run reconnaissance         ║
║    elengenix doctor            - System health check        ║
║    elengenix configure         - Configure settings         ║
║                                                              ║
║  SCANNERS:                                                   ║
║    - SSRF Scanner           - Server-Side Request Forgery   ║
║    - SSTI Scanner           - Template Injection            ║
║    - XXE Scanner            - XML External Entity           ║
║    - CORS Checker           - CORS Misconfiguration         ║
║    - JWT Tester             - JWT Vulnerabilities           ║
║    - And more...                                            ║
║                                                              ║
║  TIPS:                                                       ║
║    - Use /help in TUI for more commands                     ║
║    - All scanners are built-in Python modules               ║
║    - No external tools required                              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    )
    input("\nPress Enter to continue...")


__all__ = [
    "MENU_ITEMS",
    "SCAN_OPTIONS",
    "TOOL_CATEGORIES",
    "SETTINGS_OPTIONS",
    "render_main_menu",
    "render_scan_menu",
    "render_tools_menu",
    "render_settings_menu",
    "run_main_menu",
    "run_scan_menu",
    "run_tools_menu",
    "run_settings_menu",
    "run_memory_menu",
    "run_recon_menu",
    "run_reports_menu",
    "run_help_menu",
]
