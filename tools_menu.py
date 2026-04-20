"""
Elengenix - Tools Menu (Fixed)
Based on original by Ashveil1 (MIT License)
Fixes:
  - os.system() Shell Injection จาก user input → subprocess.run() list args
  - ไม่ validate target input → เพิ่ม validation
  - tools list มี ... placeholder → ทำให้สมบูรณ์
  - ไม่มี error handling เมื่อ tool รันไม่ได้
"""

import os
import sys
import subprocess
import logging

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

logger = logging.getLogger(__name__)
console = Console()

# ── อักขระที่ห้ามมีใน target (ป้องกัน injection) ────────────
FORBIDDEN_CHARS = set(';|&`$()><\n\r\t\\\'\"')


def _validate_target(target: str) -> bool:
    """ตรวจ target ว่าปลอดภัยพอที่จะส่งเป็น argument ไหม"""
    if not target or not target.strip():
        return False
    if any(c in target for c in FORBIDDEN_CHARS):
        return False
    # ความยาวสมเหตุสมผล
    if len(target) > 253:
        return False
    return True


# ── Tool Definitions ──────────────────────────────────────────
TOOLS = [
    {
        "name":  "OMNI-SCAN (Full Chaos)",
        "desc":  "Run EVERYTHING: Dorking -> Recon -> API -> Nuclei -> JS -> Params -> Report",
        "file":  "omni_scan.py",
    },
    {
        "name":  "Recon & Discovery",
        "desc":  "Find subdomains and check live hosts (Subfinder + httpx)",
        "file":  "base_recon.py",
    },
    {
        "name":  "Vulnerability Scanner",
        "desc":  "Run Nuclei with 5,000+ templates to find CVEs and misconfigs",
        "file":  "base_scanner.py",
    },
    {
        "name":  "API Hunter",
        "desc":  "Search for Swagger, OpenAPI, and hidden API documentation",
        "file":  "api_finder.py",
    },
    {
        "name":  "JS Secrets Analyzer",
        "desc":  "Extract API keys, tokens, and hidden paths from JavaScript files",
        "file":  "js_analyzer.py",
    },
    {
        "name":  "Hidden Param Miner",
        "desc":  "Fuzz and discover hidden URL parameters",
        "file":  "param_miner.py",
    },
    {
        "name":  "CORS Misconfig Checker",
        "desc":  "Verify if target is vulnerable to CORS attacks",
        "file":  "cors_checker.py",
    },
    {
        "name":  "Smart Google Dorking",
        "desc":  "Search for exposed files (.env, .sql, config) via Google",
        "file":  "dork_miner.py",
    },
    {
        "name":  "AI Web Research",
        "desc":  "Let AI search for latest CVEs and technical write-ups",
        "file":  "research_tool.py",
    },
]


def _run_tool(tool_file: str, target: str) -> int:
    """
    รัน tool script อย่างปลอดภัย
    แก้: os.system(f"python3 tools/{file} {target}") → Shell Injection
         เปลี่ยนเป็น subprocess.run() แบบ list args ไม่ใช้ shell=True
    """
    tools_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
    script_path = os.path.join(tools_dir, tool_file)

    # ตรวจว่า script มีอยู่จริง
    if not os.path.exists(script_path):
        console.print(f"[bold red]Script not found: tools/{tool_file}[/bold red]")
        return 1

    try:
        result = subprocess.run(
            [sys.executable, script_path, target],  # แก้: list args ไม่ใช้ shell
            shell=False,                             # แก้: shell=False เสมอ
            check=False,
        )
        return result.returncode
    except FileNotFoundError:
        console.print(f"[bold red]Could not run script[/bold red]")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Stopped by user[/yellow]")
        return 0
    except Exception as e:
        logger.error(f"_run_tool error ({tool_file}): {e}")
        console.print(f"[bold red]Error: {e}[/bold red]")
        return 1


def show_tools_menu():
    """แสดงเมนู tools และให้ผู้ใช้เลือก"""

    while True:
        console.print(Panel(
            "[bold cyan]Elengenix Interactive Arsenal  ⚔️[/bold cyan]\n"
            "[dim]Select tool to run or press 0 to return[/dim]",
            border_style="cyan"
        ))

        # สร้างตาราง
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("No.", style="dim", width=4)
        table.add_column("Tool Name", style="cyan", width=28)
        table.add_column("Capabilities", style="green")

        for idx, tool in enumerate(TOOLS, 1):
            table.add_row(str(idx), tool["name"], tool["desc"])

        console.print(table)
        console.print("[dim]Press '0' to return to Main Menu[/dim]\n")

        try:
            choice = input("Select Tool Number: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Returning to Main Menu[/yellow]")
            return

        if choice == "0":
            return

        # ตรวจว่าเป็นตัวเลขและอยู่ในช่วงที่ถูกต้อง
        if not choice.isdigit():
            console.print("[red]Please enter numbers only[/red]\n")
            continue

        selected_idx = int(choice) - 1
        if not (0 <= selected_idx < len(TOOLS)):
            console.print(f"[red]Please select within range or 0 to return[/red]\n")
            continue

        selected_tool = TOOLS[selected_idx]

        try:
            target = input(f"Target for {selected_tool['name']}: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Cancelled[/yellow]")
            continue

        # แก้: validate target ก่อนส่งเป็น argument
        if not _validate_target(target):
            console.print(
                "[red]Invalid Target - No special characters allowed "
                "e.g. ; | & ` $ ( )[/red]\n"
            )
            continue

        console.print(
            f"\n[bold yellow]Running {selected_tool['name']} "
            f"on {target}...[/bold yellow]\n"
        )

        returncode = _run_tool(selected_tool["file"], target)

        if returncode == 0:
            console.print(f"\n[bold green]{selected_tool['name']} Complete[/bold green]\n")
        else:
            console.print(f"\n[bold red]⚠️ {selected_tool['name']} finished with exit code {returncode}[/bold red]\n")

        # ถามว่าจะรัน tool อื่นต่อไหม
        try:
            again = input("Run another tool? [Y/n]: ").strip().lower()
            if again in ("n", "no"):
                return
        except (KeyboardInterrupt, EOFError):
            return


if __name__ == "__main__":
    show_tools_menu()
