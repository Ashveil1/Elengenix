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
        "desc":  "รัน EVERYTHING: Dorking → Recon → API → Nuclei → JS → Params → Report",
        "file":  "omni_scan.py",
    },
    {
        "name":  "Recon & Discovery",
        "desc":  "ค้นหา subdomain และตรวจ live hosts (Subfinder + httpx)",
        "file":  "base_recon.py",
    },
    {
        "name":  "Vulnerability Scanner",
        "desc":  "รัน Nuclei กับ 5,000+ templates เพื่อหา CVE และ misconfig",
        "file":  "base_scanner.py",
    },
    {
        "name":  "API Hunter",
        "desc":  "ค้นหา Swagger, OpenAPI และ hidden API documentation",
        "file":  "api_finder.py",
    },
    {
        "name":  "JS Secrets Analyzer",
        "desc":  "ดึง API keys, tokens และ hidden paths จาก JavaScript files",
        "file":  "js_analyzer.py",
    },
    {
        "name":  "Hidden Param Miner",
        "desc":  "Fuzz และค้นหา hidden URL parameters",
        "file":  "param_miner.py",
    },
    {
        "name":  "CORS Misconfig Checker",
        "desc":  "ตรวจว่า target มีช่องโหว่ CORS หรือเปล่า",
        "file":  "cors_checker.py",
    },
    {
        "name":  "Smart Google Dorking",
        "desc":  "ค้นหา exposed files (.env, .sql, config) ผ่าน Google",
        "file":  "dork_miner.py",
    },
    {
        "name":  "AI Web Research",
        "desc":  "ให้ AI ค้นหา CVE และ write-up ล่าสุดบนเว็บ",
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
        console.print(f"[bold red]ไม่พบ script: tools/{tool_file}[/bold red]")
        return 1

    try:
        result = subprocess.run(
            [sys.executable, script_path, target],  # แก้: list args ไม่ใช้ shell
            shell=False,                             # แก้: shell=False เสมอ
            check=False,
        )
        return result.returncode
    except FileNotFoundError:
        console.print(f"[bold red]รัน {tool_file} ไม่ได้[/bold red]")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ หยุดโดยผู้ใช้[/yellow]")
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
            "[dim]เลือก tool ที่ต้องการรัน หรือกด 0 เพื่อกลับ[/dim]",
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
        console.print("[dim]กด '0' เพื่อกลับ Main Menu[/dim]\n")

        try:
            choice = input("เลือก Tool Number: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]กลับ Main Menu[/yellow]")
            return

        if choice == "0":
            return

        # ตรวจว่าเป็นตัวเลขและอยู่ในช่วงที่ถูกต้อง
        if not choice.isdigit():
            console.print("[red]กรุณากรอกตัวเลขเท่านั้น[/red]\n")
            continue

        selected_idx = int(choice) - 1
        if not (0 <= selected_idx < len(TOOLS)):
            console.print(f"[red]กรุณาเลือก 1-{len(TOOLS)} หรือ 0 เพื่อกลับ[/red]\n")
            continue

        selected_tool = TOOLS[selected_idx]

        try:
            target = input(f"Target สำหรับ {selected_tool['name']}: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]ยกเลิก[/yellow]")
            continue

        # แก้: validate target ก่อนส่งเป็น argument
        if not _validate_target(target):
            console.print(
                "[red]Target ไม่ถูกต้อง — ห้ามมีอักขระพิเศษ "
                "เช่น ; | & ` $ ( )[/red]\n"
            )
            continue

        console.print(
            f"\n[bold yellow]กำลังรัน {selected_tool['name']} "
            f"บน {target}...[/bold yellow]\n"
        )

        returncode = _run_tool(selected_tool["file"], target)

        if returncode == 0:
            console.print(f"\n[bold green]{selected_tool['name']} เสร็จสิ้น[/bold green]\n")
        else:
            console.print(f"\n[bold red]⚠️ {selected_tool['name']} จบด้วย exit code {returncode}[/bold red]\n")

        # ถามว่าจะรัน tool อื่นต่อไหม
        try:
            again = input("รัน tool อื่นอีกไหม? [Y/n]: ").strip().lower()
            if again in ("n", "no"):
                return
        except (KeyboardInterrupt, EOFError):
            return


if __name__ == "__main__":
    show_tools_menu()
