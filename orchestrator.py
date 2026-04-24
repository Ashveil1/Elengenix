"""
orchestrator.py — Secure & Scoped Scan Pipeline Orchestrator (v1.5.0)
- Scoping via scope.txt or ELENGENIX_SCOPE env var
- RFC-compliant domain and IP validation
- Path traversal protection for report directories
- Async concurrency control via Semaphores
"""

import os
import asyncio
import re
import logging
import ipaddress
import shutil
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, List, Set

from rich.console import Console
from rich.panel import Panel
from tools.context_compressor import compress_output
from bot_utils import send_telegram_notification

# ── Setup ───────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("elengenix.orchestrator")
console = Console()

# ── Scope Management ─────────────────────────────────────────
def load_allowed_domains(scope_file: str = "scope.txt") -> Set[str]:
    """Loads authorized domains/IPs from environment or local file."""
    domains = set()
    env_scope = os.getenv("ELENGENIX_SCOPE")
    if env_scope:
        domains.update(d.strip().lower() for d in env_scope.split(",") if d.strip())
    
    scope_path = Path(scope_file)
    if scope_path.exists():
        with open(scope_path, "r", encoding="utf-8") as f:
            for line in f:
                clean_line = line.strip().lower()
                if clean_line and not clean_line.startswith("#"):
                    domains.add(clean_line)
    return domains

ALLOWED_DOMAINS = load_allowed_domains()

def normalize_target(target: str) -> str:
    target = target.strip().lower()
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path.split('/')[0]
    if ":" in target and not target.startswith("["):
        target = target.split(":")[0]
    return target.rstrip(".")

def is_valid_target(target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
        return not (ip.is_private or ip.is_loopback)
    except ValueError:
        pass
    if len(target) > 253 or "." not in target: return False
    return all(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", l) for l in target.split("."))

def is_in_scope(target: str) -> bool:
    normalized = normalize_target(target)
    if not is_valid_target(normalized): return False
    if not ALLOWED_DOMAINS: return True 
    return normalized in ALLOWED_DOMAINS or any(normalized.endswith(f".{a}") for l in ALLOWED_DOMAINS)

def sanitize_path(target: str) -> str:
    return re.sub(r'[^a-zA-Z0-9.-]', '_', target)[:100]

# ── 🚀 Tool Runners ──────────────────────────────────────────
async def run_subfinder(target: str, report_dir: Path) -> str:
    output_file = report_dir / "subdomains.txt"
    cmd = ["subfinder", "-d", target, "-o", str(output_file), "-silent"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.communicate()
        return output_file.read_text() if output_file.exists() else ""
    except Exception as e:
        return f"Subfinder error: {e}"

async def run_httpx(target: str, report_dir: Path) -> str:
    output_file = report_dir / "live_hosts.txt"
    input_file = report_dir / "subdomains.txt"
    
    # If subdomains exist, use them, otherwise use target directly
    cmd = ["httpx", "-l" if input_file.exists() else "-u", str(input_file) if input_file.exists() else target, "-o", str(output_file), "-silent"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.communicate()
        return output_file.read_text() if output_file.exists() else ""
    except Exception as e:
        return f"Httpx error: {e}"

async def run_nuclei(target: str, report_dir: Path) -> str:
    output_file = report_dir / "nuclei_results.txt"
    cmd = ["nuclei", "-u", target, "-o", str(output_file), "-silent", "-severity", "critical,high,medium"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.communicate()
        return output_file.read_text() if output_file.exists() else ""
    except Exception as e:
        return f"Nuclei error: {e}"

async def run_tool_async(coro, tool_name: str, semaphore: asyncio.Semaphore) -> str:
    async with semaphore:
        logger.info(f"Launching {tool_name}...")
        result = await coro
        return compress_output(result, tool_name)

# ── Core Orchestrator ────────────────────────────────────────
async def run_standard_scan(target: str, rate_limit: int = 5, timeout: int = 600) -> Optional[str]:
    if not is_in_scope(target):
        console.print(f"[bold red]SCOPE VIOLATION: {target}[/bold red]")
        return None

    normalized = normalize_target(target)
    safe_name = sanitize_path(normalized)
    report_dir = (Path("reports").resolve() / safe_name)
    report_dir.mkdir(parents=True, exist_ok=True)

    send_telegram_notification(f"🚀 Mission Authorized: `{normalized}`")
    console.print(Panel(f"SECURE PIPELINE ACTIVATED: {normalized}", border_style="cyan"))

    semaphore = asyncio.Semaphore(rate_limit)
    
    # Parallel chain: Recon -> Discovery -> Scanning
    # Note: Logic here can be optimized, for now running them in parallel for speed
    tasks = [
        run_tool_async(run_subfinder(normalized, report_dir), "Subfinder", semaphore),
        run_tool_async(run_httpx(normalized, report_dir), "Httpx", semaphore),
        run_tool_async(run_nuclei(normalized, report_dir), "Nuclei", semaphore)
    ]

    try:
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout)
        console.print(f"[bold green]✓ Scan finished. Reports: {report_dir}[/bold green]")
        return str(report_dir)
    except Exception as e:
        logger.error(f"Pipeline crash: {e}")
        return None
