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
    
    # Priority 1: Environment Variable
    env_scope = os.getenv("ELENGENIX_SCOPE")
    if env_scope:
        domains.update(d.strip().lower() for d in env_scope.split(",") if d.strip())
    
    # Priority 2: scope.txt file
    scope_path = Path(scope_file)
    if scope_path.exists():
        with open(scope_path, "r", encoding="utf-8") as f:
            for line in f:
                clean_line = line.strip().lower()
                if clean_line and not clean_line.startswith("#"):
                    domains.add(clean_line)
    
    if not domains:
        logger.warning("No scope defined. Running in OPEN mode (Unauthorized for production).")
    
    return domains

ALLOWED_DOMAINS = load_allowed_domains()

# ── Validation & Sanitization ────────────────────────────────
def normalize_target(target: str) -> str:
    """Canonicalize input to pure domain or IP."""
    target = target.strip().lower()
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path.split('/')[0]
    
    # Strip port if present
    if ":" in target and not target.startswith("["):
        target = target.split(":")[0]
        
    return target.rstrip(".")

def is_valid_target(target: str) -> bool:
    """RFC-compliant domain validation and private IP blocking."""
    # Check for IP
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private or ip.is_loopback:
            logger.error(f"Internal IP blocked: {target}")
            return False
        return True
    except ValueError:
        pass # Not an IP
    
    # Domain Validation
    if len(target) > 253 or "." not in target: return False
    for label in target.split("."):
        if not label or len(label) > 63: return False
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", label):
            return False
            
    # Blacklist internal keywords
    if any(p in target for p in ["localhost", ".local", ".internal", ".test"]):
        return False
        
    return True

def is_in_scope(target: str) -> bool:
    """Strictly enforces authorized targets."""
    normalized = normalize_target(target)
    if not is_valid_target(normalized): return False
    
    if not ALLOWED_DOMAINS: return True # Dev mode
    
    if normalized in ALLOWED_DOMAINS: return True
    for allowed in ALLOWED_DOMAINS:
        if normalized.endswith(f".{allowed}"): return True
        
    return False

def sanitize_path(target: str) -> str:
    """Safe directory naming."""
    return re.sub(r'[^a-zA-Z0-9.-]', '_', target)[:100]

# ── Tool Execution Wrappers ──────────────────────────────────
async def run_tool_async(cmd: List[str], tool_name: str, semaphore: asyncio.Semaphore) -> str:
    """Executes a security tool with concurrency limit."""
    async with semaphore:
        logger.info(f"Launching tool: {tool_name}")
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            output = stdout.decode().strip()
            return compress_output(output, tool_name)
        except Exception as e:
            logger.error(f"{tool_name} failed: {e}")
            return f"Error running {tool_name}"

# ── Core Orchestrator ────────────────────────────────────────
async def run_standard_scan(target: str, rate_limit: int = 5, timeout: int = 600) -> Optional[str]:
    """The master pipeline for authorized reconnaissance and scanning."""
    
    if not is_in_scope(target):
        console.print(f"[bold red]SCOPE VIOLATION: Target '{target}' is not authorized.[/bold red]")
        return None

    normalized = normalize_target(target)
    safe_name = sanitize_path(normalized)
    
    # Path Traversal Guard
    reports_base = Path("reports").resolve()
    report_dir = (reports_base / safe_name).resolve()
    if not str(report_dir).startswith(str(reports_base)):
        logger.error("Path traversal blocked.")
        return None

    report_dir.mkdir(parents=True, exist_ok=True)
    send_telegram_notification(f"🚀 Mission Authorized: `{normalized}`")
    console.print(Panel(f"SECURE PIPELINE ACTIVATED: {normalized}", border_style="cyan"))

    semaphore = asyncio.Semaphore(rate_limit)
    
    tasks = [
        run_tool_async(["subfinder", "-d", normalized, "-silent"], "Subfinder", semaphore),
        run_tool_async(["nuclei", "-target", normalized, "-as", "-silent"], "Nuclei", semaphore)
    ]

    try:
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout)
        success_count = sum(1 for r in results if "Error" not in r)
        
        console.print(f"[bold green]✓ Scan finished. {success_count}/{len(tasks)} tools succeeded.[/bold green]")
        send_telegram_notification(f"✅ Mission Complete: `{normalized}` ({success_count} results)")
        
        return str(report_dir)
        
    except asyncio.TimeoutError:
        console.print("[bold red]⏱️ Global scan timeout reached.[/bold red]")
        return None
    except Exception as e:
        logger.exception(f"Pipeline crash: {e}")
        return None
