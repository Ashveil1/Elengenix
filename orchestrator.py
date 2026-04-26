"""
orchestrator.py — Tool Registry Pipeline Orchestrator (v2.0.0)
- Uses Tool Registry for dynamic tool management
- Scoping via scope.txt or ELENGENIX_SCOPE env var
- RFC-compliant domain and IP validation
- Async concurrency control via Semaphores
- Intelligent tool chain execution
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
from tools.tool_registry import registry, ToolCategory, ToolResult
from tools.cvss_calculator import CVSSCalculator
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
    return normalized in ALLOWED_DOMAINS or any(normalized.endswith(f".{a}") for a in ALLOWED_DOMAINS)

def sanitize_path(target: str) -> str:
    return re.sub(r'[^a-zA-Z0-9.-]', '_', target)[:100]

# ── Legacy Tool Runners (for backward compatibility) ─────────
async def run_subfinder_legacy(target: str, report_dir: Path) -> str:
    output_file = report_dir / "subdomains.txt"
    cmd = ["subfinder", "-d", target, "-o", str(output_file), "-silent"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.communicate()
        return output_file.read_text() if output_file.exists() else ""
    except Exception as e:
        return f"Subfinder error: {e}"

async def run_httpx_legacy(target: str, report_dir: Path) -> str:
    output_file = report_dir / "live_hosts.txt"
    input_file = report_dir / "subdomains.txt"
    
    cmd = ["httpx", "-l" if input_file.exists() else "-u", str(input_file) if input_file.exists() else target, "-o", str(output_file), "-silent"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.communicate()
        return output_file.read_text() if output_file.exists() else ""
    except Exception as e:
        return f"Httpx error: {e}"

async def run_nuclei_legacy(target: str, report_dir: Path) -> str:
    output_file = report_dir / "nuclei_results.txt"
    cmd = ["nuclei", "-u", target, "-o", str(output_file), "-silent", "-severity", "critical,high,medium"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.communicate()
        return output_file.read_text() if output_file.exists() else ""
    except Exception as e:
        return f"Nuclei error: {e}"

# ── 🚀 Modern Tool Registry Orchestrator ───────────────────
def get_recommended_tool_chain(target_type: str = "web") -> List:
    """Get recommended tools based on target type using registry."""
    return registry.get_recommended_chain(target_type)

async def run_tool_with_registry(
    tool_name: str,
    target: str,
    report_dir: Path,
    semaphore: asyncio.Semaphore
) -> ToolResult:
    """Execute a tool via the registry."""
    tool = registry.get_tool(tool_name)
    
    if not tool:
        logger.error(f"Tool {tool_name} not found in registry")
        return ToolResult(
            success=False,
            tool_name=tool_name,
            category=ToolCategory.UTILITY,
            error_message="Tool not registered"
        )
    
    if not tool.is_available:
        logger.warning(f"Tool {tool_name} not available (binary missing)")
        return ToolResult(
            success=False,
            tool_name=tool_name,
            category=tool.metadata.category,
            error_message="Tool binary not found in PATH"
        )
    
    try:
        logger.info(f"Launching {tool_name} via registry...")
        result = await tool.execute(target, report_dir, semaphore)
        return result
    except Exception as e:
        logger.error(f"Tool {tool_name} execution failed: {e}")
        return ToolResult(
            success=False,
            tool_name=tool_name,
            category=tool.metadata.category,
            error_message=str(e)
        )

async def run_registry_pipeline(
    target: str,
    report_dir: Path,
    rate_limit: int = 5,
    tool_filter: List[str] = None
) -> List[ToolResult]:
    """Run all available tools from registry."""
    semaphore = asyncio.Semaphore(rate_limit)
    results = []
    
    # Get all registered tools or filtered list
    if tool_filter:
        tools = [registry.get_tool(name) for name in tool_filter if registry.get_tool(name)]
    else:
        # Get recommended chain for web targets
        tools = registry.get_recommended_chain("web")
    
    # Filter available tools
    available_tools = [t for t in tools if t and t.is_available]
    
    if not available_tools:
        console.print("[yellow]⚠️ No tools available in registry[/yellow]")
        return results
    
    console.print(f"[cyan]🛠️ Running {len(available_tools)} tools from registry...[/cyan]")
    
    # Execute each tool
    for tool in available_tools:
        try:
            result = await run_tool_with_registry(
                tool.metadata.name,
                target,
                report_dir,
                semaphore
            )
            results.append(result)
            
            if result.success and result.findings:
                console.print(f"  [green]✓ {tool.metadata.name}: {len(result.findings)} findings[/green]")
            elif result.success:
                console.print(f"  [dim]✓ {tool.metadata.name}: No findings[/dim]")
            else:
                console.print(f"  [red]✗ {tool.metadata.name}: {result.error_message[:50]}...[/red]")
                
        except Exception as e:
            logger.error(f"Pipeline error for {tool.metadata.name}: {e}")
    
    return results

def calculate_cvss_for_results(results: List[ToolResult]) -> List[dict]:
    """Calculate CVSS scores for all findings."""
    calculator = CVSSCalculator(use_ai=False)  # Use deterministic scoring for speed
    scored_findings = []
    
    for result in results:
        for finding in result.findings:
            score = calculator.calculate_from_tool_result(
                result.tool_name,
                finding,
                "unknown"  # Target not stored in result, use placeholder
            )
            
            scored_findings.append({
                "tool": result.tool_name,
                "finding": finding,
                "cvss_score": score.base_score,
                "severity": (score.adjusted_severity or score.severity).value,
                "vector": score.vector_string,
            })
    
    # Sort by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    scored_findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
    
    return scored_findings

def print_findings_summary(results: List[ToolResult]) -> None:
    """Print a summary of findings grouped by severity."""
    findings_by_severity = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": [],
        "Informational": [],
    }
    
    for result in results:
        for finding in result.findings:
            severity = finding.get("severity", "info").capitalize()
            if severity == "Info":
                severity = "Informational"
            
            if severity in findings_by_severity:
                findings_by_severity[severity].append({
                    "tool": result.tool_name,
                    "type": finding.get("type", "unknown"),
                    "url": finding.get("url", ""),
                })
    
    console.print("\n[bold]📊 Findings Summary:[/bold]")
    for severity, items in findings_by_severity.items():
        if items:
            color = {
                "Critical": "red",
                "High": "orange3",
                "Medium": "yellow",
                "Low": "green",
                "Informational": "blue",
            }.get(severity, "white")
            console.print(f"  [{color}]{severity}: {len(items)}[/{color}]")

# ── Core Orchestrator ────────────────────────────────────────
async def run_standard_scan(
    target: str, 
    rate_limit: int = 5, 
    timeout: int = 600,
    use_registry: bool = True,
    tool_filter: List[str] = None
) -> Optional[str]:
    """
    Run standard scan pipeline.
    
    Args:
        target: Target domain or IP
        rate_limit: Max concurrent operations
        timeout: Global timeout
        use_registry: Use new Tool Registry (True) or legacy mode (False)
        tool_filter: Optional list of specific tools to run
    """
    if not is_in_scope(target):
        console.print(f"[bold red]SCOPE VIOLATION: {target}[/bold red]")
        return None

    normalized = normalize_target(target)
    safe_name = sanitize_path(normalized)
    report_dir = (Path("reports").resolve() / safe_name)
    report_dir.mkdir(parents=True, exist_ok=True)

    send_telegram_notification(f"🚀 Mission Authorized: `{normalized}`")
    console.print(Panel(
        f"SECURE PIPELINE ACTIVATED: {normalized}\n"
        f"[dim]Mode: {'Tool Registry' if use_registry else 'Legacy'} | Rate: {rate_limit} concurrent[/dim]",
        border_style="cyan"
    ))

    try:
        if use_registry:
            # Modern Tool Registry approach
            results = await asyncio.wait_for(
                run_registry_pipeline(normalized, report_dir, rate_limit, tool_filter),
                timeout=timeout
            )
            
            # Calculate CVSS scores
            scored_findings = calculate_cvss_for_results(results)
            
            # Save CVSS results
            import json
            cvss_file = report_dir / "cvss_scores.json"
            cvss_file.write_text(json.dumps(scored_findings, indent=2))
            
            # Print summary
            print_findings_summary(results)
            
            # Summary stats
            total_findings = sum(len(r.findings) for r in results)
            critical = len([s for s in scored_findings if s["severity"] == "Critical"])
            high = len([s for s in scored_findings if s["severity"] == "High"])
            
            console.print(f"\n[bold green]✓ Scan complete: {len(results)} tools, {total_findings} findings[/bold green]")
            
            if critical > 0:
                console.print(f"[bold red]🚨 CRITICAL: {critical} findings require immediate attention![/bold red]")
            if high > 0:
                console.print(f"[bold orange3]⚠️ HIGH: {high} findings need review[/bold orange3]")
            
        else:
            # Legacy mode (fallback)
            semaphore = asyncio.Semaphore(rate_limit)
            tasks = [
                run_subfinder_legacy(normalized, report_dir),
                run_httpx_legacy(normalized, report_dir),
                run_nuclei_legacy(normalized, report_dir),
            ]
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout)
        
        console.print(f"[bold green]✓ Reports saved: {report_dir}[/bold green]")
        send_telegram_notification(f"✅ Scan complete for `{normalized}` - Reports saved")
        return str(report_dir)
        
    except asyncio.TimeoutError:
        logger.error(f"Scan timeout after {timeout}s")
        console.print(f"[bold red]⏱️ Timeout: Scan exceeded {timeout} seconds[/bold red]")
        send_telegram_notification(f"⚠️ Scan timeout for `{normalized}`")
        return str(report_dir) if report_dir.exists() else None
        
    except Exception as e:
        logger.error(f"Pipeline crash: {e}")
        console.print(f"[bold red]💥 Error: {e}[/bold red]")
        return None
