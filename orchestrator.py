"""
orchestrator.py — Tool Registry Pipeline Orchestrator
- Uses Tool Registry for dynamic tool management
- Scoping via scope.txt or ELENGENIX_SCOPE env var
- RFC-compliant domain and IP validation
- Async concurrency control via Semaphores
- Intelligent tool chain execution
"""

import os
import asyncio
import re
import json
import logging
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, List, Set, Any, Dict

# Safe import for nest_asyncio (for async compatibility)
try:
    import nest_asyncio
    nest_asyncio.apply()
except ImportError:
    pass  # nest_asyncio not available, but not critical for orchestrator

from rich.panel import Panel
from ui_components import console
from tools.tool_registry import registry, ToolCategory, ToolResult
from tools.cvss_calculator import CVSSCalculator
from scan_engine_upgrade import SmartOrchestrator
from bot_utils import send_telegram_notification

# Elengenix 5 new modules — P0-B wiring into production
from tools.active_fuzzer import ActiveFuzzer
from tools.coverage_analyzer import CoverageAnalyzer
from tools.learning_engine import LearningEngine, ExploitRecord
from tools.bola_tester import BOLATester
from tools.waf_detector import SmartWAFDetector
from tools.python_recon import PythonRecon

# ── Setup ───────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("elengenix.orchestrator")

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

# ──  Modern Tool Registry Orchestrator ───────────────────
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
        console.print("[grey70][WARN] No tools available in registry[/grey70]")
        _suggest_missing_tools(tools, target)
        return results

    console.print(f"[red][RUN] Running {len(available_tools)} tools from registry...[/red]")

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
                console.print(f"  [bold white][OK] {tool.metadata.name}: {len(result.findings)} findings[/bold white]")
            elif result.success:
                console.print(f"  [dim][ ] {tool.metadata.name}: No findings[/dim]")
            else:
                console.print(f"  [red][FAIL] {tool.metadata.name}: {result.error_message[:50]}...[/red]")

        except Exception as e:
            logger.error(f"Pipeline error for {tool.metadata.name}: {e}")

    return results


def _suggest_missing_tools(
    tools: List[Any],
    target: str = "",
) -> None:
    """Check required tools and offer auto-installation."""
    missing = [t for t in tools if t and not t.is_available]
    if not missing:
        return

    from dependency_manager import TOOLS as INSTALLABLE_TOOLS, run_with_streaming, verify_and_advise

    auto_install = []
    manual_install = []

    for tool in missing:
        name = tool.metadata.name
        if name in INSTALLABLE_TOOLS:
            auto_install.append(name)
        else:
            manual_install.append(name)

    if not auto_install and not manual_install:
        return

    console.print("\n[bold yellow]  Tools Required But Missing:[/bold yellow]")

    if auto_install:
        console.print(f"  [red]{' '.join(auto_install)}[/red]")

        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        import questionary
        try:
            install_now = questionary.confirm(
                "Install missing tools now?",
                default=True,
            ).ask()
        except Exception:
            install_now = False

        if install_now:
            from dependency_manager import check_prerequisites
            if not check_prerequisites():
                console.print("[bold red]Missing Go or Git — cannot install[/bold red]")
                return

            succeeded = []
            failed = []
            for tool_name in auto_install:
                cmd = INSTALLABLE_TOOLS[tool_name]
                with Progress(
                    SpinnerColumn(),
                    TextColumn(f"[bold yellow]Installing {tool_name}..."),
                    BarColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    progress.add_task("", total=None)
                    ok = run_with_streaming(cmd)
                if ok and verify_and_advise(tool_name):
                    console.print(f"  [bold green][OK] {tool_name}[/bold green]")
                    succeeded.append(tool_name)
                else:
                    console.print(f"  [bold red][FAIL] {tool_name}[/bold red]")
                    console.print(f"     Manual: [dim]{' '.join(cmd)}[/dim]")
                    failed.append(tool_name)

            if succeeded:
                console.print(f"\n[bold green]Installed: {', '.join(succeeded)}[/bold green]")
            if failed:
                console.print(f"[yellow]Failed: {', '.join(failed)}[/yellow]")

    if manual_install:
        from rich.table import Table
        tbl = Table(show_header=False, box=None)
        tbl.add_column(style="yellow", width=12)
        tbl.add_column(style="dim", width=60)
        for name in manual_install:
            cmd = _manual_cmd(name)
            tbl.add_row(name, cmd)
        console.print("\n[bold yellow]Need manual install:[/bold yellow]")
        console.print(tbl)


def _manual_cmd(tool_name: str) -> str:
    """Return install command for manual tools."""
    cmds = {
        "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
        "arjun": "pip install arjun",
        "trufflehog": "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
        "nmap": "sudo apt-get install nmap  # or: brew install nmap",
    }
    return cmds.get(tool_name, f"See docs for: {tool_name}")

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
    
    console.print("\n[bold]Findings Summary:[/bold]")
    for severity, items in findings_by_severity.items():
        if items:
            color = {
                "Critical": "red",
                "High": "orange3",
                "Medium": "grey70",
                "Low": "bold white",
                "Informational": "grey70",
            }.get(severity, "white")
            console.print(f"  [{color}]{severity}: {len(items)}[/{color}]")

# ── Elengenix 5-Module Pipeline (P0-B) ─────────────────────────
# Each phase is extracted into a helper so it can run in parallel
# via asyncio.gather. Phases 1+2 are independent; phases 3+4 depend
# on Phase 1 recon_result; phases 5+6 depend on accumulated findings.
async def _run_phase1_recon(
    target: str,
    base_url: str,
    report_dir: Path,
    timeout: int,
) -> Dict[str, Any]:
    """
    Phase 1: Python-based recon (always runs, no AI needed).
    Returns the recon_result dict (or empty dict on failure).
    """
    console.print("[bold red][Phase 1] Python Reconnaissance[/bold red]")
    try:
        recon = PythonRecon(timeout=1.0, max_concurrent=40)
        # Use quick mode (smaller wordlists) for production scans to keep latency reasonable
        recon_result = await asyncio.wait_for(
            asyncio.to_thread(recon.full_recon, target, True),
            timeout=min(60, timeout - 30),
        ) if False else recon.full_recon(target, quick=True)

        # Save recon report
        recon_path = report_dir / "python_recon.json"
        recon_path.write_text(json.dumps(recon_result, indent=2, default=str))

        console.print(f"  [OK] Recon: {len(recon_result.get('directories', []))} endpoints, "
                      f"{len(recon_result.get('ports', []))} ports, "
                      f"{len(recon_result.get('subdomains', []))} subdomains, "
                      f"{sum(1 for p in recon_result.get('parameters', []) if p.get('is_interesting'))} interesting params")
        return recon_result
    except Exception as e:
        logger.error(f"python_recon failed: {e}")
        console.print(f"  [WARN] python_recon error: {e}")
        return {}


def _recon_to_findings(recon_result: Dict[str, Any], base_url: str) -> List[Dict[str, Any]]:
    """Convert python_recon result into finding dicts."""
    findings: List[Dict[str, Any]] = []
    if not recon_result:
        return findings
    http = recon_result.get("http_probe", {})
    if http.get("status"):
        techs = ",".join(http.get("tech", []))
        findings.append({
            "tool": "python_recon",
            "type": "recon_http",
            "severity": "Informational",
            "url": base_url,
            "title": f"HTTP {http['status']} | {http.get('title','')[:50]}",
            "details": f"Server: {http.get('headers', {}).get('Server', '?')} | Tech: {techs}",
        })
    for d in recon_result.get("directories", []):
        findings.append({
            "tool": "python_recon",
            "type": "endpoint",
            "severity": "Low" if d.get("status") in (200, 301, 302) else "Informational",
            "url": d.get("url"),
            "title": f"Discovered endpoint: {d.get('url').split('/')[-1]}",
            "details": f"Status: {d.get('status')} | Length: {d.get('length')}",
        })
    for p in recon_result.get("ports", []):
        findings.append({
            "tool": "python_recon",
            "type": "port",
            "severity": "Informational",
            "url": f"{p.get('host')}:{p.get('port')}",
            "title": f"Open port {p.get('port')} ({p.get('service')})",
            "details": "TCP connect succeeded",
        })
    for sub in recon_result.get("subdomains", []):
        findings.append({
            "tool": "python_recon",
            "type": "subdomain",
            "severity": "Informational",
            "url": f"http://{sub.get('subdomain')}",
            "title": f"Subdomain: {sub.get('subdomain')}",
            "details": f"IPs: {','.join(sub.get('ips', []))}",
        })
    for p in recon_result.get("parameters", []):
        if p.get("is_interesting"):
            findings.append({
                "tool": "python_recon",
                "type": "param_discovery",
                "severity": "Low",
                "url": p.get("url"),
                "title": f"Interesting parameter: {p.get('param')} ({p.get('method')})",
                "details": f"Delta: {p.get('delta_pct')}% (baseline={p.get('baseline_len')}, test={p.get('test_len')})",
            })
    return findings


async def _run_phase2_waf(base_url: str) -> List[Dict[str, Any]]:
    """Phase 2: WAF detection (probe-based, no third-party)."""
    console.print("[bold red][Phase 2] Smart WAF Detection[/bold red]")
    try:
        waf = SmartWAFDetector()
        # probe() is sync; run in thread to avoid blocking event loop
        waf_result = await asyncio.wait_for(
            asyncio.to_thread(waf.probe, base_url),
            timeout=15.0,
        )
        if waf_result.waf_detected:
            console.print(f"  [OK] WAF: {waf_result.waf_name} | {len(waf_result.suggested_evasions)} evasions")
            return [{
                "tool": "waf_detector",
                "type": "waf",
                "severity": "Informational",
                "url": base_url,
                "title": f"WAF detected: {waf_result.waf_name} (conf={waf_result.confidence:.2f})",
                "details": f"Evasions: {', '.join(waf_result.suggested_evasions[:5])}",
            }]
        else:
            console.print(f"  [OK] No WAF detected")
            return []
    except Exception as e:
        logger.error(f"waf_detector failed: {e}")
        console.print(f"  [WARN] waf_detector error: {e}")
        return []


async def _run_phase3_fuzz(
    recon_result: Dict[str, Any],
    base_url: str,
) -> List[Dict[str, Any]]:
    """Phase 3: Active fuzzing (XSS / SQLi / SSTI / etc.)."""
    console.print("[bold red][Phase 3] Active Fuzzing[/bold red]")
    try:
        fuzzer = ActiveFuzzer()
        xss_payloads = ["<script>", "%3Cscript%3E", "'\"><svg onload=>", "javascript:alert(1)"]
        sqli_payloads = ["'", "1' OR '1'='1", "1' AND SLEEP(2)--", "%27"]

        # Determine targets from Phase 1 recon
        fuzz_targets = []
        if recon_result:
            for p in recon_result.get("parameters", []):
                if p.get("is_interesting"):
                    fuzz_targets.append((p.get("url"), p.get("param")))

        # Fallback if no params discovered
        if not fuzz_targets:
            fuzz_targets = [(f"{base_url}/get", "q")]
        else:
            # Limit to top 3 params to stay within time budget
            fuzz_targets = fuzz_targets[:3]

        fuzz_findings: List[Dict[str, Any]] = []
        all_fuzz_results = []
        for f_url, f_param in fuzz_targets:
            xss_fuzz = fuzzer.fuzz_parameter(f_url, f_param, xss_payloads)
            for fr in xss_fuzz:
                if fr.is_interesting:
                    fuzz_findings.append({
                        "tool": "active_fuzzer",
                        "type": "xss",
                        "severity": "High",
                        "url": fr.url,
                        "title": f"Possible XSS in {f_param}: payload {fr.payload[:30]}",
                        "details": fr.reasoning,
                    })
            all_fuzz_results.extend(xss_fuzz)

            sql_fuzz = fuzzer.fuzz_parameter(f_url, f_param, sqli_payloads)
            for fr in sql_fuzz:
                if fr.is_interesting:
                    fuzz_findings.append({
                        "tool": "active_fuzzer",
                        "type": "sqli",
                        "severity": "Critical",
                        "url": fr.url,
                        "title": f"Possible SQLi in {f_param}: payload {fr.payload[:30]}",
                        "details": fr.reasoning,
                    })
            all_fuzz_results.extend(sql_fuzz)

        console.print(f"  [OK] Fuzz: {len(all_fuzz_results)} tests on {len(fuzz_targets)} params, "
                      f"{sum(1 for r in all_fuzz_results if r.is_interesting)} interesting")
        return fuzz_findings
    except Exception as e:
        logger.error(f"active_fuzzer failed: {e}")
        console.print(f"  [WARN] active_fuzzer error: {e}")
        return []


async def _run_phase4_bola(
    recon_result: Dict[str, Any],
    base_url: str,
) -> List[Dict[str, Any]]:
    """Phase 4: BOLA / IDOR testing."""
    console.print("[bold red][Phase 4] BOLA / IDOR Testing[/bold red]")
    try:
        bola = BOLATester()
        bola.register_session("user_a", cookies={"session": "user_a_token"})
        bola.register_session("user_b", cookies={"session": "user_b_token"})

        # Determine BOLA target from Phase 1 recon
        bola_target_url = f"{base_url}/api/users/{{id}}"
        if recon_result:
            for ep in recon_result.get("endpoints", []):
                url = ep.get("url", "")
                if "api" in url and any(kw in url for kw in ["user", "account", "profile"]):
                    # Transform e.g. /api/user/123 to /api/user/{id}
                    parts = url.split('/')
                    if parts and parts[-1].isdigit():
                        parts[-1] = "{id}"
                        bola_target_url = "/".join(parts)
                        break

        # BOLA is sync; bound it to 10s
        bola_results = await asyncio.wait_for(
            asyncio.to_thread(
                bola.test_endpoint_collection,
                bola_target_url, ["1", "2", "3", "admin"],
            ),
            timeout=10.0,
        )
        bola_findings: List[Dict[str, Any]] = []
        for br in bola_results:
            if br.is_bola:
                bola_findings.append({
                    "tool": "bola_tester",
                    "type": "bola",
                    "severity": br.severity,
                    "url": bola_target_url.replace("{id}", br.object_id),
                    "title": f"BOLA: {br.object_id} accessible to other user",
                    "details": f"A={br.status_a}, B={br.status_b}",
                })
        bola_count = sum(1 for r in bola_results if r.is_bola)
        console.print(f"  [OK] BOLA: {bola_count} broken authz on {bola_target_url}")
        return bola_findings
    except Exception as e:
        logger.error(f"bola_tester failed: {e}")
        console.print(f"  [WARN] bola_tester error: {e}")
        return []


async def _run_phase5_learning(
    findings: List[Dict[str, Any]],
    target: str,
    report_dir: Path,
) -> List[Dict[str, Any]]:
    """Phase 5: Learning engine — record what we found. Returns empty (no new findings)."""
    console.print("[bold red][Phase 5] Learning Engine[/bold red]")
    try:
        learn_db = report_dir / "learning.db"
        learning = LearningEngine(db_path=learn_db, use_chroma=False)
        for f in findings:
            learning.remember(ExploitRecord(
                target=target,
                tech_stack=[],
                vuln_class=f.get("type", "unknown"),
                tool=f.get("tool", "unknown"),
                payload="",
                success=f.get("severity") in ("Critical", "High", "Medium"),
                severity=f.get("severity", "Informational"),
            ))
        stats = learning.get_stats()
        console.print(f"  [OK] Learning: {stats.get('total_records', 0)} records, "
                      f"{len(stats.get('by_tool', {}))} tools tracked")
        return []
    except Exception as e:
        logger.error(f"learning_engine failed: {e}")
        console.print(f"  [WARN] learning_engine error: {e}")
        return []


async def _run_phase6_coverage(
    findings: List[Dict[str, Any]],
    report_dir: Path,
) -> List[Dict[str, Any]]:
    """Phase 6: Coverage tracking. Returns empty (no new findings)."""
    console.print("[bold red][Phase 6] Coverage Tracking[/bold red]")
    try:
        cov_db = report_dir / "coverage.db"
        coverage = CoverageAnalyzer(db_path=cov_db)
        # Record what we tested
        for f in findings:
            if f.get("url"):
                coverage.discover_from_url(f["url"], source="recon")
        cov_report = coverage.get_coverage_report()
        console.print(f"  [OK] Coverage: {cov_report.total_endpoints} endpoints, "
                      f"{cov_report.total_tests} tests, {cov_report.coverage_pct:.1f}%")
        return []
    except Exception as e:
        logger.error(f"coverage_analyzer failed: {e}")
        console.print(f"  [WARN] coverage_analyzer error: {e}")
        return []


async def run_elengenix_modules(
    target: str,
    report_dir: Path,
    timeout: int = 300,
) -> List[Dict[str, Any]]:
    """
    Run the 5 Elengenix pure-Python modules + PythonRecon fallback.
    This is the production entry point that actually does something
    even when AI providers and third-party tools are unavailable.

    Independent phases run in parallel via asyncio.gather:
    - Phase 1 (recon) + Phase 2 (WAF) run concurrently
    - Phase 3 (fuzz) + Phase 4 (BOLA) run concurrently (both depend on recon)
    - Phase 5 (learning) + Phase 6 (coverage) run concurrently

    Returns a list of finding dicts compatible with the ToolResult format.
    """
    findings: List[Dict[str, Any]] = []
    base_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    report_dir.mkdir(parents=True, exist_ok=True)

    # ── Phase 1 + 2 in parallel (both independent of each other) ──
    recon_result, waf_findings = await asyncio.gather(
        _run_phase1_recon(target, base_url, report_dir, timeout),
        _run_phase2_waf(base_url),
    )
    findings.extend(_recon_to_findings(recon_result, base_url))
    findings.extend(waf_findings)

    # ── Phase 3 + 4 in parallel (both depend on recon_result) ──
    fuzz_findings, bola_findings = await asyncio.gather(
        _run_phase3_fuzz(recon_result, base_url),
        _run_phase4_bola(recon_result, base_url),
    )
    findings.extend(fuzz_findings)
    findings.extend(bola_findings)

    # ── Phase 5 + 6 in parallel (both depend on accumulated findings) ──
    await asyncio.gather(
        _run_phase5_learning(findings, target, report_dir),
        _run_phase6_coverage(findings, report_dir),
    )

    return findings


# ── Core Orchestrator ────────────────────────────────────────
async def run_standard_scan(
    target: str, 
    rate_limit: int = 5, 
    timeout: int = 600,
    use_registry: bool = True,
    tool_filter: List[str] = None,
    use_smart_scan: bool = False,
) -> Optional[str]:
    """
    Run standard scan pipeline.

    Args:
        target: Target domain or IP
        rate_limit: Max concurrent operations
        timeout: Global timeout
        use_registry: Use new Tool Registry (True) or legacy mode (False)
        tool_filter: Optional list of specific tools to run
        use_smart_scan: Use intelligent smart scan with file relationship
                        analysis and finding correlation (default: False)
    """
    if not is_in_scope(target):
        console.print(f"[bold red]SCOPE VIOLATION: {target}[/bold red]")
        return None

    normalized = normalize_target(target)
    safe_name = sanitize_path(normalized)
    report_dir = (Path("reports").resolve() / safe_name)
    report_dir.mkdir(parents=True, exist_ok=True)

    send_telegram_notification(f" Mission Authorized: `{normalized}`")
    console.print(Panel(
        f"SECURE PIPELINE ACTIVATED: {normalized}\n"
        f"[dim]Mode: {'Tool Registry' if use_registry else 'Legacy'} | Rate: {rate_limit} concurrent[/dim]",
        border_style="red"
    ))

    # ── Elengenix 5-module pipeline (P0-B) — runs FIRST and independently ──
    # This is the production fallback that produces real findings even when
    # AI providers and third-party tools are unavailable.
    try:
        elengenix_findings = await asyncio.wait_for(
            run_elengenix_modules(normalized, report_dir, timeout=min(timeout, 300)),
            timeout=min(timeout, 300) + 30,
        )
        # Save Elengenix findings as JSON for the report generator
        elengenix_path = report_dir / "elengenix_findings.json"
        elengenix_path.write_text(json.dumps(elengenix_findings, indent=2, default=str))
        console.print(f"[bold white][OK] Elengenix modules: {len(elengenix_findings)} findings[/bold white]")
    except asyncio.TimeoutError:
        logger.warning("Elengenix modules timed out — continuing with main pipeline")
    except Exception as e:
        logger.error(f"Elengenix modules failed: {e}")
        console.print(f"[bold yellow][WARN] Elengenix modules error: {e}[/bold yellow]")

    try:
        if use_registry:
            if use_smart_scan:
                # Smart scan with file relationship analysis
                orchestrator = SmartOrchestrator(max_concurrency=rate_limit)
                state, correlator = await orchestrator.run_smart_scan(
                    target=normalized,
                    report_dir=report_dir,
                    tools=tool_filter,
                    rate_limit=rate_limit,
                    correlate=True,
                    use_smart_chain=True,
                )
                
                # Calculate CVSS scores from smart scan state
                if state and state.results:
                    from tools.cvss_calculator import CVSSCalculator
                    calculator = CVSSCalculator(use_ai=False)
                    for result in state.results.values():
                        for finding in result.findings:
                            calculator.calculate_from_tool_result(
                                result.tool_name, finding, "unknown"
                            )
                
                console.print(f"\n[bold green][OK] Smart scan complete[/bold green]")
            else:
                # Modern Tool Registry approach (original)
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
                
                console.print(f"\n[bold green][OK] Scan complete: {len(results)} tools, {total_findings} findings[/bold green]")
                
                if critical > 0:
                    console.print(f"[bold red][CRITICAL] {critical} findings require immediate attention![/bold red]")
                if high > 0:
                    console.print(f"[bold orange3][HIGH] {high} findings need review[/bold orange3]")
            
        else:
            # Legacy mode (fallback)
            asyncio.Semaphore(rate_limit)
            tasks = [
                run_subfinder_legacy(normalized, report_dir),
                run_httpx_legacy(normalized, report_dir),
                run_nuclei_legacy(normalized, report_dir),
            ]
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout)
        
        console.print(f"[bold green][OK] Reports saved: {report_dir}[/bold green]")
        send_telegram_notification(f" Scan complete for `{normalized}` - Reports saved")
        return str(report_dir)
        
    except asyncio.TimeoutError:
        logger.error(f"Scan timeout after {timeout}s")
        console.print(f"[bold red][TIMEOUT] Scan exceeded {timeout} seconds[/bold red]")
        send_telegram_notification(f" Scan timeout for `{normalized}`")
        return str(report_dir) if report_dir.exists() else None
        
    except Exception as e:
        logger.error(f"Pipeline crash: {e}")
        console.print(f"[bold red][FAIL] Error: {e}[/bold red]")
        return None
