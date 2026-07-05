"""
orchestrator.py — Tool Registry Pipeline Orchestrator
- Uses Tool Registry for dynamic tool management
- Scoping via scope.txt or ELENGENIX_SCOPE env var
- RFC-compliant domain and IP validation
- Async concurrency control via Semaphores
- Intelligent tool chain execution
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from tools.perf import FastHTTP, SmartCache, Timer, cached

# Safe import for nest_asyncio (for async compatibility)
try:
    import nest_asyncio
except ImportError:
    nest_asyncio = None  # not critical for orchestrator

from rich.panel import Panel

from integrations.bot_utils import send_telegram_notification
from scan_engine_upgrade import SmartOrchestrator

# Elengenix 5 new modules — P0-B wiring into production
from tools.active_fuzzer import ActiveFuzzer
from tools.bola_tester import BOLATester
from tools.coverage_analyzer import CoverageAnalyzer
from tools.cvss_calculator import CVSSCalculator
from tools.learning_engine import ExploitRecord, LearningEngine
from tools.python_recon import PythonRecon
from tools.tool_registry import ToolCategory, ToolResult, registry
from tools.waf_detector import SmartWAFDetector
from cli.ui_components import console

# ── Setup ───────────────────────────────────────────────────
logger = logging.getLogger("elengenix.orchestrator")


# ── Scope Management ─────────────────────────────────────────
def load_allowed_domains(scope_file: str = "scope.txt") -> Set[str]:
    """Loads authorized domains/IPs from environment or local file."""
    domains: Set[str] = set()
    env_scope = os.getenv("ELENGENIX_SCOPE")
    if env_scope:
        domains.update(d.strip().lower() for d in env_scope.split(",") if d.strip())

    scope_path = Path(scope_file)
    if scope_path.exists():
        try:
            with open(scope_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean_line = line.strip().lower()
                    if clean_line and not clean_line.startswith("#"):
                        domains.add(clean_line)
        except Exception as e:
            logger.warning(f"Failed to read scope file {scope_path}: {e}")
    return domains


# Lazy-loaded scope (not at module level)
_allowed_domains: Optional[Set[str]] = None


def _get_allowed_domains() -> Set[str]:
    """Lazy load allowed domains."""
    global _allowed_domains
    if _allowed_domains is None:
        _allowed_domains = load_allowed_domains()
    return _allowed_domains


def reload_scope() -> None:
    """Force reload scope from file/env."""
    global _allowed_domains
    _allowed_domains = load_allowed_domains()


def normalize_target(target: str) -> str:
    if not target:
        return ""
    target = target.strip().lower()
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path.split("/")[0]
    # Handle IPv6 with brackets: [::1]:8080 → ::1
    if target.startswith("["):
        bracket_end = target.find("]")
        if bracket_end > 0:
            target = target[1:bracket_end]
    # Handle IPv4 with port: 1.2.3.4:80 → 1.2.3.4
    # But NOT IPv6 (multiple colons)
    elif ":" in target and target.count(":") == 1:
        target = target.split(":")[0]
    return target.rstrip(".")


def is_valid_target(target: str) -> bool:
    if not target:
        return False
    # Try IP address (handles both IPv4 and IPv6)
    try:
        ip = ipaddress.ip_address(target)
        return not (ip.is_private or ip.is_loopback)
    except ValueError:
        pass
    # Domain validation
    if len(target) > 253 or "." not in target:
        return False
    return all(
        re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", part) for part in target.split(".")
    )


def is_in_scope(target: str) -> bool:
    if not target:
        return False
    normalized = normalize_target(target)
    if not is_valid_target(normalized):
        return False
    allowed = _get_allowed_domains()
    if not allowed:
        return True
    return normalized in allowed or any(
        normalized.endswith(f".{a}") for a in allowed
    )


def sanitize_path(target: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.-]", "_", target)[:100]


# ──  Modern Tool Registry Orchestrator ───────────────────
def get_recommended_tool_chain(target_type: str = "web") -> List[Any]:
    """Get recommended tools based on target type using registry."""
    return registry.get_recommended_chain(target_type)


async def run_tool_with_registry(
    tool_name: str, target: str, report_dir: Path, semaphore: asyncio.Semaphore
) -> ToolResult:
    """Execute a tool via the registry."""
    tool = registry.get_tool(tool_name)

    if not tool:
        logger.error(f"Tool {tool_name} not found in registry")
        return ToolResult(
            success=False,
            tool_name=tool_name,
            category=ToolCategory.UTILITY,
            error_message="Tool not registered",
        )

    if not tool.is_available:
        logger.warning(f"Tool {tool_name} not available (binary missing)")
        return ToolResult(
            success=False,
            tool_name=tool_name,
            category=tool.metadata.category,
            error_message="Tool binary not found in PATH",
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
            error_message=str(e),
        )


async def run_registry_pipeline(
    target: str, report_dir: Path, rate_limit: int = 5, tool_filter: Optional[List[str]] = None
) -> List[ToolResult]:
    """Run all available tools from registry."""
    semaphore = asyncio.Semaphore(rate_limit)
    results: List[ToolResult] = []

    # Get all registered tools or filtered list
    available_tools: List[Any] = []
    tools: List[Any] = []
    if tool_filter:
        tools = [registry.get_tool(name) for name in tool_filter if registry.get_tool(name)]
        available_tools = [t for t in tools if t is not None and t.is_available]
    else:
        # Get recommended chain for web targets
        tools = registry.get_recommended_chain("web")
        available_tools = [t for t in tools if t.is_available]

    if not available_tools:
        console.print("[grey70][WARN] No tools available in registry[/grey70]")
        _suggest_missing_tools(tools, target)
        return results

    console.print(f"[red][RUN] Running {len(available_tools)} tools from registry...[/red]")

    # Execute each tool
    for tool in available_tools:
        try:
            result = await run_tool_with_registry(tool.metadata.name, target, report_dir, semaphore)
            results.append(result)

            if result.success and result.findings:
                console.print(
                    f"  [bold white][OK] {tool.metadata.name}: {len(result.findings)} findings[/bold white]"
                )
            elif result.success:
                console.print(f"  [dim][ ] {tool.metadata.name}: No findings[/dim]")
            else:
                console.print(
                    f"  [red][FAIL] {tool.metadata.name}: {(result.error_message or '')[:50]}...[/red]"
                )

        except Exception as e:
            logger.error(f"Pipeline error for {tool.metadata.name}: {e}")

    return results


def _suggest_missing_tools(
    tools: List[Any],
    target: str = "",
) -> None:
    """Check required tools and report missing ones."""
    missing = [t for t in tools if t and not t.is_available]
    if not missing:
        return

    console.print("\n[bold yellow]  Tools Required But Missing:[/bold yellow]")
    for tool in missing:
        console.print(f"  [red]{tool.metadata.name}[/red] - {tool.metadata.description}")
    console.print("[dim]  All scanning tools are built-in Python modules.[/dim]")


def _manual_cmd(tool_name: str) -> str:
    """Return install command for manual tools."""
    return (
        f"All scanning tools are built-in Python modules. No manual install needed for: {tool_name}"
    )


def calculate_cvss_for_results(results: List[ToolResult]) -> List[Dict[str, Any]]:
    """Calculate CVSS scores for all findings."""
    calculator = CVSSCalculator(use_ai=False)  # Use deterministic scoring for speed
    scored_findings = []

    for result in results:
        for finding in result.findings:
            score = calculator.calculate_from_tool_result(
                result.tool_name, finding, "unknown"  # Target not stored in result, use placeholder
            )

            scored_findings.append(
                {
                    "tool": result.tool_name,
                    "finding": finding,
                    "cvss_score": score.base_score,
                    "severity": (score.adjusted_severity or score.severity).value,
                    "vector": score.vector_string,
                }
            )

    # Sort by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    scored_findings.sort(key=lambda x: severity_order.get(str(x.get("severity", "")), 5))

    return scored_findings


def print_findings_summary(results: List[ToolResult]) -> None:
    """Print a summary of findings grouped by severity."""
    findings_by_severity: Dict[str, List[Dict[str, Any]]] = {
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
                findings_by_severity[severity].append(
                    {
                        "tool": result.tool_name,
                        "type": finding.get("type", "unknown"),
                        "url": finding.get("url", ""),
                    }
                )

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
    from tools.perf import Timer

    console.print("[bold red][Phase 1] Python Reconnaissance[/bold red]")
    with Timer() as timer:
        try:
            recon = PythonRecon(timeout=1.0, max_concurrent=40)
            # Use quick mode (smaller wordlists) for production scans to keep latency reasonable
            recon_result = recon.full_recon(target, quick=True)

            # Save recon report
            recon_path = report_dir / "python_recon.json"
            recon_path.write_text(json.dumps(recon_result, indent=2, default=str))

            console.print(
                f"  [OK] Recon: {len(recon_result.get('directories', []))} endpoints, "
                f"{len(recon_result.get('ports', []))} ports, "
                f"{len(recon_result.get('subdomains', []))} subdomains, "
                f"{sum(1 for p in recon_result.get('parameters', []) if p.get('is_interesting'))} interesting params"
            )
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
        findings.append(
            {
                "tool": "python_recon",
                "type": "recon_http",
                "severity": "Informational",
                "url": base_url,
                "title": f"HTTP {http['status']} | {http.get('title', '')[:50]}",
                "details": f"Server: {http.get('headers', {}).get('Server', '?')} | Tech: {techs}",
            }
        )
    for d in recon_result.get("directories", []):
        findings.append(
            {
                "tool": "python_recon",
                "type": "endpoint",
                "severity": "Low" if d.get("status") in (200, 301, 302) else "Informational",
                "url": d.get("url"),
                "title": f"Discovered endpoint: {(d.get('url') or '').split('/')[-1] or 'unknown'}",
                "details": f"Status: {d.get('status')} | Length: {d.get('length')}",
            }
        )
    for p in recon_result.get("ports", []):
        findings.append(
            {
                "tool": "python_recon",
                "type": "port",
                "severity": "Informational",
                "url": f"{p.get('host')}:{p.get('port')}",
                "title": f"Open port {p.get('port')} ({p.get('service')})",
                "details": "TCP connect succeeded",
            }
        )
    for sub in recon_result.get("subdomains", []):
        findings.append(
            {
                "tool": "python_recon",
                "type": "subdomain",
                "severity": "Informational",
                "url": f"http://{sub.get('subdomain')}",
                "title": f"Subdomain: {sub.get('subdomain')}",
                "details": f"IPs: {','.join(sub.get('ips', []))}",
            }
        )
    for p in recon_result.get("parameters", []):
        if p.get("is_interesting"):
            findings.append(
                {
                    "tool": "python_recon",
                    "type": "param_discovery",
                    "severity": "Low",
                    "url": p.get("url"),
                    "title": f"Interesting parameter: {p.get('param')} ({p.get('method')})",
                    "details": f"Delta: {p.get('delta_pct')}% (baseline={p.get('baseline_len')}, test={p.get('test_len')})",
                }
            )
    # Enrich with vuln_engine CVE detection
    findings.extend(_check_cves_for_tech(recon_result, base_url))
    return findings


_cve_scache = SmartCache(max_size=128, default_ttl=3600)  # Cache CVE results per URL for 1 hour
_cached_http = FastHTTP(
    timeout=10.0, max_connections=50, use_cache=True
)  # Cached HTTP client for probes


def http_get_cached(url: str, timeout: float = 10.0) -> Optional[str]:
    """Cached HTTP GET using FastHTTP (perf.py SmartCache inside).

    Uses the module-level _cached_http FastHTTP instance which automatically
    caches 200 responses for 5 minutes (default _HTTP_CACHE TTL).
    Returns the response text or None on failure.
    """
    try:
        result = _cached_http.get(url, timeout=timeout)
        if result and "text" in result:
            return result["text"]
        return None
    except Exception:
        return None


@cached(cache=_cve_scache, ttl=3600)  # type: ignore[misc]
def _check_cves_for_tech_cached(base_url: str, techs: tuple, server: str) -> List[Dict[str, Any]]:
    """Cached version of CVE checking."""
    # Rebuild recon_result-like dict for the actual logic
    try:
        from tools.vuln_engine import KNOWN_CVES, severity_from_cvss  # type: ignore[import-untyped]
    except Exception:
        return []
    findings: List[Dict[str, Any]] = []
    if not KNOWN_CVES:
        return findings
    for tech_key, version_map in KNOWN_CVES.items():
        if not isinstance(version_map, dict):
            continue
        for version_range, cve_list in version_map.items():
            if not isinstance(cve_list, list):
                continue
            for cve_tuple in cve_list:
                if not isinstance(cve_tuple, tuple) or len(cve_tuple) < 3:
                    continue
                cve_id, description, cvss_score = cve_tuple[0], cve_tuple[1], cve_tuple[2]
                for tech in techs:
                    if tech_key.lower() in tech.lower():
                        findings.append(
                            {
                                "tool": "vuln_engine",
                                "type": "cve_detection",
                                "severity": severity_from_cvss(cvss_score),
                                "cvss": cvss_score,
                                "url": base_url,
                                "title": f"{cve_id} in {tech}",
                                "details": (
                                    f"{description}\n"
                                    f"Version range: {version_range}\n"
                                    f"CVSS: {cvss_score}"
                                ),
                                "cve": cve_id,
                                "cwe": [],
                                "matched_tech": tech,
                            }
                        )
                        break
    return findings


def _check_cves_for_tech(recon_result: Dict[str, Any], base_url: str) -> List[Dict[str, Any]]:
    """Use vuln_engine to detect known CVEs based on tech fingerprint.

    Looks at server header, identified techs, and http_probe to match against
    the KNOWN_CVES database in tools/vuln_engine.py. Returns findings for
    each detected vulnerable version.

    Args:
        recon_result: The output from PythonRecon (contains http_probe with tech list)
        base_url: The base URL being scanned

    Returns:
        List of finding dicts (one per detected CVE)
    """
    # Extract tech info from http_probe and delegate to cached version
    http = recon_result.get("http_probe", {}) or {}
    techs_raw: List[str] = http.get("tech", []) or []
    techs = tuple(techs_raw)
    server = str((http.get("headers", {}) or {}).get("Server", ""))
    if not techs and not server:
        return []
    return _check_cves_for_tech_cached(base_url, techs, server)


async def _run_phase2_waf(base_url: str) -> List[Dict[str, Any]]:
    """Phase 2: WAF detection (probe-based, no third-party)."""
    console.print("[bold red][Phase 2] Smart WAF Detection[/bold red]")
    # Pre-cache the base URL via FastHTTP for faster subsequent probes
    with Timer() as timer:
        cached_resp = http_get_cached(base_url, timeout=5.0)
        if cached_resp is None:
            logger.debug(f"Phase 2: base URL unreachable via cached HTTP: {base_url}")
    logger.debug(f"Phase 2: cached HTTP probe for {base_url} took {timer.duration_ms:.1f}ms")
    try:
        waf = SmartWAFDetector()
        # probe() is sync; run in thread to avoid blocking event loop
        waf_result = await asyncio.wait_for(
            asyncio.to_thread(waf.probe, base_url),
            timeout=15.0,
        )
        if waf_result.waf_detected:
            console.print(
                f"  [OK] WAF: {waf_result.waf_name} | {len(waf_result.suggested_evasions)} evasions"
            )
            return [
                {
                    "tool": "waf_detector",
                    "type": "waf",
                    "severity": "Informational",
                    "url": base_url,
                    "title": f"WAF detected: {waf_result.waf_name} (conf={waf_result.confidence:.2f})",
                    "details": f"Evasions: {', '.join(waf_result.suggested_evasions[:5])}",
                }
            ]
        else:
            console.print("  [OK] No WAF detected")
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
        all_fuzz_results: List[Any] = []

        # Fuzz all targets concurrently (bounded by asyncio.to_thread parallelism)
        async def _fuzz_xss_and_sqli(f_url: str, f_param: str) -> Tuple[List[Any], List[Any]]:
            xss_results = await asyncio.to_thread(
                fuzzer.fuzz_parameter, f_url, f_param, xss_payloads
            )
            sql_results = await asyncio.to_thread(
                fuzzer.fuzz_parameter, f_url, f_param, sqli_payloads
            )
            return xss_results, sql_results

        fuzz_results_per_target = await asyncio.gather(
            *(_fuzz_xss_and_sqli(url, param) for url, param in fuzz_targets),
            return_exceptions=True,
        )
        for result in fuzz_results_per_target:
            if isinstance(result, BaseException):
                console.print(f"  [WARN] Fuzz target failed: {result}")
                continue
            if not isinstance(result, tuple) or len(result) != 2:
                continue
            xss_fuzz: List[Any]
            sql_fuzz: List[Any]
            xss_fuzz, sql_fuzz = result
            for fr in xss_fuzz:
                if fr.is_interesting:
                    fuzz_findings.append(
                        {
                            "tool": "active_fuzzer",
                            "type": "xss",
                            "severity": "High",
                            "url": fr.url,
                            "title": f"Possible XSS: payload {fr.payload[:30]}",
                            "details": fr.reasoning,
                        }
                    )
            all_fuzz_results.extend(xss_fuzz)
            for fr in sql_fuzz:
                if fr.is_interesting:
                    fuzz_findings.append(
                        {
                            "tool": "active_fuzzer",
                            "type": "sqli",
                            "severity": "Critical",
                            "url": fr.url,
                            "title": f"Possible SQLi: payload {fr.payload[:30]}",
                            "details": fr.reasoning,
                        }
                    )
            all_fuzz_results.extend(sql_fuzz)

        console.print(
            f"  [OK] Fuzz: {len(all_fuzz_results)} tests on {len(fuzz_targets)} params, "
            f"{sum(1 for r in all_fuzz_results if r.is_interesting)} interesting"
        )
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
                    parts = url.split("/")
                    if parts and parts[-1].isdigit():
                        parts[-1] = "{id}"
                        bola_target_url = "/".join(parts)
                        break

        # BOLA is sync; bound it to 10s
        bola_results = await asyncio.wait_for(
            asyncio.to_thread(
                bola.test_endpoint_collection,
                bola_target_url,
                ["1", "2", "3", "admin"],
            ),
            timeout=10.0,
        )
        bola_findings: List[Dict[str, Any]] = []
        for br in bola_results:
            if br.is_bola:
                bola_findings.append(
                    {
                        "tool": "bola_tester",
                        "type": "bola",
                        "severity": br.severity,
                        "url": bola_target_url.replace("{id}", br.object_id),
                        "title": f"BOLA: {br.object_id} accessible to other user",
                        "details": f"A={br.status_a}, B={br.status_b}",
                    }
                )
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
            learning.remember(
                ExploitRecord(
                    target=target,
                    tech_stack=[],
                    vuln_class=f.get("type", "unknown"),
                    tool=f.get("tool", "unknown"),
                    payload="",
                    success=f.get("severity") in ("Critical", "High", "Medium"),
                    severity=f.get("severity", "Informational"),
                )
            )
        stats = learning.get_stats()
        console.print(
            f"  [OK] Learning: {stats.get('total_records', 0)} records, "
            f"{len(stats.get('by_tool', {}))} tools tracked"
        )
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
        console.print(
            f"  [OK] Coverage: {cov_report.total_endpoints} endpoints, "
            f"{cov_report.total_tests} tests, {cov_report.coverage_pct:.1f}%"
        )
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
    try:
        recon_result, waf_findings = await asyncio.gather(
            _run_phase1_recon(target, base_url, report_dir, timeout),
            _run_phase2_waf(base_url),
        )
    except KeyboardInterrupt:
        console.print("[yellow][WARN] Scan cancelled by user during Phase 1-2[/yellow]")
        return findings
    findings.extend(_recon_to_findings(recon_result, base_url))
    findings.extend(waf_findings)

    # ── Phase 3 + 4 in parallel (both depend on recon_result) ──
    try:
        fuzz_findings, bola_findings = await asyncio.gather(
            _run_phase3_fuzz(recon_result, base_url),
            _run_phase4_bola(recon_result, base_url),
        )
    except KeyboardInterrupt:
        console.print("[yellow][WARN] Scan cancelled by user during Phase 3-4[/yellow]")
        return findings
    findings.extend(fuzz_findings)
    findings.extend(bola_findings)

    # ── Phase 5 + 6 in parallel (both depend on accumulated findings) ──
    try:
        await asyncio.gather(
            _run_phase5_learning(findings, target, report_dir),
            _run_phase6_coverage(findings, report_dir),
        )
    except KeyboardInterrupt:
        console.print("[yellow][WARN] Scan cancelled by user during Phase 5-6[/yellow]")
        return findings

    return findings


# ── Core Orchestrator ────────────────────────────────────────
async def run_standard_scan(
    target: str,
    rate_limit: int = 5,
    timeout: int = 600,
    use_registry: bool = True,
    tool_filter: Optional[List[str]] = None,
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
    report_dir = Path("reports").resolve() / safe_name
    report_dir.mkdir(parents=True, exist_ok=True)

    send_telegram_notification(f" Mission Authorized: `{normalized}`")
    console.print(
        Panel(
            f"SECURE PIPELINE ACTIVATED: {normalized}\n"
            f"[dim]Mode: {'Tool Registry' if use_registry else 'Legacy'} | Rate: {rate_limit} concurrent[/dim]",
            border_style="red",
        )
    )

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
        console.print(
            f"[bold white][OK] Elengenix modules: {len(elengenix_findings)} findings[/bold white]"
        )
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

                console.print("\n[bold green][OK] Smart scan complete[/bold green]")
            else:
                # Modern Tool Registry approach (original)
                results = await asyncio.wait_for(
                    run_registry_pipeline(normalized, report_dir, rate_limit, tool_filter),
                    timeout=timeout,
                )

                # Calculate CVSS scores
                scored_findings = calculate_cvss_for_results(results)

                # Save CVSS results
                cvss_file = report_dir / "cvss_scores.json"
                cvss_file.write_text(json.dumps(scored_findings, indent=2))

                # Print summary
                print_findings_summary(results)

                # Summary stats
                total_findings = sum(len(r.findings) for r in results)
                critical = len([s for s in scored_findings if s["severity"] == "Critical"])
                high = len([s for s in scored_findings if s["severity"] == "High"])

                console.print(
                    f"\n[bold green][OK] Scan complete: {len(results)} tools, {total_findings} findings[/bold green]"
                )

                if critical > 0:
                    console.print(
                        f"[bold red][CRITICAL] {critical} findings require immediate attention![/bold red]"
                    )
                if high > 0:
                    console.print(
                        f"[bold orange3][HIGH] {high} findings need review[/bold orange3]"
                    )

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
