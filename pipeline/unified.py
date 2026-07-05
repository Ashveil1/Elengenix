"""
pipeline/unified.py — Unified Scan Pipeline

Combines ScopeManager, PhaseRegistry, and all pipeline systems into
a single entry point. Replaces the fragmented orchestrator.py with
a clean, configurable interface.

Usage:
    pipeline = UnifiedPipeline()
    config = ScanConfig(target="example.com", timeout=300)
    output = await pipeline.run(config)
    print(output.summary)
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline.phase_registry import (
    Phase,
    PhaseContext,
    PhaseRegistry,
    PhaseResult,
)
from pipeline.scope import ScopeManager, sanitize_path

logger = logging.getLogger("elengenix.unified")


# ── Configuration ──────────────────────────────────────────────


@dataclass
class ScanConfig:
    """Configuration for a scan mission.

    Attributes:
        target: Target domain or IP.
        rate_limit: Max concurrent operations.
        timeout: Global timeout in seconds.
        phases: List of phase names to run (None = all).
        tool_filter: List of specific tools to run (None = all).
        use_registry: Run the tool registry pipeline.
        use_smart_scan: Use SmartOrchestrator.
    """

    target: str = ""
    rate_limit: int = 5
    timeout: int = 600
    phases: Optional[List[str]] = None
    tool_filter: Optional[List[str]] = None
    use_registry: bool = True
    use_smart_scan: bool = False


@dataclass
class ScanOutput:
    """Output from a completed scan.

    Attributes:
        success: Whether the scan completed successfully.
        findings: All findings discovered.
        report_dir: Path to the report directory.
        summary: Human-readable summary.
        errors: List of error messages from failed phases.
    """

    success: bool = False
    findings: List[Dict[str, Any]] = field(default_factory=list)
    report_dir: str = ""
    summary: str = ""
    errors: List[str] = field(default_factory=list)


# ── Phase Functions ────────────────────────────────────────────
# These wrap the existing orchestrator.py phase logic into the
# PhaseContext → PhaseResult interface.


async def _phase_recon(ctx: PhaseContext) -> PhaseResult:
    """Phase 1: Python-based reconnaissance."""
    try:
        from tools.python_recon import PythonRecon

        recon = PythonRecon(timeout=1.0, max_concurrent=40)
        recon_result = recon.full_recon(ctx.target, quick=True)

        # Save recon report
        recon_path = ctx.report_dir / "python_recon.json"
        recon_path.write_text(json.dumps(recon_result, indent=2, default=str))

        # Convert to findings
        findings = _recon_to_findings(recon_result, ctx.base_url)

        # Extract endpoints for dependent phases
        endpoints = []
        for ep in recon_result.get("directories", []):
            if ep.get("url"):
                endpoints.append(ep["url"])

        return PhaseResult(
            success=True,
            findings=findings,
            output={"recon_result": recon_result, "endpoints": endpoints},
        )
    except Exception as e:
        logger.error(f"Recon phase failed: {e}")
        return PhaseResult(success=False, error=str(e))


async def _phase_waf(ctx: PhaseContext) -> PhaseResult:
    """Phase 2: WAF detection."""
    try:
        from tools.waf_detector import SmartWAFDetector

        waf = SmartWAFDetector()
        waf_result = await asyncio.wait_for(
            asyncio.to_thread(waf.probe, ctx.base_url),
            timeout=15.0,
        )

        if waf_result.waf_detected:
            finding = {
                "tool": "waf_detector",
                "type": "waf",
                "severity": "Informational",
                "url": ctx.base_url,
                "title": f"WAF detected: {waf_result.waf_name} (conf={waf_result.confidence:.2f})",
                "details": f"Evasions: {', '.join(waf_result.suggested_evasions[:5])}",
            }
            return PhaseResult(
                success=True,
                findings=[finding],
                output={"waf_name": waf_result.waf_name, "evasions": waf_result.suggested_evasions},
            )
        else:
            return PhaseResult(success=True, findings=[], output={"waf_name": None})
    except Exception as e:
        logger.error(f"WAF phase failed: {e}")
        return PhaseResult(success=False, error=str(e))


async def _phase_fuzz(ctx: PhaseContext) -> PhaseResult:
    """Phase 3: Active fuzzing (XSS / SQLi)."""
    try:
        from tools.active_fuzzer import ActiveFuzzer

        fuzzer = ActiveFuzzer()
        xss_payloads = ["<script>", "%3Cscript%3E", "'\"><svg onload=>", "javascript:alert(1)"]
        sqli_payloads = ["'", "1' OR '1'='1", "1' AND SLEEP(2)--", "%27"]

        # Get targets from recon (stored in context.extra)
        recon_data = ctx.extra.get("recon", {})
        fuzz_targets = []

        for p in recon_data.get("recon_result", {}).get("parameters", []):
            if p.get("is_interesting"):
                fuzz_targets.append((p.get("url"), p.get("param")))

        if not fuzz_targets:
            fuzz_targets = [(f"{ctx.base_url}/get", "q")]
        else:
            fuzz_targets = fuzz_targets[:3]

        findings = []
        all_results = []

        async def _fuzz_one(f_url, f_param):
            xss = await asyncio.to_thread(fuzzer.fuzz_parameter, f_url, f_param, xss_payloads)
            sql = await asyncio.to_thread(fuzzer.fuzz_parameter, f_url, f_param, sqli_payloads)
            return xss, sql

        results = await asyncio.gather(
            *(_fuzz_one(url, param) for url, param in fuzz_targets),
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, BaseException):
                continue
            if not isinstance(result, tuple):
                continue
            xss_fuzz, sql_fuzz = result
            for fr in xss_fuzz:
                if fr.is_interesting:
                    findings.append({
                        "tool": "active_fuzzer",
                        "type": "xss",
                        "severity": "High",
                        "url": fr.url,
                        "title": f"Possible XSS: {fr.payload[:30]}",
                        "details": fr.reasoning,
                    })
            for fr in sql_fuzz:
                if fr.is_interesting:
                    findings.append({
                        "tool": "active_fuzzer",
                        "type": "sqli",
                        "severity": "Critical",
                        "url": fr.url,
                        "title": f"Possible SQLi: {fr.payload[:30]}",
                        "details": fr.reasoning,
                    })
            all_results.extend(xss_fuzz)
            all_results.extend(sql_fuzz)

        return PhaseResult(
            success=True,
            findings=findings,
            output={"total_tests": len(all_results), "targets": len(fuzz_targets)},
        )
    except Exception as e:
        logger.error(f"Fuzz phase failed: {e}")
        return PhaseResult(success=False, error=str(e))


async def _phase_bola(ctx: PhaseContext) -> PhaseResult:
    """Phase 4: BOLA / IDOR testing."""
    try:
        from tools.bola_tester import BOLATester

        bola = BOLATester()
        bola.register_session("user_a", cookies={"session": "user_a_token"})
        bola.register_session("user_b", cookies={"session": "user_b_token"})

        # Determine target from recon
        recon_data = ctx.extra.get("recon", {})
        bola_target = f"{ctx.base_url}/api/users/{{id}}"

        for ep in recon_data.get("recon_result", {}).get("endpoints", []):
            url = ep.get("url", "")
            if "api" in url and any(kw in url for kw in ["user", "account", "profile"]):
                parts = url.split("/")
                if parts and parts[-1].isdigit():
                    parts[-1] = "{id}"
                    bola_target = "/".join(parts)
                break

        bola_results = await asyncio.wait_for(
            asyncio.to_thread(
                bola.test_endpoint_collection,
                bola_target,
                ["1", "2", "3", "admin"],
            ),
            timeout=10.0,
        )

        findings = []
        for br in bola_results:
            if br.is_bola:
                findings.append({
                    "tool": "bola_tester",
                    "type": "bola",
                    "severity": br.severity,
                    "url": bola_target.replace("{id}", br.object_id),
                    "title": f"BOLA: {br.object_id} accessible to other user",
                    "details": f"A={br.status_a}, B={br.status_b}",
                })

        return PhaseResult(success=True, findings=findings)
    except Exception as e:
        logger.error(f"BOLA phase failed: {e}")
        return PhaseResult(success=False, error=str(e))


async def _phase_learn(ctx: PhaseContext) -> PhaseResult:
    """Phase 5: Learning engine (record findings)."""
    try:
        from tools.learning_engine import ExploitRecord, LearningEngine

        learn_db = ctx.report_dir / "learning.db"
        learning = LearningEngine(db_path=learn_db, use_chroma=False)

        for f in ctx.findings:
            learning.remember(
                ExploitRecord(
                    target=ctx.target,
                    tech_stack=[],
                    vuln_class=f.get("type", "unknown"),
                    tool=f.get("tool", "unknown"),
                    payload="",
                    success=f.get("severity") in ("Critical", "High", "Medium"),
                    severity=f.get("severity", "Informational"),
                )
            )

        return PhaseResult(success=True, findings=[])
    except Exception as e:
        logger.error(f"Learn phase failed: {e}")
        return PhaseResult(success=False, error=str(e))


async def _phase_coverage(ctx: PhaseContext) -> PhaseResult:
    """Phase 6: Coverage tracking."""
    try:
        from tools.coverage_analyzer import CoverageAnalyzer

        cov_db = ctx.report_dir / "coverage.db"
        coverage = CoverageAnalyzer(db_path=cov_db)

        for f in ctx.findings:
            if f.get("url"):
                coverage.discover_from_url(f["url"], source="recon")

        return PhaseResult(success=True, findings=[])
    except Exception as e:
        logger.error(f"Coverage phase failed: {e}")
        return PhaseResult(success=False, error=str(e))


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
            "title": f"HTTP {http['status']} | {http.get('title', '')[:50]}",
            "details": f"Server: {http.get('headers', {}).get('Server', '?')} | Tech: {techs}",
        })

    for d in recon_result.get("directories", []):
        findings.append({
            "tool": "python_recon",
            "type": "endpoint",
            "severity": "Low" if d.get("status") in (200, 301, 302) else "Informational",
            "url": d.get("url"),
            "title": f"Discovered endpoint: {(d.get('url') or '').split('/')[-1] or 'unknown'}",
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
                "details": f"Delta: {p.get('delta_pct')}%",
            })

    return findings


# ── Unified Pipeline ───────────────────────────────────────────


class UnifiedPipeline:
    """Unified scan pipeline that combines all pipeline systems.

    Uses ScopeManager for scope enforcement, PhaseRegistry for
    configurable phase execution, and optionally runs the tool
    registry pipeline and SmartOrchestrator.

    Args:
        scope_manager: ScopeManager instance (default: new).
        phase_registry: PhaseRegistry instance (default: new with default phases).
    """

    def __init__(
        self,
        scope_manager: Optional[ScopeManager] = None,
        phase_registry: Optional[PhaseRegistry] = None,
    ):
        self.scope_manager = scope_manager or ScopeManager()
        self.phase_registry = phase_registry or self._create_default_registry()

    def _create_default_registry(self) -> PhaseRegistry:
        """Create a PhaseRegistry with the 6 default phases."""
        registry = PhaseRegistry()
        registry.register(Phase(name="recon", func=_phase_recon, deps=[]))
        registry.register(Phase(name="waf", func=_phase_waf, deps=[]))
        registry.register(Phase(name="fuzz", func=_phase_fuzz, deps=["recon"]))
        registry.register(Phase(name="bola", func=_phase_bola, deps=["recon"]))
        registry.register(
            Phase(
                name="learn",
                func=_phase_learn,
                deps=["recon", "waf", "fuzz", "bola"],
            )
        )
        registry.register(
            Phase(
                name="coverage",
                func=_phase_coverage,
                deps=["recon", "waf", "fuzz", "bola"],
            )
        )
        return registry

    async def run(self, config: ScanConfig) -> ScanOutput:
        """Run the unified scan pipeline.

        Args:
            config: Scan configuration.

        Returns:
            ScanOutput with findings and summary.
        """
        # 1. Validate scope
        if not self.scope_manager.is_in_scope(config.target):
            return ScanOutput(
                success=False,
                summary=f"SCOPE VIOLATION: {config.target}",
                errors=["Target not in scope"],
            )

        # 2. Normalize target and create report dir
        normalized = self.scope_manager.normalize_target(config.target)
        safe_name = sanitize_path(normalized)
        report_dir = Path("reports").resolve() / safe_name
        report_dir.mkdir(parents=True, exist_ok=True)

        base_url = (
            config.target
            if config.target.startswith(("http://", "https://"))
            else f"http://{config.target}"
        )

        # 3. Create phase context
        ctx = PhaseContext(
            target=normalized,
            base_url=base_url,
            report_dir=report_dir,
            timeout=config.timeout,
        )

        # 4. Run phases
        errors = []
        try:
            results = await self.phase_registry.run(ctx, phases=config.phases)
            for r in results:
                if not r.success and r.error:
                    errors.append(r.error)
        except Exception as e:
            errors.append(f"Phase execution failed: {e}")

        # 5. Save findings
        findings_path = report_dir / "unified_findings.json"
        findings_path.write_text(
            json.dumps(ctx.findings, indent=2, default=str)
        )

        # 6. Build summary
        total = len(ctx.findings)
        critical = sum(1 for f in ctx.findings if f.get("severity") == "Critical")
        high = sum(1 for f in ctx.findings if f.get("severity") == "High")

        summary_parts = [
            f"Scan complete: {normalized}",
            f"Findings: {total} total, {critical} critical, {high} high",
            f"Reports: {report_dir}",
        ]
        if errors:
            summary_parts.append(f"Errors: {len(errors)} phases failed")

        return ScanOutput(
            success=len(errors) == 0,
            findings=ctx.findings,
            report_dir=str(report_dir),
            summary="\n".join(summary_parts),
            errors=errors,
        )
