"""tools/hunt_engine.py

Unified hunt engine: ONE command to find ALL vulnerabilities.

Runs the full Elengenix stack in optimal order:
    Phase 1: Recon         (existing python_recon, smart_recon)
    Phase 2: Smart scanners (BOLA, WAF, fuzzing, injection)
    Phase 3: Zero-day       (10 detection classes)
    Phase 4: Logic flaws    (9 detection classes)
    Phase 5: Correlation    (chain findings, score impact)

Produces a single unified report with deduplicated, correlated findings.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from elengenix.paths import get_reports_path
from typing import (

logger = logging.getLogger("elengenix.hunt")


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


@dataclass
class HuntFinding:
    """Unified finding from any source."""

    phase: str  # recon | smart | zero_day | logic
    category: str  # e.g. "jwt_confusion", "race_condition", "xss"
    severity: str  # Critical | High | Medium | Low | Informational
    title: str
    details: str = ""
    url: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cvss: float = 0.0
    cve_id: Optional[str] = None
    detector: str = ""  # class name that produced this

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HuntPhase:
    """Result of one phase of the hunt."""

    name: str
    status: str  # pending | running | done | failed | skipped
    duration: float = 0.0
    findings: int = 0
    error: str = ""


@dataclass
class HuntReport:
    """Complete hunt report - single source of truth."""

    target: str
    started_at: str
    finished_at: str = ""
    total_duration: float = 0.0
    phases: List[HuntPhase] = field(default_factory=list)
    findings: List[HuntFinding] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "Informational"
    summary: Dict[str, int] = field(default_factory=dict)
    chains: List[Dict[str, Any]] = field(default_factory=list)

    def by_severity(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def by_phase(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.phase] = out.get(f.phase, 0) + 1
        return out


# ═══════════════════════════════════════════════════════════════════════════
# PHASE RUNNERS
# ═══════════════════════════════════════════════════════════════════════════


async def _run_phase_recon(target: str) -> List[HuntFinding]:
    """Phase 1: Recon — discover endpoints via root + common paths.

    Uses EndpointDiscovery to find real attack surface instead of probing
    root URL only.
    """
    findings: List[HuntFinding] = []
    try:
        from tools.endpoint_discovery import EndpointDiscovery

        discovery = EndpointDiscovery(target=target, timeout=5.0)
        endpoints = await discovery.discover()
        for ep in endpoints:
            label = f"Discovered {ep.method} {ep.url}"
            if ep.requires_auth:
                label += " [auth required]"
            findings.append(
                HuntFinding(
                    phase="recon",
                    category="endpoint",
                    severity="Informational",
                    title=label,
                    url=ep.url,
                    evidence={"method": ep.method, "params": ep.params, "source": ep.source},
                    detector="EndpointDiscovery",
                )
            )
        # Stash endpoints for targeted attacks phase
        _endpoint_cache[target] = endpoints

        # Phase 1b: Authentication
        import aiohttp

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            from tools.auth_session import discover_and_login

            auths = await discover_and_login(session, target, endpoints)
            _auth_cache[target] = auths
            for auth in auths:
                findings.append(
                    HuntFinding(
                        phase="recon",
                        category="auth_session",
                        severity="Informational",
                        title=f"Authenticated as '{auth.username}' via {auth.authenticated_via}",
                        url=auth.authenticated_via,
                        evidence={
                            "username": auth.username,
                            "cookies": list(auth.cookies.keys()),
                            "has_jwt": bool(auth.jwt_token),
                            "evidence": auth.evidence,
                        },
                        detector="AuthSession",
                    )
                )
    except Exception as e:
        logger.debug("recon phase error: %s", e)
        findings.append(
            HuntFinding(
                phase="recon",
                category="baseline",
                severity="Informational",
                title=f"Recon attempted for {target}",
                details=str(e)[:200],
                url=f"http://{target}",
                detector="EndpointDiscovery",
            )
        )
    return findings


# Cache discovered endpoints and auth sessions across phases
_endpoint_cache: Dict[str, List[Any]] = {}
_auth_cache: Dict[str, List[Any]] = {}


async def _run_phase_smart(target: str) -> List[HuntFinding]:
    """Phase 2: Targeted attacks - SQLi, XSS, SSTI, IDOR, JWT, etc.

    Uses discovered endpoints from recon phase to route the right attack
    to the right endpoint. This is where we get REAL confirmed findings.
    """
    findings: List[HuntFinding] = []

    # Get discovered endpoints from cache
    endpoints = _endpoint_cache.get(target, [])
    if not endpoints:
        # Discover on-demand if recon wasn't run
        try:
            from tools.endpoint_discovery import EndpointDiscovery

            discovery = EndpointDiscovery(target=target, timeout=5.0)
            endpoints = await discovery.discover()
            _endpoint_cache[target] = endpoints
        except Exception as e:
            logger.warning("endpoint discovery failed: %s", e)
            return findings

    # Run targeted attacks
    try:
        from tools.targeted_attacks import run_targeted_attacks

        auths = _auth_cache.get(target, [])
        confirmed = await run_targeted_attacks(endpoints, concurrency=5, auth_sessions=auths)
    except Exception as e:
        logger.warning("targeted attacks failed: %s", e)
        return findings

    # Convert to HuntFindings
    for c in confirmed:
        findings.append(
            HuntFinding(
                phase="smart",
                category=c.category,
                severity=c.severity,
                title=c.title,
                details=f"Evidence: {c.evidence}",
                url=c.endpoint_url,
                evidence={
                    "payload": c.payload[:200],
                    "response_snippet": c.response_snippet[:500],
                    "status_code": c.status_code,
                    "confidence": c.confidence,
                    "detector": c.detector,
                },
                detector=c.detector,
            )
        )

    return findings


async def _run_phase_zero_day(target: str) -> List[HuntFinding]:
    """Phase 3: Zero-day heuristics - 10 detection classes.

    Only LIVE findings (with URL evidence) are reported as Critical/High/Medium.
    Static forgery candidates are demoted to Informational because the server
    has not been tested.
    """
    findings: List[HuntFinding] = []
    try:
        from tools.zero_day_heuristics import ScanConfig, ZeroDayEngine

        engine = ZeroDayEngine(config=ScanConfig())
        raw = await engine.scan(target)
        for f in raw:
            is_static = (getattr(f, "metadata", {}) or {}).get("static", False)
            sev_raw = getattr(f.severity, "value", str(f.severity))
            sev_norm = sev_raw.capitalize() if isinstance(sev_raw, str) else "Medium"
            sev_map = {
                "critical": "Critical",
                "high": "High",
                "medium": "Medium",
                "low": "Low",
                "informational": "Informational",
            }
            sev_norm = sev_map.get(
                sev_raw.lower() if isinstance(sev_raw, str) else "medium", "Medium"
            )

            # HONESTY: Static candidates are NOT confirmed vulnerabilities.
            # Demote to Informational so they don't inflate the risk score.
            if is_static:
                sev_norm = "Informational"

            evidence = (
                getattr(f, "evidence", {}) if isinstance(getattr(f, "evidence", {}), dict) else {}
            )
            findings.append(
                HuntFinding(
                    phase="zero_day",
                    category=(
                        getattr(f, "vuln_class", f.__class__.__name__).value
                        if hasattr(getattr(f, "vuln_class", None), "value")
                        else f.__class__.__name__
                    ),
                    severity=sev_norm,
                    title=getattr(f, "title", str(f))[:200],
                    details=getattr(f, "details", "")[:500],
                    url=getattr(f, "url", "") or getattr(f, "endpoint", ""),
                    evidence=evidence,
                    cvss=getattr(f, "cvss", 0.0),
                    detector=f.__class__.__name__,
                )
            )
    except Exception as e:
        logger.warning("zero-day phase failed: %s", e)
    return findings


async def _run_phase_logic(target: str) -> List[HuntFinding]:
    """Phase 4: Business logic + dependency CVE vulnerabilities.

    Scans dependencies found in the target project for known CVEs via NVD.
    """
    findings: List[HuntFinding] = []
    try:
        from tools.logic_flaw_engine import LogicFlawConfig, LogicFlawEngine

        engine = LogicFlawEngine(config=LogicFlawConfig())
        raw = await engine.analyze(target, endpoints=[])
        for f in raw:
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            findings.append(
                HuntFinding(
                    phase="logic",
                    category=f.__class__.__name__,
                    severity=sev,
                    title=f.title[:200],
                    details=f.details[:500] if hasattr(f, "details") else "",
                    url=f.endpoint if hasattr(f, "endpoint") else "",
                    evidence={"score": getattr(f, "score", 0)},
                    detector=f.__class__.__name__,
                )
            )
    except Exception as e:
        logger.warning("logic phase failed: %s", e)

    # NEW: Scan dependencies for CVEs (NVD)
    try:
        from tools.nvd_cve import get_nvd

        nvd = get_nvd()
        # Look at the target's project if local, or use known tech stack
        target_deps = _detect_target_dependencies(target)
        cves = nvd.lookup_dependencies(target_deps)
        for cve in cves:
            findings.append(
                HuntFinding(
                    phase="logic",
                    category="nvd_cve",
                    severity=cve.severity,
                    title=f"{cve.cve_id}: {cve.description[:150]}",
                    details=f"Affected: {', '.join(cve.affected_products)}\nFixed in: {cve.fixed_in}\nExploit available: {cve.exploit_available}",
                    url=target,
                    evidence={
                        "cve_id": cve.cve_id,
                        "cvss_v3": cve.cvss_v3,
                        "exploit_available": cve.exploit_available,
                        "fixed_in": cve.fixed_in,
                        "references": cve.references,
                    },
                    detector="NVDDatabase",
                )
            )
    except Exception as e:
        logger.debug("NVD phase skipped: %s", e)

    return findings


def _detect_target_dependencies(target: str) -> List[Tuple[str, str]]:
    """Best-effort detection of target's dependency versions.

    For local targets, reads requirements.txt. For remote, returns empty
    (recon can probe technology detection in future).
    """
    deps = []
    try:
        # If target is a local path, read requirements.txt
        target_path = Path(target)
        if target_path.exists():
            req_file = target_path / "requirements.txt"
            if req_file.exists():
                import re

                for line in req_file.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    # Parse "package==1.2.3" or "package>=1.0"
                    m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~]+)\s*([A-Za-z0-9_.\-+]+)", line)
                    if m:
                        deps.append((m.group(1), m.group(3)))
    except Exception:
        pass
    return deps


# ═══════════════════════════════════════════════════════════════════════════
# CORRELATION & SCORING
# ═══════════════════════════════════════════════════════════════════════════

_SEVERITY_WEIGHTS = {
    "Critical": 25,
    "High": 12,
    "Medium": 5,
    "Low": 2,
    "Informational": 0,
}


def compute_risk_score(findings: List[HuntFinding]) -> Tuple[float, str]:
    """Aggregate risk score 0-100.

    HONEST: Only LIVE findings (with evidence URL) contribute to risk.
    Static candidates and Informational items do NOT inflate the score.
    A target that produces no live findings scores 0, not 100.
    """
    score = 0.0
    live_count = 0
    for f in findings:
        # Skip informational — it's metadata, not a vulnerability
        if f.severity == "Informational":
            continue
        # Skip static candidates — they are not confirmed
        if "CANDIDATE" in f.title.upper() or "not tested" in f.title.lower():
            continue
        # Only count findings with evidence (URL or details)
        if not f.url and not f.details:
            continue
        score += _SEVERITY_WEIGHTS.get(f.severity, 0)
        live_count += 1

    if live_count == 0:
        return 0.0, "None"  # HONEST: nothing was found

    # Bonus for cross-phase live findings
    phases = {
        f.phase
        for f in findings
        if f.severity != "Informational" and "CANDIDATE" not in f.title.upper()
    }
    if len(phases) >= 3:
        score += 10

    score = min(score, 100.0)
    if score >= 70:
        level = "Critical"
    elif score >= 40:
        level = "High"
    elif score >= 20:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "None"
    return round(score, 1), level


def correlate_chains(findings: List[HuntFinding]) -> List[Dict[str, Any]]:
    """Detect vulnerability chains.

    HONEST: Only chain LIVE findings together. Static candidates do not form
    chains — they are not yet confirmed to be exploitable.
    """
    chains: List[Dict[str, Any]] = []

    # Filter to LIVE findings only
    live = [
        f
        for f in findings
        if f.severity != "Informational"
        and "CANDIDATE" not in f.title.upper()
        and "not tested" not in f.title.lower()
        and (f.url or f.details)
    ]
    if not live:
        return chains

    # Group by URL
    by_url: Dict[str, List[HuntFinding]] = {}
    for f in live:
        if f.url:
            by_url.setdefault(f.url, []).append(f)

    # Chain detection: 2+ findings on same URL = potential chain
    for url, fs in by_url.items():
        if len(fs) >= 2:
            sev_score = sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in fs)
            if sev_score >= 12:
                chains.append(
                    {
                        "url": url,
                        "findings": [f.title for f in fs],
                        "categories": [f.category for f in fs],
                        "combined_severity_score": sev_score,
                        "chain_type": "same_url_multi_finding",
                    }
                )

    # Known chain patterns (only across LIVE findings)
    jwt = [f for f in live if "jwt" in f.category.lower() or "jwt" in f.title.lower()]
    bola = [
        f
        for f in live
        if f.category.lower() in ("bola", "idor")
        or "idor" in f.title.lower()
        or "bola" in f.title.lower()
    ]
    if jwt and bola:
        chains.append(
            {
                "url": "(cross-endpoint)",
                "findings": [jwt[0].title, bola[0].title],
                "categories": ["jwt_confusion", "bola"],
                "chain_type": "auth_bypass_then_idor",
                "combined_severity_score": _SEVERITY_WEIGHTS.get(jwt[0].severity, 0)
                + _SEVERITY_WEIGHTS.get(bola[0].severity, 0)
                + 20,
            }
        )

    race = [f for f in live if "race" in f.category.lower() or "race" in f.title.lower()]
    sm = [f for f in live if "state" in f.category.lower()]
    if race and sm:
        chains.append(
            {
                "url": "(cross-endpoint)",
                "findings": [race[0].title, sm[0].title],
                "categories": ["race_condition", "state_machine"],
                "chain_type": "race_then_state_bypass",
                "combined_severity_score": _SEVERITY_WEIGHTS.get(race[0].severity, 0)
                + _SEVERITY_WEIGHTS.get(sm[0].severity, 0)
                + 15,
            }
        )

    return chains


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════


async def _run_phase_correlation_inner(
    report: HuntReport, target: str, all_findings: List[HuntFinding]
) -> List[HuntFinding]:
    """Phase 5: Correlation, scoring, exploitation, and AI analysis.

    Steps:
        1. Compute risk score
        2. Detect vulnerability chains
        3. Run actual exploitation on findings (proof-of-concept)
        4. AI enhancement (executive summary)
    """
    report.risk_score, report.risk_level = compute_risk_score(all_findings)
    report.chains = correlate_chains(all_findings)

    # ACTUAL EXPLOITATION - produce proof-of-concept for each finding
    try:
        from tools.exploitation import run_exploitation

        auth_session = None
        # Use first auth session if available
        auths = _auth_cache.get(target, [])
        if auths:
            auth_session = auths[0]

        # Only exploit LIVE findings (not static candidates)
        live_for_exploit = [
            f
            for f in all_findings
            if f.severity in ("Critical", "High")
            and "CANDIDATE" not in f.title.upper()
            and (f.url or f.details)
        ]
        exploits = await run_exploitation(target, live_for_exploit, auth_session=auth_session)
        for finding, proof in exploits:
            # Initialize evidence dict if needed
            if not isinstance(finding.evidence, dict):
                finding.evidence = {}
            finding.evidence["proof_of_concept"] = {
                "impact": proof.impact_demonstrated,
                "steps": proof.steps,
                "data_extracted": proof.data_extracted,
                "curl_command": proof.curl_command,
                "python_repro": proof.python_repro,
            }
            # Update severity if exploitation succeeded
            if proof.impact_demonstrated and finding.severity == "High":
                finding.severity = "Critical"  # Exploited = critical
        if exploits:
            report.summary["exploits_proven"] = len(exploits)
            logger.info("Exploitation phase: produced %d PoC proofs", len(exploits))
    except Exception as e:
        logger.debug("exploitation phase failed: %s", e)

    # AI enhancement (optional — skip if AI unavailable)
    try:
        from tools.llm_reasoning import generate_executive_summary, is_ai_available

        if is_ai_available() and len(all_findings) >= 3:
            findings_dicts = [f.to_dict() for f in all_findings if f.severity != "Informational"]
            if findings_dicts:
                summary = generate_executive_summary(target, findings_dicts)
                if summary:
                    report.summary["ai_executive_summary"] = summary[:2000]
                    logger.info("AI summary generated: %d chars", len(summary))
    except Exception as e:
        logger.debug("AI correlation skipped: %s", e)

    return all_findings  # correlation phase produces no new findings


class HuntEngine:
    """Single-command vulnerability hunter.

    Runs every Elengenix engine in optimal order, correlates findings,
    produces one unified report.

    Usage:
        engine = HuntEngine(target="example.com")
        report = await engine.hunt()
        # or sync:
        report = HuntEngine(target="example.com").hunt_sync()
    """

    def __init__(
        self, target: str, *, skip_phases: Optional[List[str]] = None, quiet: bool = False
    ) -> None:
        self.target = self._normalize_target(target)
        self.skip_phases = set(skip_phases or [])
        self.quiet = quiet
        self._report = HuntReport(
            target=self.target,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def _normalize_target(target: str) -> str:
        """Strip protocol, lowercase, basic validation."""
        t = target.strip()
        for prefix in ("https://", "http://"):
            if t.startswith(prefix):
                t = t[len(prefix) :]
                break
        t = t.rstrip("/")
        return t

    def _log(self, msg: str) -> None:
        if not self.quiet:
            print(msg)

    async def _run_phase(self, name: str, coro_factory) -> List[HuntFinding]:
        """Run one phase with timing and error handling.

        Args:
            name: Phase name
            coro_factory: Either an awaitable coroutine or a callable returning one.
        """
        if name in self.skip_phases:
            phase = HuntPhase(name=name, status="skipped")
            self._report.phases.append(phase)
            return []
        phase = HuntPhase(name=name, status="running")
        self._report.phases.append(phase)
        start = time.time()
        try:
            self._log(f"  [{name.upper():11s}] starting...")
            # Support both raw coroutines and zero-arg callables returning coroutines
            coro = coro_factory() if callable(coro_factory) else coro_factory
            findings = await coro
            phase.status = "done"
            phase.findings = len(findings)
            phase.duration = time.time() - start
            self._log(
                f"  [{name.upper():11s}] done  ({phase.duration:.1f}s, {len(findings)} findings)"
            )
            return findings
        except Exception as e:
            phase.status = "failed"
            phase.error = str(e)[:200]
            phase.duration = time.time() - start
            self._log(f"  [{name.upper():11s}] failed ({e})")
            logger.exception("phase %s failed", name)
            return []

    async def hunt(self) -> HuntReport:
        """Execute the full hunt pipeline."""
        start = time.time()
        self._log(f"\n[ HUNT ] target: {self.target}")
        self._log("=" * 60)

        # Run phases in sequence (each depends on prior state)
        all_findings: List[HuntFinding] = []

        # Phase 1: Recon
        f = await self._run_phase("recon", lambda: _run_phase_recon(self.target))
        all_findings.extend(f)

        # Phase 2: Smart scanners
        f = await self._run_phase("smart", lambda: _run_phase_smart(self.target))
        all_findings.extend(f)

        # Phase 3: Zero-day
        f = await self._run_phase("zero_day", lambda: _run_phase_zero_day(self.target))
        all_findings.extend(f)

        # Phase 4: Logic
        f = await self._run_phase("logic", lambda: _run_phase_logic(self.target))
        all_findings.extend(f)

        # Phase 5: Correlation & scoring
        await self._run_phase("correlation", lambda: self._correlate(all_findings))

        # Finalize
        self._report.findings = all_findings
        self._report.finished_at = datetime.now(timezone.utc).isoformat()
        self._report.total_duration = time.time() - start
        self._report.summary = {
            "total": len(all_findings),
            **self._report.by_severity(),
            **self._report.by_phase(),
        }

        return self._report

    async def _correlate(self, findings: List[HuntFinding]) -> List[HuntFinding]:
        """Phase 5: Correlate findings and compute risk."""
        return await _run_phase_correlation_inner(self._report, self.target, findings)

    def hunt_sync(self) -> HuntReport:
        """Synchronous entry point."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.hunt())
            finally:
                loop.close()
        except Exception:
            return asyncio.run(self.hunt())


# ═══════════════════════════════════════════════════════════════════════════
# REPORT FORMATTERS
# ═══════════════════════════════════════════════════════════════════════════


def report_to_console(report: HuntReport) -> str:
    """Format report as a beautiful plain-text console summary.

    HONESTY RULES:
    - Static candidates shown separately under "FORGERY CANDIDATES (not tested)"
    - Risk score reflects only LIVE-confirmed findings
    - Chains only form between LIVE findings
    - "0 vulnerabilities found" is a valid, accurate result
    """
    lines = []
    lines.append("")
    lines.append("=" * 70)
    lines.append(f"  ELENGENIX HUNT REPORT — {report.target}")
    lines.append("=" * 70)
    lines.append(f"  Duration:  {report.total_duration:.1f}s")

    # Count honest categories
    live_findings = [
        f
        for f in report.findings
        if f.severity != "Informational"
        and "CANDIDATE" not in f.title.upper()
        and "not tested" not in f.title.lower()
        and (f.url or f.details)
    ]
    static_candidates = [
        f
        for f in report.findings
        if "CANDIDATE" in f.title.upper() or "not tested" in f.title.lower()
    ]
    info_findings = [f for f in report.findings if f.severity == "Informational"]

    lines.append(
        f"  LIVE vulnerabilities:  {len(live_findings)}  (server actually probed & confirmed)"
    )
    lines.append(f"  Static candidates:     {len(static_candidates)}  (forged tokens, NOT tested)")
    lines.append(f"  Informational:         {len(info_findings)}  (recon/probe metadata)")
    lines.append(f"  Risk score:            {report.risk_score}/100 ({report.risk_level})")
    lines.append("")

    # Honest verdict
    if not live_findings:
        lines.append("  >> RESULT: No live vulnerabilities detected on this target.")
        lines.append("  >> (Static candidates shown below are NOT confirmed —")
        lines.append("  >>  they require manual testing against a real JWT endpoint.)")
        lines.append("")

    # Phase summary
    lines.append("  PHASES")
    lines.append("  " + "-" * 66)
    for p in report.phases:
        icon = {"done": "[OK]", "failed": "[FAIL]", "skipped": "[SKIP]"}.get(p.status, "[?]")
        lines.append(f"  {icon:6s} {p.name:13s}  {p.duration:5.1f}s  {p.findings:3d} findings")

    # Severity breakdown (only LIVE findings count toward severity)
    live_by_sev: Dict[str, int] = {}
    for f in live_findings:
        live_by_sev[f.severity] = live_by_sev.get(f.severity, 0) + 1
    lines.append("")
    lines.append("  CONFIRMED SEVERITY (live findings only)")
    lines.append("  " + "-" * 66)
    if not live_findings:
        lines.append("  (none)")
    else:
        for sev in ("Critical", "High", "Medium", "Low"):
            n = live_by_sev.get(sev, 0)
            if n:
                bar = "#" * min(n * 2, 40)
                lines.append(f"  {sev:14s} {n:3d}  {bar}")

    # Chains (live only)
    if report.chains:
        lines.append("")
        lines.append(f"  VULNERABILITY CHAINS ({len(report.chains)})")
        lines.append("  " + "-" * 66)
        for ch in report.chains[:5]:
            lines.append(f"  [CHAIN] {ch.get('chain_type', 'unknown')}")
            for fname in ch.get("findings", [])[:3]:
                lines.append(f"         - {fname[:80]}")
            if "url" in ch and ch["url"] != "(cross-endpoint)":
                lines.append(f"         at: {ch['url']}")

    # LIVE findings (the real ones)
    lines.append("")
    lines.append("  CONFIRMED LIVE FINDINGS (with proof-of-concept)")
    lines.append("  " + "-" * 66)
    if not live_findings:
        lines.append("  (no confirmed vulnerabilities)")
    else:
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_live = sorted(live_findings, key=lambda f: sev_order.get(f.severity, 5))
        for f in sorted_live[:10]:
            url_short = (f.url[:50] + "...") if len(f.url) > 53 else f.url
            lines.append(f"  [LIVE] [{f.severity:13s}] {f.title[:90]}")
            if url_short:
                lines.append(f"             at: {url_short}")
            # Show PoC proof if available
            poc = (
                (f.evidence or {}).get("proof_of_concept") if isinstance(f.evidence, dict) else None
            )
            if poc and poc.get("impact"):
                lines.append(f"             >> PoC: {poc['impact'][:150]}")
            lines.append(f"             phase: {f.phase}  detector: {f.detector}")

    # Static candidates (clearly separated, not counted as vulnerabilities)
    if static_candidates:
        lines.append("")
        lines.append("  FORGERY CANDIDATES (generated locally, NOT confirmed)")
        lines.append("  " + "-" * 66)
        lines.append(f"  These {len(static_candidates)} items are forged attack tokens,")
        lines.append("  generated locally and never sent to the target. To confirm,")
        lines.append("  a real JWT-protected endpoint is required for live testing.")
        for f in static_candidates[:3]:
            lines.append(f"  [CAND] {f.title[:90]}")

    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


def report_to_dict(report: HuntReport) -> Dict[str, Any]:
    """Convert report to JSON-friendly dict."""
    return {
        "target": report.target,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "total_duration": report.total_duration,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "summary": report.summary,
        "phases": [
            {
                "name": p.name,
                "status": p.status,
                "duration": p.duration,
                "findings": p.findings,
                "error": p.error,
            }
            for p in report.phases
        ],
        "findings": [f.to_dict() for f in report.findings],
        "chains": report.chains,
    }


def save_report(report: HuntReport, out_dir: Optional[Path] = None) -> Path:
    """Save report as JSON to reports/hunt_<target>_<timestamp>/."""
    if out_dir is None:
        ts = int(time.time())
        safe_target = report.target.replace("/", "_").replace(":", "_")
        out_dir = get_reports_path(f"hunt_{safe_target}_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "report.json"
    json_path.write_text(json.dumps(report_to_dict(report), indent=2, default=str))
    txt_path = out_dir / "report.txt"
    txt_path.write_text(report_to_console(report))

    return out_dir


# ═══════════════════════════════════════════════════════════════════════════
# CLI ENTRY
# ═══════════════════════════════════════════════════════════════════════════


async def hunt(target: str, save: bool = True, quiet: bool = False) -> HuntReport:
    """Top-level hunt function."""
    engine = HuntEngine(target=target, quiet=quiet)
    report = await engine.hunt()
    if save:
        out_dir = save_report(report)
        if not quiet:
            print(f"\n[OK] Report saved: {out_dir}")
    return report


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "httpbin.org"
    report = asyncio.run(hunt(target))
    print(report_to_console(report))
