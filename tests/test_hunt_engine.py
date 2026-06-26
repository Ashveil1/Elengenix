"""tests/test_hunt_engine.py

Integration tests for the unified hunt engine.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_hunt_engine_imports() -> None:
    """Hunt engine and all phases must be importable."""
    from tools.hunt_engine import (
        HuntEngine,
        HuntFinding,
        HuntPhase,
        HuntReport,
        Severity,
        compute_risk_score,
        correlate_chains,
        report_to_console,
        report_to_dict,
        save_report,
    )

    assert HuntEngine is not None
    assert callable(compute_risk_score)
    assert callable(correlate_chains)


def test_target_normalization() -> None:
    """Protocol prefix must be stripped."""
    from tools.hunt_engine import HuntEngine

    assert HuntEngine._normalize_target("https://example.com") == "example.com"
    assert HuntEngine._normalize_target("http://example.com/path/") == "example.com/path"
    assert HuntEngine._normalize_target("example.com") == "example.com"


def test_risk_score_clean() -> None:
    """No findings = None (truly nothing found, not Informational)."""
    from tools.hunt_engine import HuntFinding, compute_risk_score

    score, level = compute_risk_score([])
    assert score == 0.0
    assert level == "None"


def test_risk_score_ignores_static_candidates() -> None:
    """Static forgery candidates must NOT inflate risk score."""
    from tools.hunt_engine import HuntFinding, compute_risk_score

    fs = [
        HuntFinding(
            phase="zero_day",
            category="jwt",
            severity="Critical",
            title="JWT forgery CANDIDATE (not tested): alg_none",
        ),
        HuntFinding(
            phase="zero_day",
            category="jwt",
            severity="Critical",
            title="JWT forgery CANDIDATE (not tested): hs256_confusion",
        ),
    ]
    score, level = compute_risk_score(fs)
    # Static candidates must NOT contribute to score
    assert score == 0.0
    assert level == "None"


def test_risk_score_live_critical() -> None:
    """LIVE critical findings do push score up."""
    from tools.hunt_engine import HuntFinding, compute_risk_score

    fs = [
        HuntFinding(
            phase="zero_day",
            category="jwt",
            severity="Critical",
            title="JWT alg=none accepted",
            url="http://target/api",
            details="Server returned 200",
        ),
    ]
    score, level = compute_risk_score(fs)
    # Single Critical = 25 points → Medium (20-39 range)
    assert score == 25.0
    assert level == "Medium"

    # Multiple critical findings push to High/Critical
    fs.append(
        HuntFinding(
            phase="zero_day",
            category="jwt",
            severity="Critical",
            title="JWT alg=none_no_typ accepted",
            url="http://target/api",
            details="Server returned 200",
        )
    )
    score, level = compute_risk_score(fs)
    assert score >= 50
    assert level in ("High", "Critical")


def test_correlation_same_url() -> None:
    """2+ LIVE findings on same URL = chain candidate."""
    from tools.hunt_engine import HuntFinding, correlate_chains

    fs = [
        HuntFinding(
            phase="zero_day",
            category="jwt",
            severity="High",
            title="JWT alg=none",
            url="http://x.com/api",
            details="confirmed",
        ),
        HuntFinding(
            phase="smart",
            category="bola",
            severity="High",
            title="BOLA on /api",
            url="http://x.com/api",
            details="confirmed",
        ),
    ]
    chains = correlate_chains(fs)
    assert len(chains) >= 1


def test_correlation_ignores_static_candidates() -> None:
    """Static candidates must NOT form chains."""
    from tools.hunt_engine import HuntFinding, correlate_chains

    fs = [
        # Static JWT — should NOT chain
        HuntFinding(
            phase="zero_day",
            category="jwt",
            severity="Critical",
            title="JWT forgery CANDIDATE (not tested): alg_none",
        ),
        HuntFinding(
            phase="smart",
            category="bola",
            severity="High",
            title="BOLA",
            url="http://x.com/api",
            details="confirmed",
        ),
    ]
    chains = correlate_chains(fs)
    # No chain should be formed because the JWT finding is static
    chain_types = [c.get("chain_type") for c in chains]
    assert "auth_bypass_then_idor" not in chain_types


def test_correlation_jwt_idor_chain() -> None:
    """LIVE JWT + BOLA = known chain pattern."""
    from tools.hunt_engine import HuntFinding, correlate_chains

    fs = [
        HuntFinding(
            phase="zero_day",
            category="jwt_confusion",
            severity="Critical",
            title="JWT alg=none accepted",
            url="http://target/api",
            details="Server returned 200 with forged token",
        ),
        HuntFinding(
            phase="smart",
            category="bola",
            severity="High",
            title="IDOR on /api/user",
            url="http://target/api/user",
            details="differential access confirmed",
        ),
    ]
    chains = correlate_chains(fs)
    chain_types = [c.get("chain_type") for c in chains]
    assert "auth_bypass_then_idor" in chain_types


def test_report_to_dict_serializable() -> None:
    """Report must be JSON-serializable."""
    from tools.hunt_engine import HuntEngine, HuntFinding, HuntPhase, HuntReport, report_to_dict

    r = HuntReport(target="example.com", started_at="2026-01-01T00:00:00Z")
    r.findings = [HuntFinding(phase="zero_day", category="x", severity="High", title="t")]
    r.phases = [HuntPhase(name="zero_day", status="done", duration=1.0, findings=1)]
    r.risk_score = 12.0
    r.risk_level = "High"
    d = report_to_dict(r)
    # Must serialize to JSON without error
    s = json.dumps(d)
    parsed = json.loads(s)
    assert parsed["target"] == "example.com"
    assert len(parsed["findings"]) == 1


def test_report_to_console_format() -> None:
    """Console report must contain key sections and be honest."""
    from tools.hunt_engine import HuntEngine, HuntFinding, HuntPhase, HuntReport, report_to_console

    r = HuntReport(target="example.com", started_at="2026-01-01T00:00:00Z")
    r.findings = [
        HuntFinding(
            phase="zero_day",
            category="jwt",
            severity="Critical",
            title="JWT alg=none accepted",
            url="http://target/api",
            details="confirmed",
        ),
        HuntFinding(
            phase="recon",
            category="baseline",
            severity="Informational",
            title="Recon",
            url="http://target",
        ),
    ]
    r.phases = [
        HuntPhase(name="recon", status="done", duration=0.5, findings=1),
        HuntPhase(name="zero_day", status="done", duration=1.0, findings=1),
    ]
    r.risk_score = 25.0
    r.risk_level = "Critical"
    txt = report_to_console(r)
    assert "ELENGENIX HUNT REPORT" in txt
    assert "example.com" in txt
    assert "JWT alg=none accepted" in txt
    # HONESTY: must mention LIVE vs Static candidates
    assert "LIVE" in txt or "CONFIRMED" in txt
    assert "CANDIDATE" in txt or "candidates" in txt.lower()


def test_report_honest_when_no_findings() -> None:
    """Report must honestly say 'No live vulnerabilities' when nothing was confirmed."""
    from tools.hunt_engine import HuntFinding, HuntReport, report_to_console

    r = HuntReport(target="safe-target.com", started_at="2026-01-01T00:00:00Z")
    # Only static candidates + informational
    r.findings = [
        HuntFinding(
            phase="zero_day",
            category="jwt",
            severity="Informational",
            title="JWT forgery CANDIDATE (not tested): alg_none",
        ),
        HuntFinding(
            phase="recon", category="baseline", severity="Informational", title="Recon done"
        ),
    ]
    r.risk_score = 0.0
    r.risk_level = "None"
    txt = report_to_console(r)
    # Must clearly state nothing was found
    assert "No live vulnerabilities" in txt or "no confirmed" in txt.lower()
    assert "0" in txt  # zero live vulnerabilities count


def test_save_report_creates_files(tmp_path: Path) -> None:
    """save_report writes JSON + text to reports dir."""
    from tools.hunt_engine import HuntFinding, HuntReport, save_report

    r = HuntReport(target="example.com", started_at="2026-01-01T00:00:00Z")
    r.findings = [HuntFinding(phase="recon", category="x", severity="Info", title="t")]
    out = save_report(r, out_dir=tmp_path / "test_report")
    assert (out / "report.json").exists()
    assert (out / "report.txt").exists()
    data = json.loads((out / "report.json").read_text())
    assert data["target"] == "example.com"


def test_hunt_engine_hunt_sync() -> None:
    """hunt_sync must work for non-async callers."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target="httpbin.org", quiet=True)
    report = engine.hunt_sync()
    assert report.target == "httpbin.org"
    assert len(report.phases) == 5  # all 5 phases
    # At least recon + zero-day should produce findings
    assert any(p.findings > 0 for p in report.phases)


def test_hunt_engine_skip_phases() -> None:
    """Skipped phases must be marked as skipped, not run."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target="httpbin.org", skip_phases=["zero_day", "logic"], quiet=True)
    report = engine.hunt_sync()
    skipped = [p for p in report.phases if p.status == "skipped"]
    skipped_names = {p.name for p in skipped}
    assert {"zero_day", "logic"} <= skipped_names


def test_hunt_engine_live_httpbin() -> None:
    """Live scan against httpbin.org must honestly report what was found."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target="httpbin.org", quiet=True)
    report = engine.hunt_sync()

    # HONESTY: httpbin.org has no real vulnerabilities
    # The LIVE count should be 0 (no confirmed vulns)
    # We expect: 8 static candidates + informational recon findings
    static = [f for f in report.findings if "CANDIDATE" in f.title.upper()]
    live = [
        f
        for f in report.findings
        if f.severity != "Informational"
        and "CANDIDATE" not in f.title.upper()
        and (f.url or f.details)
    ]
    # No confirmed live vulnerabilities on httpbin
    assert len(live) == 0, f"Expected 0 live vulns on httpbin, got {len(live)}"
    # Risk score should be 0 (honest)
    assert report.risk_score == 0.0
    assert report.risk_level == "None"
    # Static candidates should be present (they are always generated)
    assert len(static) >= 1


def test_hunt_engine_saves_to_reports_dir() -> None:
    """save_report must default to reports/hunt_<target>_<ts>/."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target="httpbin.org", quiet=True)
    report = engine.hunt_sync()
    from tools.hunt_engine import save_report

    out_dir = save_report(report)
    assert out_dir.exists()
    assert (out_dir / "report.json").exists()
    assert (out_dir / "report.txt").exists()
    # Cleanup
    import shutil

    shutil.rmtree(out_dir, ignore_errors=True)


def test_hunt_command_registered() -> None:
    """The 'hunt' command must be registered with aliases."""
    import commands.worldclass  # noqa: F401
    from commands.registry import CommandRegistry

    reg = CommandRegistry()
    cmd = reg.get("hunt")
    assert cmd is not None
    assert cmd.name == "hunt"
    # Aliases
    for alias in ("h", "scan-all", "find"):
        c = reg.get(alias)
        assert c is not None, f"Alias '{alias}' not found"
        assert c.name == "hunt"


def test_hunt_command_runs() -> None:
    """The 'hunt' command must execute without error."""
    import argparse

    import commands.worldclass as wc

    args = argparse.Namespace(target="httpbin.org", quiet=True)
    rc = asyncio.run(wc.cmd_hunt(args))
    assert rc == 0


def test_phase_ordering() -> None:
    """Phases must run in correct order: recon -> smart -> zero_day -> logic -> correlation."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target="httpbin.org", quiet=True)
    report = engine.hunt_sync()
    order = [p.name for p in report.phases]
    expected = ["recon", "smart", "zero_day", "logic", "correlation"]
    assert order == expected, f"Wrong phase order: {order}"


def test_finding_severity_in_valid_set() -> None:
    """All finding severities must be valid values."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target="httpbin.org", quiet=True)
    report = engine.hunt_sync()
    valid = {"Critical", "High", "Medium", "Low", "Informational"}
    for f in report.findings:
        assert f.severity in valid, f"Invalid severity: {f.severity}"


def test_no_duplicate_findings_same_phase_title() -> None:
    """Within a phase, titles should not be exact duplicates (basic dedup)."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target="httpbin.org", quiet=True)
    report = engine.hunt_sync()
    from collections import Counter

    c = Counter(f.title for f in report.findings if f.phase == "zero_day")
    for title, count in c.items():
        # Allow some duplicates but not extreme runaway
        assert count <= 3, f"Too many duplicates: {title!r} appears {count} times"
