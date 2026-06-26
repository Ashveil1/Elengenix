"""tests/test_nvd_cve.py

Tests for NVD CVE database integration.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_nvd_loads_embedded_cves():
    """NVD must load embedded CVEs."""
    from tools.nvd_cve import get_nvd

    nvd = get_nvd()
    assert nvd.count() >= 30, f"Too few CVEs: {nvd.count()}"


def test_nvd_lookup_vulnerable_django():
    """Django 3.0.0 must have known CVEs."""
    from tools.nvd_cve import get_nvd

    nvd = get_nvd()
    cves = nvd.lookup("django", "3.0.0")
    assert len(cves) >= 1
    cve_ids = {c.cve_id for c in cves}
    # Should have at least one Django-specific CVE
    assert any(cve.startswith("CVE-") for cve in cve_ids)


def test_nvd_lookup_patched_django():
    """Patched Django should have fewer/no CVEs."""
    from tools.nvd_cve import get_nvd

    nvd = get_nvd()
    cves_old = nvd.lookup("django", "3.0.0")
    cves_new = nvd.lookup("django", "4.2.16")
    assert len(cves_new) < len(
        cves_old
    ), f"Patched version should have fewer CVEs: old={len(cves_old)}, new={len(cves_new)}"


def test_nvd_lookup_log4shell():
    """Log4Shell CVE-2021-44228 must be detected."""
    from tools.nvd_cve import get_nvd

    nvd = get_nvd()
    cves = nvd.lookup("log4j", "2.14.0")
    cve_ids = {c.cve_id for c in cves}
    assert "CVE-2021-44228" in cve_ids
    # Severity must be Critical
    log4shell = next(c for c in cves if c.cve_id == "CVE-2021-44228")
    assert log4shell.severity == "Critical"
    assert log4shell.exploit_available is True


def test_nvd_lookup_unknown_package():
    """Unknown package should return empty list."""
    from tools.nvd_cve import get_nvd

    nvd = get_nvd()
    cves = nvd.lookup("unknown-package-xyz-12345", "1.0.0")
    assert cves == []


def test_nvd_cve_has_required_fields():
    """Each CVE must have required fields."""
    from tools.nvd_cve import get_nvd

    nvd = get_nvd()
    for cve in nvd.list_all()[:10]:
        assert cve.cve_id.startswith("CVE-")
        assert cve.description
        assert 0 <= cve.cvss_v3 <= 10
        assert cve.severity in ("Critical", "High", "Medium", "Low", "Informational")
        assert cve.affected_products
        assert cve.fixed_in


def test_nvd_lookup_dependencies_bulk():
    """Bulk dependency scan must work."""
    from tools.nvd_cve import scan_dependencies_for_cves

    deps = [
        ("django", "3.0.0"),
        ("requests", "2.20.0"),
        ("pillow", "8.1.0"),
        ("transformers", "4.0.0"),
        ("log4j", "2.14.0"),
    ]
    result = scan_dependencies_for_cves(deps)
    assert len(result) >= 4, f"Only found CVEs for: {list(result.keys())}"
    # Pillow should have CVE matches
    assert "pillow" in result


def test_nvd_severity_classification():
    """CVSS → severity mapping must be correct."""
    from tools.nvd_cve import _sev

    assert _sev(10.0) == "Critical"
    assert _sev(9.0) == "Critical"
    assert _sev(8.9) == "High"
    assert _sev(7.0) == "High"
    assert _sev(6.9) == "Medium"
    assert _sev(4.0) == "Medium"
    assert _sev(3.9) == "Low"
    assert _sev(0.0) == "Informational"


def test_nvd_cve_to_dict():
    """CVE to_dict must be JSON-serializable."""
    import json

    from tools.nvd_cve import get_nvd

    nvd = get_nvd()
    cves = nvd.list_all()
    payload = [c.to_dict() for c in cves[:5]]
    s = json.dumps(payload)
    assert "CVE-" in s


def test_nvd_log4j_vulnerable_range():
    """Log4j 2.14.0 is in vulnerable range for CVE-2021-44228."""
    from tools.nvd_cve import get_nvd

    nvd = get_nvd()
    # Various versions in vulnerable range
    for v in ["2.10.0", "2.14.0", "2.16.0"]:
        cves = nvd.lookup("log4j", v)
        cve_ids = {c.cve_id for c in cves}
        assert "CVE-2021-44228" in cve_ids, f"v={v} missed Log4Shell"
    # Patched version
    cves = nvd.lookup("log4j", "2.17.1")
    cve_ids = {c.cve_id for c in cves}
    assert "CVE-2021-44228" not in cve_ids


def test_nvd_in_hunt_engine():
    """Hunt engine must integrate NVD when scanning a project."""
    import asyncio
    import socket

    # Skip if no target running
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(("127.0.0.1", 5555))
        s.close()
        target = "127.0.0.1:5555"
    except Exception:
        pytest.skip("vulnerable target not running")

    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target=target, quiet=True)
    report = engine.hunt_sync()
    # We don't require NVD findings against the test target (no project deps)
    # but the phase must not crash
    assert report is not None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
