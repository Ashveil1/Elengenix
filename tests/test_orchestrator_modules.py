import asyncio
from pathlib import Path

from orchestrator import run_elengenix_modules


def test_run_elengenix_modules_returns_findings(tmp_path: Path):
    """Test it returns > 0 findings on httpbin.org"""
    target = "httpbin.org"
    # timeout 60s should be enough to capture quick recon and maybe some fuzzing
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    findings = loop.run_until_complete(run_elengenix_modules(target, tmp_path, timeout=60))
    loop.close()

    assert isinstance(findings, list)
    # Even a quick run on httpbin.org should return at least some ports or recon_http
    assert len(findings) > 0, "run_elengenix_modules returned 0 findings on httpbin.org"

    # Check if python_recon.json was created
    recon_json = tmp_path / "python_recon.json"
    assert recon_json.exists(), "python_recon.json was not saved"


def test_run_elengenix_modules_unreachable_target(tmp_path: Path):
    """Test it returns 0 findings gracefully on unreachable target"""
    target = "198.51.100.1:1"  # TEST-NET-2, effectively a blackhole

    # This should fail fast and return an empty list or very few findings (0)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    findings = loop.run_until_complete(run_elengenix_modules(target, tmp_path, timeout=10))
    loop.close()

    assert isinstance(findings, list)
    # The target is unreachable, so finding count should be 0
    assert len(findings) == 0, f"Expected 0 findings for unreachable target, got {len(findings)}"
