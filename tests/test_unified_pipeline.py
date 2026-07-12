"""tests/test_unified_pipeline.py — Tests for pipeline.unified"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pipeline.phase_registry import Phase, PhaseContext, PhaseRegistry, PhaseResult
from pipeline.scope import ScopeManager
from pipeline.unified import (
    ScanConfig,
    ScanOutput,
    UnifiedPipeline,
    _recon_to_findings,
)


# ── ScanConfig Tests ───────────────────────────────────────────


class TestScanConfig:
    def test_defaults(self):
        cfg = ScanConfig(target="example.com")
        assert cfg.target == "example.com"
        assert cfg.rate_limit == 5
        assert cfg.timeout == 600
        assert cfg.phases is None
        assert cfg.use_registry is True

    def test_custom_values(self):
        cfg = ScanConfig(
            target="example.com",
            rate_limit=3,
            timeout=120,
            phases=["recon", "waf"],
            use_registry=False,
        )
        assert cfg.rate_limit == 3
        assert cfg.timeout == 120
        assert cfg.phases == ["recon", "waf"]
        assert cfg.use_registry is False


# ── ScanOutput Tests ──────────────────────────────────────────


class TestScanOutput:
    def test_defaults(self):
        out = ScanOutput()
        assert out.success is False
        assert out.findings == []
        assert out.errors == []

    def test_with_values(self):
        out = ScanOutput(success=True, summary="Done", findings=[{"type": "xss"}])
        assert out.success is True
        assert out.summary == "Done"
        assert len(out.findings) == 1


# ── Recon to Findings Tests ───────────────────────────────────


class TestReconToFindings:
    def test_empty_recon(self):
        assert _recon_to_findings({}, "http://example.com") == []

    def test_http_probe_finding(self):
        recon = {
            "http_probe": {
                "status": 200,
                "title": "Test Page",
                "tech": ["PHP", "WordPress"],
                "headers": {"Server": "Apache"},
            }
        }
        findings = _recon_to_findings(recon, "http://example.com")
        assert len(findings) == 1
        assert findings[0]["type"] == "recon_http"

    def test_endpoints(self):
        recon = {
            "directories": [
                {"url": "http://example.com/admin", "status": 200, "length": 1000},
                {"url": "http://example.com/login", "status": 301, "length": 0},
            ]
        }
        findings = _recon_to_findings(recon, "http://example.com")
        assert len(findings) == 2
        assert findings[0]["type"] == "endpoint"

    def test_ports(self):
        recon = {"ports": [{"host": "example.com", "port": 80, "service": "http"}]}
        findings = _recon_to_findings(recon, "http://example.com")
        assert len(findings) == 1
        assert findings[0]["type"] == "port"

    def test_subdomains(self):
        recon = {"subdomains": [{"subdomain": "api.example.com", "ips": ["1.2.3.4"]}]}
        findings = _recon_to_findings(recon, "http://example.com")
        assert len(findings) == 1
        assert findings[0]["type"] == "subdomain"

    def test_interesting_params(self):
        recon = {
            "parameters": [
                {
                    "url": "http://example.com/api",
                    "param": "q",
                    "method": "GET",
                    "is_interesting": True,
                    "delta_pct": 50,
                }
            ]
        }
        findings = _recon_to_findings(recon, "http://example.com")
        assert len(findings) == 1
        assert findings[0]["type"] == "param_discovery"


# ── UnifiedPipeline Creation Tests ────────────────────────────


class TestUnifiedPipelineCreation:
    def test_create_with_defaults(self):
        pipeline = UnifiedPipeline()
        assert pipeline.scope_manager is not None
        assert pipeline.phase_registry is not None

    def test_default_registry_has_6_phases(self):
        pipeline = UnifiedPipeline()
        phases = pipeline.phase_registry.list_phases()
        assert len(phases) == 6
        assert "recon" in phases
        assert "waf" in phases
        assert "fuzz" in phases
        assert "bola" in phases
        assert "learn" in phases
        assert "coverage" in phases

    def test_create_with_custom_scope(self):
        sm = ScopeManager(scope_file="custom.txt")
        pipeline = UnifiedPipeline(scope_manager=sm)
        assert pipeline.scope_manager is sm

    def test_create_with_custom_registry(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="custom", func=AsyncMock()))
        pipeline = UnifiedPipeline(phase_registry=reg)
        assert "custom" in pipeline.phase_registry.list_phases()


# ── Scope Validation Tests ────────────────────────────────────


class TestScopeValidation:
    @pytest.mark.asyncio
    async def test_scope_violation_returns_error(self):
        pipeline = UnifiedPipeline()
        config = ScanConfig(target="192.168.1.1")  # Private IP

        output = await pipeline.run(config)

        assert output.success is False
        assert "SCOPE VIOLATION" in output.summary

    @pytest.mark.asyncio
    async def test_empty_scope_denies_all(self):
        pipeline = UnifiedPipeline()
        # Override scope to be empty (deny all — fail-closed)
        pipeline.scope_manager._domains = set()

        config = ScanConfig(target="example.com")
        output = await pipeline.run(config)

        assert output.success is False
        assert "SCOPE VIOLATION" in output.summary


# ── Pipeline Execution Tests ──────────────────────────────────


class TestPipelineExecution:
    @pytest.mark.asyncio
    async def test_run_with_noop_phases(self):
        pipeline = UnifiedPipeline()
        pipeline.scope_manager._domains = {"example.com"}  # Configure scope

        # Replace with simple phases
        pipeline.phase_registry = PhaseRegistry()
        pipeline.phase_registry.register(
            Phase(
                name="test",
                func=AsyncMock(return_value=PhaseResult(success=True, findings=[{"type": "test"}])),
            )
        )

        config = ScanConfig(target="example.com", phases=["test"])
        output = await pipeline.run(config)

        assert output.success is True
        assert len(output.findings) == 1
        assert "example.com" in output.summary

    @pytest.mark.asyncio
    async def test_run_saves_findings(self, tmp_path):
        pipeline = UnifiedPipeline()
        pipeline.scope_manager._domains = {"example.com"}

        pipeline.phase_registry = PhaseRegistry()
        pipeline.phase_registry.register(
            Phase(
                name="test",
                func=AsyncMock(return_value=PhaseResult(success=True, findings=[{"type": "xss"}])),
            )
        )

        config = ScanConfig(target="example.com", phases=["test"])
        output = await pipeline.run(config)

        # Check that findings were saved
        findings_path = Path(output.report_dir) / "unified_findings.json"
        assert findings_path.exists()

    @pytest.mark.asyncio
    async def test_run_collects_errors(self):
        pipeline = UnifiedPipeline()
        pipeline.scope_manager._domains = {"example.com"}

        async def failing_phase(ctx):
            return PhaseResult(success=False, error="Intentional failure")

        pipeline.phase_registry = PhaseRegistry()
        pipeline.phase_registry.register(Phase(name="fail", func=failing_phase))

        config = ScanConfig(target="example.com", phases=["fail"])
        output = await pipeline.run(config)

        assert output.success is False
        assert len(output.errors) == 1
        assert "Intentional failure" in output.errors[0]


# ── Phase Wiring Tests ────────────────────────────────────────


class TestPhaseWiring:
    def test_phase_functions_are_async(self):
        """Verify all phase functions are async coroutines."""
        from pipeline.unified import (
            _phase_bola,
            _phase_coverage,
            _phase_fuzz,
            _phase_learn,
            _phase_recon,
            _phase_waf,
        )

        import asyncio

        for func in [
            _phase_recon,
            _phase_waf,
            _phase_fuzz,
            _phase_bola,
            _phase_learn,
            _phase_coverage,
        ]:
            assert asyncio.iscoroutinefunction(func), f"{func.__name__} is not async"

    def test_registry_has_correct_deps(self):
        """Verify dependency graph is correct."""
        pipeline = UnifiedPipeline()
        waves = pipeline.phase_registry.get_execution_waves()

        # Wave 0: recon, waf (no deps)
        wave0_names = {p.name for p in waves[0]}
        assert "recon" in wave0_names
        assert "waf" in wave0_names

        # Wave 1: fuzz, bola (depend on recon)
        wave1_names = {p.name for p in waves[1]}
        assert "fuzz" in wave1_names
        assert "bola" in wave1_names

        # Wave 2: learn, coverage (depend on all)
        wave2_names = {p.name for p in waves[2]}
        assert "learn" in wave2_names
        assert "coverage" in wave2_names
