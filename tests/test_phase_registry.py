"""tests/test_phase_registry.py — Tests for pipeline.phase_registry"""

import asyncio

import pytest

from pipeline.phase_registry import (
    CyclicDependencyError,
    Phase,
    PhaseContext,
    PhaseRegistry,
    PhaseResult,
)


# ── Helper Functions ───────────────────────────────────────────


async def _phase_noop(ctx: PhaseContext) -> PhaseResult:
    """No-op phase for testing."""
    return PhaseResult(success=True)


async def _phase_recon(ctx: PhaseContext) -> PhaseResult:
    """Mock recon phase."""
    return PhaseResult(
        success=True,
        findings=[{"type": "recon", "url": ctx.target}],
        output={"endpoints": ["/api", "/admin"]},
    )


async def _phase_fuzz(ctx: PhaseContext) -> PhaseResult:
    """Mock fuzz phase that uses recon output."""
    recon_output = ctx.extra.get("recon", {})
    endpoints = recon_output.get("endpoints", [])
    findings = [{"type": "xss", "url": f"{ctx.target}{ep}"} for ep in endpoints]
    return PhaseResult(success=True, findings=findings)


async def _phase_failing(ctx: PhaseContext) -> PhaseResult:
    """Phase that fails."""
    return PhaseResult(success=False, error="Intentional failure")


async def _phase_slow(ctx: PhaseContext) -> PhaseResult:
    """Slow phase for timeout testing."""
    await asyncio.sleep(10)
    return PhaseResult(success=True)


# ── PhaseContext Tests ─────────────────────────────────────────


class TestPhaseContext:
    def test_default_values(self):
        ctx = PhaseContext()
        assert ctx.target == ""
        assert ctx.findings == []
        assert ctx.extra == {}

    def test_with_values(self):
        ctx = PhaseContext(target="example.com", timeout=60)
        assert ctx.target == "example.com"
        assert ctx.timeout == 60


# ── PhaseResult Tests ──────────────────────────────────────────


class TestPhaseResult:
    def test_default_values(self):
        r = PhaseResult()
        assert r.success is True
        assert r.findings == []
        assert r.output is None
        assert r.error == ""

    def test_with_values(self):
        r = PhaseResult(success=False, error="failed")
        assert r.success is False
        assert r.error == "failed"


# ── PhaseRegistry Creation Tests ──────────────────────────────


class TestPhaseRegistryCreation:
    def test_create_empty(self):
        reg = PhaseRegistry()
        assert len(reg.phases) == 0

    def test_list_phases_empty(self):
        reg = PhaseRegistry()
        assert reg.list_phases() == []


# ── Registration Tests ─────────────────────────────────────────


class TestRegistration:
    def test_register_phase(self):
        reg = PhaseRegistry()
        phase = Phase(name="recon", func=_phase_noop)
        reg.register(phase)
        assert "recon" in reg.list_phases()

    def test_register_multiple(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="recon", func=_phase_noop))
        reg.register(Phase(name="fuzz", func=_phase_noop))
        assert len(reg.list_phases()) == 2

    def test_register_duplicate_raises(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="recon", func=_phase_noop))
        with pytest.raises(ValueError, match="already registered"):
            reg.register(Phase(name="recon", func=_phase_noop))

    def test_unregister(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="recon", func=_phase_noop))
        reg.unregister("recon")
        assert "recon" not in reg.list_phases()

    def test_unregister_nonexistent(self):
        reg = PhaseRegistry()
        reg.unregister("nonexistent")  # Should not raise

    def test_get_phase(self):
        reg = PhaseRegistry()
        phase = Phase(name="recon", func=_phase_noop)
        reg.register(phase)
        assert reg.get("recon") is phase

    def test_get_nonexistent(self):
        reg = PhaseRegistry()
        assert reg.get("nonexistent") is None


# ── Dependency Resolution Tests ────────────────────────────────


class TestDependencyResolution:
    def test_no_deps_single_wave(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="a", func=_phase_noop, deps=[]))
        waves = reg.get_execution_waves()
        assert len(waves) == 1
        assert len(waves[0]) == 1
        assert waves[0][0].name == "a"

    def test_independent_phases_same_wave(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="a", func=_phase_noop, deps=[]))
        reg.register(Phase(name="b", func=_phase_noop, deps=[]))
        waves = reg.get_execution_waves()
        assert len(waves) == 1
        assert len(waves[0]) == 2

    def test_dependent_phases_separate_waves(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="recon", func=_phase_noop, deps=[]))
        reg.register(Phase(name="fuzz", func=_phase_noop, deps=["recon"]))
        waves = reg.get_execution_waves()
        assert len(waves) == 2
        assert waves[0][0].name == "recon"
        assert waves[1][0].name == "fuzz"

    def test_complex_dependency_graph(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="recon", func=_phase_noop, deps=[]))
        reg.register(Phase(name="waf", func=_phase_noop, deps=[]))
        reg.register(Phase(name="fuzz", func=_phase_noop, deps=["recon"]))
        reg.register(Phase(name="bola", func=_phase_noop, deps=["recon"]))
        reg.register(Phase(name="learn", func=_phase_noop, deps=["recon", "waf", "fuzz", "bola"]))
        reg.register(Phase(name="coverage", func=_phase_noop, deps=["recon", "waf", "fuzz", "bola"]))

        waves = reg.get_execution_waves()
        assert len(waves) == 3
        # Wave 0: recon, waf (no deps)
        assert len(waves[0]) == 2
        # Wave 1: fuzz, bola (depend on recon)
        assert len(waves[1]) == 2
        # Wave 2: learn, coverage (depend on all)
        assert len(waves[2]) == 2

    def test_cyclic_dependency_raises(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="a", func=_phase_noop, deps=["b"]))
        reg.register(Phase(name="b", func=_phase_noop, deps=["a"]))
        with pytest.raises(CyclicDependencyError):
            reg.get_execution_waves()

    def test_missing_dependency_raises(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="a", func=_phase_noop, deps=["nonexistent"]))
        with pytest.raises(ValueError, match="not registered"):
            reg.get_execution_waves()


# ── Execution Tests ────────────────────────────────────────────


class TestExecution:
    @pytest.mark.asyncio
    async def test_run_single_phase(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="recon", func=_phase_recon, deps=[]))

        ctx = PhaseContext(target="example.com")
        results = await reg.run(ctx)

        assert len(results) == 1
        assert results[0].success is True
        assert len(results[0].findings) == 1

    @pytest.mark.asyncio
    async def test_run_parallel_phases(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="a", func=_phase_recon, deps=[]))
        reg.register(Phase(name="b", func=_phase_recon, deps=[]))

        ctx = PhaseContext(target="example.com")
        results = await reg.run(ctx)

        assert len(results) == 2
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_run_with_dependencies(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="recon", func=_phase_recon, deps=[]))
        reg.register(Phase(name="fuzz", func=_phase_fuzz, deps=["recon"]))

        ctx = PhaseContext(target="http://example.com")
        results = await reg.run(ctx)

        assert len(results) == 2
        # Recon should have output
        recon_result = next(r for r in results if r.output is not None)
        assert recon_result.output["endpoints"] == ["/api", "/admin"]
        # Fuzz should have findings from recon output
        fuzz_result = next(r for r in results if len(r.findings) == 2)
        assert len(fuzz_result.findings) == 2

    @pytest.mark.asyncio
    async def test_run_failing_phase(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="fail", func=_phase_failing, deps=[]))

        ctx = PhaseContext(target="example.com")
        results = await reg.run(ctx)

        assert len(results) == 1
        assert results[0].success is False
        assert "Intentional failure" in results[0].error

    @pytest.mark.asyncio
    async def test_run_with_filter(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="a", func=_phase_recon, deps=[]))
        reg.register(Phase(name="b", func=_phase_recon, deps=[]))

        ctx = PhaseContext(target="example.com")
        results = await reg.run(ctx, phases=["a"])

        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_findings_accumulated(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="recon", func=_phase_recon, deps=[]))
        reg.register(Phase(name="fuzz", func=_phase_fuzz, deps=["recon"]))

        ctx = PhaseContext(target="http://example.com")
        await reg.run(ctx)

        # Context should have accumulated findings from both phases
        assert len(ctx.findings) == 3  # 1 from recon + 2 from fuzz

    @pytest.mark.asyncio
    async def test_output_passed_via_extra(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="recon", func=_phase_recon, deps=[]))
        reg.register(Phase(name="fuzz", func=_phase_fuzz, deps=["recon"]))

        ctx = PhaseContext(target="http://example.com")
        await reg.run(ctx)

        # Fuzz should have received recon's output via extra
        assert "recon" in ctx.extra
        assert ctx.extra["recon"]["endpoints"] == ["/api", "/admin"]


# ── Timeout Tests ──────────────────────────────────────────────


class TestTimeout:
    @pytest.mark.asyncio
    async def test_phase_timeout(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="slow", func=_phase_slow, deps=[], timeout=1))

        ctx = PhaseContext(target="example.com")
        results = await reg.run(ctx)

        assert len(results) == 1
        assert results[0].success is False
        assert "timed out" in results[0].error

    @pytest.mark.asyncio
    async def test_context_timeout_used(self):
        reg = PhaseRegistry()
        reg.register(Phase(name="slow", func=_phase_slow, deps=[]))

        ctx = PhaseContext(target="example.com", timeout=1)
        results = await reg.run(ctx)

        assert len(results) == 1
        assert results[0].success is False
