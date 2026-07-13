"""
pipeline/phase_registry.py — Configurable Phase Registry

Manages scan phases with dependency resolution. Phases are registered
with their dependencies, and the registry resolves the execution order
into waves that can run in parallel.

Extracted from orchestrator.py's hardcoded 6-phase system.

Usage:
    registry = PhaseRegistry()
    registry.register(Phase(name="recon", func=recon_func, deps=[]))
    registry.register(Phase(name="waf", func=waf_func, deps=[]))
    registry.register(Phase(name="fuzz", func=fuzz_func, deps=["recon"]))

    waves = registry.get_execution_waves()
    # [[recon, waf], [fuzz]]

    result = await registry.run(context)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("elengenix.phase_registry")


# ── Data Classes ───────────────────────────────────────────────


@dataclass
class PhaseContext:
    """Context passed to each phase function.

    Attributes:
        target: Normalized target domain/IP.
        base_url: Full URL with scheme.
        report_dir: Directory for reports.
        findings: Accumulated findings from previous phases.
        timeout: Per-phase timeout in seconds.
        extra: Arbitrary data for passing between phases.
    """

    target: str = ""
    base_url: str = ""
    report_dir: Path = field(default_factory=lambda: get_reports_path())
    findings: List[Dict[str, Any]] = field(default_factory=list)
    timeout: int = 300
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PhaseResult:
    """Result returned by a phase function.

    Attributes:
        success: Whether the phase completed successfully.
        findings: Findings discovered by this phase.
        output: Any additional output (e.g., recon results).
        error: Error message if the phase failed.
    """

    success: bool = True
    findings: List[Dict[str, Any]] = field(default_factory=list)
    output: Any = None
    error: str = ""


@dataclass
class Phase:
    """A scan phase with dependencies.

    Attributes:
        name: Unique phase identifier.
        func: Async function to execute. Signature:
            async def func(ctx: PhaseContext) -> PhaseResult
        deps: List of phase names this phase depends on.
        description: Human-readable description.
        timeout: Override per-phase timeout (None = use context timeout).
    """

    name: str
    func: Callable
    deps: List[str] = field(default_factory=list)
    description: str = ""
    timeout: Optional[int] = None


class CyclicDependencyError(Exception):
    """Raised when a cyclic dependency is detected."""

    pass


# ── Phase Registry ─────────────────────────────────────────────


class PhaseRegistry:
    """Manages scan phases with dependency resolution.

    Phases are registered with their dependencies. The registry
    resolves the execution order into waves that can run in parallel.

    Usage:
        registry = PhaseRegistry()
        registry.register(Phase(name="recon", func=recon_func, deps=[]))
        registry.register(Phase(name="fuzz", func=fuzz_func, deps=["recon"]))

        waves = registry.get_execution_waves()
        # [[recon], [fuzz]]

        result = await registry.run(context)
    """

    def __init__(self):
        self.phases: Dict[str, Phase] = {}

    def register(self, phase: Phase) -> None:
        """Register a phase.

        Args:
            phase: The phase to register.

        Raises:
            ValueError: If a phase with the same name is already registered.
        """
        if phase.name in self.phases:
            raise ValueError(f"Phase '{phase.name}' is already registered")
        self.phases[phase.name] = phase

    def unregister(self, name: str) -> None:
        """Unregister a phase.

        Args:
            name: Name of the phase to remove.
        """
        self.phases.pop(name, None)

    def get(self, name: str) -> Optional[Phase]:
        """Get a phase by name.

        Args:
            name: Phase name.

        Returns:
            The phase, or None if not found.
        """
        return self.phases.get(name)

    def list_phases(self) -> List[str]:
        """List all registered phase names.

        Returns:
            List of phase names.
        """
        return list(self.phases.keys())

    def get_execution_waves(self) -> List[List[Phase]]:
        """Resolve dependency graph into execution waves.

        Uses topological sort with level grouping. Phases in the same
        wave have no dependencies on each other and can run in parallel.

        Returns:
            List of waves, where each wave is a list of phases.

        Raises:
            CyclicDependencyError: If a cycle is detected.
            ValueError: If a dependency references an unregistered phase.
        """
        # Validate dependencies
        for name, phase in self.phases.items():
            for dep in phase.deps:
                if dep not in self.phases:
                    raise ValueError(f"Phase '{name}' depends on '{dep}' which is not registered")

        resolved: Set[str] = set()
        waves: List[List[Phase]] = []
        max_iterations = len(self.phases) + 1

        for _ in range(max_iterations):
            # Find phases whose deps are all resolved
            wave = []
            for name, phase in self.phases.items():
                if name in resolved:
                    continue
                if all(dep in resolved for dep in phase.deps):
                    wave.append(phase)

            if not wave:
                # No progress — cycle detected
                remaining = [n for n in self.phases if n not in resolved]
                raise CyclicDependencyError(f"Cyclic dependency detected among: {remaining}")

            waves.append(wave)
            resolved.update(p.name for p in wave)

            if len(resolved) == len(self.phases):
                break

        return waves

    async def run(
        self,
        context: PhaseContext,
        phases: Optional[List[str]] = None,
    ) -> List[PhaseResult]:
        """Run phases in dependency order.

        Args:
            context: The phase context (shared across all phases).
            phases: Optional list of phase names to run (None = all).

        Returns:
            List of PhaseResult from all executed phases.
        """
        waves = self.get_execution_waves()
        all_results: List[PhaseResult] = []

        for wave in waves:
            # Filter to requested phases if specified
            if phases:
                wave = [p for p in wave if p.name in phases]
                if not wave:
                    continue

            # Run wave in parallel
            tasks = []
            for phase in wave:
                timeout = phase.timeout or context.timeout
                tasks.append(self._run_phase(phase, context, timeout))

            wave_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for phase, result in zip(wave, wave_results):
                if isinstance(result, Exception):
                    logger.error(f"Phase '{phase.name}' failed: {result}")
                    all_results.append(PhaseResult(success=False, error=str(result)))
                elif isinstance(result, PhaseResult):
                    all_results.append(result)
                    # Accumulate findings for dependent phases
                    context.findings.extend(result.findings)
                    # Store output in extra for dependent phases
                    if result.output is not None:
                        context.extra[phase.name] = result.output
                else:
                    all_results.append(PhaseResult(success=True))

        return all_results

    async def _run_phase(
        self,
        phase: Phase,
        context: PhaseContext,
        timeout: int,
    ) -> PhaseResult:
        """Run a single phase with timeout.

        Args:
            phase: The phase to run.
            context: The phase context.
            timeout: Timeout in seconds.

        Returns:
            PhaseResult from the phase.
        """
        try:
            result = await asyncio.wait_for(
                phase.func(context),
                timeout=timeout,
            )
            return result
        except asyncio.TimeoutError:
            logger.warning(f"Phase '{phase.name}' timed out after {timeout}s")
            return PhaseResult(
                success=False,
                error=f"Phase timed out after {timeout}s",
            )
        except Exception as e:
            logger.error(f"Phase '{phase.name}' raised: {e}")
            return PhaseResult(success=False, error=str(e))
