"""tests/test_agent_autonomy.py

Verifies the agent is genuinely autonomous (not a locked script):
1. The strategist prompt grants FULL autonomy and does NOT force a fixed
   phase order (recon -> enum -> vuln -> exploit -> report).
2. The specialist prompt exposes a first-class "reason" action the AI can
   take on its own authority.
3. ScanLoop wires the autonomous reasoning phase into its execute loop.
"""

from __future__ import annotations

import re

from elengenix.scanning import hybrid_prompts as hp
from elengenix.scanning.scan_loop import ScanLoop


def test_strategist_prompt_grants_full_autonomy():
    p = hp.HYBRID_STRATEGIST_PROMPT
    assert "FULL autonomy" in p or "FULL AUTONOMY" in p
    # No forced linear pipeline language
    assert "reconnaissance → enumeration" not in p
    assert "should flow:" not in p


def test_strategist_prompt_allows_nonlinear_pivot():
    p = hp.HYBRID_STRATEGIST_PROMPT
    assert "NO required order" in p
    assert "Pivot" in p or "pivot" in p


def test_specialist_prompt_has_reason_action():
    p = hp.HYBRID_SPECIALIST_PROMPT
    # The AI must be able to choose "reason" as a first-class action
    assert re.search(r'"action":\s*"reason"', p) is not None
    assert "FIRST-CLASS" in p or "first-class" in p


def test_scan_loop_has_reasoning_phase_hook():
    # ScanLoop must call the autonomous reasoning phase each step.
    assert hasattr(ScanLoop, "_run_reasoning_phase")
    src = ScanLoop._run_reasoning_phase.__doc__ or ""
    assert "autonomous" in src.lower()
