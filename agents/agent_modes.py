"""agents/agent_modes.py — Mode processing for ElengenixAgent.

Extracted from agent_brain.py to improve modularity. Handles:
- Universal mode processing
- Hybrid mode processing
- Team Aegis mode processing
"""

from __future__ import annotations

import logging
import re
import time
import traceback
from pathlib import Path
from elengenix.paths import get_reports_path
from typing import (

from tools.cvss_calculator import CVSSCalculator
from tools.governance import Governance
from tools.mission_state import MissionState
from tools.vector_memory import remember

logger = logging.getLogger("elengenix.agent.modes")


class ModeProcessor:
    """Processes different operational modes for the agent.

    This class encapsulates mode-specific logic that was previously
    inlined in ElengenixAgent.
    """

    def __init__(
        self,
        client: Any,
        governance: Optional[Governance] = None,
        cvss_calc: Optional[CVSSCalculator] = None,
        cve_db: Any = None,
        enable_memory: bool = True,
    ):
        """Initialize the mode processor.

        Args:
            client: AI client for mode processing.
            governance: Governance instance for permission checks.
            cvss_calc: CVSS calculator for scoring.
            cve_db: CVE database for lookups.
            enable_memory: Whether to enable memory operations.
        """
        self.client = client
        self.governance = governance
        self.cvss_calc = cvss_calc
        self.cve_db = cve_db
        self.enable_memory = enable_memory

    def process_universal(
        self,
        user_input: str,
        conversation_history: List[Dict[str, str]],
        base_prompt: str,
        callback: Optional[Callable] = None,
        target: str = "",
        mode: str = "auto",
        preflight_findings: Optional[List[Dict]] = None,
    ) -> str:
        """Universal mode — delegates to agents/agent_universal.py.

        Args:
            user_input: The user's input.
            conversation_history: Current conversation history.
            base_prompt: Base system prompt.
            callback: Live output callback.
            target: Target domain/IP.
            mode: Processing mode.
            preflight_findings: Optional preflight findings.

        Returns:
            Response string.
        """
        from agents.agent_universal import process_universal as _run_universal

        return _run_universal(
            user_input=user_input,
            client=self.client,
            conversation_history=conversation_history,
            base_prompt=base_prompt,
            governance=self.governance,
            reflection_tracker=None,
            skill_registry=None,
            target=target,
            mode=mode,
            callback=callback,
            check_context_overflow=None,
            preflight_findings=preflight_findings,
        )

    def process_hybrid(
        self,
        user_input: str,
        callback: Optional[Callable] = None,
        target: str = "",
        mode: str = "auto",
        team_aegis_clients: Optional[Dict] = None,
    ) -> str:
        """Hybrid mode — combines redteam_agent with structured analysis.

        Args:
            user_input: The user's input.
            callback: Live output callback.
            target: Target domain/IP.
            mode: Processing mode.
            team_aegis_clients: TeamAegis client configuration.

        Returns:
            Response string.
        """
        from agents.agent_helpers import _extract_target_from_text
        from agents.hybrid_agent import HybridAgent

        logger.info(f"Hybrid mode started: target={target}, intent={user_input[:100]}")

        # Extract target if needed
        if not target:
            inferred = _extract_target_from_text(user_input)
            if inferred:
                target = inferred

        if not target:
            return "No target specified. Use 'hunt <target>' or provide a domain/IP."

        # Normalize
        target = re.sub(r"^https?://", "", target.rstrip("/"))

        # Initialize HybridAgent
        ta = team_aegis_clients or {}
        hybrid = HybridAgent(
            client=self.client,
            governance=self.governance,
            target=target,
            max_steps=50,
            strategist_interval=5,
            enable_analysis=True,
            enable_memory=True,
            callback=callback,
            strategist_client=ta.get("strategist_client"),
            specialist_client=ta.get("specialist_client"),
            critic_client=ta.get("critic_client"),
            strategist_label=ta.get("strategist_label", "Strategist AI"),
            specialist_label=ta.get("specialist_label", "Specialist AI"),
            critic_label=ta.get("critic_label", "Critic AI"),
        )

        # Wire up shared infrastructure
        hybrid.mission_state = MissionState(
            mission_id=f"hybrid:{target}:{int(time.time())}",
            target=target,
            objective=user_input,
        )
        hybrid.mission_key = hybrid.mission_state.mission_id
        hybrid.cvss_calc = self.cvss_calc
        hybrid.cve_db = self.cve_db

        # Remember mission start
        if target and self.enable_memory:
            remember(
                f"Hybrid mission: {user_input[:120]}",
                target,
                "mission_start",
                session_type="hybrid",
            )

        # Run the hybrid loop
        logger.info("Hybrid hunt starting")
        try:
            result = hybrid.run(user_input)
        except KeyboardInterrupt:
            logger.info("Hybrid mission interrupted by user")
            result = hybrid._finalize_mission() + "\n\n*Mission interrupted by user.*"
        except Exception as e:
            logger.error(f"Hybrid mode failed: {e}\n{traceback.format_exc()}")
            return f"Hybrid mode error: {e}"

        # Save report
        if result and target:
            safe_name = re.sub(r"[^a-zA-Z0-9.-]", "_", target)[:40]
            report_path = get_reports_path(f"hybrid_{safe_name}_{int(time.time())}.md")
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(result, encoding="utf-8")

            remember(
                f"Hybrid completed for {target}. Findings: {len(hybrid.all_findings)}",
                target,
                "mission_complete",
                session_type="hybrid",
            )

            if callback:
                callback(f"Report saved: {report_path}")

        if callback:
            callback("Hybrid hunt complete")
        return result or "Hybrid mission completed."
