"""agents/agent_logger.py — Chain of Thought Logger extracted from agent_brain.py."""

from __future__ import annotations

import atexit
import json
import logging
import time
from pathlib import Path
from elengenix.paths import get_data_dir
from typing import (

from elengenix.scanning.dataclasses import AgentThought

logger = logging.getLogger("elengenix.agent")


class ChainOfThoughtLogger:
    """Logs agent reasoning for audit and debugging.

    Improvements:
    - ``_pending_target`` remembers the target so an atexit hook can save
      even if ``process_query`` exits via exception / KeyboardInterrupt /
      the LLM never returns the ``finish`` action.
    - ``save_session`` is idempotent (won't double-write the same session).
    - ``log`` does not silently fail on serialization issues.
    """

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or get_data_dir("cot_logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: List[AgentThought] = []
        self._pending_target: Optional[str] = None
        self._saved_paths: set = set()
        atexit.register(self._atexit_save)

    def set_target(self, target: str) -> None:
        """Remember the current target for atexit save-on-exit fallback."""
        self._pending_target = target

    def log(
        self,
        step: int,
        context: str,
        reasoning: str,
        action: str,
        result: str,
        confidence: float = 0.0,
    ) -> None:
        thought = AgentThought(
            step=step,
            timestamp=time.time(),
            context=context,
            reasoning=reasoning,
            action_taken=action,
            result=result,
            confidence=confidence,
        )
        self.current_session.append(thought)

    def save_session(self, target: str) -> Optional[Path]:
        """Persist the current session to ``data/cot_logs/cot_<target>_<ts>.json``.

        Idempotent: if a session for the same target + size was already saved,
        returns the existing path. Returns ``None`` when there is nothing to save.
        """
        if not self.current_session:
            logger.debug("CoT: nothing to save (empty session)")
            return None

        safe_target = (target or "global").replace("/", "_").replace(".", "_")
        # Idempotency fingerprint
        fingerprint = f"{safe_target}_{len(self.current_session)}"
        if fingerprint in self._saved_paths:
            return None

        filename = f"cot_{safe_target}_{int(time.time())}.json"
        filepath = self.log_dir / filename
        session_data = {
            "target": target,
            "timestamp": time.time(),
            "thoughts": [
                {
                    "step": t.step,
                    "timestamp": t.timestamp,
                    "context": t.context,
                    "reasoning": t.reasoning,
                    "action": t.action_taken,
                    "result": t.result,
                    "confidence": t.confidence,
                }
                for t in self.current_session
            ],
        }
        try:
            filepath.write_text(json.dumps(session_data, indent=2, ensure_ascii=False))
            self._saved_paths.add(fingerprint)
            self._pending_target = None
            logger.info(f"CoT session saved: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to save CoT session: {e}")
            return None

    def _atexit_save(self) -> None:
        """Best-effort save on process exit so a crash or Ctrl-C doesn't lose work."""
        if self.current_session and self._pending_target:
            try:
                self.save_session(self._pending_target)
            except Exception:
                pass  # atexit must not raise

    def get_summary(self) -> str:
        lines = ["## Chain of Thought Summary\n"]
        for thought in self.current_session:
            lines.append(f"**Step {thought.step}** ({thought.confidence:.0%} confidence)")
            lines.append(f"- Context: {thought.context[:100]}...")
            lines.append(f"- Reasoning: {thought.reasoning[:150]}...")
            lines.append(f"- Action: {thought.action_taken}")
            lines.append(f"- Result: {thought.result[:100]}...\n")
        return "\n".join(lines)
