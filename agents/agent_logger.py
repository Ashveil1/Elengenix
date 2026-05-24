"""agents/agent_logger.py — Chain of Thought Logger extracted from agent_brain.py."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import List

from agents.agent_dataclasses import AgentThought

logger = logging.getLogger("elengenix.agent")


class ChainOfThoughtLogger:
    """Logs agent reasoning for audit and debugging."""

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("data/cot_logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: List[AgentThought] = []

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

    def save_session(self, target: str) -> Path:
        filename = f"cot_{target.replace('/', '_').replace('.', '_')}_{int(time.time())}.json"
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
        filepath.write_text(json.dumps(session_data, indent=2))
        logger.info(f"CoT session saved: {filepath}")
        return filepath

    def get_summary(self) -> str:
        lines = ["## Chain of Thought Summary\n"]
        for thought in self.current_session:
            lines.append(f"**Step {thought.step}** ({thought.confidence:.0%} confidence)")
            lines.append(f"- Context: {thought.context[:100]}...")
            lines.append(f"- Reasoning: {thought.reasoning[:150]}...")
            lines.append(f"- Action: {thought.action_taken}")
            lines.append(f"- Result: {thought.result[:100]}...\n")
        return "\n".join(lines)
