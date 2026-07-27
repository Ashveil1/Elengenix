"""elengenix/agents/reflector.py — Reflector auxiliary agent.

Auto-invoked by ``perform_agent_chain`` whenever a specialist agent emits a
free-text response that contains **no** tool call.  The Reflector's job is to
produce a *correction prompt* that is appended to the parent agent's chain so
the next iteration emits a properly-formatted tool call (or a recognised
barrier tool such as ``done`` / ``ask``).

Ported from PentAGI ``backend/pkg/providers/performer.go::performReflector``.

Design notes
------------
* **Synchronous** — the parent loop already runs inside an async task; the
  Reflector performs a single short LLM round-trip and is allowed to block.
* **Tool-less** — the Reflector itself does not invoke any tools, it only
  emits a short structured text response which is re-injected into the parent
  agent's message chain as an assistant-turn that ends with a system
  re-prompt.
* **Idempotent** — repeated calls on the same failed-response string produce
  the same correction prompt (the LLM is seeded with a deterministic
  template).
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Protocol, runtime_checkable

from elengenix.agents.base import AgentContext, AgentType

logger = logging.getLogger("elengenix.agents.reflector")


# ---------------------------------------------------------------------------
# System prompt — ported from pentagi/templates/prompts/reflector.tmpl
# ---------------------------------------------------------------------------
REFLECTOR_SYSTEM_PROMPT = """\
You are the Reflector, a meta-agent inside the Elengenix multi-agent system.

A specialist agent just produced a response that did NOT contain a tool call.
The agent loop is *tool-driven*: every turn MUST end with either a tool call
or one of the barrier tools (done / ask). Free-text replies are not allowed
because the orchestrator cannot act on them.

Your job:
1. Read the failed response carefully.
2. Identify what the agent was *trying* to do.
3. Emit a concise correction prompt that:
   - Acknowledges the agent's intent.
   - Reminds the agent that it MUST emit a tool call.
   - Suggests the most likely tool name(s) that fit the intent.
   - Asks the agent to repeat its turn using the proper tool-call format.

Output format (exactly):
<reflection>
<one-line acknowledgement of intent>
</reflection>
<correction>
<2-4 sentences redirecting the agent to a proper tool call>
</correction>

Do not call any tools yourself. Do not add commentary outside the XML tags.
"""


# ---------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------
@runtime_checkable
class SyncLLMProvider(Protocol):
    """Minimal sync LLM interface the Reflector depends on."""

    def complete(self, prompt: str, *, system: Optional[str] = None) -> str:  # noqa: D401
        """Return the model's text completion for ``prompt``."""
        ...


# ---------------------------------------------------------------------------
# Reflector
# ---------------------------------------------------------------------------
class Reflector:
    """Repair free-text agent responses by emitting a correction prompt.

    Parameters
    ----------
    provider:
        Any object implementing :class:`SyncLLMProvider` (a ``complete``
        method). If omitted, the Reflector operates in *static* mode: it
        returns a deterministic template without invoking an LLM. The static
        mode is useful for tests, offline flows, and as a safety net when
        the LLM client is unavailable.
    """

    def __init__(self, provider: Optional[SyncLLMProvider] = None) -> None:
        self.provider = provider

    # -- public API --------------------------------------------------------
    def run(
        self,
        agent_type: AgentType,
        failed_response: str,
        *,
        ctx: Optional[AgentContext] = None,
        hint: Optional[str] = None,
    ) -> str:
        """Return a correction prompt to append to the parent agent's chain.

        Parameters
        ----------
        agent_type:
            The :class:`AgentType` of the agent that produced the failed
            response. Used to tailor the suggested tool list.
        failed_response:
            The verbatim text the agent emitted without a tool call.
        ctx:
            Optional :class:`AgentContext` for telemetry/logging.
        hint:
            Optional human-readable hint (e.g. ``"expected done tool"``)
            that further constrains the reflection.

        Returns
        -------
        str
            A correction prompt wrapped in ``<reflection>`` /
            ``<correction>`` XML tags, ready to be appended to the parent
            agent's chain as a system message.
        """
        if not failed_response or not failed_response.strip():
            # Empty response → generic nudge.
            return self._static_prompt(agent_type, "", hint)

        if self.provider is None:
            logger.debug(
                "reflector.static agent_type=%s hint=%s", agent_type, hint
            )
            return self._static_prompt(agent_type, failed_response, hint)

        prompt = self._build_user_prompt(agent_type, failed_response, hint)
        try:
            correction = self.provider.complete(
                prompt, system=REFLECTOR_SYSTEM_PROMPT
            )
        except Exception as exc:  # noqa: BLE001 — never break the agent loop
            logger.warning(
                "reflector.llm_failed agent_type=%s err=%s — falling back",
                agent_type,
                exc,
            )
            return self._static_prompt(agent_type, failed_response, hint)

        if not correction or not correction.strip():
            return self._static_prompt(agent_type, failed_response, hint)

        logger.debug(
            "reflector.ok agent_type=%s bytes=%d",
            agent_type,
            len(correction),
        )
        return correction.strip()

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _build_user_prompt(
        agent_type: AgentType,
        failed_response: str,
        hint: Optional[str],
    ) -> str:
        hint_line = f"\nAdditional hint: {hint}" if hint else ""
        return (
            f"The {agent_type.value if hasattr(agent_type, 'value') else agent_type} "
            f"agent produced the following response that contained NO tool call:\n"
            f"\n--- BEGIN FAILED RESPONSE ---\n{failed_response}\n"
            f"--- END FAILED RESPONSE ---\n"
            f"\nGenerate the correction prompt now.{hint_line}"
        )

    @staticmethod
    def _static_prompt(
        agent_type: AgentType,
        failed_response: str,
        hint: Optional[str],
    ) -> str:
        """Deterministic fallback prompt used when no LLM provider is set."""
        agent_label = (
            agent_type.value if hasattr(agent_type, "value") else str(agent_type)
        )
        suggestion = hint or "the most relevant tool for your stated intent"
        body = (
            "Your previous turn produced plain text without a tool call. "
            "The agent loop is tool-driven: every turn MUST end with a tool "
            "call (or the `done` / `ask` barrier tools). Please repeat your "
            f"turn, this time emitting {suggestion}. Do not produce free-text "
            "responses."
        )
        return (
            "<reflection>\n"
            f"The {agent_label} agent emitted a free-text response.\n"
            "</reflection>\n"
            "<correction>\n"
            f"{body}\n"
            "</correction>"
        )


__all__ = ["Reflector", "REFLECTOR_SYSTEM_PROMPT", "SyncLLMProvider"]
