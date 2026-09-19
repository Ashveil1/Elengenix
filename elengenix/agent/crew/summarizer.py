"""elengenix/agents/summarizer.py — Chain summarization auxiliary agent.

Ports PentAGI's ChainAST + 3-phase summarization algorithm
(``backend/pkg/cast`` + ``backend/pkg/csum`` in the Go upstream, documented
under Task 1-c of the worklog) into Elengenix.

The summarizer condenses long conversation chains so they fit inside the
provider's context window without losing the agent's working state. It is
**byte-aware** (every AST node carries a cached ``size_bytes`` field) and
**reasoning-signature-aware** (it preserves the cryptographic /
``thought_signature`` / ``reasoning_content`` payloads that some providers
require on every tool call in the *current* turn).

Three-phase pipeline (``summarize_chain``)
------------------------------------------
1. **Section summarization** — replace every old section's body with a single
   summary body pair. Concurrent across sections. Type preservation:
   *all-Completion* sections become a ``Completion`` pair prefixed with
   ``SummarizedContentPrefix``; mixed sections become a ``Summarization``
   pair (a virtual tool call to ``execute_task_and_return_summary`` whose
   response IS the summary).
2. **Last-section rotation** — for each of the last ``keep_qa_sections``
   sections (right-to-left): first summarise oversized body pairs in parallel
   (always skipping the *last* pair so the current-turn reasoning signatures
   survive), then if the section still exceeds ``last_sec_bytes`` split it
   into keep / summarise halves.
3. **QA-pair summarisation** — if ``use_qa`` and either the section count or
   total byte count exceeds the cap, build a fresh AST = [summary section +
   preserved recent sections]. The last ``keep_qa_sections`` are always kept
   verbatim.

Idempotency
-----------
``contains_summarized_content(pair)`` returns ``True`` for ``Summarization``
pairs *or* ``Completion`` pairs whose text starts with
``SummarizedContentPrefix`` — already-summarised content is skipped on
subsequent calls so re-running the summariser never re-summarises.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable

from elengenix.agent.crew.base import AgentContext, AgentType

logger = logging.getLogger("elengenix.agent.crew.summarizer")


# ---------------------------------------------------------------------------
# Constants — ported verbatim from pentagi/pkg/csum
# ---------------------------------------------------------------------------
SUMMARIZED_CONTENT_PREFIX = "Summarized content:"
SUMMARY_TOOL_NAME = "execute_task_and_return_summary"
GEMINI_FAKE_THOUGHT_SIGNATURE = "skip_thought_signature_validator"


# ---------------------------------------------------------------------------
# Provider protocol — async because the summarizer fans out across sections
# ---------------------------------------------------------------------------
@runtime_checkable
class AsyncLLMProvider(Protocol):
    """Minimal async LLM interface the Summarizer depends on."""

    async def complete_async(
        self, prompt: str, *, system: Optional[str] = None
    ) -> str:  # noqa: D401
        """Return the model's text completion for ``prompt``."""
        ...


# ---------------------------------------------------------------------------
# Summarizer system prompt — ported from summarizer.tmpl
# ---------------------------------------------------------------------------
SUMMARIZER_SYSTEM_PROMPT = """\
You are the Summarizer, a meta-agent inside the Elengenix multi-agent system.

You condense a slice of an agent's conversation chain into a faithful summary
that preserves:
- All decisions made and their rationale.
- All tool calls issued and their high-level outcomes (success/failure).
- Any unresolved questions or pending actions.
- The agent's current working hypothesis.

Rules:
- Be concise but loss-less: a downstream agent reading your summary must be
  able to continue the task without re-reading the original messages.
- Do NOT invent facts. If something is ambiguous, say "unclear".
- Do NOT include tool-call IDs, raw JSON payloads, or verbatim command output.
- Output a single Markdown block of <= 400 words.
"""


# ---------------------------------------------------------------------------
# ChainAST data structures
# ---------------------------------------------------------------------------
class BodyPairType(str, Enum):
    """Mirror of PentAGI's ``BodyPairType`` enum."""

    COMPLETION = "Completion"
    REQUEST_RESPONSE = "RequestResponse"
    SUMMARIZATION = "Summarization"


@dataclass
class BodyPair:
    """One AI message + its matching tool-response messages.

    ``type`` controls how the pair is summarised and serialised:

    * ``Completion``       — plain AI text reply, no tool calls.
    * ``RequestResponse``  — AI message with tool calls + matching tool
                             response messages.
    * ``Summarization``    — a virtual tool call to
                             ``execute_task_and_return_summary`` whose
                             response IS the summary text. Lets summaries
                             masquerade as normal tool interactions to
                             preserve provider invariants.
    """

    type: BodyPairType
    ai_message: dict[str, Any]
    tool_messages: list[dict[str, Any]] = field(default_factory=list)
    size_bytes: int = 0

    def recompute_size(self) -> int:
        """Recompute and cache ``size_bytes`` from the underlying messages."""
        total = _msg_size_bytes(self.ai_message)
        for tm in self.tool_messages:
            total += _msg_size_bytes(tm)
        self.size_bytes = total
        return total


@dataclass
class SectionHeader:
    """System + Human messages that open a section."""

    system_message: Optional[dict[str, Any]] = None
    human_message: Optional[dict[str, Any]] = None
    size_bytes: int = 0

    def recompute_size(self) -> int:
        total = 0
        if self.system_message is not None:
            total += _msg_size_bytes(self.system_message)
        if self.human_message is not None:
            total += _msg_size_bytes(self.human_message)
        self.size_bytes = total
        return total


@dataclass
class ChainSection:
    """A header + a sequence of body pairs.

    A new section is opened on every Human message encountered while walking
    the chain.
    """

    header: SectionHeader = field(default_factory=SectionHeader)
    body_pairs: list[BodyPair] = field(default_factory=list)
    size_bytes: int = 0

    def recompute_size(self) -> int:
        total = self.header.recompute_size()
        for bp in self.body_pairs:
            total += bp.recompute_size()
        self.size_bytes = total
        return total

    # -- convenience predicates -------------------------------------------
    def is_all_completion(self) -> bool:
        """True iff every body pair is a plain Completion (no tool calls)."""
        return bool(self.body_pairs) and all(
            bp.type == BodyPairType.COMPLETION for bp in self.body_pairs
        )

    def is_already_summarized(self) -> bool:
        """True iff every body pair is already a summary artifact."""
        return bool(self.body_pairs) and all(
            contains_summarized_content(bp) for bp in self.body_pairs
        )


@dataclass
class ChainAST:
    """Root of the chain AST."""

    sections: list[ChainSection] = field(default_factory=list)
    size_bytes: int = 0

    def recompute_sizes(self) -> int:
        total = 0
        for sec in self.sections:
            total += sec.recompute_size()
        self.size_bytes = total
        return total


# ---------------------------------------------------------------------------
# Summarizer config — defaults ported from SummarizerConfig in Go
# ---------------------------------------------------------------------------
@dataclass
class SummarizerConfig:
    """Tunable knobs for :meth:`Summarizer.summarize_chain`.

    Defaults match PentAGI's ``SummarizerConfig`` zero-value.
    """

    preserve_last: bool = True
    use_qa: bool = False
    summ_human_in_qa: bool = False
    last_sec_bytes: int = 51200          # 50 KiB per-section cap
    max_bp_bytes: int = 16384            # 16 KiB per-body-pair cap
    max_qa_sections: int = 10
    max_qa_bytes: int = 65536            # 64 KiB total QA cap
    keep_qa_sections: int = 1            # recent sections NEVER summarised
    last_section_reserve_pct: int = 25   # headroom for future msgs in last sec


# ---------------------------------------------------------------------------
# Byte-size helpers
# ---------------------------------------------------------------------------
def _msg_size_bytes(msg: dict[str, Any]) -> int:
    """Deterministic byte size of a message dict.

    Uses ``json.dumps(..., sort_keys=True, ensure_ascii=False)`` so the size
    is stable regardless of dict insertion order or unicode escaping.
    """
    if not msg:
        return 0
    try:
        return len(json.dumps(msg, sort_keys=True, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        # Fallback for non-serialisable payloads — fall back to repr length.
        return len(repr(msg).encode("utf-8", errors="replace"))


def _content_to_text(msg: dict[str, Any]) -> str:
    """Flatten a message's ``content`` (str OR list-of-parts) to plain text."""
    content = msg.get("content")
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                # LangChain-style {"type": "text", "text": "..."}
                # or {"type": "tool_use", "input": {...}, ...}
                if "text" in part and isinstance(part["text"], str):
                    parts.append(part["text"])
                elif "content" in part and isinstance(part["content"], str):
                    parts.append(part["content"])
        return "\n".join(parts)
    return str(content)


def _has_tool_calls(msg: Optional[dict[str, Any]]) -> bool:
    if not msg:
        return False
    calls = msg.get("tool_calls")
    return bool(calls)


def _is_summary_tool_call(call: dict[str, Any]) -> bool:
    """True iff a tool call is the virtual summarization tool."""
    name = call.get("name") or call.get("function", {}).get("name")
    return name == SUMMARY_TOOL_NAME


# ---------------------------------------------------------------------------
# Idempotency check
# ---------------------------------------------------------------------------
def contains_summarized_content(pair: BodyPair) -> bool:
    """Return True for body pairs that are already summary artifacts.

    * ``Summarization`` type → always True (the whole pair IS a summary).
    * ``Completion`` type whose AI text starts with
      ``SummarizedContentPrefix`` → True.
    * Everything else → False.
    """
    if pair.type == BodyPairType.SUMMARIZATION:
        return True
    if pair.type == BodyPairType.COMPLETION:
        text = _content_to_text(pair.ai_message).lstrip()
        return text.startswith(SUMMARIZED_CONTENT_PREFIX)
    return False


# ---------------------------------------------------------------------------
# Reasoning-signature helpers (provider invariants)
# ---------------------------------------------------------------------------
def _inject_fake_thought_signatures(msg: dict[str, Any]) -> None:
    """Inject ``thought_signature`` on every tool call (Gemini requirement).

    Gemini requires every tool call in the *current* turn to carry a
    ``thought_signature``. Summarising a turn would strip it and trigger
    HTTP 400. PentAGI's workaround is to inject a fake sentinel value that
    Gemini's validator short-circuits on.
    """
    calls = msg.get("tool_calls")
    if not isinstance(calls, list):
        return
    for call in calls:
        if not isinstance(call, dict):
            continue
        call.setdefault("thought_signature", GEMINI_FAKE_THOUGHT_SIGNATURE)


def _strip_reasoning(msg: dict[str, Any]) -> None:
    """Wipe reasoning fields from a message (Anthropic cross-provider safety).

    Anthropic's extended-thinking cryptographic sigs only validate for the
    current turn; on previous turns they may safely be stripped. This is
    also required when migrating a chain across providers.
    """
    if not isinstance(msg, dict):
        return
    msg.pop("reasoning_content", None)
    msg.pop("reasoning", None)
    content = msg.get("content")
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict):
                part.pop("reasoning_content", None)
                part.pop("reasoning", None)
    calls = msg.get("tool_calls")
    if isinstance(calls, list):
        for call in calls:
            if isinstance(call, dict):
                call.pop("reasoning", None)


def _extract_reasoning_message(section: ChainSection) -> Optional[dict[str, Any]]:
    """Return the first AI message carrying ``reasoning_content`` (Kimi/Moonshot).

    Kimi/Moonshot require every AI message with tool calls to be preceded by
    a TextContent part carrying ``reasoning_content``. Preserving the first
    such message lets the summariser rebuild a valid chain after collapsing
    the section.
    """
    for bp in section.body_pairs:
        msg = bp.ai_message
        content = msg.get("content")
        if isinstance(content, list):
            for part in content:
                if (
                    isinstance(part, dict)
                    and part.get("type") == "text"
                    and isinstance(part.get("reasoning_content"), str)
                ):
                    return msg
        if isinstance(msg.get("reasoning_content"), str):
            return msg
    return None


def _contains_tool_call_reasoning(section: ChainSection) -> bool:
    """True iff any body pair has both tool calls and a reasoning part (Kimi)."""
    for bp in section.body_pairs:
        if not _has_tool_calls(bp.ai_message):
            continue
        content = bp.ai_message.get("content")
        if isinstance(content, list):
            for part in content:
                if (
                    isinstance(part, dict)
                    and isinstance(part.get("reasoning_content"), str)
                ):
                    return True
        if isinstance(bp.ai_message.get("reasoning_content"), str):
            return True
    return False


# ---------------------------------------------------------------------------
# ChainAST construction
# ---------------------------------------------------------------------------
def build_chain_ast(chain: list[dict[str, Any]], *, force: bool = True) -> ChainAST:
    """Construct a :class:`ChainAST` from a flat list of message dicts.

    Parameters
    ----------
    chain:
        LangChain-style message dicts. Each dict must have a ``role`` key
        (one of ``"system"``, ``"human"``/``"user"``, ``"ai"``/``"assistant"``,
        ``"tool"``).
    force:
        When True (default), repair inconsistencies the same way PentAGI's
        ``NewChainAST(chain, force=true)`` does:

        * merge consecutive Human messages,
        * add placeholder tool responses for orphan tool calls,
        * drop orphan Tool messages.
    """
    ast = ChainAST()
    current: Optional[ChainSection] = None
    pending_pair: Optional[BodyPair] = None
    pending_tool_calls: int = 0
    pending_system: Optional[dict[str, Any]] = None

    def _flush_pair() -> None:
        nonlocal pending_pair, pending_tool_calls
        if pending_pair is not None and current is not None:
            if force and pending_tool_calls > 0:
                # Repair: add placeholder tool responses for unmatched calls.
                while len(pending_pair.tool_messages) < pending_tool_calls:
                    pending_pair.tool_messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": f"placeholder-{len(pending_pair.tool_messages)}",
                            "content": "(no tool response recorded)",
                        }
                    )
            pending_pair.recompute_size()
            current.body_pairs.append(pending_pair)
        pending_pair = None
        pending_tool_calls = 0

    def _flush_section() -> None:
        nonlocal current, pending_system
        _flush_pair()
        if current is not None:
            current.recompute_size()
            ast.sections.append(current)
        current = None
        # Note: pending_system is intentionally NOT cleared here — a system
        # message lives until the next human message consumes it.

    for msg in chain:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role", "").lower()
        if role in ("system",):
            # Buffer for the *next* section's header. If we already have an
            # open section, attach there instead (mid-chain system override).
            if current is not None and current.body_pairs:
                current.header.system_message = msg
            else:
                pending_system = msg
            continue
        if role in ("human", "user"):
            _flush_section()
            current = ChainSection(
                header=SectionHeader(
                    system_message=pending_system,
                    human_message=msg,
                )
            )
            pending_system = None
            continue
        if role in ("ai", "assistant"):
            _flush_pair()
            if current is None:
                # Orphan AI message — open a section without a human msg,
                # but consume any pending system message.
                if not force:
                    continue
                current = ChainSection(
                    header=SectionHeader(system_message=pending_system)
                )
                pending_system = None
            tool_calls = msg.get("tool_calls") or []
            if tool_calls and all(
                _is_summary_tool_call(tc)
                for tc in tool_calls
                if isinstance(tc, dict)
            ):
                pair_type = BodyPairType.SUMMARIZATION
            elif tool_calls:
                pair_type = BodyPairType.REQUEST_RESPONSE
            else:
                pair_type = BodyPairType.COMPLETION
            pending_pair = BodyPair(type=pair_type, ai_message=msg)
            pending_tool_calls = len(tool_calls)
            continue
        if role in ("tool",):
            if pending_pair is None or current is None:
                # Orphan tool message.
                if not force:
                    continue
                # Synthesise a minimal pair to host it.
                if current is None:
                    current = ChainSection(
                        header=SectionHeader(system_message=pending_system)
                    )
                    pending_system = None
                pending_pair = BodyPair(
                    type=BodyPairType.REQUEST_RESPONSE,
                    ai_message={"role": "ai", "content": ""},
                )
                pending_tool_calls = 0
            pending_pair.tool_messages.append(msg)
            continue
        # Unknown role — skip silently.

    _flush_section()
    # If a trailing system message was buffered with no following human,
    # emit it as a section on its own (rare but valid).
    if pending_system is not None and force:
        trailing = ChainSection(header=SectionHeader(system_message=pending_system))
        trailing.recompute_size()
        ast.sections.append(trailing)
    ast.recompute_sizes()
    return ast


def serialize_chain(ast: ChainAST) -> list[dict[str, Any]]:
    """Serialise a :class:`ChainAST` back into a flat message list."""
    out: list[dict[str, Any]] = []
    for sec in ast.sections:
        if sec.header.system_message is not None:
            out.append(sec.header.system_message)
        if sec.header.human_message is not None:
            out.append(sec.header.human_message)
        for bp in sec.body_pairs:
            out.append(bp.ai_message)
            out.extend(bp.tool_messages)
    return out


# ---------------------------------------------------------------------------
# Summarizer
# ---------------------------------------------------------------------------
class Summarizer:
    """Condense long conversation chains to fit context windows.

    Parameters
    ----------
    provider:
        Async LLM provider (object with ``complete_async``). If ``None``,
        the summariser operates in *static* mode: it replaces summarised
        content with deterministic placeholder text rather than calling an
        LLM. Static mode is useful for tests and as a fail-safe.
    config:
        Default :class:`SummarizerConfig`. May be overridden per-call.
    agent_type:
        Optional :class:`AgentType` of the agent whose chain is being
        summarised — used for telemetry.
    """

    def __init__(
        self,
        provider: Optional[AsyncLLMProvider] = None,
        config: Optional[SummarizerConfig] = None,
        agent_type: Optional[AgentType] = None,
    ) -> None:
        self.provider = provider
        self.config = config or SummarizerConfig()
        self.agent_type = agent_type

    # -- public API --------------------------------------------------------
    async def summarize_chain(
        self,
        chain: list[dict[str, Any]],
        config: Optional[SummarizerConfig] = None,
        *,
        ctx: Optional[AgentContext] = None,
    ) -> list[dict[str, Any]]:
        """Run the 3-phase summariser over ``chain`` and return a new chain.

        Idempotent: re-running on an already-summarised chain is a no-op.
        """
        cfg = config or self.config
        if not chain:
            return []

        ast = build_chain_ast(chain, force=True)
        return await self.summarize_ast(ast, cfg, ctx=ctx)

    async def summarize_ast(
        self,
        ast: ChainAST,
        config: Optional[SummarizerConfig] = None,
        *,
        ctx: Optional[AgentContext] = None,
    ) -> list[dict[str, Any]]:
        """Run the 3-phase summariser over a pre-built :class:`ChainAST`."""
        cfg = config or self.config
        if not ast.sections:
            return []

        # Phase 1: section summarization (all but the last `keep_qa_sections`).
        await self._phase1_section_summarization(ast, cfg)

        # Phase 2: last-section rotation (right-to-left over keep_qa_sections).
        if cfg.preserve_last:
            await self._phase2_last_section_rotation(ast, cfg)

        # Phase 3: QA pair summarization (optional).
        if cfg.use_qa:
            await self._phase3_qa_pair_summarization(ast, cfg)

        ast.recompute_sizes()
        return serialize_chain(ast)

    # -- Phase 1: section summarization -----------------------------------
    async def _phase1_section_summarization(
        self, ast: ChainAST, cfg: SummarizerConfig
    ) -> None:
        keep = max(0, cfg.keep_qa_sections)
        if len(ast.sections) <= keep:
            return  # nothing old enough to summarise

        # Sections [0 .. n-keep) are candidates for summarisation.
        candidates = ast.sections[: len(ast.sections) - keep]

        async def _summarise_one(sec: ChainSection) -> None:
            if not sec.body_pairs:
                return
            if sec.is_already_summarized():
                return
            new_pair = await self._summarize_section(sec, cfg)
            sec.body_pairs = [new_pair]
            sec.recompute_size()

        # Fan out concurrently — errors fall back to a static placeholder.
        results = await asyncio.gather(
            *(_summarise_one(sec) for sec in candidates),
            return_exceptions=True,
        )
        for sec, res in zip(candidates, results):
            if isinstance(res, Exception):
                logger.warning(
                    "summarizer.phase1.failed section_bytes=%d err=%s",
                    sec.size_bytes,
                    res,
                )
        ast.recompute_sizes()

    async def _summarize_section(
        self, sec: ChainSection, cfg: SummarizerConfig
    ) -> BodyPair:
        """Collapse a section's body into a single summary body pair."""
        rendered = self._render_section_for_llm(sec)
        summary_text = await self._llm_summarize(rendered)

        if sec.is_all_completion():
            # Completion pair — prefix the summary text.
            ai_msg = {
                "role": "ai",
                "content": f"{SUMMARIZED_CONTENT_PREFIX}\n\n{summary_text}",
            }
            return BodyPair(
                type=BodyPairType.COMPLETION,
                ai_message=ai_msg,
                tool_messages=[],
            )

        # Summarization pair — virtual tool call whose response IS the summary.
        tool_call_id = f"summary_{abs(hash(rendered)) & 0xFFFFFFFF:08x}"
        ai_msg = {
            "role": "ai",
            "content": "",
            "tool_calls": [
                {
                    "id": tool_call_id,
                    "name": SUMMARY_TOOL_NAME,
                    "args": {"section_summary": summary_text},
                }
            ],
        }
        # Apply provider invariants for the synthesised pair.
        _strip_reasoning(ai_msg)
        tool_msg = {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": SUMMARY_TOOL_NAME,
            "content": summary_text,
        }
        return BodyPair(
            type=BodyPairType.SUMMARIZATION,
            ai_message=ai_msg,
            tool_messages=[tool_msg],
        )

    # -- Phase 2: last-section rotation -----------------------------------
    async def _phase2_last_section_rotation(
        self, ast: ChainAST, cfg: SummarizerConfig
    ) -> None:
        keep = max(0, cfg.keep_qa_sections)
        if keep == 0:
            return
        # Iterate over the last `keep` sections, right-to-left.
        recent = ast.sections[-keep:]
        for sec in reversed(recent):
            # Step A: summarise oversized body pairs in parallel,
            # ALWAYS skipping the last pair (preserves current-turn sigs).
            await self._summarize_oversized_body_pairs(sec, cfg)

            # Step B: if the section is still too large, split keep/summarise.
            sec.recompute_size()
            reserve_bytes = (cfg.last_section_reserve_pct * cfg.last_sec_bytes) // 100
            budget = cfg.last_sec_bytes - reserve_bytes
            if sec.size_bytes <= budget:
                continue
            await self._rotate_last_section(sec, cfg, budget)

        ast.recompute_sizes()

    async def _summarize_oversized_body_pairs(
        self, sec: ChainSection, cfg: SummarizerConfig
    ) -> None:
        """Summarise body pairs that individually exceed ``max_bp_bytes``.

        Always skips the *last* pair so the current-turn reasoning
        signatures survive.
        """
        if len(sec.body_pairs) <= 1:
            return
        targets: list[tuple[int, BodyPair]] = []
        for idx, bp in enumerate(sec.body_pairs[:-1]):
            if bp.size_bytes <= cfg.max_bp_bytes:
                continue
            if contains_summarized_content(bp):
                continue
            targets.append((idx, bp))
        if not targets:
            return

        async def _shrink(bp: BodyPair) -> BodyPair:
            try:
                return await self._summarize_body_pair(bp, cfg)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "summarizer.phase2.shrink_failed bp_bytes=%d err=%s",
                    bp.size_bytes,
                    exc,
                )
                return bp

        new_pairs = await asyncio.gather(*(_shrink(bp) for _, bp in targets))
        for (idx, _), new_bp in zip(targets, new_pairs):
            sec.body_pairs[idx] = new_bp
        sec.recompute_size()

    async def _rotate_last_section(
        self, sec: ChainSection, cfg: SummarizerConfig, budget: int
    ) -> None:
        """Split an oversized last section into keep / summarise halves.

        Recent pairs + the last pair are preserved; old pairs are collapsed
        into one summary body pair at the front of the section.
        """
        # Walk from the tail backwards, accumulating pairs until we hit the
        # byte budget. Everything before that point gets summarised.
        # `keep_from` ends up being the smallest KEPT index, so:
        #   old_pairs = body_pairs[:keep_from]   (to be summarised)
        #   kept_pairs = body_pairs[keep_from:]  (preserved verbatim)
        keep_from: int = len(sec.body_pairs)
        running = 0
        for i in range(len(sec.body_pairs) - 1, -1, -1):
            bp = sec.body_pairs[i]
            if running + bp.size_bytes > budget and i < len(sec.body_pairs) - 1:
                keep_from = i + 1
                break
            running += bp.size_bytes
            keep_from = i

        # Force-keep at least the last pair (preserves current-turn reasoning
        # signatures). If the budget is so tight that even one pair would
        # exceed it, we still keep the last pair and summarise the rest.
        if keep_from >= len(sec.body_pairs):
            keep_from = len(sec.body_pairs) - 1
        if keep_from < 1:
            keep_from = 1

        old_pairs = sec.body_pairs[:keep_from]
        kept_pairs = sec.body_pairs[keep_from:]
        if not old_pairs or not kept_pairs:
            return

        # Idempotency: if every old pair is already a summary artifact, do
        # NOT re-summarise — that would produce a summary-of-summaries and
        # violate the "re-running is a no-op" contract. Accept the oversized
        # section as-is rather than lose information or thrash the chain.
        if all(contains_summarized_content(bp) for bp in old_pairs):
            return

        # Build a synthetic section view for the LLM.
        synthetic = ChainSection(
            header=SectionHeader(),
            body_pairs=list(old_pairs),
        )
        synthetic.recompute_size()
        summary_pair = await self._summarize_section(synthetic, cfg)
        sec.body_pairs = [summary_pair, *kept_pairs]
        sec.recompute_size()

    # -- Phase 3: QA pair summarization -----------------------------------
    async def _phase3_qa_pair_summarization(
        self, ast: ChainAST, cfg: SummarizerConfig
    ) -> None:
        """Coalesce the chain into a single summary section + recent kept ones."""
        keep = max(0, cfg.keep_qa_sections)
        n_sections = len(ast.sections)
        total_bytes = ast.size_bytes
        if n_sections <= cfg.max_qa_sections and total_bytes <= cfg.max_qa_bytes:
            return
        if n_sections <= keep:
            return  # nothing to coalesce

        old_sections = ast.sections[: n_sections - keep]
        kept_sections = ast.sections[n_sections - keep :]

        # Idempotency guard: if the chain is already in post-Phase-3 form
        # (exactly 1 old section AND that section is already a summary
        # artifact), do NOT re-coalesce — that would produce a
        # summary-of-summaries and break the no-op contract. The general
        # short-circuit `n_sections <= max_qa_sections` already handles
        # the common case; this guard handles the degenerate
        # `max_qa_sections == 0` scenario.
        if (
            len(old_sections) == 1
            and old_sections[0].is_already_summarized()
        ):
            return

        # Build a human-side summary (concatenated or summarised per flag).
        human_summary = await self._summarize_humans(old_sections, cfg)
        # Build an AI-side summary of the old sections' bodies.
        ai_summary = await self._summarize_sections_bodies(old_sections, cfg)

        summary_section = ChainSection(
            header=SectionHeader(
                human_message={
                    "role": "human",
                    "content": (
                        f"{SUMMARIZED_CONTENT_PREFIX}\n\n"
                        f"Prior conversation summary:\n{human_summary}"
                    ),
                }
            ),
            body_pairs=[
                BodyPair(
                    type=BodyPairType.COMPLETION,
                    ai_message={
                        "role": "ai",
                        "content": (
                            f"{SUMMARIZED_CONTENT_PREFIX}\n\n"
                            f"Agent activity summary:\n{ai_summary}"
                        ),
                    },
                )
            ],
        )
        summary_section.recompute_size()
        ast.sections = [summary_section, *kept_sections]
        ast.recompute_sizes()

    async def _summarize_humans(
        self, sections: list[ChainSection], cfg: SummarizerConfig
    ) -> str:
        """Build the human-side summary of the dropped sections."""
        human_texts: list[str] = []
        for sec in sections:
            if sec.header.human_message is not None:
                human_texts.append(_content_to_text(sec.header.human_message))
        if not cfg.summ_human_in_qa or not human_texts:
            return "\n\n---\n\n".join(human_texts) if human_texts else "(no human turns)"
        joined = "\n\n---\n\n".join(human_texts)
        return await self._llm_summarize(joined)

    async def _summarize_sections_bodies(
        self, sections: list[ChainSection], cfg: SummarizerConfig
    ) -> str:
        """Build the AI-side summary of the dropped sections' bodies."""
        rendered_parts: list[str] = []
        for sec in sections:
            rendered_parts.append(self._render_section_for_llm(sec))
        joined = "\n\n===\n\n".join(rendered_parts)
        return await self._llm_summarize(joined)

    # -- Single body-pair summarization -----------------------------------
    async def _summarize_body_pair(
        self, bp: BodyPair, cfg: SummarizerConfig
    ) -> BodyPair:
        """Shrink a single oversized body pair in place (preserve type)."""
        rendered = self._render_body_pair_for_llm(bp)
        summary_text = await self._llm_summarize(rendered)

        if bp.type == BodyPairType.COMPLETION:
            new_msg = {
                "role": "ai",
                "content": f"{SUMMARIZED_CONTENT_PREFIX}\n\n{summary_text}",
            }
            _strip_reasoning(new_msg)
            return BodyPair(
                type=BodyPairType.COMPLETION,
                ai_message=new_msg,
                tool_messages=[],
            )

        # RequestResponse / Summarization — keep tool_calls but replace
        # their args/response with summarised versions.
        tool_calls = bp.ai_message.get("tool_calls") or []
        new_tool_calls: list[dict[str, Any]] = []
        new_tool_msgs: list[dict[str, Any]] = []
        for idx, tc in enumerate(tool_calls):
            if not isinstance(tc, dict):
                continue
            tc_id = tc.get("id", f"call_{idx}")
            tc_name = tc.get("name") or tc.get("function", {}).get("name", "tool")
            new_tool_calls.append(
                {
                    "id": tc_id,
                    "name": tc_name,
                    "args": {"summary": summary_text},
                }
            )
            new_tool_msgs.append(
                {
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "name": tc_name,
                    "content": summary_text,
                }
            )
        new_ai = {
            "role": "ai",
            "content": "",
            "tool_calls": new_tool_calls,
        }
        _strip_reasoning(new_ai)
        new_pair = BodyPair(
            type=bp.type,
            ai_message=new_ai,
            tool_messages=new_tool_msgs,
        )
        new_pair.recompute_size()
        return new_pair

    # -- LLM helpers -------------------------------------------------------
    async def _llm_summarize(self, text: str) -> str:
        """Call the provider (or fall back to a deterministic placeholder)."""
        if not text or not text.strip():
            return "(empty)"
        if self.provider is None:
            # Static-mode fallback — keep the first 800 chars.
            snippet = text[:800].strip()
            return f"[static-mode summary]\n{snippet}"
        try:
            result = await self.provider.complete_async(
                f"Summarise the following agent activity concisely:\n\n{text}",
                system=SUMMARIZER_SYSTEM_PROMPT,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("summarizer.llm_failed err=%s — static fallback", exc)
            snippet = text[:800].strip()
            return f"[llm-error fallback]\n{snippet}"
        return (result or "").strip() or "(empty summary)"

    # -- Rendering helpers -------------------------------------------------
    @staticmethod
    def _render_section_for_llm(sec: ChainSection) -> str:
        parts: list[str] = []
        if sec.header.system_message is not None:
            parts.append(f"[SYSTEM] {_content_to_text(sec.header.system_message)}")
        if sec.header.human_message is not None:
            parts.append(f"[HUMAN] {_content_to_text(sec.header.human_message)}")
        for i, bp in enumerate(sec.body_pairs, start=1):
            parts.append(f"[TURN {i}]")
            parts.append(
                f"  AI: {_content_to_text(bp.ai_message)}"
            )
            if bp.tool_messages:
                for tm in bp.tool_messages:
                    parts.append(f"  TOOL[{tm.get('name', '?')}]: {_content_to_text(tm)}")
        return "\n".join(parts)

    @staticmethod
    def _render_body_pair_for_llm(bp: BodyPair) -> str:
        parts: list[str] = [f"AI: {_content_to_text(bp.ai_message)}"]
        for tm in bp.tool_messages:
            parts.append(
                f"TOOL[{tm.get('name', '?')}]: {_content_to_text(tm)}"
            )
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------
_default_summarizer: Optional[Summarizer] = None


def get_default_summarizer(
    provider: Optional[AsyncLLMProvider] = None,
    config: Optional[SummarizerConfig] = None,
) -> Summarizer:
    """Return a process-wide default :class:`Summarizer` (cached)."""
    global _default_summarizer
    if _default_summarizer is None or provider is not None or config is not None:
        _default_summarizer = Summarizer(provider=provider, config=config)
    return _default_summarizer


async def summarize_chain(
    chain: list[dict[str, Any]],
    config: Optional[SummarizerConfig] = None,
    *,
    provider: Optional[AsyncLLMProvider] = None,
    ctx: Optional[AgentContext] = None,
) -> list[dict[str, Any]]:
    """Module-level shortcut — see :meth:`Summarizer.summarize_chain`."""
    summarizer = get_default_summarizer(provider=provider, config=config)
    return await summarizer.summarize_chain(chain, config, ctx=ctx)


__all__ = [
    "SUMMARIZED_CONTENT_PREFIX",
    "SUMMARY_TOOL_NAME",
    "GEMINI_FAKE_THOUGHT_SIGNATURE",
    "SUMMARIZER_SYSTEM_PROMPT",
    "AsyncLLMProvider",
    "BodyPairType",
    "BodyPair",
    "SectionHeader",
    "ChainSection",
    "ChainAST",
    "SummarizerConfig",
    "Summarizer",
    "contains_summarized_content",
    "build_chain_ast",
    "serialize_chain",
    "get_default_summarizer",
    "summarize_chain",
]
