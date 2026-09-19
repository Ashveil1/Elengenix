"""Chain summarization helpers — public re-export of ``elengenix.agent.crew.summarizer``.

Ports PentAGI's ``pentagi/pkg/cast`` chain helpers (documented under Task 1-c
of the worklog) into the observability package so callers outside the
``elengenix.agent.crew`` namespace can use them without creating a cross-package
dependency.

The full ChainAST + 3-phase summarisation algorithm lives in
``elengenix.agent.crew.summarizer`` — this module re-exports the public API
(``ChainAST``, ``summarize_chain``, ``SummarizerConfig``) and adds four
chain-level helper functions that PentAGI's Go upstream exposes as methods
on the ``ChainAST`` type but which Elengenix callers prefer to invoke on
raw chain lists:

* ``normalize_tool_call_ids(chain, template)`` — regenerate tool-call IDs
  that don't match the new provider's pattern (e.g. switching from
  ``call_<hex24>`` to ``toolu_<base62_24>``).
* ``clear_reasoning(chain)`` — strip provider-specific reasoning signatures
  (Anthropic extended-thinking sigs, Gemini ``thought_signature``,
  Kimi/Moonshot ``reasoning_content``) — required when migrating a chain
  across providers.
* ``contains_tool_call_reasoning(body_pair) -> bool`` — true iff a body
  pair has both tool calls and a reasoning part (Kimi invariant).
* ``extract_reasoning_message(body_pair) -> str | None`` — first
  ``reasoning_content`` string found in a body pair (Kimi/Moonshot).

All helpers operate either on a flat ``list[dict]`` chain (LangChain-style
message dicts) or on a pre-built :class:`ChainAST`. The flat-list form is
canonical for callers; the AST form is convenient when the caller already
built one.
"""

from __future__ import annotations

import logging
import re
import secrets
from typing import Any, Optional, Union

from elengenix.agent.crew.summarizer import (  # noqa: F401  (re-exports)
    GEMINI_FAKE_THOUGHT_SIGNATURE,
    SUMMARY_TOOL_NAME,
    SUMMARIZED_CONTENT_PREFIX,
    SUMMARIZER_SYSTEM_PROMPT,
    AsyncLLMProvider,
    BodyPair,
    BodyPairType,
    ChainAST,
    ChainSection,
    SectionHeader,
    Summarizer,
    SummarizerConfig,
    build_chain_ast,
    contains_summarized_content,
    get_default_summarizer,
    serialize_chain,
)
from elengenix.agent.crew.summarizer import (
    _extract_reasoning_message as _section_extract_reasoning,
)
from elengenix.agent.crew.summarizer import (
    _contains_tool_call_reasoning as _section_contains_tool_call_reasoning,
)
from elengenix.agent.crew.summarizer import (
    _strip_reasoning as _strip_message_reasoning,
)

# Public alias for ``summarize_chain`` — kept here for IDE re-discovery
# (the function lives in ``elengenix.agent.crew.summarizer`` but callers
# commonly import it from the observability package).
from elengenix.agent.crew.summarizer import summarize_chain  # noqa: F401

logger = logging.getLogger("elengenix.observability.chains")


# ---------------------------------------------------------------------------
# Tool-call ID pattern handling (ports PentAGI templates.GenerateFromPattern)
# ---------------------------------------------------------------------------
_DEFAULT_TOOL_CALL_TEMPLATE = "call_{r:24:x}"

_PATTERN_RE = re.compile(
    r"\{r:(\d+):(d|digit|l|lower|u|upper|a|alpha|x|alnum|h|hex|H|HEX|b|base62)\}|\{f\}"
)

_CHARSETS: dict[str, str] = {
    "d": "0123456789",
    "digit": "0123456789",
    "l": "abcdefghijklmnopqrstuvwxyz",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "a": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alpha": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "x": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alnum": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "h": "0123456789abcdef",
    "hex": "0123456789abcdef",
    "H": "0123456789ABCDEF",
    "HEX": "0123456789ABCDEF",
    "b": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "base62": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
}


class _PatternPart:
    __slots__ = ("literal", "is_random", "is_function", "length", "charset")

    def __init__(
        self,
        literal: str = "",
        is_random: bool = False,
        is_function: bool = False,
        length: int = 0,
        charset: str = "",
    ) -> None:
        self.literal = literal
        self.is_random = is_random
        self.is_function = is_function
        self.length = length
        self.charset = charset


def _parse_pattern(pattern: str) -> list[_PatternPart]:
    """Parse ``"call_{r:24:x}"`` style patterns into a list of parts."""
    parts: list[_PatternPart] = []
    pos = 0
    for match in _PATTERN_RE.finditer(pattern):
        if match.start() > pos:
            parts.append(_PatternPart(literal=pattern[pos:match.start()]))
        if match.group(1) is not None:
            length = int(match.group(1))
            charset_name = match.group(2)
            charset = _CHARSETS.get(charset_name, _CHARSETS["x"])
            parts.append(_PatternPart(is_random=True, length=length, charset=charset))
        else:
            parts.append(_PatternPart(is_function=True))
        pos = match.end()
    if pos < len(pattern):
        parts.append(_PatternPart(literal=pattern[pos:]))
    return parts


def _generate_from_pattern(pattern: str, function_name: str = "") -> str:
    """Generate a random string matching ``pattern``.

    Mirrors ``templates.GenerateFromPattern`` — never raises; falls back to
    sensible defaults for invalid patterns.
    """
    parts = _parse_pattern(pattern)
    out: list[str] = []
    for part in parts:
        if part.is_random:
            out.append("".join(secrets.choice(part.charset) for _ in range(part.length)))
        elif part.is_function:
            out.append(function_name or "function")
        else:
            out.append(part.literal)
    return "".join(out)


def _validate_pattern(pattern: str, value: str, function_name: str = "") -> bool:
    """Return True iff ``value`` matches ``pattern`` for the given function name."""
    parts = _parse_pattern(pattern)
    pos = 0
    for part in parts:
        if part.is_random:
            if pos + part.length > len(value):
                return False
            chunk = value[pos:pos + part.length]
            if not all(c in part.charset for c in chunk):
                return False
            pos += part.length
        elif part.is_function:
            fn = function_name or "function"
            if not value.startswith(fn, pos):
                return False
            pos += len(fn)
        else:
            if not value.startswith(part.literal, pos):
                return False
            pos += len(part.literal)
    return pos == len(value)


# ---------------------------------------------------------------------------
# Chain normalisation helpers
# ---------------------------------------------------------------------------
ChainLike = Union[list[dict[str, Any]], ChainAST]


def _iter_messages(chain: ChainLike) -> list[dict[str, Any]]:
    """Flatten a chain (list of messages or :class:`ChainAST`) to a list of dicts."""
    if isinstance(chain, ChainAST):
        return serialize_chain(chain)
    return list(chain)


def _ensure_ast(chain: ChainLike) -> ChainAST:
    """Return a :class:`ChainAST` view over ``chain`` (builds one if needed)."""
    if isinstance(chain, ChainAST):
        return chain
    return build_chain_ast(chain, force=True)


def normalize_tool_call_ids(chain: ChainLike, template: str) -> list[dict[str, Any]]:
    """Regenerate tool-call IDs that don't match ``template``.

    Mirrors ``ChainAST.NormalizeToolCallIDs`` from PentAGI:

    1. Validate each tool-call ``id`` against ``template``.
    2. If validation fails, generate a fresh ID via :func:`_generate_from_pattern`
       and remember the old → new mapping.
    3. Update all matching tool-response ``tool_call_id`` fields.

    Parameters
    ----------
    chain:
        Flat list of LangChain-style message dicts OR a pre-built
        :class:`ChainAST`. When an AST is supplied it is mutated in place
        and the corresponding serialised list is returned.
    template:
        New template, e.g. ``"call_{r:24:x}"`` for OpenAI / Gemini or
        ``"toolu_{r:24:b}"`` for Anthropic.

    Returns
    -------
    list[dict[str, Any]]
        The (possibly mutated) flat message list. When an AST was passed
        in, the returned list is a fresh serialisation of the mutated AST.
    """
    if not template:
        logger.debug("normalize_tool_call_ids called with empty template — no-op")
        return _iter_messages(chain)

    is_ast = isinstance(chain, ChainAST)
    ast = chain if is_ast else build_chain_ast(chain, force=True)
    id_mapping: dict[str, str] = {}

    for section in ast.sections:
        for bp in section.body_pairs:
            if bp.type not in (BodyPairType.REQUEST_RESPONSE, BodyPairType.SUMMARIZATION):
                continue
            ai_msg = bp.ai_message
            if not isinstance(ai_msg, dict):
                continue

            # --- Validate & rewrite tool call ids in the AI message ---
            calls = ai_msg.get("tool_calls")
            if isinstance(calls, list):
                for call in calls:
                    if not isinstance(call, dict):
                        continue
                    old_id = call.get("id")
                    if not isinstance(old_id, str) or not old_id:
                        continue
                    fn_name = (
                        call.get("name")
                        or call.get("function", {}).get("name")
                        or ""
                    )
                    if _validate_pattern(template, old_id, fn_name):
                        # Already valid — leave alone.
                        continue
                    new_id = _generate_from_pattern(template, fn_name)
                    id_mapping[old_id] = new_id
                    call["id"] = new_id

            # --- Rewrite corresponding tool-response ids ---
            for tool_msg in bp.tool_messages:
                if not isinstance(tool_msg, dict):
                    continue
                tc_id = tool_msg.get("tool_call_id")
                if isinstance(tc_id, str) and tc_id in id_mapping:
                    tool_msg["tool_call_id"] = id_mapping[tc_id]

    if id_mapping:
        logger.debug(
            "normalize_tool_call_ids rewrote %d tool-call id(s) to template %r",
            len(id_mapping),
            template,
        )

    return serialize_chain(ast)


def clear_reasoning(chain: ChainLike) -> list[dict[str, Any]]:
    """Strip all reasoning signatures from ``chain``.

    Mirrors ``ChainAST.ClearReasoning`` from PentAGI. Required when migrating
    a chain across providers — Anthropic extended-thinking cryptographic sigs
    won't validate on Gemini (and vice versa), and Kimi/Moonshot
    ``reasoning_content`` payloads should be discarded when leaving their
    ecosystem.

    Wipes the following fields from every message (and every content part):

    * ``reasoning_content``
    * ``reasoning``
    * ``thought_signature`` (Gemini)

    Parameters
    ----------
    chain:
        Flat list of message dicts OR a pre-built :class:`ChainAST`.

    Returns
    -------
    list[dict[str, Any]]
        The (possibly mutated) flat message list.
    """
    is_ast = isinstance(chain, ChainAST)
    ast = chain if is_ast else build_chain_ast(chain, force=True)

    for section in ast.sections:
        if section.header.system_message is not None:
            _strip_message_reasoning(section.header.system_message)
        if section.header.human_message is not None:
            _strip_message_reasoning(section.header.human_message)
        for bp in section.body_pairs:
            if bp.ai_message:
                _strip_message_reasoning(bp.ai_message)
                # Gemini thought signatures live on tool calls.
                _strip_thought_signatures(bp.ai_message)
            for tm in bp.tool_messages:
                _strip_message_reasoning(tm)

    return serialize_chain(ast)


def _strip_thought_signatures(msg: dict[str, Any]) -> None:
    """Wipe ``thought_signature`` from every tool call (Gemini invariant)."""
    calls = msg.get("tool_calls")
    if not isinstance(calls, list):
        return
    for call in calls:
        if isinstance(call, dict):
            call.pop("thought_signature", None)


def contains_tool_call_reasoning(body_pair: Union[BodyPair, ChainSection, list[dict[str, Any]]]) -> bool:
    """Return True iff the input has both tool calls and a reasoning payload.

    Mirrors PentAGI's ``ContainsToolCallReasoning``. Accepts:

    * a :class:`BodyPair` (preferred — matches the task spec signature),
    * a :class:`ChainSection` (delegates to the underlying summariser helper),
    * a flat list of message dicts (the AI message is the first ``"ai"`` /
      ``"assistant"`` role entry).

    Returns ``False`` for empty input.
    """
    if isinstance(body_pair, BodyPair):
        return _body_pair_contains_tool_call_reasoning(body_pair)
    if isinstance(body_pair, ChainSection):
        return _section_contains_tool_call_reasoning(body_pair)
    if isinstance(body_pair, list):
        # Walk the flat list, treat each AI message as a one-shot body pair.
        for msg in body_pair:
            if not isinstance(msg, dict):
                continue
            role = (msg.get("role") or "").lower()
            if role not in ("ai", "assistant"):
                continue
            calls = msg.get("tool_calls")
            if not isinstance(calls, list) or not calls:
                continue
            if _msg_has_reasoning(msg):
                return True
        return False
    return False


def _body_pair_contains_tool_call_reasoning(bp: BodyPair) -> bool:
    """BodyPair-specialised helper (replaces the section-level private one)."""
    calls = bp.ai_message.get("tool_calls") if isinstance(bp.ai_message, dict) else None
    if not isinstance(calls, list) or not calls:
        return False
    return _msg_has_reasoning(bp.ai_message)


def _msg_has_reasoning(msg: dict[str, Any]) -> bool:
    """True iff ``msg`` carries a reasoning payload in any part."""
    if not isinstance(msg, dict):
        return False
    if isinstance(msg.get("reasoning_content"), str):
        return True
    content = msg.get("content")
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("reasoning_content"), str):
                return True
    return False


def extract_reasoning_message(
    body_pair: Union[BodyPair, ChainSection, list[dict[str, Any]]],
) -> Optional[str]:
    """Return the first ``reasoning_content`` text found in ``body_pair``.

    Mirrors PentAGI's ``ExtractReasoningMessage``. Returns ``None`` when no
    reasoning payload is present (the typical case for non-Kimi/Moonshot
    providers).

    Accepts the same input shapes as :func:`contains_tool_call_reasoning`.
    """
    if isinstance(body_pair, BodyPair):
        return _body_pair_extract_reasoning(body_pair)
    if isinstance(body_pair, ChainSection):
        msg = _section_extract_reasoning(body_pair)
        return _first_reasoning_text(msg) if msg is not None else None
    if isinstance(body_pair, list):
        for msg in body_pair:
            if not isinstance(msg, dict):
                continue
            role = (msg.get("role") or "").lower()
            if role not in ("ai", "assistant"):
                continue
            text = _first_reasoning_text(msg)
            if text is not None:
                return text
        return None
    return None


def _body_pair_extract_reasoning(bp: BodyPair) -> Optional[str]:
    """BodyPair-specialised helper — returns the first reasoning text."""
    if not isinstance(bp.ai_message, dict):
        return None
    return _first_reasoning_text(bp.ai_message)


def _first_reasoning_text(msg: dict[str, Any]) -> Optional[str]:
    """Return the first ``reasoning_content`` string found in ``msg``."""
    if not isinstance(msg, dict):
        return None
    rc = msg.get("reasoning_content")
    if isinstance(rc, str) and rc:
        return rc
    content = msg.get("content")
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict):
                rc2 = part.get("reasoning_content")
                if isinstance(rc2, str) and rc2:
                    return rc2
    return None


__all__ = [
    # Re-exports from elengenix.agent.crew.summarizer
    "GEMINI_FAKE_THOUGHT_SIGNATURE",
    "SUMMARY_TOOL_NAME",
    "SUMMARIZED_CONTENT_PREFIX",
    "SUMMARIZER_SYSTEM_PROMPT",
    "AsyncLLMProvider",
    "BodyPair",
    "BodyPairType",
    "ChainAST",
    "ChainSection",
    "SectionHeader",
    "Summarizer",
    "SummarizerConfig",
    "build_chain_ast",
    "contains_summarized_content",
    "get_default_summarizer",
    "serialize_chain",
    "summarize_chain",
    # Chain-level helpers added by this module
    "normalize_tool_call_ids",
    "clear_reasoning",
    "contains_tool_call_reasoning",
    "extract_reasoning_message",
]
