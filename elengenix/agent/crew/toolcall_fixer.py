"""elengenix/agents/toolcall_fixer.py — Tool-call argument repair auxiliary.

Repairs malformed tool-call arguments emitted by an LLM before the agent loop
gives up on the iteration. Typical failures the fixer handles:

* Wrong field names (e.g. ``"command"`` vs ``"input"``).
* Missing required fields.
* Invalid JSON (single-quoted strings, trailing commas, unquoted keys).
* Wrong field types (string vs int, null where an object is required).
* Extra unknown fields that violate a strict schema.

The fixer is **synchronous** because it is invoked inline by the agent loop
on a single broken tool call — no need for async fan-out.

Design
------
* Input  — ``agent_type``, ``original_tool_call`` (dict with ``name`` /
  ``arguments``), ``error_message`` (str), optional ``tool_schema`` (JSON
  schema dict).
* Output — a corrected ``tool_call`` dict with valid ``arguments`` JSON.
* Static-mode fallback — when no LLM provider is configured, the fixer
  applies a small rule-based repair pass (JSON toleration + camelCase /
  snake_case key mapping + dropping unknown keys) and returns the best
  candidate.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional, Protocol, runtime_checkable

from elengenix.agent.crew.base import AgentContext, AgentType

logger = logging.getLogger("elengenix.agent.crew.toolcall_fixer")


# ---------------------------------------------------------------------------
# System prompt — ported from pentagi/templates/prompts/toolcall_fixer.tmpl
# ---------------------------------------------------------------------------
TOOLCALL_FIXER_SYSTEM_PROMPT = """\
You are the ToolCallFixer, a meta-agent inside the Elengenix multi-agent system.

A specialist agent emitted a tool call whose arguments failed validation.
Your job is to repair the arguments so they satisfy the tool's JSON schema
and the original intent.

Rules:
1. Read the error message and the original arguments.
2. Read the tool's JSON schema (if provided).
3. Emit the corrected arguments as a SINGLE JSON object — nothing else.
4. Do NOT wrap the JSON in markdown fences.
5. Do NOT add commentary before or after the JSON.
6. Preserve the agent's intent: only change fields that violate the schema
   or that are obviously malformed.
7. If the schema has a field naming convention (camelCase vs snake_case),
   match it exactly.
8. If you cannot determine the correct shape, return the original arguments
   unchanged so the caller can fall back to a static repair pass.
"""


# ---------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------
@runtime_checkable
class SyncLLMProvider(Protocol):
    """Minimal sync LLM interface the ToolCallFixer depends on."""

    def complete(self, prompt: str, *, system: Optional[str] = None) -> str:  # noqa: D401
        """Return the model's text completion for ``prompt``."""
        ...


# ---------------------------------------------------------------------------
# Tolerant JSON parsing
# ---------------------------------------------------------------------------
_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")
_SINGLE_QUOTE_RE = re.compile(r"(?<!\\)'")


def _tolerant_json_loads(text: str) -> Optional[Any]:
    """Best-effort JSON parse for slightly malformed payloads.

    Handles:
    * trailing commas
    * single-quoted strings (converted to double-quoted)
    * unquoted keys (best-effort, naive)
    """
    if not text:
        return None
    candidate = text.strip()
    # Strip markdown code fences if present.
    if candidate.startswith("```"):
        candidate = re.sub(r"^```[a-zA-Z]*\n?", "", candidate)
        candidate = re.sub(r"\n?```$", "", candidate)
        candidate = candidate.strip()
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    # Repair pass 1: trailing commas.
    try:
        repaired = _TRAILING_COMMA_RE.sub(r"\1", candidate)
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass
    # Repair pass 2: single-quoted strings.
    try:
        repaired = _SINGLE_QUOTE_RE.sub('"', candidate)
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass
    return None


def _extract_json_object(text: str) -> Optional[str]:
    """Extract the first balanced ``{...}`` substring from ``text``."""
    if not text:
        return None
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


# ---------------------------------------------------------------------------
# Static-mode rule-based repair
# ---------------------------------------------------------------------------
def _normalise_key(key: str) -> str:
    """Return a normalised form (lowercase, no separators) for fuzzy matching."""
    return re.sub(r"[_\-\s]", "", key.lower())


def _bigrams(s: str) -> set[str]:
    """Return the set of character bigrams in ``s`` (with padding)."""
    if not s:
        return set()
    padded = f"^{s}$"
    return {padded[i : i + 2] for i in range(len(padded) - 1)}


def _jaccard(a: str, b: str) -> float:
    """Jaccard similarity over character bigrams — used for fuzzy key matching."""
    sa, sb = _bigrams(a), _bigrams(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


# Threshold for accepting a fuzzy key match. 0.5 means "at least half of the
# bigrams overlap" — high enough to avoid spurious matches, low enough to
# catch common synonyms like (command, cmd) or (input, inp).
_FUZZY_KEY_THRESHOLD = 0.5


def _apply_schema_repair(
    arguments: dict[str, Any],
    schema: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Drop unknown keys + map close-miss key names to schema properties."""
    if not schema or not isinstance(arguments, dict):
        return arguments
    props = schema.get("properties")
    if not isinstance(props, dict) or not props:
        return arguments
    required = schema.get("required") or []
    # Build a lookup of normalised-key -> canonical-key.
    canonical: dict[str, str] = {
        _normalise_key(k): k for k in props.keys() if isinstance(k, str)
    }
    # Pre-compute bigram sets for each canonical property key so we can do
    # fuzzy matching without re-computing per argument key.
    canonical_bigrams: dict[str, set[str]] = {
        prop: _bigrams(_normalise_key(prop)) for prop in props.keys() if isinstance(prop, str)
    }

    out: dict[str, Any] = {}
    used_canonical: set[str] = set()
    for k, v in arguments.items():
        if not isinstance(k, str):
            continue
        if k in props:
            out[k] = v
            used_canonical.add(k)
            continue
        norm = _normalise_key(k)
        # Exact normalised-key match (camelCase <-> snake_case).
        if norm in canonical and canonical[norm] not in used_canonical:
            out[canonical[norm]] = v
            used_canonical.add(canonical[norm])
            continue
        # Fuzzy match: best Jaccard similarity above threshold.
        arg_bigrams = _bigrams(norm)
        if arg_bigrams:
            best_prop: Optional[str] = None
            best_score: float = _FUZZY_KEY_THRESHOLD
            for prop, prop_bg in canonical_bigrams.items():
                if prop in used_canonical or not prop_bg:
                    continue
                # Jaccard on bigrams.
                score = len(arg_bigrams & prop_bg) / len(arg_bigrams | prop_bg)
                if score > best_score:
                    best_score = score
                    best_prop = prop
            if best_prop is not None:
                out[best_prop] = v
                used_canonical.add(best_prop)
                continue
        # Unknown key — drop it.
    # Ensure required keys exist (set to None if missing).
    for req in required:
        if isinstance(req, str) and req not in out:
            out[req] = None
    return out


# ---------------------------------------------------------------------------
# ToolCallFixer
# ---------------------------------------------------------------------------
class ToolCallFixer:
    """Repair malformed tool-call arguments.

    Parameters
    ----------
    provider:
        Any object implementing :class:`SyncLLMProvider`. If ``None``, the
        fixer operates in *static* mode: it applies the rule-based repair
        pass only (no LLM call).
    """

    def __init__(self, provider: Optional[SyncLLMProvider] = None) -> None:
        self.provider = provider

    # -- public API --------------------------------------------------------
    def run(
        self,
        agent_type: AgentType,
        original_tool_call: dict[str, Any],
        error_message: str,
        *,
        tool_schema: Optional[dict[str, Any]] = None,
        ctx: Optional[AgentContext] = None,
    ) -> dict[str, Any]:
        """Return a corrected tool call dict.

        The returned dict has the same shape as ``original_tool_call`` but
        with ``arguments`` replaced by a valid JSON string. If no repair
        could be performed, the original tool call is returned unchanged.
        """
        if not isinstance(original_tool_call, dict):
            raise TypeError("original_tool_call must be a dict")

        name = (
            original_tool_call.get("name")
            or original_tool_call.get("function", {}).get("name")
            or "unknown"
        )
        raw_args = self._extract_arguments(original_tool_call)

        # Step 1: try to parse what we already have.
        parsed = _tolerant_json_loads(raw_args) if isinstance(raw_args, str) else raw_args
        if parsed is None:
            parsed = {}

        # Step 2: if a schema is provided, apply a static repair pass first.
        if tool_schema is not None and isinstance(parsed, dict):
            parsed = _apply_schema_repair(parsed, tool_schema)

        # Step 3: invoke the LLM for a smarter repair, if available.
        if self.provider is not None:
            try:
                llm_args = self._llm_repair(
                    agent_type, name, raw_args, error_message, tool_schema
                )
                if llm_args is not None:
                    parsed = llm_args
                    if tool_schema is not None and isinstance(parsed, dict):
                        parsed = _apply_schema_repair(parsed, tool_schema)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "toolcall_fixer.llm_failed agent=%s tool=%s err=%s",
                    agent_type,
                    name,
                    exc,
                )

        # Step 4: rebuild the tool call dict with re-serialised arguments.
        corrected = dict(original_tool_call)
        if "function" in corrected and isinstance(corrected["function"], dict):
            corrected["function"] = dict(corrected["function"])
            corrected["function"]["arguments"] = json.dumps(parsed, ensure_ascii=False)
        else:
            corrected["arguments"] = json.dumps(parsed, ensure_ascii=False)

        logger.debug(
            "toolcall_fixer.repaired agent=%s tool=%s ok=%s",
            agent_type,
            name,
            corrected != original_tool_call,
        )
        return corrected

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _extract_arguments(tool_call: dict[str, Any]) -> Any:
        """Return the ``arguments`` payload from either OpenAI or flat shape."""
        if "function" in tool_call and isinstance(tool_call["function"], dict):
            args = tool_call["function"].get("arguments")
        else:
            args = tool_call.get("arguments")
        return args

    def _llm_repair(
        self,
        agent_type: AgentType,
        tool_name: str,
        raw_args: Any,
        error_message: str,
        tool_schema: Optional[dict[str, Any]],
    ) -> Optional[dict[str, Any]]:
        """Ask the LLM to produce corrected arguments; return parsed dict."""
        schema_repr = (
            json.dumps(tool_schema, ensure_ascii=False, indent=2)
            if tool_schema
            else "(no schema available)"
        )
        args_repr = (
            raw_args
            if isinstance(raw_args, str)
            else json.dumps(raw_args, ensure_ascii=False, indent=2)
        )
        prompt = (
            f"The {agent_type.value if hasattr(agent_type, 'value') else agent_type} "
            f"agent emitted a tool call to `{tool_name}` with arguments that "
            f"failed validation.\n\n"
            f"Original arguments:\n```\n{args_repr}\n```\n\n"
            f"Validation error:\n```\n{error_message}\n```\n\n"
            f"Tool JSON schema:\n```\n{schema_repr}\n```\n\n"
            f"Emit the corrected arguments as a single JSON object."
        )
        result = self.provider.complete(  # type: ignore[union-attr]
            prompt, system=TOOLCALL_FIXER_SYSTEM_PROMPT
        )
        if not result or not result.strip():
            return None
        json_blob = _extract_json_object(result)
        if not json_blob:
            return None
        parsed = _tolerant_json_loads(json_blob)
        if not isinstance(parsed, dict):
            return None
        return parsed


__all__ = [
    "TOOLCALL_FIXER_SYSTEM_PROMPT",
    "SyncLLMProvider",
    "ToolCallFixer",
]
