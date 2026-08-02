"""elengenix/scanning/provider_bridge.py — Bridge between Stack A providers and the scan loop.

Stack A (``elengenix.providers``) is the "good" provider stack: 10 providers
behind a clean ``Provider`` Protocol (call / call_ex / call_with_tools /
get_models / get_price_info) with a working ``call_with_tools`` path that —
before this change — was never wired into a live agent loop.

Stack B (``tools.universal_ai_client``) is the legacy live client the
``process_universal`` scan loop talks to today: an OpenAI-compatible HTTP
client that combines native tool-calling with a free-text JSON extraction
fallback. This module lets the loop prefer Stack A when a Stack A provider is
configured, with a clean fall-through to Stack B when it is not (unknown name
in Stack A's registry, missing env key, stubbed factory, …).

Resolution order for the provider name and model honors
``tools/ai_config.py``'s existing priority (constructor param → config.yaml
``providers.{name}.*`` → env ``{NAME}_MODEL``) — the registry default is used
only when neither is set.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from elengenix.providers.base import (
    MessageContent,
    Provider,
    ProviderConfig,
    ProviderOptionsType,
    ProviderType,
    TextPart,
    ToolCall,
)
from elengenix.providers import registry as _prov_registry

logger = logging.getLogger("elengenix.scanning.provider_bridge")

#: The agent slot scan-decide calls use. ``PRIMARY_AGENT`` matches the
#: canonical decide call in PentAGI; slot-level switching is overkill for a
#: one-shot "what next?" decision.
PROVIDER_SLOT: ProviderOptionsType = ProviderOptionsType.PRIMARY_AGENT


class _ProviderCompletionAdapter:
    """Adapt a Stack-A ``Provider`` to the fixer's tiny ``SyncLLMProvider`` surface.

    :class:`~elengenix.agents.toolcall_fixer.ToolCallFixer` only needs
    ``provider.complete(prompt, *, system=None) -> str``. We forward to
    ``Provider.call(slot, prompt)`` for the plain case and prepend the
    ``system`` hint as a proper system-role chain entry via
    ``Provider.call_ex`` when one is given, so adapters see it exactly once.
    """

    def __init__(self, provider: Provider, slot: ProviderOptionsType) -> None:
        self._provider = provider
        self._slot = slot

    def complete(self, prompt: str, *, system: Optional[str] = None) -> str:
        """Return the model's text completion for ``prompt``."""
        if system:
            chain: List[MessageContent] = [
                MessageContent(role="system", parts=[TextPart(text=system)]),
                MessageContent(role="user", parts=[TextPart(text=prompt)]),
            ]
            resp = self._provider.call_ex(self._slot, chain, stream_cb=None)
            return resp.choices[0].content if resp.choices else ""
        return self._provider.call(self._slot, prompt)


class StackAFixingBackend:
    """The object the scan loop's Stack-A branch talks to.

    ``decide`` is the only entry the loop calls. It returns either a typed
    dict ``{"name": ..., "arguments": {...}}`` for the chosen tool call, or
    ``None`` to signal "no usable decision — let Stack B handle it".

    Malformed tool-call arguments go through the shared
    :class:`~elengenix.agents.toolcall_fixer.ToolCallFixer` (LLM-assisted,
    lazily constructed) so the loop never needs the regex-path extractor when
    this backend is active.
    """

    def __init__(
        self,
        *,
        provider: Provider,
        provider_type: ProviderType,
        slot: ProviderOptionsType = PROVIDER_SLOT,
    ) -> None:
        self.provider = provider
        self.provider_type = provider_type
        self.slot = slot
        self._fixer: Optional[Any] = None  # ToolCallFixer, created on demand

    # -- decide-call backend ----------------------------------------------

    def decide(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        action_tools: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Run one scan-decide call via Stack-A ``call_with_tools``.

        Returns ``{"name": str, "arguments": dict}`` on success; ``None``
        when the provider errored or returned a content-only response. The
        caller treats ``None`` as "fall back to the Stack-B client path".
        """
        chain: List[MessageContent] = [
            MessageContent(role="system", parts=[TextPart(text=system_prompt)]),
            MessageContent(role="user", parts=[TextPart(text=user_prompt)]),
        ]
        try:
            resp = self.provider.call_with_tools(self.slot, chain, action_tools)
        except NotImplementedError:
            # Registry stub for this provider type — Stack B owns it.
            raise
        except Exception:  # noqa: BLE001
            logger.exception("stack A decide failed; falling back to Stack B")
            return None

        if not resp or not resp.choices:
            return None

        choice = resp.choices[0]
        if not choice.tool_calls:
            # Content-only response: let the Stack-B text-JSON extractor take
            # that route (the caller re-runs via the legacy path on None).
            logger.debug("stack A decide returned content-only; falling back")
            return None

        # Universal-loop semantics: only the first tool call is consumed.
        tc = choice.tool_calls[0]
        fixed = self._repair_or_keep_tool_call(tc, tools_schema=action_tools)
        return fixed

    def _repair_or_keep_tool_call(
        self,
        tc: ToolCall,
        *,
        tools_schema: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Return ``{"name", "arguments"}`` — parse-or-repair the raw JSON."""
        name = tc.name or ""
        try:
            parsed = json.loads(tc.arguments)
            if isinstance(parsed, dict):
                return {"name": name, "arguments": parsed}
            raise ValueError("tool arguments not a dict")
        except Exception:  # noqa: BLE001 — fall through to repair
            pass

        return self._fix_arguments(name=name, raw=tc.arguments, tools_schema=tools_schema)

    def _fix_arguments(
        self,
        *,
        name: str,
        raw: Any,
        tools_schema: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Repair malformed tool-call arguments via ToolCallFixer.

        Falls back to ``{}`` so the caller can still dispatch the tool by
        name (the executor treats missing params as defaults).
        """
        if self._fixer is None:
            from elengenix.agents.toolcall_fixer import ToolCallFixer

            self._fixer = ToolCallFixer(
                provider=_ProviderCompletionAdapter(self.provider, self.slot)
            )

        tool_schema: Optional[Dict[str, Any]] = None
        for tool in tools_schema:
            try:
                func = tool.get("function", {}) if isinstance(tool, dict) else {}
                if func.get("name") == name:
                    tool_schema = func.get("parameters")
                    break
            except Exception:  # noqa: BLE001
                continue

        try:
            corrected = self._fixer.run(
                agent_type=_agent_type(),
                original_tool_call={"name": name, "arguments": raw},
                error_message=f"Could not parse arguments for tool {name!r} as JSON",
                tool_schema=tool_schema,
            )
            fixed_raw = corrected.get("arguments", raw)
            parsed = json.loads(fixed_raw) if isinstance(fixed_raw, str) else fixed_raw
            if isinstance(parsed, dict):
                return {"name": name, "arguments": parsed}
        except Exception:  # noqa: BLE001
            logger.exception("toolcall fixer failed for %r; dropping args", name)

        return {"name": name, "arguments": {}}


def _agent_type():
    """Return the AgentType for the fixer log lines (lazy import)."""
    from elengenix.agents import base as _agents_base

    return _agents_base.AgentType.PRIMARY


# ---------------------------------------------------------------------------
# Module-level lazy resolver
# ---------------------------------------------------------------------------

_CONFIG_CACHE: Dict[str, Optional[StackAFixingBackend]] = {}


def resolve_stack_a_backend(
    *,
    provider_name: Optional[str] = None,
    model_name: Optional[str] = None,
) -> Optional[StackAFixingBackend]:
    """Resolve the active provider (+model) into a :class:`StackAFixingBackend`.

    Returns ``None`` when the provider is unavailable in Stack A — either
    because ``provider_name`` doesn't map to a ``ProviderType`` (e.g.
    ``groq``, ``nvidia``, Stack-B-only names), or because the registry
    shipped a stub factory (missing SDK). The caller keeps Stack B in both
    cases.

    ``provider_name`` defaults to the result of
    ``tools.ai_config.get_active_provider()``; return ``None`` when that is
    the ``"auto"`` sentinel *or* when the resolved name has no explicit
    ``ai.providers.<name>.*`` block in config.yaml — Stack A ignores the
    config.yaml provider section entirely, so treating a boilerplate
    ``active_provider`` plus an empty block as a Stack-A opt-in would
    silently reconfigure the scan loop onto an unconfigured env-var-only
    provider. Only providers explicitly configured in config.yaml are
    candidates for the Stack-A fast path.
    """
    # Late import to keep ``elengenix.scanning`` importable without tools/.
    from tools.ai_config import (
        get_active_provider,
        get_provider_config,
        resolve_provider_settings,
    )

    name = (provider_name or "").strip().lower() or None
    if name is None:
        active = get_active_provider()
        if active == "auto":
            return None
        name = active

    # Stack A reads its credentials from env vars only; Stack B reads
    # config.yaml + env. Only escalate to Stack A when the user actually put
    # a block for this name under ``ai.providers`` — that's the existing
    # "I configured this provider" signal the two stacks both honor.
    if not get_provider_config(name):
        return None

    try:
        provider_type = ProviderType(name)
    except ValueError:
        return None

    settings = resolve_provider_settings(name, model=model_name)
    model = model_name or settings.get("model") or ""

    key = f"{name}|{model or ''}"
    cached = _CONFIG_CACHE.get(key)
    if cached is not None:
        return cached

    registry = _prov_registry.get_default_registry()
    try:
        cfg = _build_provider_config(provider_type, model=model or None)
        provider = registry.get_provider(provider_type, config=cfg)
    except NotImplementedError:
        _CONFIG_CACHE[key] = None
        return None
    except Exception:
        logger.debug(
            "stack A provider %s unavailable; falling back to Stack B", name,
            exc_info=True,
        )
        _CONFIG_CACHE[key] = None
        return None

    if provider is None:
        _CONFIG_CACHE[key] = None
        return None

    backend = StackAFixingBackend(provider=provider, provider_type=provider_type)
    _CONFIG_CACHE[key] = backend

    slot_cfg = cfg.get_agent_config(PROVIDER_SLOT) if cfg else None
    logger.info(
        "scan decide routed via Stack A provider=%s model=%s",
        name,
        slot_cfg.model if slot_cfg else "(registry default)",
    )
    return backend


def _build_provider_config(
    provider_type: ProviderType,
    *,
    model: Optional[str] = None,
) -> Optional[ProviderConfig]:
    """Deep-copy the registry default for ``provider_type``, overriding the
    scan-decide slot's model when the caller supplied one. Returns ``None``
    when the registry has no default config (caller uses the factory's own
    built-in default instead).
    """
    registry = _prov_registry.get_default_registry()
    try:
        default_cfg = registry.get_default_config(provider_type)
    except KeyError:
        return None

    import copy as _copy

    cfg = _copy.deepcopy(default_cfg)
    if model:
        slot_agent = getattr(default_cfg, PROVIDER_SLOT.value, None)
        if slot_agent is not None:
            setattr(cfg, PROVIDER_SLOT.value, _copy.deepcopy(slot_agent))
            getattr(cfg, PROVIDER_SLOT.value).model = model
    return cfg


__all__ = ["StackAFixingBackend", "resolve_stack_a_backend", "PROVIDER_SLOT"]
