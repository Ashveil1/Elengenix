"""elengenix/agents/assistant.py — interactive conversational Assistant.

The Assistant is the **only** agent in the hierarchy that operates OUTSIDE
the Task / SubTask orchestration loop. It powers ``elengenix hack`` chat
mode and any other free-form conversational surface.

Key differences vs. the orchestration agents:

* **No barrier tool** — the Assistant does NOT have ``done`` / ``ask``
  available; it returns plain text to the user.
* **Streaming-first** — primary entry point is :meth:`Assistant.stream`,
  an async generator that yields token chunks as they arrive.
* **Tool-augmented but optional** — the Assistant may invoke any of the
  PrimaryAgent's tools (search, terminal, browser, memory, etc.) but is
  never *required* to do so. Free-text replies are valid.
* **Stateless across CLI invocations** — the caller is responsible for
  threading chat history through :class:`AssistantConversation`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncIterator, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from elengenix.agents.base import AgentContext, AgentType

logger = logging.getLogger("elengenix.agents.assistant")


# ---------------------------------------------------------------------------
# System prompt — ported from pentagi/templates/prompts/assistant.tmpl
# ---------------------------------------------------------------------------
ASSISTANT_SYSTEM_PROMPT = """\
You are the Elengenix Assistant, an interactive conversational agent that
operates OUTSIDE the task/subtask hierarchy. You power `elengenix hack`
chat mode.

Capabilities:
- Answer security research questions directly in plain prose.
- Invoke any of the registered tools (search, terminal, browser, memory,
  etc.) when an answer requires live data or side effects.
- Stream your reply token-by-token to the user's terminal.

Rules:
- You are NOT required to call a tool on every turn; free-text replies are
  valid and encouraged when no tool is needed.
- When you DO call a tool, briefly tell the user what you are doing in one
  short sentence, then call the tool, then continue your reply.
- Never call the `done` or `ask` barrier tools — they are not available to
  you. The conversation ends when the user types `exit` or `quit`.
- Match the user's language. Technical channel (tool args, code) stays in
  English.
"""


# ---------------------------------------------------------------------------
# Provider protocol — async + streaming
# ---------------------------------------------------------------------------
@runtime_checkable
class StreamingLLMProvider(Protocol):
    """Async LLM interface with streaming support the Assistant depends on."""

    async def complete_async(
        self, prompt: str, *, system: Optional[str] = None
    ) -> str:  # noqa: D401
        """Non-streaming completion — used by :meth:`Assistant.run`."""
        ...

    async def stream_async(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        history: Optional[list[dict[str, Any]]] = None,
        tools: Optional[list[dict[str, Any]]] = None,
    ) -> AsyncIterator[str]:
        """Streaming completion — yields text chunks as they arrive.

        Implementations should also yield any tool-call decisions as a
        sentinel chunk (see :data:`Assistant.TOOL_CALL_SENTINEL`) so the
        Assistant loop can execute the tool and continue the conversation.
        """
        ...


# ---------------------------------------------------------------------------
# Pydantic v2 schemas
# ---------------------------------------------------------------------------
class ToolSpec(BaseModel):
    """Specification of a tool the Assistant may invoke."""

    name: str = Field(..., description="Tool name as registered in the tool registry")
    description: str = Field("", description="Short human-readable description")
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON schema for the tool's arguments",
    )

    model_config = {"extra": "ignore"}


class ToolInvocation(BaseModel):
    """A single tool invocation parsed from a model's streamed response."""

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "ignore"}


class ChatTurn(BaseModel):
    """One turn in the Assistant's conversation history."""

    role: str = Field(..., description="One of: 'user', 'assistant', 'tool'")
    content: str = Field("", description="Text content of the turn")
    tool_calls: list[ToolInvocation] = Field(default_factory=list)
    tool_call_id: Optional[str] = Field(
        None, description="ID linking a tool result back to its call"
    )

    model_config = {"extra": "ignore"}

    def to_message_dict(self) -> dict[str, Any]:
        """Convert to a LangChain-style message dict for LLM providers."""
        msg: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_calls:
            msg["tool_calls"] = [
                {
                    "id": f"call_{i}",
                    "name": tc.name,
                    "args": tc.arguments,
                }
                for i, tc in enumerate(self.tool_calls)
            ]
        if self.tool_call_id is not None:
            msg["tool_call_id"] = self.tool_call_id
        return msg


class AssistantConversation(BaseModel):
    """Full state of an Assistant chat session."""

    turns: list[ChatTurn] = Field(default_factory=list)

    model_config = {"extra": "ignore"}

    def append(self, turn: ChatTurn) -> None:
        self.turns.append(turn)

    def to_history(self) -> list[dict[str, Any]]:
        return [t.to_message_dict() for t in self.turns]


# ---------------------------------------------------------------------------
# Tool invocation parser (best-effort)
# ---------------------------------------------------------------------------
_TOOL_CALL_PREFIX = "[TOOL_CALL:"
_TOOL_CALL_SUFFIX = "]"


def _parse_tool_call_chunk(chunk: str) -> Optional[ToolInvocation]:
    """Detect a sentinel-encoded tool call inside a stream chunk.

    The Assistant protocol uses a simple in-band sentinel:

        [TOOL_CALL:{"name":"...","arguments":{...}}]

    Returns ``None`` if the chunk is plain text.
    """
    if not chunk or _TOOL_CALL_PREFIX not in chunk:
        return None
    start = chunk.find(_TOOL_CALL_PREFIX)
    if start < 0:
        return None
    payload_start = start + len(_TOOL_CALL_PREFIX)
    end = chunk.find(_TOOL_CALL_SUFFIX, payload_start)
    if end < 0:
        return None
    payload = chunk[payload_start:end].strip()
    try:
        data = json.loads(payload)
        if not isinstance(data, dict):
            return None
        return ToolInvocation(
            name=data.get("name", ""),
            arguments=data.get("arguments", {}) or {},
        )
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Assistant
# ---------------------------------------------------------------------------
class Assistant:
    """Interactive conversational agent (chat mode).

    Parameters
    ----------
    provider:
        Any object implementing :class:`StreamingLLMProvider`. Required for
        both :meth:`run` and :meth:`stream`.
    tools:
        Optional mapping of tool name -> callable. Each callable must
        accept a single ``arguments: dict`` parameter (plus optional
        keyword-only ``ctx``) and return a string. The Assistant will
        invoke registered tools when the model emits a tool call.
    tool_specs:
        Optional list of :class:`ToolSpec` objects describing the
        registered tools. When provided, the Assistant forwards them to
        the provider so the model can make informed tool choices.
    system_prompt:
        Override the default :data:`ASSISTANT_SYSTEM_PROMPT`.
    max_tool_iterations:
        Safety cap on how many tool calls a single :meth:`run` / :meth:`stream`
        invocation may make before forcing a final text reply.
    """

    TOOL_CALL_SENTINEL = _TOOL_CALL_PREFIX

    def __init__(
        self,
        provider: StreamingLLMProvider,
        *,
        tools: Optional[dict[str, Any]] = None,
        tool_specs: Optional[list[ToolSpec]] = None,
        system_prompt: str = ASSISTANT_SYSTEM_PROMPT,
        max_tool_iterations: int = 8,
    ) -> None:
        if provider is None:
            raise ValueError("Assistant requires a streaming LLM provider")
        self.provider = provider
        self.tools: dict[str, Any] = dict(tools or {})
        self.tool_specs: list[ToolSpec] = list(tool_specs or [])
        self.system_prompt = system_prompt
        self.max_tool_iterations = max_tool_iterations

    # -- public API --------------------------------------------------------
    async def run(
        self,
        user_input: str,
        history: Optional[list[dict[str, Any]]] = None,
        *,
        ctx: Optional[AgentContext] = None,
    ) -> str:
        """Non-streaming reply — collect all chunks and return as one string.

        Useful for callers that don't care about token streaming (e.g.
        programmatic API consumers).
        """
        chunks: list[str] = []
        async for chunk in self.stream(user_input, history, ctx=ctx):
            chunks.append(chunk)
        return "".join(chunks)

    async def stream(
        self,
        user_input: str,
        history: Optional[list[dict[str, Any]]] = None,
        *,
        ctx: Optional[AgentContext] = None,
    ) -> AsyncIterator[str]:
        """Stream the Assistant's reply as an async generator of text chunks.

        Tool invocations are executed transparently: when the model emits a
        tool call (encoded via :data:`Assistant.TOOL_CALL_SENTINEL`), the
        Assistant runs the tool, appends the result to the working history,
        and continues streaming the follow-up reply. The caller only sees
        the *visible* text chunks plus the tool-call sentinel chunks (so a
        TUI can render "calling tool X…" indicators).
        """
        if not user_input:
            return

        working_history: list[dict[str, Any]] = list(history or [])
        working_history.append({"role": "user", "content": user_input})

        tool_specs_dicts = [spec.model_dump() for spec in self.tool_specs]

        for iteration in range(self.max_tool_iterations):
            accumulated: list[str] = []
            tool_invocation: Optional[ToolInvocation] = None

            async for chunk in self.provider.stream_async(
                user_input,
                system=self.system_prompt,
                history=working_history,
                tools=tool_specs_dicts or None,
            ):
                if not chunk:
                    continue
                parsed = _parse_tool_call_chunk(chunk)
                if parsed is not None:
                    tool_invocation = parsed
                    # Yield a visible marker so the TUI can render the call.
                    yield f"\n[calling tool: {parsed.name}]\n"
                    continue
                accumulated.append(chunk)
                yield chunk

            assistant_text = "".join(accumulated).strip()
            if assistant_text:
                working_history.append(
                    {"role": "assistant", "content": assistant_text}
                )

            if tool_invocation is None:
                # No further tool call — the model is done talking.
                return

            # Execute the tool and feed the result back.
            tool_result = await self._invoke_tool(tool_invocation, ctx=ctx)
            working_history.append(
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": f"call_{iteration}",
                            "name": tool_invocation.name,
                            "args": tool_invocation.arguments,
                        }
                    ],
                }
            )
            working_history.append(
                {
                    "role": "tool",
                    "tool_call_id": f"call_{iteration}",
                    "name": tool_invocation.name,
                    "content": tool_result,
                }
            )
            # Loop continues — the model will see the tool result and either
            # call another tool or produce its final text reply.

        # Safety cap reached — emit a brief note and stop.
        yield "\n[assistant: max tool iterations reached, stopping]\n"

    # -- helpers -----------------------------------------------------------
    async def _invoke_tool(
        self,
        invocation: ToolInvocation,
        *,
        ctx: Optional[AgentContext] = None,
    ) -> str:
        """Run a tool by name; return its string result.

        Unknown tools return a structured error string instead of raising —
        the model can recover by trying a different tool or answering
        directly.
        """
        handler = self.tools.get(invocation.name)
        if handler is None:
            logger.warning(
                "assistant.tool_unknown name=%s", invocation.name
            )
            return f"Error: tool '{invocation.name}' is not available."

        try:
            result = handler(invocation.arguments, ctx=ctx) if ctx is not None else handler(invocation.arguments)
            if asyncio.iscoroutine(result):
                result = await result
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "assistant.tool_failed name=%s err=%s",
                invocation.name,
                exc,
            )
            return f"Error: tool '{invocation.name}' raised: {exc}"

        if not isinstance(result, str):
            try:
                result = json.dumps(result, ensure_ascii=False, default=str)
            except (TypeError, ValueError):
                result = str(result)
        return result


__all__ = [
    "ASSISTANT_SYSTEM_PROMPT",
    "StreamingLLMProvider",
    "ToolSpec",
    "ToolInvocation",
    "ChatTurn",
    "AssistantConversation",
    "Assistant",
]
