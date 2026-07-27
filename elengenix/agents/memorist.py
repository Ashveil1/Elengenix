"""elengenix/agents/memorist.py — long-term memory retrieval specialist.

Ports PentAGI's ``templates/prompts/memorist.tmpl`` system prompt,
``templates/prompts/question_memorist.tmpl`` user prompt, and the
``GetMemoristHandler`` factory from ``providers/handlers.go`` into Elengenix.
The Memorist is a *limited* agent (``MAX_LIMITED_ITERATIONS`` = 20) that
retrieves comprehensive historical context from:

- the pgvector / ChromaDB vector store (reusable knowledge indexed across
  all engagements) via the ``search_in_memory`` tool
- the Graphiti temporal knowledge graph (episodic memory of what agents
  actually did) via the ``graphiti_search`` tool with 7 search types

…and MAY also write new reusable knowledge back to the vector store via the
``store_answer`` / ``store_guide`` / ``store_code`` tools.

The Memorist terminates by calling the ``memorist_result`` barrier tool;
its ``result`` field becomes the calling specialist's historical-context
write-up.

Two-channel language policy (ported verbatim from PentAGI):
    * Engagement log (``message`` fields, closing ``message``) -> {{ lang }}
    * Technical channel (queries, stored content, closing ``result``) ->
      English

Data anonymization rule (ported from PentAGI's ``anonymizer.Replacer``):
ALL content written to long-term memory via the ``store_answer``,
``store_guide``, or ``store_code`` tools MUST be anonymized BEFORE storing.
The :func:`anonymize` helper performs the programmatic replacement:

- IPv4 addresses  → ``{ip}``
- Domains / hosts → ``{domain}``
- Usernames       → ``{username}``
- Passwords       → ``{password}``

The system prompt ALSO instructs the LLM to anonymize before emitting store
payloads (defense-in-depth: prompt + programmatic).

Implementation note: this module wires its tools into the universal
:func:`elengenix.agents.base.perform_agent_chain` loop via a small
``_MemoristToolExecutor`` adapter that implements the ``ToolExecutor``
protocol — exactly the pattern used by
:class:`elengenix.agents.primary_agent.PrimaryAgent`. The chain is seeded
with ``[system, user]`` messages, the LLM client drives tool-calling, and
the loop terminates when the model emits ``memorist_result`` (captured by
the executor and surfaced via the ``on_barrier`` callback).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field, ValidationError

from elengenix.agents.base import (
    AgentContext,
    AgentType,
    MAX_LIMITED_ITERATIONS,
    Message,
    PerformResult,
    perform_agent_chain,
)

logger = logging.getLogger("elengenix.agents.memorist")

# --- Tool-name constants (ported from pentagi/backend/pkg/tools/registry.go) --
MEMORIST_RESULT_TOOL_NAME = "memorist_result"
SEARCH_IN_MEMORY_TOOL_NAME = "search_in_memory"
STORE_ANSWER_TOOL_NAME = "store_answer"
STORE_GUIDE_TOOL_NAME = "store_guide"
STORE_CODE_TOOL_NAME = "store_code"
GRAPHITI_SEARCH_TOOL_NAME = "graphiti_search"

# --- Shared prompt constants (ported from cast/csum packages) ----------------
SUMMARIZATION_TOOL_NAME = "execute_task_and_return_summary"
SUMMARIZED_CONTENT_PREFIX = "**summarized content:**\\n"
TOOL_PLACEHOLDER = (
    "Execute operations via function invocation - textual responses are not "
    "acceptable for task completion."
)

CONTAINER_WORK_DIR = "/work"
DEFAULT_DOCKER_IMAGE = "debian:latest"

#: The 7 Graphiti search types advertised in the system prompt.
GRAPHITI_SEARCH_TYPES: tuple[str, ...] = (
    "recent_context",
    "episode_context",
    "temporal_window",
    "successful_tools",
    "entity_relationships",
    "entity_by_label",
    "diverse_results",
)


# --- Data anonymization (ported from PentAGI's anonymizer.Replacer) ----------
# IPv4 address (with 0-255 octet validation).
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# URL with embedded credentials: scheme://user:pass@host
# Captured BEFORE domain/IP regexes so the user/pass don't get re-matched.
_URL_CRED_RE = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*)://"
    r"(?P<user>[^:/@\s]+):(?P<password>[^@/\s]+)@",
)

# Email address: user@domain — anonymized to {username}@{domain}.
_EMAIL_RE = re.compile(
    r"\b(?P<user>[A-Za-z0-9._%+\-]+)@(?P<domain>[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"
)

# Password / secret key-value pair: password=foo, pwd:bar, "api-key":"xyz".
_PASSWORD_KV_RE = re.compile(
    r"(?P<key>(?:password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret))\s*[:=]\s*"
    r"(?P<value>[^\s,;\"'\]\}|>]+)",
    re.IGNORECASE,
)

# Username / login key-value pair: username=foo, user:bar, login=baz.
_USERNAME_KV_RE = re.compile(
    r"(?P<key>(?:username|user[_-]?name|user|login|account))\s*[:=]\s*"
    r"(?P<value>[^\s,;\"'\]\}|>]+)",
    re.IGNORECASE,
)

# Domain / hostname: labels.dotted.tld — applied AFTER URL creds + email.
# Conservative TLD list to avoid false positives on sentences like "foo.bar".
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,24}|local|internal|test|corp|lan|htb|localdomain|"
    r"home\.arpa|invalid|example)\b"
)


def anonymize(text: str | None) -> str | None:
    """Anonymize sensitive data in ``text`` before storing in long-term memory.

    Replaces IPv4 addresses, domains, usernames, and passwords with the
    placeholders ``{ip}``, ``{domain}``, ``{username}``, ``{password}``
    respectively. Applied as defense-in-depth alongside the system-prompt
    instruction that tells the LLM to anonymize before emitting store
    payloads.

    Order of operations matters:

    1. URL credentials (``scheme://user:pass@host``) — captured whole so the
       embedded user/pass aren't re-matched by later patterns.
    2. Password key-value pairs (``password=foo``).
    3. Username key-value pairs (``username=foo``).
    4. Email addresses (``user@domain`` → ``{username}@{domain}``).
    5. Bare IPv4 addresses.
    6. Bare domains / hostnames.

    Args:
        text: The content to anonymize (e.g. a guide, answer, or code sample
            about to be stored in the vector store). ``None`` is passed
            through unchanged.

    Returns:
        The anonymized content. If ``text`` is empty or ``None``, it is
        returned unchanged.
    """
    if not text:
        return text

    # 1. URL credentials
    text = _URL_CRED_RE.sub(
        lambda m: f"{m.group('scheme')}://{{username}}:{{password}}@", text
    )
    # 2. Password key-value
    text = _PASSWORD_KV_RE.sub(
        lambda m: f"{m.group('key')}={{password}}", text
    )
    # 3. Username key-value
    text = _USERNAME_KV_RE.sub(
        lambda m: f"{m.group('key')}={{username}}", text
    )
    # 4. Email
    text = _EMAIL_RE.sub("{username}@{domain}", text)
    # 5. IPv4
    text = _IPV4_RE.sub("{ip}", text)
    # 6. Domains
    text = _DOMAIN_RE.sub("{domain}", text)
    return text


# --- Pydantic schema for the barrier-tool payload ----------------------------
class MemoristResult(BaseModel):
    """Completion-tool payload for the ``memorist_result`` barrier tool.

    Two-channel policy (mirrors PentAGI):

    - ``result``  — technical channel, English. The historical-context
      write-up consumed by the calling agent. Contains synthesized findings
      from the vector store and Graphiti knowledge graph.
    - ``message`` — engagement log, engagement language. A 1–2 sentence
      running commentary on what was retrieved / produced.
    """

    result: str = Field(
        ...,
        description=(
            "Technical-channel payload — fully detailed long-term memory "
            "search report (or error explanation) returned to the calling "
            "agent for further reasoning. Always written in English; never "
            "translated."
        ),
    )
    message: str = Field(
        ...,
        max_length=500,
        description=(
            "Engagement-log entry — a 1-2 short sentence running commentary "
            "with a short answer summary. Written in the engagement language."
        ),
    )


# --- System prompt template (Jinja2; ported from memorist.tmpl) ---------------
SYSTEM_PROMPT_TEMPLATE = """\
# LONG-TERM MEMORY SPECIALIST

You are an elite archivist specialized in retrieving information from vector database storage to provide comprehensive historical context for team operations.

## LANGUAGE POLICY

<language_policy>
You operate on two parallel channels. The channel of each tool argument is fixed by its JSON-schema description and must not be inferred from the surrounding context.

1. **Engagement log — engagement language `{{ lang }}`.** Your running commentary on this engagement. Entries are every `message` field of every tool call you make (vector-store searches{% if graphiti_enabled %}, knowledge-graph searches{% endif %}, the closing call) and the `message` of your closing `{{ memorist_result_tool_name }}` call. The engagement coordination team reads the log in `{{ lang }}`. Keep `message` log entries to 1-2 short sentences narrating what you are about to do or what you just produced.

2. **Technical channel — English.** The wire between you, the vector store{% if graphiti_enabled %}, the temporal knowledge graph,{% endif %} and the runtime container. Outgoing entries are:
   - vector-store semantic queries against long-term memory (the `questions` array of the `{{ search_in_memory_tool_name }}` tool){% if graphiti_enabled %}
   - knowledge-graph queries: `{{ graphiti_search_tool_name }}.query`{% endif %}
   - the `result` field of your closing `{{ memorist_result_tool_name }}` call — the full historical-context write-up consumed by the calling agent for further reasoning

The vector store{% if graphiti_enabled %} and the temporal knowledge graph{% endif %} {{ "are" if graphiti_enabled else "is" }} indexed in English and shared across all engagements regardless of their working language: any non-English query retrieves nothing. Never translate or localise an outgoing technical-channel field — search queries and the closing `{{ memorist_result_tool_name }}.result` stay strictly in English even when the engagement language is not English.
</language_policy>

## KNOWLEDGE MANAGEMENT

<memory_protocol>
{% if graphiti_enabled %}
<graphiti_search>ALWAYS search Graphiti FIRST to check execution history and episodic memory</graphiti_search>
{% endif %}
<primary_action>Split complex questions into precise vector database queries</primary_action>
<search_optimization>Use exact sentence matching for optimal retrieval
accuracy</search_optimization>
<result_handling>Combine multiple search results into cohesive responses</result_handling>
<anonymization_rule>
ALL content written to long-term memory via the `{{ store_answer_tool_name }}`,
`{{ store_guide_tool_name }}`, or `{{ store_code_tool_name }}` tools MUST be anonymized BEFORE storing. Replace sensitive data with descriptive placeholders:

- IPv4 addresses  → `{ip}`
- Domains / hosts → `{domain}`
- Usernames       → `{username}`
- Passwords       → `{password}`

Example: `curl https://admin:Str0ngP@ss@example.com/api` →
`curl https://{username}:{password}@{domain}/api`.

The system also applies programmatic anonymization as defense-in-depth, but
YOU are responsible for emitting already-anonymized payloads.
</anonymization_rule>
</memory_protocol>
{% if graphiti_enabled %}

## HISTORICAL CONTEXT RETRIEVAL

<graphiti_search_protocol>
<overview>
You have access to a temporal knowledge graph (Graphiti) that stores ALL previous agent responses and tool execution records from this engagement. This is your primary source for episodic memory - use it to provide complete historical context of what actually happened during operations.
</overview>

<when_to_search>
ALWAYS search Graphiti BEFORE searching vector database:
- When asked about past events → Check what actually occurred
- When asked about agent activities → Find specific agent responses
- When asked about discoveries → Retrieve actual findings
- When asked about tool usage → Find execution records
- When building timelines → Get chronological context
- When asked about entities → Understand their relationships
</when_to_search>

<search_type_selection>
Choose the appropriate search type based on the information need:

1. **recent_context** - Your DEFAULT starting point for recent history
   - Use: "What happened recently regarding [topic]?"
   - When: Answering questions about recent activities, current state
   - Example: `search_type: "recent_context", query: "recent pentester findings about web application", recency_window: "6h"`

2. **episode_context** - Get detailed agent work and responses
   - Use: "What did [agent] do/discover about [topic]?"
   - When: Need complete agent reasoning and execution details
   - Example: `search_type: "episode_context", query: "pentester agent exploitation of SQL injection vulnerability"`

3. **temporal_window** - Search within specific time period
   - Use: "What occurred between [time] and [time]?"
   - When: Need to retrieve events from specific timeframe
   - Example: `search_type: "temporal_window", query: "all reconnaissance activities", time_start: "2024-01-01T00:00:00Z", time_end: "2024-01-01T23:59:59Z"`

4. **successful_tools** - Find proven techniques and commands
   - Use: "What [tool/technique] executions succeeded?"
   - When: Looking for working command examples, successful approaches
   - Example: `search_type: "successful_tools", query: "successful nmap scans revealing services", min_mentions: 2`

5. **entity_relationships** - Explore entity connections (requires entity UUID from prior search)
   - Use: "What is connected to [entity]?"
   - When: Understanding relationships between discovered entities
   - Example: `search_type: "entity_relationships", query: "related vulnerabilities and services", center_node_uuid: "[uuid]", max_depth: 2`

6. **entity_by_label** - Type-specific inventory (requires specific labels from prior discovery)
   - Use: "List all [entity type] discovered"
   - When: Creating inventories, generating comprehensive reports
   - Example: `search_type: "entity_by_label", query: "all discovered vulnerabilities", node_labels: ["VULNERABILITY"]`

7. **diverse_results** - Get varied perspectives and alternatives
   - Use: "What are different approaches/findings about [topic]?"
   - When: Need comprehensive view with minimal redundancy
   - Example: `search_type: "diverse_results", query: "different privilege escalation techniques discovered", diversity_level: "high"`
</search_type_selection>

<query_construction>
Effective queries are SPECIFIC and CONTEXTUAL:

GOOD queries:
- "pentester agent nmap scan results for 192.168.1.100 showing open ports"
- "coder agent Python script for parsing JSON vulnerability data"
- "searcher agent research findings about CVE-2024-1234 exploitation"
- "developer tool executions modifying exploit payloads"

BAD queries (too vague):
- "findings"
- "results"
- "activities"
- "information"

Include:
- Agent type when relevant (pentester, coder, searcher, installer)
- Specific topics or targets
- Technical details (IPs, CVEs, tools, techniques)
- Time context when available
- Action types (scan, exploit, research, development)
</query_construction>

<integration_with_memory_protocol>
The existing memory protocol (vector database search) is for REUSABLE KNOWLEDGE.
Graphiti is for EPISODIC MEMORY of what actually happened.

Use both in sequence:
1. Search Graphiti for "what did we do?" (execution history, actual events)
2. Search vector database for "what knowledge exists?" (stored solutions, guides)

Graphiti provides the "story" of the engagement.
Vector database provides the "library" of reusable solutions.
</integration_with_memory_protocol>

<tool_name>{{ graphiti_search_tool_name }}</tool_name>
</graphiti_search_protocol>
{% endif %}

## OPERATIONAL ENVIRONMENT

<container_constraints>
<runtime>Docker {{ docker_image }} with working directory {{ cwd }}</runtime>
<timeout>Default: 120 seconds (Hard limit: 20 minutes)</timeout>
<restrictions>
- No GUI applications
- No Docker host access
- Command-line operations only
</restrictions>
</container_constraints>

## SUMMARIZATION AWARENESS PROTOCOL

<summarized_content_handling>
<identification>
- Summarized historical interactions appear in TWO distinct forms:
  1. **Tool Call Summary:** An AI message containing ONLY a call to the `{{ summarization_tool_name }}` tool, immediately followed by a Tool message containing the summary in its response content.
  2. **Prefixed Summary:** An AI message whose text content starts EXACTLY with the prefix: `{{ summarized_content_prefix }}`.
- These summaries are condensed records of previous actions and conversations, NOT templates for your own responses.
</identification>

<prohibited_behavior>
- NEVER mimic or copy the format of summarized content.
- NEVER use the prefix `{{ summarized_content_prefix }}` in your messages.
- NEVER call the `{{ summarization_tool_name }}` tool yourself.
- NEVER produce plain text responses simulating tool calls or their outputs.
</prohibited_behavior>

<required_behavior>
- ALWAYS use proper, structured tool calls for ALL actions you perform.
- Interpret summarized information to guide your strategy.
</required_behavior>
</summarized_content_handling>

## TOOL UTILIZATION

<available_tools>
<tool name="{{ search_in_memory_tool_name }}">
<purpose>Search the long-term vector store (pgvector / ChromaDB) for stored knowledge, guides, answers, and code from previous engagements</purpose>
<usage>Primary retrieval source — split complex questions into 1-5 precise semantic queries</usage>
<query_format>Each query is an exact, context-rich English sentence</query_format>
</tool>

<tool name="{{ store_answer_tool_name }}">
<purpose>Store a reusable answer in the vector store for future retrieval</purpose>
<usage>Write back knowledge gained during this engagement</usage>
<anonymization>Anonymize IPs/domains/credentials BEFORE storing</anonymization>
</tool>

<tool name="{{ store_guide_tool_name }}">
<purpose>Store a reusable how-to guide in the vector store</purpose>
<usage>Write back step-by-step instructions for future retrieval</usage>
<anonymization>Anonymize IPs/domains/credentials BEFORE storing</anonymization>
</tool>

<tool name="{{ store_code_tool_name }}">
<purpose>Store a reusable code sample in the vector store</purpose>
<usage>Write back proven code snippets for future retrieval</usage>
<anonymization>Anonymize IPs/domains/credentials/API keys BEFORE storing</anonymization>
</tool>
{% if graphiti_enabled %}

<tool name="{{ graphiti_search_tool_name }}">
<purpose>Search the Graphiti temporal knowledge graph for episodic memory and execution history</purpose>
<usage>Find what agents actually did and discovered during operations (7 search types)</usage>
<search_types>{{ graphiti_search_types }}</search_types>
</tool>
{% endif %}
</available_tools>

## EXECUTION CONTEXT

<current_time>
{{ current_time }}
</current_time>

<execution_context_usage>
- Use the current execution context to understand the precise current objective
- Extract Flow, Task, and SubTask details (IDs, Status, Titles, Descriptions)
- Determine operational scope and parent task relationships
- Identify relevant history within the current operational branch
- Tailor your approach specifically to the current SubTask objective
</execution_context_usage>

<execution_context>
{{ execution_context }}
</execution_context>
{% if user_files %}

## TASK MATERIALS

<task_materials_protocol>
The following files are attached to this flow and available READ-ONLY in the container:
- `{{ cwd }}/uploads` — files delivered specifically for this flow
- `{{ cwd }}/resources` — reference materials prepared for this engagement

If memory retrieval requires verifying or cross-referencing file contents, access them using the full path (`<base>/<relative_path>`). These directories are READ-ONLY.
</task_materials_protocol>

{{ user_files }}
{% endif %}

## COMPLETION REQUIREMENTS

1. Decompose the user question into precise vector-store queries
2. Use exact sentence matching for better search results
3. Follow the LANGUAGE POLICY above on every tool call. Every `message` is an engagement-log entry written in `{{ lang }}`; every search query, stored payload, and the closing `{{ memorist_result_tool_name }}.result` stay on the technical channel in English
4. Anonymize ALL content emitted via `{{ store_answer_tool_name }}`, `{{ store_guide_tool_name }}`, `{{ store_code_tool_name }}` per the `<anonymization_rule>` above BEFORE storing
5. Closing entries: you MUST use the `{{ memorist_result_tool_name }}` tool — `result` is the technical-channel historical-context write-up consumed by the calling agent (English), `message` is the engagement-log closing summary (`{{ lang }}`)

{{ tool_placeholder }}

User's question will be provided in the next message.
"""


USER_PROMPT_TEMPLATE = """\
<question_memorist_context>
  <instruction>
  Retrieve and synthesize historical information relevant to the user's question. Split complex queries into precise vector database searches using exact sentence matching for optimal retrieval.

  Combine multiple search results into a cohesive response that provides comprehensive historical context. Focus on extracting precise information from vector database storage that directly addresses the user's query.
  </instruction>

  <user_question>
  {{ question }}
  </user_question>
</question_memorist_context>
"""


# --- Jinja2 rendering helper (with str.format fallback) -----------------------
def _render(template: str, **context: Any) -> str:
    """Render a Jinja2 template string with the given context.

    Falls back to a tolerant ``str.format``-style substitution when Jinja2 is
    not installed; in that case ``{% if %}`` / ``{% endif %}`` blocks are
    stripped (treated as always-false) so the template still renders cleanly.
    """
    try:  # pragma: no cover - import guarded for minimal envs
        from jinja2 import Template

        return Template(template).render(**context)
    except ImportError:  # pragma: no cover
        stripped = re.sub(r"{%\s*if .*?%}.*?{%\s*endif\s*%}", "", template, flags=re.S)
        return stripped.format_map(_DefaultDict(context))


class _DefaultDict(dict):
    """``dict`` subclass returning empty string for missing keys (format fallback)."""

    def __missing__(self, key: str) -> str:  # noqa: D401
        return ""


# --- Tool-argument parsing helper --------------------------------------------
def _parse_args(arguments: str | dict[str, Any] | None) -> dict[str, Any]:
    """Parse a JSON-encoded tool-arguments string into a dict.

    Tolerates dict inputs (already-parsed callers), ``None``, and empty
    strings. Malformed JSON degrades to an empty dict rather than raising
    so a buggy LLM emission doesn't crash the chain — the executor's
    ``store_*`` handlers will see an empty payload and the model can recover
    on the next iteration.
    """
    if isinstance(arguments, dict):
        return arguments
    if not arguments:
        return {}
    try:
        parsed = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


# --- Default JSON-Schema tool definitions ------------------------------------
def _default_tool_schemas(graphiti_enabled: bool) -> list[dict[str, Any]]:
    """Return the JSON-schema tool definitions exposed to the LLM.

    Mirrors the registry entries for the Memorist's 4 store/search tools
    plus the optional ``graphiti_search`` and the ``memorist_result``
    barrier. Each store tool takes a free-form ``question`` (English) plus
    the payload field; the barrier takes ``result`` + ``message``.
    """
    schemas: list[dict[str, Any]] = []

    schemas.append({
        "type": "function",
        "function": {
            "name": SEARCH_IN_MEMORY_TOOL_NAME,
            "description": (
                "Search the long-term vector store (pgvector / ChromaDB) for "
                "stored knowledge, guides, answers, and code from previous "
                "engagements. Split complex questions into 1-5 precise "
                "English semantic queries."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "questions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "1-5 precise English semantic queries — each an "
                            "exact, context-rich sentence."
                        ),
                    },
                    "message": {
                        "type": "string",
                        "description": (
                            "Short engagement-log entry narrating what you "
                            "are about to search for, in the engagement "
                            "language."
                        ),
                    },
                },
                "required": ["questions", "message"],
            },
        },
    })

    schemas.append({
        "type": "function",
        "function": {
            "name": STORE_ANSWER_TOOL_NAME,
            "description": (
                "Store a reusable answer in the vector store. Anonymize "
                "IPs/domains/credentials BEFORE storing (replace with "
                "{ip}/{domain}/{username}/{password})."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "answer": {
                        "type": "string",
                        "description": "The answer text (anonymized, English).",
                    },
                    "question": {
                        "type": "string",
                        "description": "The question this answer addresses (English).",
                    },
                    "message": {
                        "type": "string",
                        "description": "Short engagement-log entry (engagement language).",
                    },
                },
                "required": ["answer", "question", "message"],
            },
        },
    })

    schemas.append({
        "type": "function",
        "function": {
            "name": STORE_GUIDE_TOOL_NAME,
            "description": (
                "Store a reusable how-to guide in the vector store. Anonymize "
                "IPs/domains/credentials BEFORE storing."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "guide": {
                        "type": "string",
                        "description": "The step-by-step guide text (anonymized, English).",
                    },
                    "question": {
                        "type": "string",
                        "description": "The question this guide addresses (English).",
                    },
                    "message": {
                        "type": "string",
                        "description": "Short engagement-log entry (engagement language).",
                    },
                },
                "required": ["guide", "question", "message"],
            },
        },
    })

    schemas.append({
        "type": "function",
        "function": {
            "name": STORE_CODE_TOOL_NAME,
            "description": (
                "Store a reusable code sample in the vector store. Anonymize "
                "credentials/API keys BEFORE storing."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "The code sample (anonymized, English).",
                    },
                    "question": {
                        "type": "string",
                        "description": "The question this code addresses (English).",
                    },
                    "message": {
                        "type": "string",
                        "description": "Short engagement-log entry (engagement language).",
                    },
                },
                "required": ["code", "question", "message"],
            },
        },
    })

    if graphiti_enabled:
        schemas.append({
            "type": "function",
            "function": {
                "name": GRAPHITI_SEARCH_TOOL_NAME,
                "description": (
                    "Search the Graphiti temporal knowledge graph for "
                    "episodic memory and execution history. 7 search types: "
                    + ", ".join(GRAPHITI_SEARCH_TYPES)
                    + "."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "English search query (specific & contextual).",
                        },
                        "search_type": {
                            "type": "string",
                            "enum": list(GRAPHITI_SEARCH_TYPES),
                            "description": "One of the 7 Graphiti search types.",
                        },
                        "message": {
                            "type": "string",
                            "description": "Short engagement-log entry (engagement language).",
                        },
                    },
                    "required": ["query", "search_type", "message"],
                },
            },
        })

    schemas.append({
        "type": "function",
        "function": {
            "name": MEMORIST_RESULT_TOOL_NAME,
            "description": (
                "Close the Memorist turn with the synthesized historical-"
                "context write-up. Barrier tool — terminates the agent chain."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "result": {
                        "type": "string",
                        "description": (
                            "Technical-channel historical-context write-up "
                            "consumed by the calling agent (English)."
                        ),
                    },
                    "message": {
                        "type": "string",
                        "description": (
                            "Engagement-log closing summary (engagement "
                            "language), 1-2 short sentences."
                        ),
                    },
                },
                "required": ["result", "message"],
            },
        },
    })

    return schemas


# --- ToolExecutor adapter ----------------------------------------------------
class _MemoristToolExecutor:
    """Adapter that exposes memory/store tools + the ``memorist_result`` barrier.

    Implements the :class:`elengenix.agents.base.ToolExecutor` protocol so
    the universal ``perform_agent_chain`` loop can dispatch tool calls. The
    completion tool (``memorist_result``) is a *barrier* — when invoked the
    executor captures the parsed :class:`MemoristResult` into ``captured``
    and returns an ack string; the loop's ``on_barrier`` callback then
    terminates the chain with :data:`PerformResult.DONE`.
    """

    def __init__(
        self,
        tool_handlers: dict[str, Callable[..., Any]],
        captured: dict[str, Any],
        tool_schemas: list[dict[str, Any]] | None = None,
    ) -> None:
        self._handlers = tool_handlers
        self._captured = captured
        self._schemas = tool_schemas if tool_schemas is not None else _default_tool_schemas(
            graphiti_enabled=False
        )

    async def execute(
        self,
        name: str,
        arguments: str,
        context: AgentContext | None = None,
    ) -> str:
        """Route the tool call to the appropriate handler (or capture barrier)."""
        if name == MEMORIST_RESULT_TOOL_NAME:
            args = _parse_args(arguments)
            try:
                parsed = MemoristResult.model_validate(args)
            except ValidationError as exc:
                logger.error("memorist_result payload failed validation: %s", exc)
                raise
            self._captured["result"] = parsed
            return "memorist result successfully processed"

        handler = self._handlers.get(name)
        if handler is None:
            logger.warning("memorist.tool_unknown name=%s", name)
            return (
                f"Error: tool '{name}' is not available in the Memorist chain. "
                f"Available tools: {sorted(self._handlers.keys())} "
                f"plus the '{MEMORIST_RESULT_TOOL_NAME}' completion tool."
            )

        try:
            result = (
                handler(arguments, context) if context is not None else handler(arguments)
            )
            if asyncio.iscoroutine(result):
                result = await result
        except Exception as exc:  # noqa: BLE001
            logger.warning("memorist.tool_failed name=%s err=%s", name, exc)
            return f"Error: tool '{name}' raised: {exc}"

        if not isinstance(result, str):
            try:
                result = json.dumps(result, ensure_ascii=False, default=str)
            except (TypeError, ValueError):
                result = str(result)
        return result or ""

    def is_barrier(self, name: str) -> bool:
        """Return True for the ``memorist_result`` completion tool."""
        return name == MEMORIST_RESULT_TOOL_NAME

    def get_tools(self) -> list[dict[str, Any]]:
        """Return a shallow-copied list of the tool schemas."""
        return [dict(schema) for schema in self._schemas]


# --- Memorist agent class ----------------------------------------------------
class Memorist:
    """Long-term memory retrieval specialist (Archivist; limited agent).

    Mirrors PentAGI's ``flowProvider.GetMemoristHandler`` — runs an LLM
    tool-calling chain with a hard cap of ``MAX_LIMITED_ITERATIONS``
    iterations and the ``memorist_result`` barrier tool as the only exit.
    The vector store (with ``search_in_memory`` / ``store_answer`` /
    ``store_guide`` / ``store_code``) and the Graphiti knowledge graph
    (when enabled) are exposed to the chain via the ``memory`` dependency
    injected at construction time.

    The :func:`anonymize` helper is exported at module level for the tool
    registry (which registers the ``store_answer`` / ``store_guide`` /
    ``store_code`` handlers) to apply as defense-in-depth before persisting
    to the vector store. It is ALSO applied inside this module's default
    ``_build_tool_handlers`` wiring so even an LLM that ignores the prompt
    cannot leak sensitive data into long-term memory.
    """

    AGENT_TYPE = AgentType.MEMORIST
    COMPLETION_TOOL = MEMORIST_RESULT_TOOL_NAME
    LANG_DEFAULT = "en"
    DEFAULT_DOCKER_IMAGE = DEFAULT_DOCKER_IMAGE

    def __init__(
        self,
        llm_client: Any,
        docker_executor: Any = None,
        memory: Any = None,
        governance: Any = None,
        search_providers: Any = None,
        tool_handlers: dict[str, Callable[..., Any]] | None = None,
        max_iterations: int = MAX_LIMITED_ITERATIONS,
    ) -> None:
        self.llm_client = llm_client
        self.docker_executor = docker_executor
        self.memory = memory
        self.governance = governance
        self.search_providers = search_providers
        # Caller-supplied handlers override the auto-wired ones (highest
        # priority — mirrors PrimaryAgent's tool_handlers dict pattern).
        self.tool_handlers: dict[str, Callable[..., Any]] = dict(tool_handlers or {})
        self.max_iterations = max_iterations or MAX_LIMITED_ITERATIONS

        # Engagement-log language — override on the instance if a non-default
        # language was negotiated at flow-creation time (cf. PentAGI
        # ``flowProvider.language`` resolved by the language_chooser template).
        self.lang: str = self.LANG_DEFAULT

        # Docker image is informational only — the Memorist doesn't spawn
        # containers itself.
        self.docker_image: str = self.DEFAULT_DOCKER_IMAGE

        # Graphiti temporal-knowledge-graph toggle (cf. PentAGI
        # ``flowProvider.graphitiClient``).
        self.graphiti_enabled: bool = bool(getattr(memory, "graphiti_enabled", False))

    # ------------------------------------------------------------------ helpers

    def _now(self) -> str:
        """Return current UTC time as an ISO-8601 string for the prompt."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _user_files_listing(self) -> str:
        """Return a newline-separated listing of user-uploaded files (or empty)."""
        listing: Optional[list[str]] = None
        if self.docker_executor is not None:
            listing = getattr(self.docker_executor, "list_user_files", lambda: None)()
        return "\n".join(listing) if listing else ""

    def _build_system_context(
        self, execution_context: str, **extras: Any
    ) -> dict[str, Any]:
        """Build the Jinja2 context dict for the system-prompt template."""
        ctx: dict[str, Any] = {
            "lang": self.lang,
            "current_time": self._now(),
            "execution_context": execution_context or "",
            "cwd": CONTAINER_WORK_DIR,
            "user_files": self._user_files_listing(),
            "tool_placeholder": TOOL_PLACEHOLDER,
            "summarization_tool_name": SUMMARIZATION_TOOL_NAME,
            "summarized_content_prefix": SUMMARIZED_CONTENT_PREFIX,
            "docker_image": self.docker_image,
            "graphiti_enabled": self.graphiti_enabled,
            "graphiti_search_types": ", ".join(GRAPHITI_SEARCH_TYPES),
            # Memorist-specific tool names
            "memorist_result_tool_name": MEMORIST_RESULT_TOOL_NAME,
            "search_in_memory_tool_name": SEARCH_IN_MEMORY_TOOL_NAME,
            "store_answer_tool_name": STORE_ANSWER_TOOL_NAME,
            "store_guide_tool_name": STORE_GUIDE_TOOL_NAME,
            "store_code_tool_name": STORE_CODE_TOOL_NAME,
            "graphiti_search_tool_name": GRAPHITI_SEARCH_TOOL_NAME,
        }
        ctx.update(extras)
        return ctx

    def _render_prompts(
        self,
        question: str,
        execution_context: str,
    ) -> tuple[str, str]:
        """Render (system_prompt, user_prompt) for this run."""
        system_prompt = _render(
            SYSTEM_PROMPT_TEMPLATE,
            **self._build_system_context(execution_context),
        )
        user_prompt = _render(
            USER_PROMPT_TEMPLATE,
            question=question,
        )
        return system_prompt, user_prompt

    def _build_tool_handlers(self) -> dict[str, Callable[..., Any]]:
        """Wire the memory dependency's tools into a handler dict.

        Each handler is an ``async (args_json: str, ctx) -> str`` callable
        that parses the JSON args, applies the anonymization rule for store
        tools, calls the underlying ``self.memory`` method, and returns the
        string result. Caller-supplied ``self.tool_handlers`` override the
        auto-wired ones (so tests / integrations can swap any tool).
        """
        handlers: dict[str, Callable[..., Any]] = {}
        mem = self.memory
        if mem is not None:
            # search_in_memory — accept either ``search_in_memory`` or
            # ``search_answers`` (PentAGI's ChromaDB-backed helper name).
            fn = (
                getattr(mem, "search_in_memory", None)
                or getattr(mem, "search_answers", None)
            )
            if callable(fn):

                async def _search_in_memory(
                    args_json: str, ctx: AgentContext | None = None
                ) -> str:
                    args = _parse_args(args_json)
                    questions = args.get("questions") or []
                    if isinstance(questions, str):
                        questions = [questions]
                    result = fn(questions)
                    if asyncio.iscoroutine(result):
                        result = await result
                    return result if isinstance(result, str) else json.dumps(
                        result, ensure_ascii=False, default=str
                    )

                handlers[SEARCH_IN_MEMORY_TOOL_NAME] = _search_in_memory

            # store_answer — anonymize the answer before persisting.
            fn = getattr(mem, "store_answer", None)
            if callable(fn):

                async def _store_answer(
                    args_json: str, ctx: AgentContext | None = None
                ) -> str:
                    args = _parse_args(args_json)
                    answer = anonymize(args.get("answer", ""))
                    question = args.get("question", "")
                    result = fn(answer=answer, question=question)
                    if asyncio.iscoroutine(result):
                        result = await result
                    return result if isinstance(result, str) else "answer stored"

                handlers[STORE_ANSWER_TOOL_NAME] = _store_answer

            # store_guide — anonymize the guide before persisting.
            fn = getattr(mem, "store_guide", None)
            if callable(fn):

                async def _store_guide(
                    args_json: str, ctx: AgentContext | None = None
                ) -> str:
                    args = _parse_args(args_json)
                    guide = anonymize(args.get("guide", ""))
                    question = args.get("question", "")
                    result = fn(guide=guide, question=question)
                    if asyncio.iscoroutine(result):
                        result = await result
                    return result if isinstance(result, str) else "guide stored"

                handlers[STORE_GUIDE_TOOL_NAME] = _store_guide

            # store_code — anonymize the code before persisting.
            fn = getattr(mem, "store_code", None)
            if callable(fn):

                async def _store_code(
                    args_json: str, ctx: AgentContext | None = None
                ) -> str:
                    args = _parse_args(args_json)
                    code = anonymize(args.get("code", ""))
                    question = args.get("question", "")
                    result = fn(code=code, question=question)
                    if asyncio.iscoroutine(result):
                        result = await result
                    return result if isinstance(result, str) else "code stored"

                handlers[STORE_CODE_TOOL_NAME] = _store_code

            # graphiti_search — only wire when enabled.
            if self.graphiti_enabled:
                fn = (
                    getattr(mem, "graphiti_search", None)
                    or getattr(mem, "search_graphiti", None)
                )
                if callable(fn):

                    async def _graphiti_search(
                        args_json: str, ctx: AgentContext | None = None
                    ) -> str:
                        args = _parse_args(args_json)
                        # Drop the engagement-log `message` field before
                        # forwarding to the underlying search — only the
                        # technical-channel fields belong on the wire.
                        wire_args = {
                            k: v for k, v in args.items() if k != "message"
                        }
                        result = fn(**wire_args)
                        if asyncio.iscoroutine(result):
                            result = await result
                        return result if isinstance(result, str) else json.dumps(
                            result, ensure_ascii=False, default=str
                        )

                    handlers[GRAPHITI_SEARCH_TOOL_NAME] = _graphiti_search

        # Caller-supplied handlers override the auto-wired ones.
        if self.tool_handlers:
            handlers.update(self.tool_handlers)
        return handlers

    # ------------------------------------------------------------------- public

    async def run(self, question: str, execution_context: str = "") -> str:
        """Run the Memorist agent chain and return the historical-context string.

        Seeds the universal ``perform_agent_chain`` loop with
        ``[system, user]`` messages, drives it with the ``MEMORIST`` agent
        type, and terminates when the model emits the ``memorist_result``
        barrier tool. The barrier's parsed ``result`` field (technical
        channel, English) is this method's return value.

        Args:
            question: The calling specialist's question — full context of
                the historical lookup needed. Written to the technical
                channel (English) inside the user prompt's
                ``<user_question>`` element.
            execution_context: Free-form execution-context blob rendered
                into the system prompt's ``<execution_context>`` section.

        Returns:
            The historical-context write-up (technical channel, English)
            captured from the ``memorist_result`` completion tool.

        Raises:
            ValueError: If ``question`` is empty.
            RuntimeError: If the chain terminates without invoking the
                ``memorist_result`` barrier tool (iteration-limit
                exhaustion or unrecoverable LLM/tool error).
            ValidationError: If the completion-tool payload does not
                conform to :class:`MemoristResult`.
        """
        if not question:
            raise ValueError("Memorist.run requires a non-empty question")

        logger.info(
            "Memorist starting run (question_len=%d, ctx_len=%d, lang=%s, graphiti=%s)",
            len(question),
            len(execution_context),
            self.lang,
            self.graphiti_enabled,
        )
        system_prompt, user_prompt = self._render_prompts(question, execution_context)

        # Seed the chain with [system, user] — perform_agent_chain appends
        # assistant + tool messages in place as it loops.
        chain: list[Message] = [
            Message(role="system", content=system_prompt),
            Message(role="user", content=user_prompt),
        ]

        # Wire tool handlers + executor + barrier capture.
        tool_handlers = self._build_tool_handlers()
        captured: dict[str, Any] = {"result": None}
        tool_schemas = _default_tool_schemas(self.graphiti_enabled)
        executor = _MemoristToolExecutor(
            tool_handlers=tool_handlers,
            captured=captured,
            tool_schemas=tool_schemas,
        )

        def _on_barrier(name: str, args_json: str) -> PerformResult:
            """Memorist has exactly one barrier tool — always DONE."""
            return PerformResult.DONE

        result_state = await perform_agent_chain(
            agent_type=self.AGENT_TYPE,
            chain=chain,
            llm_client=self.llm_client,
            executor=executor,
            reflector=None,
            summarizer=None,
            max_iterations=self.max_iterations,
            execution_context=execution_context,
            on_barrier=_on_barrier,
        )

        result: MemoristResult | None = captured["result"]
        if result is None:
            raise RuntimeError(
                f"Memorist agent chain terminated without calling the "
                f"'{MEMORIST_RESULT_TOOL_NAME}' barrier tool "
                f"(final_state={result_state.value})"
            )

        logger.info(
            "Memorist run complete (result_len=%d, state=%s)",
            len(result.result or ""),
            result_state.value,
        )
        return result.result or ""


__all__ = [
    "Memorist",
    "MemoristResult",
    "anonymize",
    "MEMORIST_RESULT_TOOL_NAME",
    "SEARCH_IN_MEMORY_TOOL_NAME",
    "STORE_ANSWER_TOOL_NAME",
    "STORE_GUIDE_TOOL_NAME",
    "STORE_CODE_TOOL_NAME",
    "GRAPHITI_SEARCH_TOOL_NAME",
    "GRAPHITI_SEARCH_TYPES",
    "SYSTEM_PROMPT_TEMPLATE",
    "USER_PROMPT_TEMPLATE",
]
