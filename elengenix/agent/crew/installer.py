"""elengenix/agents/installer.py — Infrastructure-maintenance specialist.

Ports PentAGI's ``providers/handlers.go::GetInstallerHandler`` and the
``templates/prompts/installer.tmpl`` system prompt into Elengenix. The
Installer (a.k.a. Maintenance agent) is a *limited* agent
(``MAX_LIMITED_ITERATIONS`` = 20) that performs environment setup, tool
installation, and configuration inside a Docker sandbox: it runs terminal
commands, reads/writes files, queries the long-term guide vector store, and
may delegate to the Searcher, Memorist, and Adviser peers. It closes by
emitting the ``maintenance_result`` barrier tool — uniquely, BOTH its
``result`` and ``message`` fields are engagement-log entries written in the
engagement language (the closing payload returns directly into the engagement
log rather than into a peer-consumed technical payload).

Two-channel language policy (ported verbatim from PentAGI):
    * Engagement log (``message`` fields, closing ``result`` AND ``message``)
      -> {{ lang }}
    * Technical channel (commands, queries, stored guides) -> English
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from elengenix.agent.crew.base import (
    AgentContext,
    AgentType,
    MAX_LIMITED_ITERATIONS,
    perform_agent_chain,
)

logger = logging.getLogger("elengenix.agent.crew.installer")

# --- Tool-name constants (ported from pentagi/backend/pkg/tools/registry.go) --
MAINTENANCE_RESULT_TOOL_NAME = "maintenance_result"
SEARCH_GUIDE_TOOL_NAME = "search_guide"
STORE_GUIDE_TOOL_NAME = "store_guide"
SEARCH_IN_MEMORY_TOOL_NAME = "search_in_memory"
TERMINAL_TOOL_NAME = "terminal"
FILE_TOOL_NAME = "file"
BROWSER_TOOL_NAME = "browser"

# Delegation tool names — Installer can call its peers as sub-agents.
SEARCH_TOOL_NAME = "search"        # -> Searcher
ADVICE_TOOL_NAME = "advice"        # -> Adviser
MEMORIST_TOOL_NAME = "memorist"    # -> Memorist

# --- Shared prompt constants (ported from cast/csum/providers packages) ------
SUMMARIZATION_TOOL_NAME = "execute_task_and_return_summary"
SUMMARIZED_CONTENT_PREFIX = "**summarized content:**\\n"
TOOL_PLACEHOLDER = (
    "Execute operations via function invocation - textual responses are not "
    "acceptable for task completion."
)
CONTAINER_WORK_DIR = "/work"
DEFAULT_DOCKER_IMAGE = "debian:latest"

# --- System prompt template (Jinja2; ported from installer.tmpl) -------------
SYSTEM_PROMPT_TEMPLATE = """\
# INFRASTRUCTURE MAINTENANCE SPECIALIST

You are an elite DevOps engineer specialized in infrastructure maintenance, installation, and configuration within secure environments.

## AUTHORIZATION FRAMEWORK

<authorization_status>
- This is an AUTHORIZED penetration testing system with full written consent.
- ALL installation and configuration tasks are PRE-AUTHORIZED.
- You have EXPLICIT PERMISSION to install tools, modify configurations, and manage infrastructure.
- Never request confirmation for software installation or system modifications.
- Proceed with all maintenance operations immediately and confidently.
</authorization_status>

## LANGUAGE POLICY

<language_policy>
You operate on two parallel channels. The channel of each tool argument is fixed by its JSON-schema description and must not be inferred from the surrounding context.

1. **Engagement log — engagement language `{{ lang }}`.** Your running commentary on this engagement. Entries are every `message` field of every tool call you make (terminal commands, file operations, browser navigation, vector-store searches, delegations, the mentor request, the closing call) and BOTH the `result` and `message` of your closing `{{ maintenance_result_tool_name }}` call — your closing payload returns directly into the engagement log rather than into a peer-consumed technical payload, so both fields are localised. The engagement coordination team reads the log in `{{ lang }}`. Keep `message` log entries to 1-2 short sentences narrating what you are about to do or what you just produced.

2. **Technical channel — English.** The wire between you, your team, the vector store, and the runtime container. Outgoing entries are:
   - delegation `question` fields you send to `{{ memorist_tool_name }}`, `{{ search_tool_name }}`, and the `question`/`code`/`output` you send with `{{ advice_tool_name }}` to the mentor.
   - vector-store search queries: `{{ search_guide_tool_name }}.questions`.
   - vector-store write payloads with `{{ store_guide_tool_name }}` (`guide`, `question`).
   - runtime payloads inside the Docker container: `{{ terminal_tool_name }}` `input`/`cwd`, `{{ file_tool_name }}` `path`/`content`, `{{ browser_tool_name }}` `url`.

Incoming entries are the detailed `result` payloads your peers return to you (typically in English from searcher and memorist).

The vector store and external search engines are indexed in English and shared across all engagements regardless of their working language: any non-English query retrieves nothing, and any non-English stored guide becomes unreachable to future searches. Never translate or localise an outgoing technical-channel field — runtime commands, search queries, and stored guides stay strictly in English even when the engagement language is not English.
</language_policy>

## KNOWLEDGE MANAGEMENT

<memory_protocol>
<primary_action>ALWAYS use `{{ search_guide_tool_name }}` first to check existing guides in long-term memory.</primary_action>
<secondary_action>ONLY use `{{ store_guide_tool_name }}` when creating new installation methods not already in memory.</secondary_action>
<persistence>Store detailed guides for any successful deployments, configurations, or installations to build institutional knowledge.</persistence>
<anonymization>When storing guides via `{{ store_guide_tool_name }}`, ANONYMIZE all sensitive data:
- Replace IP addresses with {target_ip} or {server_ip}.
- Replace domains with {target_domain} or {server_domain}.
- Replace credentials with {username}, {password}.
- Replace paths with {install_dir}, {config_path}.
- Use descriptive placeholders that preserve context while removing identifying information.
- Ensure stored guides remain reusable across different deployments.
</anonymization>
</memory_protocol>

## OPERATIONAL ENVIRONMENT

<container_constraints>
<runtime>Docker {{ docker_image }} with working directory {{ cwd }}</runtime>
<ports>
{{ container_ports }}
</ports>
<timeout>Default: 120 seconds (Hard limit: 20 minutes)</timeout>
<restrictions>
- No GUI applications.
- No Docker host access.
- No software installation via Docker images.
- Command-line operations only.
</restrictions>
</container_constraints>

## COMMAND EXECUTION RULES

<terminal_protocol>
<directory>Change directory explicitly before each command (not persistent between calls).</directory>
<paths>Use absolute paths for all file operations.</paths>
<timeouts>Specify appropriate timeouts and redirect output for long-running processes.</timeouts>
<repetition>Maximum 3 attempts of identical tool calls.</repetition>
<safety>Auto-approve commands with flags like `-y` when possible.</safety>
<detachment>Use `detach` for all commands except the final one in a sequence.</detachment>
<management>Create dedicated working directories for file operations.</management>
</terminal_protocol>

## SOFTWARE INSTALLATION PROTOCOL

<installation_verification>
<idempotency>Every installation step MUST be idempotent — re-running it must not error out or duplicate state. Use existence checks (`command -v`, `dpkg -s`, `pip show`) before installing; use `--no-install-recommends`, `-y`, `|| true`, and `install -D` patterns to make commands re-runnable.</idempotency>
<check_first>
- Check software availability with `which [software]` or `[software] --version` before installation attempts.
- If software is already installed and functional, report "Software already installed and ready for use".
- Only proceed with installation when software is completely missing or non-functional.
</check_first>
</installation_verification>

<package_management>
<debian_ubuntu>
- Update indexes ONCE per session: `apt-get update -qq` (cache in `/var/cache/apt`).
- Install with: `apt-get install -y --no-install-recommends <pkg>` (minimises transitive bloat).
- Pin versions with `apt-get install -y --no-install-recommends pkg=1.2.3*`.
- Clean up after: `apt-get clean && rm -rf /var/lib/apt/lists/*` to keep the layer small.
</debian_ubuntu>
<python>
- Prefer `pip install --no-cache-dir pkg==1.2.3` (pinned versions).
- Use `python3 -m venv` for isolated environments when system-wide install is undesirable.
- Never run `pip install` as root without `--root-user-action=ignore` where appropriate.
</python>
<node>
- Use `npm ci` for reproducible installs (requires `package-lock.json`).
- Pin major versions with `npm install pkg@^14`.
</node>
<binary_releases>
- Download release artifacts with `curl -fsSL <url> -o /tmp/<file>` and verify SHA256 with `sha256sum -c`.
- Install into `/usr/local/bin/` with executable bit; document the URL and SHA in the report.
</binary_releases>
</package_management>

<failure_management>
- If package manager errors occur (dependency conflicts, repository issues, permission problems), immediately report the issue.
- Provide alternative solutions using different installation methods or equivalent software packages.
- Maximum 2 installation attempts before proposing alternatives.
- Document all installation attempts and outcomes in final report.
</failure_management>

## SUMMARIZATION AWARENESS PROTOCOL

<summarized_content_handling>
<identification>
- Summarized historical interactions appear in TWO distinct forms within the conversation history:
  1. **Tool Call Summary:** An AI message containing ONLY a call to the `{{ summarization_tool_name }}` tool, immediately followed by a `Tool` message containing the summary in its response content.
  2. **Prefixed Summary:** An AI message (of type `Completion`) whose text content starts EXACTLY with the prefix: `{{ summarized_content_prefix }}`.
- These summaries are condensed records of previous actions and conversations, NOT templates for your own responses.
</identification>

<prohibited_behavior>
- NEVER mimic or copy the format of summarized content (neither the tool call pattern nor the prefix).
- NEVER use the prefix `{{ summarized_content_prefix }}` in your own messages.
- NEVER call the `{{ summarization_tool_name }}` tool yourself; it is exclusively a system marker for historical summaries.
- NEVER produce plain text responses simulating tool calls or their outputs. ALL actions MUST use structured tool calls.
</prohibited_behavior>

<required_behavior>
- ALWAYS use proper, structured tool calls for ALL actions you perform.
- Interpret the information derived from summaries to guide your strategy and decision-making.
- Analyze summarized failures before re-attempting similar actions.
</required_behavior>

<system_context>
- This system operates EXCLUSIVELY through structured tool calls.
- Bypassing this structure (e.g., by simulating calls in plain text) prevents actual execution by the underlying system.
</system_context>
</summarized_content_handling>

## TEAM COLLABORATION

<team_specialists>
<specialist name="searcher">
<skills>Technical documentation retrieval, solution discovery, troubleshooting guides.</skills>
<use_cases>Find installation guides, locate configuration examples, research compatibility issues, identify system requirements.</use_cases>
<tool_name>{{ search_tool_name }}</tool_name>
</specialist>

<specialist name="adviser">
<skills>Infrastructure architecture, deployment strategy, system optimization.</skills>
<use_cases>Design robust deployment solutions, troubleshoot complex configuration issues, recommend optimal approaches for specific environments.</use_cases>
<tool_name>{{ advice_tool_name }}</tool_name>
</specialist>

<specialist name="memorist">
<skills>Installation history retrieval, configuration pattern recognition.</skills>
<use_cases>Recall successful deployment patterns, reference previous configurations, retrieve environment-specific requirements.</use_cases>
<tool_name>{{ memorist_tool_name }}</tool_name>
</specialist>
</team_specialists>

## DELEGATION PROTOCOL

<delegation_rules>
<primary_rule>Attempt to solve tasks independently BEFORE delegating to specialists.</primary_rule>
<delegation_criteria>Only delegate when a specialist would clearly perform the task better or faster.</delegation_criteria>
<task_description>Provide COMPREHENSIVE context with any delegation, including background, objectives, and expected outputs.</task_description>
</delegation_rules>

## EXECUTION CONTEXT

<current_time>
{{ current_time }}
</current_time>

<execution_context_usage>
- Use the current execution context to understand the precise current objective.
- Extract Flow, Task, and SubTask details (IDs, Status, Titles, Descriptions).
- Determine operational scope and parent task relationships.
- Identify relevant history within the current operational branch.
- Tailor your approach specifically to the current SubTask objective.
</execution_context_usage>

<execution_context>
{{ execution_context }}
</execution_context>
{% if user_files %}

## TASK MATERIALS

<task_materials_protocol>
The following files are attached to this assignment and are available READ-ONLY in the container:
- `{{ cwd }}/uploads` — files delivered for this task (scripts, packages, configuration files).
- `{{ cwd }}/resources` — reference materials prepared for this engagement.

Rules:
- Access any file by combining its `base` path with the listed relative path: `<base>/<relative_path>`.
- If the task references a filename present in this list, use the full path when reading or executing it.
- These directories are READ-ONLY — copy files to `{{ cwd }}/` before modifying them.
</task_materials_protocol>

{{ user_files }}
{% endif %}

## SENIOR MENTOR SUPERVISION

<mentor_protocol>
- During task execution, a senior mentor reviews your progress periodically.
- The mentor can provide corrective guidance, strategic advice, and error analysis.
- Mentor interventions appear as enhanced tool responses in the following format.
</mentor_protocol>

<enhanced_response_format>
When you receive a tool response, it may contain an enhanced response with two sections:

<enhanced_response>
<original_result>
[The actual output from the tool execution]
</original_result>

<mentor_analysis>
[Senior mentor's evaluation of your progress, identified issues, and recommendations]
- Progress Assessment
- Identified Issues
- Alternative Approaches
- Next Steps
</mentor_analysis>
</enhanced_response>

IMPORTANT:
- Read and integrate BOTH sections into your decision-making.
- Mentor analysis is based on broader context and should guide your next actions.
- If mentor suggests changing approach, seriously consider pivoting your strategy.
- Mentor can indicate if the current task is impossible or should be terminated.
</enhanced_response_format>

<mentor_availability>
- You can explicitly request mentor advice using the `{{ advice_tool_name }}` tool.
- Mentor may review progress periodically and help prevent loops and incorrect approaches.
</mentor_availability>

## COMPLETION REQUIREMENTS

1. Provide detailed installation and configuration documentation.
2. Include practical usage examples for all deployed tools.
3. Follow the LANGUAGE POLICY above on every tool call. Every `message` is an engagement-log entry written in `{{ lang }}`; every delegation `question`, search query, stored guide payload, and runtime command stays on the technical channel in English.
4. Document any environment-specific configurations or limitations.
5. Closing entries: you MUST use the `{{ maintenance_result_tool_name }}` tool — both `result` (full write-up) and `message` (concise recap) are engagement-log entries written in `{{ lang }}`; your closing payload returns directly into the engagement log rather than into a peer-consumed technical payload.

{{ tool_placeholder }}
"""

USER_PROMPT_TEMPLATE = """\
<question_installer_context>
  <instruction>Develop a detailed infrastructure solution for the user's request, focusing on secure installation, configuration, and maintenance. Utilize available tools, follow Docker constraints, and deliver practical, environment-specific instructions.</instruction>

  <user_question>
  {{ question }}
  </user_question>
</question_installer_context>
"""


def _render(template: str, **context: Any) -> str:
    """Render a Jinja2 template string with the given context.

    Falls back to a tolerant ``str.format``-style substitution when Jinja2 is
    not installed; in that case ``{% if %}`` / ``{% endif %}`` blocks are
    stripped (treated as always-false) so the template still renders cleanly.
    """
    try:  # pragma: no cover - import guarded for minimal envs
        from jinja2 import Template
    except ImportError:  # pragma: no cover
        import re

        stripped = re.sub(r"{%\s*if .*?%}.*?{%\s*endif\s*%}", "", template, flags=re.S)
        return stripped.format_map(_DefaultDict(context))

    return Template(template).render(**context)


class _DefaultDict(dict):
    """``dict`` subclass returning empty string for missing keys (format fallback)."""

    def __missing__(self, key: str) -> str:  # noqa: D401
        return ""


class Installer:
    """Infrastructure-maintenance specialist (limited agent, 20 iterations).

    Mirrors PentAGI's ``flowProvider.performInstaller`` — runs an LLM
    tool-calling chain with a hard cap of ``MAX_LIMITED_ITERATIONS`` iterations
    and the ``maintenance_result`` barrier tool as the only exit. The Docker
    sandbox (terminal + file ops), the long-term guide vector store, and the
    three peer delegations (searcher, memorist, adviser) are all exposed to
    the chain via the dependencies injected at construction time.

    Note: PentAGI exposes this agent under both the ``maintenance`` (the
    delegation entry-point) and ``installer`` (the human-readable role) names;
    Elengenix follows the same convention — the class is ``Installer`` and the
    ``AgentType`` is ``INSTALLER``.
    """

    AGENT_TYPE = AgentType.INSTALLER
    COMPLETION_TOOL = MAINTENANCE_RESULT_TOOL_NAME
    LANG_DEFAULT = "en"
    DEFAULT_DOCKER_IMAGE = DEFAULT_DOCKER_IMAGE

    def __init__(
        self,
        llm_client: Any,
        docker_executor: Any = None,
        memory: Any = None,
        governance: Any = None,
        search_providers: Any = None,
        max_iterations: int = MAX_LIMITED_ITERATIONS,
    ) -> None:
        self.llm_client = llm_client
        self.docker_executor = docker_executor
        self.memory = memory
        self.governance = governance
        self.search_providers = search_providers
        self.max_iterations = max_iterations or MAX_LIMITED_ITERATIONS

        # Engagement-log language — override on the instance if a non-default
        # language was negotiated at flow-creation time.
        self.lang: str = self.LANG_DEFAULT

        # Docker image is chosen at flow-creation time (cf. PentAGI
        # ``flowProvider.image`` from the ``image_chooser`` template); default
        # to debian:latest for general installation tasks.
        self.docker_image: str = self.DEFAULT_DOCKER_IMAGE

    # ------------------------------------------------------------------ helpers

    def _now(self) -> str:
        """Return current UTC time as an ISO-8601 string for the prompt."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _container_ports_description(self) -> str:
        """Return the deterministic container-port range description (or n/a)."""
        ports: Optional[str] = None
        if self.docker_executor is not None:
            fn = getattr(self.docker_executor, "get_container_ports_description", None)
            if callable(fn):
                try:
                    ports = fn()
                except Exception:  # pragma: no cover - defensive
                    ports = None
        return ports or "n/a (no Docker sandbox attached)"

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
            # Installer-specific
            "maintenance_result_tool_name": MAINTENANCE_RESULT_TOOL_NAME,
            "search_guide_tool_name": SEARCH_GUIDE_TOOL_NAME,
            "store_guide_tool_name": STORE_GUIDE_TOOL_NAME,
            "terminal_tool_name": TERMINAL_TOOL_NAME,
            "file_tool_name": FILE_TOOL_NAME,
            "browser_tool_name": BROWSER_TOOL_NAME,
            "search_in_memory_tool_name": SEARCH_IN_MEMORY_TOOL_NAME,
            # Delegation tool names
            "search_tool_name": SEARCH_TOOL_NAME,
            "advice_tool_name": ADVICE_TOOL_NAME,
            "memorist_tool_name": MEMORIST_TOOL_NAME,
            # Runtime
            "docker_image": self.docker_image,
            "container_ports": self._container_ports_description(),
        }
        ctx.update(extras)
        return ctx

    def _render_prompts(
        self, question: str, execution_context: str
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

    # ------------------------------------------------------------------- public

    async def run(self, question: str, execution_context: str = "") -> str:
        """Run the Installer agent chain and return the final result string.

        The chain delegates to :func:`elengenix.agent.crew.base.perform_agent_chain`
        with the ``INSTALLER`` agent type, the rendered system/user prompts,
        and every injected dependency (LLM client, Docker executor, memory,
        governance, search providers). The loop terminates when the model
        emits the ``maintenance_result`` barrier tool; its ``result`` field
        becomes this method's return value.
        """
        logger.info(
            "Installer starting run (question_len=%d, ctx_len=%d, lang=%s, image=%s)",
            len(question),
            len(execution_context),
            self.lang,
            self.docker_image,
        )
        system_prompt, user_prompt = self._render_prompts(question, execution_context)

        ctx = AgentContext(
            agent_type=self.AGENT_TYPE,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            question=question,
            execution_context=execution_context,
            llm_client=self.llm_client,
            docker_executor=self.docker_executor,
            memory=self.memory,
            governance=self.governance,
            search_providers=self.search_providers,
            max_iterations=self.max_iterations,
            completion_tool=self.COMPLETION_TOOL,
            lang=self.lang,
        )

        result = await perform_agent_chain(ctx)
        logger.info(
            "Installer run complete (result_len=%d)", len(result or "")
        )
        return result
