"""agents/agent_universal.py — Universal Agent Mode extracted from agent_brain.py.

Processes user queries with AI-driven intent classification, multi-turn conversation,
file editing, web research, and bug bounty specialization.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional

from elengenix.scanning.helpers import _get_memory_profile_context, _get_now_context, extract_json
from elengenix.scanning.intent import analyze_intent
from tools.agent_reflection import AgentReflection
from tools.cvss_calculator import CVSSCalculator
from tools.governance import Governance
from tools.tool_registry import registry
from tools.universal_ai_client import AIMessage
from tools.universal_executor import get_universal_executor
from tools.vector_memory import get_context_for_ai, remember

logger = logging.getLogger("elengenix.agent")


def _format_preflight_context(findings: List[Dict[str, Any]]) -> str:
    """Format Elengenix Framework preflight findings as AI context.

    Groups findings by type, shows severity, and gives the AI clear hints
    about what was already discovered so it can focus on confirmation
    rather than re-doing recon.
    """
    if not findings:
        return ""

    # Group by type
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        ftype = f.get("type", "unknown")
        by_type.setdefault(ftype, []).append(f)

    # Severity breakdown
    sev_count: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "Informational")
        sev_count[sev] = sev_count.get(sev, 0) + 1

    lines: List[str] = [
        "### ELENGENIX FRAMEWORK PREFLIGHT FINDINGS (already discovered)",
        "The framework's pure-Python modules + PythonRecon have already gathered this data.",
        f"Total: {len(findings)} findings across {len(by_type)} categories.",
        "",
        "Severity breakdown: "
        + ", ".join(f"{k}={v}" for k, v in sorted(sev_count.items(), key=lambda x: -x[1])),
        "",
    ]

    # Highlight critical findings
    crit = [f for f in findings if f.get("severity") in ("Critical", "High")]
    if crit:
        lines.append("**HIGH-PRIORITY TARGETS:**")
        for f in crit[:10]:
            lines.append(f"  - [{f.get('severity')}] {f.get('type')}: {f.get('title', '?')[:80]}")
            if f.get("url"):
                lines.append(f"    URL: {f.get('url')}")
        lines.append("")

    # Show top by category
    for ftype, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
        lines.append(f"**{ftype}** ({len(items)}):")
        for it in items[:5]:  # max 5 per type
            url = it.get("url", "")
            title = it.get("title", "?")[:60]
            lines.append(f"  - {title}" + (f" → {url}" if url else ""))
        if len(items) > 5:
            lines.append(f"  ... +{len(items) - 5} more")
        lines.append("")

    lines.extend(
        [
            "**HOW TO USE THIS:**",
            "- DO NOT re-discover these endpoints/params/ports — they're already in your context",
            "- FOCUS on vulnerability confirmation: probe interesting params, test access controls, validate findings",
            "- If a finding is already at a URL, run targeted checks (XSS, SQLi, auth) on THAT URL",
            "- Use `read_file` to load `reports/preflight_<target>/elengenix_findings.json` for the full list",
        ]
    )

    return "\n".join(lines)


def _run_brain_mode(
    user_input: str,
    client: Any,
    target: str,
    governance: Governance,
    executor: Any,
    callback: Optional[Callable] = None,
    max_steps: int = 50,
) -> Optional[str]:
    """Run the cognitive brain mode: perceive → reason → decide → execute → reflect.

    Uses TrueAIBrain for autonomous security testing with:
    - PlanningEngine generates an attack plan
    - DecisionEngine scores and picks actions
    - ReasoningEngine analyzes results
    - PerceptionModule tracks situation awareness
    - Persistent Memory: recalls past findings, remembers new ones
    - Self-Correction: auto-replans when stuck

    Returns:
        Summary string or None if brain mode is unavailable.
    """
    try:
        from elengenix.brain import TrueAIBrain
        from elengenix.memory import CognitiveMemoryManager
        from elengenix.constitution_engine import ConstitutionalAIEngine
        from elengenix.types import MissionContext
    except ImportError as e:
        logger.warning(f"Brain components not available: {e}")
        return None

    if not client:
        return None

    logger.info("Brain mode: initializing cognitive architecture...")

    # Create brain components
    try:
        memory = CognitiveMemoryManager(backends=[])

        brain = TrueAIBrain(
            llm_client=client,
            memory=memory,
            tools=None,
            governance=governance,
            constitutional_engine=ConstitutionalAIEngine(),
        )

        context = MissionContext(
            target=target or "unknown",
            objectives=[user_input],
            scope=["full"],
            constraints={},
            metadata={},
        )

        # ── Step 0: Recall past memories (persistent memory) ──────────
        memory_context = ""
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    memory_entries = pool.submit(
                        asyncio.run,
                        memory.recall(f"target={target}", limit=10)
                    ).result(timeout=10)
            else:
                memory_entries = loop.run_until_complete(
                    memory.recall(f"target={target}", limit=10)
                )
            if memory_entries:
                memory_lines = [f"- {m.content[:150]}" for m in memory_entries[:5]]
                memory_context = "\n".join(memory_lines)
                if callback:
                    callback(f"[Brain] Recalled {len(memory_entries)} past memories")
        except Exception as e:
            logger.debug(f"Memory recall failed (non-fatal): {e}")

        if callback:
            callback("[Brain] Planning attack strategy...")

        # ── Step 1: Plan the attack (with memory context) ─────────────
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    plan = pool.submit(
                        asyncio.run,
                        brain.planner.plan(user_input, context)
                    ).result(timeout=30)
            else:
                plan = loop.run_until_complete(brain.planner.plan(user_input, context))
        except Exception as e:
            logger.warning(f"Brain planning failed: {e}")
            return None

        if callback:
            phases = len(plan.phases) if plan.phases else 0
            callback(f"[Brain] Attack plan: {phases} phases, {len(plan.success_criteria)} success criteria")

        # ── Step 2: Execute plan phases (with self-correction) ───────
        exec_engine = get_universal_executor()
        all_findings = []
        consecutive_no_findings = 0
        max_no_findings = 3  # replan after 3 consecutive empty results
        tried_tools = set()  # track what we've tried for dedup

        for phase_idx, phase in enumerate(plan.phases if plan.phases else []):
            if callback:
                callback(f"[Brain] Phase {phase_idx + 1}: {phase.name}")

            for action_data in phase.actions:
                tool_name = action_data.get("tool", "")
                if not tool_name:
                    continue

                # Self-correction: skip tools we've already tried
                if tool_name in tried_tools:
                    logger.debug(f"Skipping already-tried tool: {tool_name}")
                    continue
                tried_tools.add(tool_name)

                try:
                    exec_result = exec_engine.execute_action({
                        "type": "run_tool",
                        "params": {"tool": tool_name, "target": target},
                    })
                    result_text = exec_result.output if exec_result.success else exec_result.error

                    if callback:
                        callback(f"[Brain] [{tool_name}] → {result_text[:100]}...")

                    # Score findings
                    try:
                        from tools.cvss_calculator import CVSSCalculator
                        calc = CVSSCalculator(use_ai=False)
                        score = calc.from_finding(tool_name, result_text[:200], result_text[:500], "")
                        all_findings.append({
                            "type": tool_name,
                            "severity": score.severity.value,
                            "cvss": score.base_score,
                            "source": "brain_reasoning",
                            "phase": phase.name,
                        })
                        consecutive_no_findings = 0  # reset on finding
                    except Exception:
                        consecutive_no_findings += 1

                    # ── Self-correction: replan when stuck ───────────
                    if consecutive_no_findings >= max_no_findings:
                        if callback:
                            callback(f"[Brain] Self-correction: no findings after {consecutive_no_findings} tools, replanning...")
                        try:
                            failure = {
                                "reason": f"No findings after {consecutive_no_findings} consecutive tool executions",
                                "tried_tools": list(tried_tools),
                            }
                            import asyncio as _ai
                            _loop = _ai.get_event_loop()
                            if _loop.is_running():
                                import concurrent.futures
                                with concurrent.futures.ThreadPoolExecutor() as _pool:
                                    new_plan = _pool.submit(
                                        _ai.run,
                                        brain.planner.replan(failure, context)
                                    ).result(timeout=30)
                            else:
                                new_plan = _loop.run_until_complete(brain.planner.replan(failure, context))
                            if new_plan and new_plan.phases:
                                plan.phases.extend(new_plan.phases)
                                if callback:
                                    callback(f"[Brain] Replan: added {len(new_plan.phases)} new phases")
                            consecutive_no_findings = 0  # reset after replan
                        except Exception as e:
                            logger.debug(f"Replan failed: {e}")

                except Exception as e:
                    logger.debug(f"Brain tool execution failed for {tool_name}: {e}")
                    consecutive_no_findings += 1

        # ── Step 3: Remember findings (persistent memory) ─────────────
        try:
            if all_findings:
                import asyncio
                finding_summary = f"Target: {target}. Found {len(all_findings)} vulnerabilities: {', '.join(f['type'] for f in all_findings[:5])}"
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        pool.submit(
                            asyncio.run,
                            memory.remember(finding_summary, target=target, category="semantic", importance=0.8)
                        ).result(timeout=10)
                else:
                    loop.run_until_complete(
                        memory.remember(finding_summary, target=target, category="semantic", importance=0.8)
                    )
                if callback:
                    callback(f"[Brain] Remembered {len(all_findings)} findings for future reference")
        except Exception as e:
            logger.debug(f"Memory save failed (non-fatal): {e}")

        # ── Step 4: Generate summary ──────────────────────────────────
        lines = ["## Brain Mode — Cognitive Security Assessment", ""]
        if target:
            lines.append(f"**Target**: {target}")
        lines.append(f"**Objective**: {user_input}")
        lines.append(f"**Plan Phases**: {len(plan.phases)}")
        lines.append(f"**Success Criteria**: {', '.join(plan.success_criteria)}")

        if memory_context:
            lines.append(f"**Past Memories**: {len(memory_context.splitlines())} entries recalled")
        lines.append("")

        if all_findings:
            sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            all_findings.sort(key=lambda s: sev_order.get(s["severity"], 5))
            lines.append("| Severity | Type | CVSS |")
            lines.append("|----------|------|------|")
            for f in all_findings:
                lines.append(f"| {f['severity']} | {f['type']} | {f['cvss']:.1f} |")
        else:
            lines.append("No confirmed vulnerabilities found in this assessment.")

        if memory_context:
            lines.append("")
            lines.append("### Past Mission Context")
            lines.append(memory_context)

        if callback:
            callback(f"[Brain] Assessment complete: {len(all_findings)} findings")

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Brain mode failed: {e}", exc_info=True)
        if callback:
            callback(f"[Brain] Error: {e}")
        return None


def _create_mission_context(target: str, objective: str):
    """Create a MissionContext for the brain components.
    
    Always returns a valid MissionContext — never None.
    """
    from elengenix.types import MissionContext
    return MissionContext(
        target=target or "unknown",
        objectives=[objective],
        scope=["full"],
        constraints={},
        metadata={},
    )


def process_universal(
    user_input: str,
    client: Any,
    conversation_history: List[Dict[str, str]],
    base_prompt: str,
    governance: Governance,
    reflection_tracker: Optional[AgentReflection] = None,
    skill_registry: Any = None,
    target: str = "",
    mode: str = "auto",
    callback: Optional[Callable] = None,
    check_context_overflow: Optional[Callable] = None,
    preflight_findings: Optional[List[Dict]] = None,
    use_brain: bool = False,
) -> str:
    """Universal Agent Mode—Flexible AI-driven security assistant.

    Core helpers expected (can be lambdas that close over your agent):
      check_context_overflow() → None       (call self._check_context_overflow)
    """
    logger.info(f"Universal mode started: {user_input}")

    # ── Intent classification ───────────────────────────────────────────
    intent = "security_chat"
    try:
        intent = analyze_intent(client, user_input)
    except Exception as e:
        logger.debug(f"Universal intent classification failed: {e}")
        intent = "security_chat"
    if callback:
        callback(f"AI classified intent as: {intent.upper()}")

    # ── Self-reflection ─────────────────────────────────────────────────
    try:
        if reflection_tracker and hasattr(reflection_tracker, "retrieve_caution"):
            reflection_caution = reflection_tracker.retrieve_caution(user_input)
        else:
            reflection_caution = ""
    except Exception:
        reflection_caution = ""

    # Initialize universal executor
    executor = get_universal_executor()

    is_security_task = (
        mode == "bug_bounty"
        or intent == "scan"
        or (bool(target) and intent in ("scan", "security_chat"))
    )

    # ── Casual / chat without target ─────────────────────────────────────
    if intent in ["casual", "security_chat"] and not target:
        past_memories = get_context_for_ai(
            user_input,
            target=target or "universal",
            max_memories=12,
            conversation_history=conversation_history,
        )
        logger.info(f"Retrieved {len(past_memories.splitlines())} memories from the cloud.")

        now_context = _get_now_context()
        profile_context = _get_memory_profile_context()

        available_tools = registry.list_available_tools()
        tool_names = [name for name, info in available_tools.items() if info.get("available")]
        tool_list = ", ".join(tool_names[:10]) + ("..." if len(tool_names) > 10 else "")

        has_thai = bool(re.search(r"[฀-๿]", user_input))
        detected_lang = "Thai" if has_thai else "English"

        chat_prompt = f"""You are Elengenix AI — A Universal AI Agent specialized for Bug Bounty and Security Research.
Intent category: {intent}
Detected user language: {detected_lang}

{now_context}

### [PROFILE] LONG-TERM PROFILE:
{profile_context}

### [MEMORY] PAST CONVERSATIONS (RELEVANT CONTEXT):
{past_memories}

{reflection_caution}

### YOUR IDENTITY & CAPABILITIES:
- Name: Elengenix AI (Elengenix AI)
- Version:
- Primary role: Security researcher and penetration testing assistant

### WHAT YOU CAN DO:

[LIVE INTERNET ACCESS - Real-time data:]
- Search Google for current news, sports scores, weather, stock prices
- Get TODAY's information - no knowledge cutoff!
- Research CVEs, exploits, and security advisories

[SECURITY TOOLS:]
{tool_list}
Plus: Built-in Python scanners for SSRF, SSTI, XXE, Deserialization,
GraphQL, CORS, JWT, Race Conditions, Business Logic, Supply Chain

[GENERAL CAPABILITIES:]
- File editing, shell commands, package installation
- Code review and script generation
- Web research and OSINT

### LANGUAGE RULE:
- Detect the language of the user's input
- If user wrote Thai → respond in Thai
- If user wrote English → respond in English
- Respond naturally in the detected language

### OTHER RULES:
1. Do not use emojis.
2. Do not attempt to run scans or use tools for this casual query.
3. Answer directly based on your knowledge above.
4. If asked what you can do, explain your capabilities including LIVE WEB SEARCH."""

        messages = _build_chat_messages(conversation_history, chat_prompt, user_input)
        direct = (client.chat(messages).content or "").strip()

        if direct:
            _append_history(conversation_history, "user", user_input)
            _append_history(conversation_history, "assistant", direct)
            remember(
                content=f"User interaction: {user_input} | AI Response: {direct[:150]}...",
                target=target or "universal",
                category="conversation",
            )
            return direct
        if has_thai:
            return "สวัสดีครับ! ผมคือ Elengenix AI ผู้ช่วยวิจัยความปลอดภัย มีอะไรให้ช่วยไหมครับ?"
        return (
            "Hello! I'm Elengenix AI, your security research assistant. How can I help you today?"
        )

    # ── Research mode (no target) ────────────────────────────────────────
    if intent == "research" and not target:
        pass  # falls through to main loop

    # ── Simple greeting fast-path (deterministic, no AI call) ────────────
    simple_greetings = [
        "hi",
        "hello",
        "hey",
        "hiya",
        "yo",
        "สวัสดี",
        "สวัสดีครับ",
        "สวัสดีค่ะ",
        "หวัดดี",
        "หวัดดีครับ",
        "หวัดดีค่ะ",
        "สัวสดี",
        "สวัส",
        "สวัดดี",
        "สวัสดีจ้า",
        "ไง",
        "ไงครับ",
        "ไงค่ะ",
        "ไงจ้า",
        "ว่าไง",
        "sawasdee",
        "sawasdee krub",
        "sawasdee krap",
    ]
    simple_questions = ["how are you", "what can you do", "help", "?", "who are you"]
    normalized = user_input.lower().strip()

    starts_with_thai_greeting = any(
        normalized.replace(" ", "").startswith(g.replace(" ", ""))
        for g in simple_greetings
        if re.search(r"[฀-๿]", g)
    )
    thai_only = bool(re.fullmatch(r"[\s฀-๿\.!?]+", user_input.strip()))
    is_thai_greeting = starts_with_thai_greeting or (
        thai_only and any(g in user_input.strip() for g in ["สวั", "หวัด", "ดี"])
    )
    is_short_thai_chat = thai_only and 0 < len(user_input.strip()) <= 8
    is_simple_query = (
        (
            any(normalized.startswith(g) for g in simple_greetings)
            or any(q in normalized for q in simple_questions)
            or is_thai_greeting
            or is_short_thai_chat
        )
        and not is_security_task
        and not target
        and intent not in ("research", "scan")
    )

    if is_simple_query:
        wants_thai = bool(re.search(r"[฀-๿]", user_input))
        if wants_thai:
            return "Hello! How can I help you?"
        lang_rule = "Respond in Thai ONLY." if wants_thai else "Respond in English ONLY."
        simple_prompt = f"""You are Elengenix AI 1.0.0.
User input: "{user_input}"
Contains Thai characters: {wants_thai}

### LANGUAGE RULE (STRICT):
{lang_rule}
- If Thai detected in input → respond in Thai language
- If English detected → respond in English language
- ABSOLUTELY NO other languages (no Turkish, Spanish, French, etc.)
- This is a HARD requirement

### RESPONSE:
Keep it short and conversational. No tools. No emojis."""

        response = (
            client.chat(
                [
                    AIMessage(role="system", content=simple_prompt),
                    AIMessage(role="user", content="Greeting"),
                ]
            ).content
            or ""
        )
        if not response.strip():
            return (
                "Hello! How can I help you?" if wants_thai else "Hello! How can I help you today?"
            )
        return response.strip()

    # ── Build mode-specific prompt ──────────────────────────────────────
    now_context = _get_now_context()
    if intent == "research" and not target:
        base_prompt_text = _build_research_prompt(user_input, now_context)
    elif mode == "bug_bounty" or target:
        base_prompt_text = _build_bug_bounty_prompt(
            user_input, now_context, target, client, governance, skill_registry
        )
    else:
        base_prompt_text = _build_general_prompt(user_input, now_context)

    # ── Inject Elengenix preflight findings as context ──────────────────
    # This is the framework's own recon data — the AI should use it as
    # a starting point instead of re-discovering everything.
    if preflight_findings:
        preflight_context = _format_preflight_context(preflight_findings)
        base_prompt_text = base_prompt_text + "\n\n" + preflight_context

    # ── Brain Mode: TrueAIBrain integration ────────────────────────────
    # When use_brain=True and it's a security task, use the cognitive brain
    # architecture (perceive → reason → decide → execute → reflect).
    if use_brain and is_security_task:
        brain_result = _run_brain_mode(
            user_input=user_input,
            client=client,
            target=target,
            governance=governance,
            executor=executor,
            callback=callback,
        )
        if brain_result:
            return brain_result
        # Fall through to legacy loop if brain mode fails

    # ── Main execution loop ────────────────────────────────────────────
    max_steps = 5 if intent == "research" else 50
    history: List[Dict] = [{"role": "user", "content": user_input}]
    all_findings: List[Dict] = []
    consecutive_ai_failures = 0  # P2.4: track consecutive AI failures for early exit
    ai_unavailable_marker = "[ELENGENIX_AI_UNAVAILABLE]"  # marker for main.py to detect
    step = -1  # initialize for summary reference

    # ── Brain-enhanced loop (when use_brain=True) ─────────────────────
    # Uses PlanningEngine → DecisionEngine → ReasoningEngine for real
    # cognitive processing instead of simple JSON parse.
    _brain_loop = False
    _brain_planner = None
    _brain_decision = None
    _brain_plan = None

    if use_brain and is_security_task and client:
        try:
            from elengenix.brain import PlanningEngine, DecisionEngine, ReasoningEngine
            from elengenix.memory import CognitiveMemoryManager
            from elengenix.constitution_engine import ConstitutionalAIEngine

            _memory = CognitiveMemoryManager(backends=[])
            _reasoning = ReasoningEngine(client, _memory)
            _brain_decision = DecisionEngine(client, _reasoning, ConstitutionalAIEngine(), governance)
            _brain_planner = PlanningEngine(client, _reasoning, _memory)
            _brain_loop = True

            if callback:
                callback("[Brain Loop] Initializing planning engine...")

            # Generate initial plan
            try:
                import asyncio as _ai
                loop = _ai.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        _plan = pool.submit(
                            _ai.run,
                            _brain_planner.plan(user_input, _create_mission_context(target, user_input))
                        ).result(timeout=30)
                else:
                    _plan = loop.run_until_complete(
                        _brain_planner.plan(user_input, _create_mission_context(target, user_input))
                    )
                _brain_plan = _plan
                if callback and _brain_plan:
                    callback(f"[Brain Loop] Plan: {len(_brain_plan.phases)} phases")
            except Exception as e:
                logger.debug(f"Brain planning failed, falling back to legacy: {e}")
                _brain_loop = False

        except Exception as e:
            logger.debug(f"Brain components not available: {e}")
            _brain_loop = False

    for step in range(max_steps):
        # Build conversation context
        recent = history[-10:]
        history_text = "\n".join([f"{m['role'].capitalize()}: {m['content']}" for m in recent])

        step_prompt = f"""{base_prompt_text}

### CONVERSATION HISTORY:
{history_text}

### USER REQUEST:
{user_input}

### CURRENT STEP: {step + 1}/{max_steps}

Respond with JSON:
{{"thought": "...",
"action": {{"type": "shell|run_tool|read_file|write_file|edit_file|search_file|search_web|finish",
"params": {{...}}}},
"next_step": "..."}}"""

        # Get AI decision
        try:
            from tools.universal_ai_client import ACTION_TOOLS

            _resp = client.chat(
                [
                    AIMessage(role="system", content=step_prompt),
                    AIMessage(role="user", content="What is the next action?"),
                ],
                temperature=0.2,
                tools=ACTION_TOOLS,
            )
            # Prefer native tool-calling; fall back to text-JSON extraction
            if _resp.tool_calls:
                _tc = _resp.tool_calls[0]
                response_text = json.dumps(
                    {
                        "thought": _tc.arguments.pop("thought", "execute action"),
                        "action": {"type": _tc.name, "params": _tc.arguments},
                    }
                )
            else:
                response_text = _resp.content or ""
            consecutive_ai_failures = 0  # reset on success
        except Exception as e:
            consecutive_ai_failures += 1
            logger.error(f"AI decision failed (consecutive={consecutive_ai_failures}): {e}")
            if consecutive_ai_failures >= 2:
                # Two failures in a row = AI is definitely unavailable. Bail early
                # with a clear marker that main.py can detect.
                logger.warning("All AI providers failed twice in a row. Exiting early.")
                if callback:
                    callback(ai_unavailable_marker)
                return (
                    f"{ai_unavailable_marker} All AI providers failed after "
                    f"{consecutive_ai_failures} consecutive errors. "
                    f"Check API keys in .env or visit "
                    f"https://aistudio.google.com/apikey to fix Gemini quota."
                )
            # Single failure: break and fall through, but if 0 actions taken, signal AI unavailable
            break

        # ── Brain-enhanced decision path ──────────────────────────────
        thought = ""
        action_data: Dict[str, Any] = {"type": "finish"}

        if _brain_loop and _brain_decision:
            # Use DecisionEngine to score and pick action
            try:
                import asyncio as _ai
                situation = {
                    "step": step,
                    "max_steps": max_steps,
                    "history": history[-5:],
                    "findings": all_findings,
                    "plan_phases": [p.name for p in (_brain_plan.phases if _brain_plan else [])],
                }
                available_actions = _brain_plan.phases[step].actions if (_brain_plan and step < len(_brain_plan.phases)) else [{"tool": "finish", "risk_level": "safe"}]

                ctx = _create_mission_context(target, user_input)
                loop = _ai.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        ai_action = pool.submit(
                            _ai.run,
                            _brain_decision.decide(situation, available_actions, ctx)
                        ).result(timeout=30)
                else:
                    ai_action = loop.run_until_complete(
                        _brain_decision.decide(situation, available_actions, ctx)
                    )

                action_data = {
                    "type": "run_tool" if ai_action.tool else "shell",
                    "params": {"tool": ai_action.tool, "target": ai_action.target or target, "command": f"{ai_action.tool} {ai_action.target or target}"}
                }
                thought = ai_action.description

                if callback and thought:
                    callback(f"thought:{thought}")
            except Exception as e:
                logger.debug(f"Brain decision failed: {e}")
                _brain_loop = False  # fall through to legacy

        # ── Legacy decision path (JSON parse) ─────────────────────────
        decision = None
        if not _brain_loop:
            # Get AI decision
            try:
                from tools.universal_ai_client import ACTION_TOOLS

                _resp = client.chat(
                    [
                        AIMessage(role="system", content=step_prompt),
                        AIMessage(role="user", content="What is the next action?"),
                    ],
                    temperature=0.2,
                    tools=ACTION_TOOLS,
                )
                # Prefer native tool-calling; fall back to text-JSON extraction
                if _resp.tool_calls:
                    _tc = _resp.tool_calls[0]
                    response_text = json.dumps(
                        {
                            "thought": _tc.arguments.pop("thought", "execute action"),
                            "action": {"type": _tc.name, "params": _tc.arguments},
                        }
                    )
                else:
                    response_text = _resp.content or ""
                consecutive_ai_failures = 0  # reset on success
            except Exception as e:
                consecutive_ai_failures += 1
                logger.error(f"AI decision failed (consecutive={consecutive_ai_failures}): {e}")
                if consecutive_ai_failures >= 2:
                    logger.warning("All AI providers failed twice in a row. Exiting early.")
                    if callback:
                        callback(ai_unavailable_marker)
                    return (
                        f"{ai_unavailable_marker} All AI providers failed after "
                        f"{consecutive_ai_failures} consecutive errors. "
                        f"Check API keys in .env or visit "
                        f"https://aistudio.google.com/apikey to fix Gemini quota."
                    )
                break

            # Parse JSON
            decision = extract_json(response_text)
            if not decision or not isinstance(decision, dict):
                action_data = {"type": "finish"}
            else:
                thought = decision.get("thought", "")
                action_data = decision.get("action", decision)
                if isinstance(action_data, dict) and "type" not in action_data:
                    action_data = {"type": "shell", "params": action_data}

            if callback and thought:
                callback(f"thought:{thought}")

        action_type = action_data.get("type", "shell") if isinstance(action_data, dict) else "shell"
        params = action_data.get("params", {}) if isinstance(action_data, dict) else {}

        # Convert action types
        if action_type == "run_shell":
            action_type = "shell"

        if action_type == "run_tool":
            tool_name = params.get("tool", "")
            tool_target = params.get("target", target)
            if tool_name:
                params = {"tool": tool_name, "target": tool_target, "args": params.get("args", "")}
            else:
                action_type = "shell"

        # Governance gate for shell commands
        if action_type == "shell" and governance:
            cmd = params.get("command", "")
            gate = governance.gate(
                mission_id=f"universal:{target}:{int(time.time())}",
                target=target or "unknown",
                action={"type": "run_shell", "command": cmd},
            )
            if gate.decision == "deny":
                result = f"Command blocked: {gate.rationale}"
                _append_history(history, "assistant", result)
                continue
            elif gate.decision == "needs_approval":
                from cli.ui_components import confirm

                try:
                    approved = confirm(f"Run: {cmd[:80]}?", default=False)
                except Exception:
                    approved = False
                if not approved:
                    result = "Command rejected by user."
                    _append_history(history, "assistant", result)
                    continue

        # Execute
        result_obj = executor.execute_action({"type": action_type, "params": params})
        result = result_obj.output if result_obj.success else f"{result_obj.error}"

        # Include the model's own thought in the history so its reasoning
        # feeds the next step (self-reinforcing chain-of-thought).
        _entry = f"[{action_type}] {result[:300]}"
        if thought:
            _entry = f"[Thought: {thought}]\n{_entry}"
        _append_history(history, "assistant", _entry)

        # Score findings
        if is_security_task and result_obj.success:
            calc = CVSSCalculator(use_ai=False)
            finding_type = params.get("tool", action_type)
            try:
                score = calc.from_finding(finding_type, result[:200], result[:500], "")
                all_findings.append(
                    {
                        "type": finding_type,
                        "severity": score.severity.value,
                        "cvss": score.base_score,
                        "source": "ai_reasoning",  # produced by the agent's own scoring loop
                    }
                )
            except Exception:
                pass

        # Finish condition
        if action_type == "finish":
            break

    # ── Generate summary ───────────────────────────────────────────────
    if is_security_task and all_findings:
        scored = all_findings
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        scored.sort(key=lambda s: sev_order.get(s["severity"], 5))

        lines = ["## Universal Agent Summary", ""]
        if target:
            lines.append(f"**Target**: {target}")
        lines.append(f"**Steps**: {step + 1}")
        lines.append(f"**Findings**: {len(scored)}")
        lines.append("")
        if scored:
            lines.append("| Severity | Type | CVSS |")
            lines.append("|----------|------|------|")
            for s in scored:
                lines.append(f"| {s['severity']} | {s['type']} | {s['cvss']:.1f} |")

        summary = "\n".join(lines)
        _append_history(history, "assistant", summary)
        return summary

    # P2.4: If loop exited with 0 actions, AI is likely unavailable
    if len(history) <= 1 and not all_findings:
        return (
            f"{ai_unavailable_marker} All AI providers failed. "
            f"{len(history)-1} actions taken. "
            f"Check API keys in .env or visit "
            f"https://aistudio.google.com/apikey to fix Gemini quota."
        )

    return f"Universal session reached {max_steps} steps. History: {len(history)} actions."


# ── Helper functions ────────────────────────────────────────────────────


def _build_chat_messages(
    conversation_history: List[Dict[str, str]],
    system_prompt: str,
    user_input: str,
) -> List[AIMessage]:
    """Build message list from system prompt + conversation history."""
    messages = [AIMessage(role="system", content=system_prompt)]
    for msg in conversation_history[-10:]:
        messages.append(AIMessage(role=msg.get("role", "user"), content=msg.get("content", "")))
    messages.append(AIMessage(role="user", content=user_input))
    return messages


def _append_history(history: List[Dict[str, str]], role: str, content: str) -> None:
    """Append to an in-memory conversation history list."""
    history.append({"role": role, "content": content})


def _build_research_prompt(user_input: str, now_context: str) -> str:
    return f"""You are Elengenix AI in RESEARCH MODE.

### USER QUERY:
"{user_input}"

{now_context}

### YOUR ROLE:
Research Assistant with LIVE INTERNET ACCESS via DuckDuckGo / Tavily search.

### ANTI-HALLUCINATION RULES (CRITICAL):
- You MUST call search_web before answering any live/current question.
- ONLY report facts that appear in the actual search results returned to you.
- Do NOT invent scores, results, prices, or any data.
- If search results are incomplete or unclear, say so honestly.
- Always include the source URL when citing a result.

### IMPORTANT - THIS IS NOT A SECURITY TASK:
- NO target domain/IP to scan
- NO penetration testing required
- NO 5-phase methodology
- This is simple INFORMATION RETRIEVAL for the user's question

### YOUR CAPABILITIES:
- `search_web`: Search live internet (DuckDuckGo/Tavily) for current information
- `finish`: Complete the task and provide the answer

### WHEN TO USE search_web:
- Current events, news, sports scores, weather, stock prices
- Recent CVEs or security advisories
- Any question where your training data might be outdated

### WORKFLOW (Simple):
1. ALWAYS search_web first (don't rely on training data for current info)
2. Read search results
3. Provide answer with source URLs

### RESPONSE FORMAT:
Always respond with valid JSON:
{{"thought": "...",
"action": {{"type": "search_web|finish",
"params": {{"query": "..."}}}},
"next_step": "..."}}"""


def _build_bug_bounty_prompt(
    user_input: str,
    now_context: str,
    target: str,
    client: Any,
    governance: Governance,
    skill_registry: Any,
) -> str:
    # Gather available tools
    available_tools = registry.list_available_tools()
    tool_descriptions = []
    for name, info in available_tools.items():
        if info.get("available"):
            tool_descriptions.append(f"  - {name}: {info.get('description', name)}")

    # Gather skills
    available_skills = []
    missing_skills = []
    if skill_registry:
        try:
            available_skills = skill_registry.list_available_skills()
            missing_skills = skill_registry.get_missing_skills()
        except Exception:
            pass

    tools_list_str = "\n".join(tool_descriptions)
    available_list = (
        "\n".join([f"  - {s.name}: {s.description}" for s in available_skills])
        if available_skills
        else "  (No additional tools registered)"
    )
    missing_list = (
        "\n".join(
            [
                f"  - {s.name}: {s.description} [MISSING - install: {s.install_command}]"
                for s in missing_skills[:5]
            ]
        )
        if missing_skills
        else ""
    )

    return f"""You are an autonomous AI security researcher. Your mission: Find vulnerabilities on {target}

{now_context}

### AVAILABLE TOOLS & CAPABILITIES:
You have access to these security tools. CHOOSE which to use based on the situation:
{tools_list_str}

### SKILL REGISTRY:
Additional tools available:
{available_list}

{"MISSING TOOLS (can request install):" + chr(10) + missing_list if missing_list else ""}

### TOOL RECOMMENDATION:
If a tool is missing and would be useful, ask the user with a format like:
"Tool [name] is useful for [purpose] but not installed. Shall I install it? (Command: [install_command])"

### VULNERABILITY DISCOVERY METHODOLOGY (Apply as needed):
Think step-by-step which tools fit each phase:

**PHASE 1: RECONNAISSANCE**
- DNS enumeration: Use dig, nslookup, or Python DNS libraries
- HTTP probing: Use curl or Python requests
- Technology fingerprinting: Analyze response headers and body
- Choose based on: target size, rate limits, accuracy needs

**PHASE 2: CONTENT DISCOVERY**
- Directory/path enumeration: Use Python wordlist scanners
- Parameter discovery: Analyze forms and URLs
- JS analysis for hidden endpoints
- Choose based on: time constraints, depth needed

**PHASE 3: VULNERABILITY SCANNING**
- Use built-in Python scanners: SSRF, SSTI, XXE, Deserialization, GraphQL, CORS, JWT
- SQL injection testing: Use Python-based testers
- XSS testing: Use Python-based testers
- Secret scanning: Check for exposed credentials in responses
- Choose based on: what was discovered, what's in scope

**PHASE 4: EXPLOITATION**
- Manual verification of found vulnerabilities
- Write PoC scripts when needed
- Understand impact before reporting

**PHASE 5: REPORTING**
- Document all findings with severity
- Include CVSS scores
- Provide reproduction steps

### YOUR FULL CAPABILITIES:
- Full shell access (any command, script, or tool)
- File editing (read, write, edit, search)
- Package installation (pip, npm, apt, go, gem)
- Web search and research
- CVE database lookup
- GitHub code search for leaked credentials
- JS analysis for hidden endpoints/secrets
- Subdomain takeover checks

### YOU HAVE THESE CAPABILITIES -- use them as you see fit:

### RESPONSE FORMAT:
Always respond with valid JSON:
{{"thought": "...",
"action": {{"type": "shell|run_tool|read_file|write_file|edit_file|search_file|search_web|ask_user|finish",
"params": {{...}}}},
"next_step": "..."}}"""


def _build_general_prompt(user_input: str, now_context: str) -> str:
    return f"""You are Elengenix AI 1.0.0 — A Universal AI Agent.

{now_context}

### UNIVERSAL AGENT MODE — GENERAL PURPOSE
You can help with code, security research, OSINT, system administration, and general tasks.

### AVAILABLE TOOLS (Use as needed):
- Built-in Python scanners: SSRF, SSTI, XXE, Deserialization, GraphQL, CORS, JWT, Race Conditions
- General: curl, dig, python, ripgrep, jq
- Web search, file editing, package management

### YOUR FULL CAPABILITIES:
- Full shell access (any command, script, or tool)
- File editing (read, write, edit, search)
- Package installation (pip, npm, apt, go, gem)
- Web search and research
- CVE database lookup
- GitHub code search
- JS analysis
- Security scanning

### RESPONSE FORMAT:
Always respond with valid JSON:
{{"thought": "...",
"action": {{"type": "shell|run_tool|read_file|write_file|edit_file|search_file|search_web|finish",
"params": {{...}}}},
"next_step": "..."}}

### PRINCIPLES:
1. If you are unsure about a command, think step by step
2. If a command fails, debug it and try alternatives
3. Prefer registered tools (run_tool) for security scanning
4. Use shell for custom commands, scripts, and data processing
5. Always validate results before reporting findings"""
