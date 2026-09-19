"""elengenix.agent.crew — PentAGI-style multi-agent system ported to Elengenix.

This package contains the hierarchical orchestrator pattern with 15 agent types
ported from PentAGI's Go implementation:
    PrimaryAgent (Orchestrator) — root, delegates to 6 specialists
    Searcher (Researcher)       — information gathering
    Pentester                   — hands-on security testing
    Coder (Developer)           — writes exploits/scripts
    Installer (Maintenance)     — environment setup
    Memorist (Archivist)        — vector + KG retrieval
    Adviser (Mentor)            — strategic guidance
    Enricher                    — sub-agent of Adviser
    Generator                   — decomposes task into subtasks
    Refiner                     — patches subtask plan
    Reporter                    — final task report
    Reflector                   — repairs non-tool-call responses
    Summarizer                  — condenses long chains
    ToolCallFixer               — repairs malformed tool calls
    Assistant                   — interactive conversational

Architecture (ported from PentAGI backend/pkg/providers/performer.go):
    Universal perform_agent_chain() loop with:
      - Iteration caps (100 for general agents, 20 for limited)
      - Reflector injection on no-tool-call
      - Summarizer on context overflow
      - Barrier tool termination (done/ask)
      - Back-propagation state machine (created→running→waiting→finished|failed)
"""

from __future__ import annotations

from elengenix.agent.crew.base import (
    AgentType,
    AgentContext,
    perform_agent_chain,
    MAX_GENERAL_ITERATIONS,
    MAX_LIMITED_ITERATIONS,
)
from elengenix.agent.crew.primary_agent import PrimaryAgent
from elengenix.agent.crew.searcher import Searcher
from elengenix.agent.crew.pentester import Pentester
from elengenix.agent.crew.coder import Coder
from elengenix.agent.crew.installer import Installer
from elengenix.agent.crew.memorist import Memorist
from elengenix.agent.crew.adviser import Adviser
from elengenix.agent.crew.enricher import Enricher
from elengenix.agent.crew.generator import Generator
from elengenix.agent.crew.refiner import Refiner
from elengenix.agent.crew.reporter import Reporter
from elengenix.agent.crew.reflector import Reflector
from elengenix.agent.crew.summarizer import Summarizer
from elengenix.agent.crew.toolcall_fixer import ToolCallFixer
from elengenix.agent.crew.assistant import Assistant

__all__ = [
    "AgentType",
    "AgentContext",
    "perform_agent_chain",
    "MAX_GENERAL_ITERATIONS",
    "MAX_LIMITED_ITERATIONS",
    "PrimaryAgent",
    "Searcher",
    "Pentester",
    "Coder",
    "Installer",
    "Memorist",
    "Adviser",
    "Enricher",
    "Generator",
    "Refiner",
    "Reporter",
    "Reflector",
    "Summarizer",
    "ToolCallFixer",
    "Assistant",
]
