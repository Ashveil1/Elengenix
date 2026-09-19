"""DEPRECATED — use :mod:`elengenix.agent.crew` instead.

The PentAGI-ported multi-agent crew moved to ``elengenix/agent/crew/`` so all
agent code lives under one home. This shim keeps the old
``elengenix.agents.*`` import paths working (including submodule imports like
``from elengenix.agents.base import LLMClient``) and will be removed in a
future release.
"""

from __future__ import annotations

import importlib
import sys
import warnings

warnings.warn(
    "elengenix.agents is deprecated — import from elengenix.agent.crew instead",
    DeprecationWarning,
    stacklevel=2,
)

_CREW = "elengenix.agent.crew"

from elengenix.agent.crew.base import (  # noqa: F401  (re-exports)
    MAX_GENERAL_ITERATIONS,
    MAX_LIMITED_ITERATIONS,
    AgentContext,
    AgentType,
    perform_agent_chain,
)
from elengenix.agent.crew.primary_agent import PrimaryAgent  # noqa: F401
from elengenix.agent.crew.searcher import Searcher  # noqa: F401
from elengenix.agent.crew.pentester import Pentester  # noqa: F401
from elengenix.agent.crew.coder import Coder  # noqa: F401
from elengenix.agent.crew.installer import Installer  # noqa: F401
from elengenix.agent.crew.memorist import Memorist  # noqa: F401
from elengenix.agent.crew.adviser import Adviser  # noqa: F401
from elengenix.agent.crew.enricher import Enricher  # noqa: F401
from elengenix.agent.crew.generator import Generator  # noqa: F401
from elengenix.agent.crew.refiner import Refiner  # noqa: F401
from elengenix.agent.crew.reporter import Reporter  # noqa: F401
from elengenix.agent.crew.reflector import Reflector  # noqa: F401
from elengenix.agent.crew.summarizer import Summarizer  # noqa: F401
from elengenix.agent.crew.toolcall_fixer import ToolCallFixer  # noqa: F401
from elengenix.agent.crew.assistant import Assistant  # noqa: F401

# Alias every former submodule so ``from elengenix.agents.<mod> import X``
# keeps resolving to the relocated module.
for _mod in (
    "adviser",
    "assistant",
    "base",
    "coder",
    "enricher",
    "generator",
    "installer",
    "memorist",
    "pentester",
    "primary_agent",
    "refiner",
    "reflector",
    "reporter",
    "searcher",
    "summarizer",
    "toolcall_fixer",
):
    sys.modules.setdefault(f"elengenix.agents.{_mod}", importlib.import_module(f"{_CREW}.{_mod}"))

__all__ = [
    "MAX_GENERAL_ITERATIONS",
    "MAX_LIMITED_ITERATIONS",
    "AgentContext",
    "AgentType",
    "perform_agent_chain",
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
