"""elengenix.api.routes — APIRouter-per-resource-group registry.

Mirrors PentAGI's ``setXxxGroup`` helpers (one helper per resource
group, mounted under the ``/api/v1`` prefix). Each module in this
package exposes a single ``APIRouter`` named ``router``.

Currently registered routers (Phase 6-a):

* ``health``    — public: ``/info``, ``/health``, ``/metrics``.
* ``auth``      — session: ``/auth/login``, ``/auth/logout``,
                  ``/auth/me``, ``/auth/refresh``.
* ``tokens``    — session: ``/tokens`` (POST/GET), ``/tokens/{id}`` (DELETE).
* ``providers`` — bearer-or-session: ``/providers``,
                  ``/providers/test``, ``/providers/{name}/models``.
* ``knowledge`` — bearer-or-session: ``/knowledge/documents`` (GET/POST),
                  ``/knowledge/documents/{id}`` (DELETE),
                  ``/knowledge/search`` (POST).
* ``flows``     — bearer-or-session: full ``/flows/*`` surface (17
                  endpoints) — create, list, get, update, delete,
                  graph, tasks, subtasks, containers, toolcalls,
                  msglogs, termlogs, searchlogs, screenshots, usage,
                  input, stop, report.

Future routers (planned for later phases):

* ``users``, ``roles``                  — Phase 6-d (admin endpoints).
* ``settings``                          — Phase 6-d (prompt + provider settings).
* ``resources``, ``assistants``         — Phase 6-e.
* ``containers``, ``toolcalls``, ``msglogs``, ``termlogs``,
  ``searchlogs``, ``screenshots``       — Phase 6-e (cross-flow lists).
* ``prompts``                           — Phase 6-d.
* ``usage``                             — Phase 6-f (usage stats aggregations).
* ``oauth``                             — Phase 6-c (OAuth2 callbacks).
* ``graphql``                           — Phase 6-g (strawberry-graphql).

Use ``all_routers()`` to get the iterable of ``(name, router)`` tuples
for mounting.
"""

from __future__ import annotations

import logging
from typing import Iterator, Tuple

from fastapi import APIRouter

from . import auth, flows, health, knowledge, providers, tokens

logger = logging.getLogger("elengenix.api.routes")

__all__ = [
    "auth",
    "flows",
    "health",
    "knowledge",
    "providers",
    "tokens",
    "all_routers",
    "ALL_ROUTERS",
]


# Ordered list — health first (so /health is callable during startup),
# then auth (so login works), then the protected resource groups.
ALL_ROUTERS: list[Tuple[str, APIRouter]] = [
    ("health", health.router),
    ("auth", auth.router),
    ("tokens", tokens.router),
    ("providers", providers.router),
    ("knowledge", knowledge.router),
    ("flows", flows.router),
]


def all_routers() -> Iterator[Tuple[str, APIRouter]]:
    """Yield ``(name, router)`` tuples for every registered router."""
    yield from ALL_ROUTERS
