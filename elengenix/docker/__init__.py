"""elengenix.docker — Docker container lifecycle, cleanup, resource limits, networks.

This subpackage ports PentAGI's Docker sandbox layer
(``backend/pkg/docker/client.go`` + the container portions of
``backend/pkg/tools/tools.go``) to Python. It is composed of five
modules:

* ``db``              — SQLite-backed container state (``ContainerDB``)
* ``resource_limits`` — cgroup/ulimit/network hardening (``ResourceLimits``)
* ``network``         — per-flow isolated bridge networks (``DockerNetwork``)
* ``lifecycle``       — high-level prepare/run/release (``ContainerLifecycle``)
* ``cleanup``         — startup-time + on-demand cleanup (``ContainerCleanup``)

All modules are async-first and lazy-import their heavy dependencies
(``aiodocker``, ``aiosqlite``) so the package can be imported for
AST-level inspection even when those packages aren't installed.
"""

from __future__ import annotations

from .db import (
    ACTIVE_CONTAINER_STATUSES,
    ORPHAN_FLOW_STATUSES,
    ContainerDB,
    ContainerInfo,
    ContainerStatus,
    ContainerType,
    FlowStatus,
)
from .resource_limits import (
    ResourceLimits,
    apply_to_container_config,
    parse_size_to_bytes,
    validate_limits,
)

__all__ = [
    # db
    "ContainerDB",
    "ContainerInfo",
    "ContainerStatus",
    "ContainerType",
    "FlowStatus",
    "ACTIVE_CONTAINER_STATUSES",
    "ORPHAN_FLOW_STATUSES",
    # resource_limits
    "ResourceLimits",
    "apply_to_container_config",
    "parse_size_to_bytes",
    "validate_limits",
]
