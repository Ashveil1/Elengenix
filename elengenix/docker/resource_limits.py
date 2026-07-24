"""elengenix/docker/resource_limits.py — cgroup-backed hardening for sandboxes.

PentAGI's Docker sandbox sets only ``CapAdd=[NET_RAW, NET_ADMIN?]``,
``RestartPolicy=on-failure(5)``, json-file log rotation, and port
bindings. It does NOT set any of the cgroup-based resource limits
(``Memory``, ``NanoCpus``, ``PidsLimit``, ``Ulimits``) — it relies on
the host having enough RAM/CPU and on the LLM agent being well-behaved.

Elengenix adds an extra layer of defense-in-depth:

* ``mem_limit``   — 2 GiB per container (fork-bomb / leak protection)
* ``cpu_quota``   — 50% of one CPU (50_000 us out of a 100_000 us period)
* ``pids_limit``  — 100 processes (prevents fork bombs)
* ``shm_size``    — 256 MiB (matches scraper container's 2g default scaled down)
* ``ulimit_nofile`` — 1024 open files
* ``ulimit_nproc``  — 256 processes (kernel-level backstop for ``pids_limit``)
* ``read_only_root`` — make the rootfs read-only; ``/work`` stays writable via tmpfs
* ``network_mode``   — ``bridge`` (default), ``host`` (raw-packet testing,
  ``--network-host`` flag), or ``none`` (complete isolation,
  ``--network-internal`` flag)

The dataclass is intentionally JSON-serializable (no Path objects, no
enums) so it can be persisted to SQLite as part of the flow record.

``apply_to_container_config`` merges a ``ResourceLimits`` instance into
an aiodocker ``ContainerConfig`` dict. The mapping is:

  - ``mem_limit``      -> ``HostConfig.Memory``
  - ``cpu_quota``      -> ``HostConfig.CpuQuota``
  - ``cpu_period``     -> ``HostConfig.CpuPeriod``
  - ``pids_limit``     -> ``HostConfig.PidsLimit``
  - ``shm_size``       -> ``HostConfig.ShmSize``
  - ``ulimit_nofile``  -> ``HostConfig.Ulimits`` (``nofile``)
  - ``ulimit_nproc``   -> ``HostConfig.Ulimits`` (``nproc``)
  - ``read_only_root`` -> ``HostConfig.ReadonlyRootfs``
  - ``network_mode``   -> ``HostConfig.NetworkMode``

``validate_limits`` returns a list of human-readable error strings
(empty list = valid). This is called from ``ContainerLifecycle.prepare``
before the container is created, so misconfiguration is caught early.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("elengenix.docker.resource_limits")

# ---------------------------------------------------------------------------
# Defaults — chosen for a single-flow sandbox running on a developer laptop.
# Multi-tenant / production deployments should override via config.yaml.
# ---------------------------------------------------------------------------

DEFAULT_MEM_LIMIT: str = "2g"
DEFAULT_CPU_QUOTA: int = 50_000          # 50% of one CPU
DEFAULT_CPU_PERIOD: int = 100_000        # 100 ms (Linux default)
DEFAULT_PIDS_LIMIT: int = 100
DEFAULT_SHM_SIZE: str = "256m"
DEFAULT_ULIMIT_NOFILE: int = 1024
DEFAULT_ULIMIT_NPROC: int = 256
DEFAULT_READ_ONLY_ROOT: bool = False
DEFAULT_NETWORK_MODE: str = "bridge"

# Supported network modes — these map 1:1 to Docker's ``--network`` flag
# values. ``host`` is special-cased in PentAGI (no port bindings); ``none``
# is Elengenix-specific (full isolation for sensitive flows).
SUPPORTED_NETWORK_MODES: frozenset[str] = frozenset({"bridge", "host", "none", "container"})

# Regex for a Docker size string: integer + optional unit (k/m/g/t, case-
# insensitive). Matches "256m", "2g", "1024" (bytes), etc.
_SIZE_RE = re.compile(r"^\d+(\.\d+)?[kKmMgGtT]?$")


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class ResourceLimits:
    """Cgroup-backed hardening knobs applied to every Elengenix sandbox.

    Defaults are deliberately conservative — a single agent flow should
    not need more than 2 GiB of RAM or 50% of one CPU. Pentest workloads
    that need more (e.g. running nmap against a large subnet) can
    override via CLI flags or config.yaml.
    """

    mem_limit: str = DEFAULT_MEM_LIMIT
    cpu_quota: int = DEFAULT_CPU_QUOTA
    cpu_period: int = DEFAULT_CPU_PERIOD
    pids_limit: int = DEFAULT_PIDS_LIMIT
    shm_size: str = DEFAULT_SHM_SIZE
    ulimit_nofile: int = DEFAULT_ULIMIT_NOFILE
    ulimit_nproc: int = DEFAULT_ULIMIT_NPROC
    read_only_root: bool = DEFAULT_READ_ONLY_ROOT
    network_mode: str = DEFAULT_NETWORK_MODE
    # Optional cap_add / cap_drop lists — kept here (rather than in the
    # lifecycle class) so a single ``ResourceLimits`` instance fully
    # describes the sandbox's security posture. Defaults match PentAGI.
    cap_add: list[str] = field(default_factory=lambda: ["NET_RAW"])
    cap_drop: list[str] = field(default_factory=lambda: [])

    # ------------------------------------------------------------------
    # Convenience constructors for common profiles
    # ------------------------------------------------------------------

    @classmethod
    def default(cls) -> "ResourceLimits":
        """Conservative defaults for general-purpose agent flows."""
        return cls()

    @classmethod
    def pentest(cls, net_admin: bool = False) -> "ResourceLimits":
        """Pentest profile: keeps ``NET_RAW``, optionally adds ``NET_ADMIN``
        (mirrors PentAGI's ``cfg.DockerNetAdmin``). Same cgroup limits as
        default — pentest tools rarely need more RAM, just more
        capabilities."""
        caps = ["NET_RAW"]
        if net_admin:
            caps.append("NET_ADMIN")
        return cls(cap_add=caps)

    @classmethod
    def isolated(cls) -> "ResourceLimits":
        """Maximum isolation: no network, read-only rootfs, tightest
        limits. For handling untrusted inputs (e.g. analysing a
        suspicious binary)."""
        return cls(
            mem_limit="512m",
            cpu_quota=25_000,        # 25% of one CPU
            pids_limit=32,
            shm_size="64m",
            ulimit_nofile=256,
            ulimit_nproc=64,
            read_only_root=True,
            network_mode="none",
            cap_add=[],
            cap_drop=["ALL"],
        )

    @classmethod
    def host_network(cls) -> "ResourceLimits":
        """Host-network profile: for raw-packet testing (nmap SYN scan,
        ARP spoofing, etc). PentAGI's ``--network-host`` equivalent."""
        return cls(
            network_mode="host",
            cap_add=["NET_RAW", "NET_ADMIN"],
        )

    def to_dict(self) -> dict[str, Any]:
        """Plain-dict view (JSON-serializable, no Path/Enum)."""
        return {
            "mem_limit": self.mem_limit,
            "cpu_quota": self.cpu_quota,
            "cpu_period": self.cpu_period,
            "pids_limit": self.pids_limit,
            "shm_size": self.shm_size,
            "ulimit_nofile": self.ulimit_nofile,
            "ulimit_nproc": self.ulimit_nproc,
            "read_only_root": self.read_only_root,
            "network_mode": self.network_mode,
            "cap_add": list(self.cap_add),
            "cap_drop": list(self.cap_drop),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def parse_size_to_bytes(size: str | int) -> int:
    """Parse a Docker size string (``"256m"``, ``"2g"``, ``"1024"``) to bytes.

    Raises ``ValueError`` if the string is malformed. Used by
    ``validate_limits`` to cross-check that ``shm_size <= mem_limit``.
    """
    if isinstance(size, int):
        return size
    s = str(size).strip()
    if not s:
        raise ValueError("empty size string")
    m = _SIZE_RE.match(s)
    if not m:
        raise ValueError(f"invalid size string: {size!r}")
    # Split numeric prefix from unit suffix.
    unit_idx = len(s)
    for i, ch in enumerate(s):
        if ch.isalpha():
            unit_idx = i
            break
    num = float(s[:unit_idx])
    unit = s[unit_idx:].lower()
    multipliers = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    if unit not in multipliers:
        raise ValueError(f"unknown size unit: {unit!r}")
    return int(num * multipliers[unit])


def apply_to_container_config(
    config: dict[str, Any],
    limits: ResourceLimits,
) -> dict[str, Any]:
    """Merge ``limits`` into an aiodocker-style container config dict.

    The input ``config`` is the dict that would be passed to
    ``aiodocker.containers.create(config=...)``. The function mutates
    AND returns it (so it can be chained). The ``HostConfig`` sub-dict
    is created if missing.

    Port bindings and bind mounts are NOT touched — those are the
    lifecycle layer's responsibility. This function only sets cgroup
    knobs, capabilities, ulimits, and network mode.
    """
    host_config: dict[str, Any] = dict(config.get("HostConfig") or {})

    # --- cgroup limits -------------------------------------------------
    if limits.mem_limit:
        # Docker accepts both the string ("2g") and the byte count; we
        # pass the string for readability in `docker inspect` output.
        host_config["Memory"] = parse_size_to_bytes(limits.mem_limit)
    if limits.cpu_quota > 0:
        host_config["CpuQuota"] = int(limits.cpu_quota)
    if limits.cpu_period > 0:
        host_config["CpuPeriod"] = int(limits.cpu_period)
    if limits.pids_limit > 0:
        host_config["PidsLimit"] = int(limits.pids_limit)
    if limits.shm_size:
        host_config["ShmSize"] = parse_size_to_bytes(limits.shm_size)

    # --- ulimits -------------------------------------------------------
    ulimits: list[dict[str, Any]] = list(host_config.get("Ulimits") or [])
    if limits.ulimit_nofile > 0:
        ulimits.append(
            {"Name": "nofile", "Soft": limits.ulimit_nofile, "Hard": limits.ulimit_nofile}
        )
    if limits.ulimit_nproc > 0:
        ulimits.append(
            {"Name": "nproc", "Soft": limits.ulimit_nproc, "Hard": limits.ulimit_nproc}
        )
    if ulimits:
        # Deduplicate by Name (last wins) so callers can pre-populate.
        seen: dict[str, dict[str, Any]] = {}
        for u in ulimits:
            seen[u["Name"]] = u
        host_config["Ulimits"] = list(seen.values())

    # --- filesystem hardening -----------------------------------------
    if limits.read_only_root:
        host_config["ReadonlyRootfs"] = True
        # tmpfs for /tmp and /run — without these, even ``apt update``
        # fails because it can't write to /var/cache/apt.
        tmpfs: list[dict[str, Any]] = list(host_config.get("Tmpfs") or {})
        # Docker accepts ``Tmpfs`` as a dict mapping mount-point -> opts.
        tmpfs_dict: dict[str, str] = dict(host_config.get("Tmpfs") or {})
        tmpfs_dict.setdefault("/tmp", "rw,noexec,nosuid,size=64m")
        tmpfs_dict.setdefault("/run", "rw,noexec,nosuid,size=16m")
        host_config["Tmpfs"] = tmpfs_dict

    # --- network mode --------------------------------------------------
    if limits.network_mode:
        host_config["NetworkMode"] = limits.network_mode

    # --- capabilities --------------------------------------------------
    if limits.cap_add:
        existing_add: list[str] = list(host_config.get("CapAdd") or [])
        for cap in limits.cap_add:
            if cap not in existing_add:
                existing_add.append(cap)
        host_config["CapAdd"] = existing_add
    if limits.cap_drop:
        existing_drop: list[str] = list(host_config.get("CapDrop") or [])
        for cap in limits.cap_drop:
            if cap not in existing_drop:
                existing_drop.append(cap)
        host_config["CapDrop"] = existing_drop

    config["HostConfig"] = host_config
    return config


def validate_limits(limits: ResourceLimits) -> list[str]:
    """Return a list of human-readable validation errors.

    An empty list means the limits are safe to apply. This is called
    from ``ContainerLifecycle.prepare`` before the container is created
    so misconfiguration is caught without spawning a doomed container.
    """
    errors: list[str] = []

    # --- mem_limit -----------------------------------------------------
    try:
        mem_bytes = parse_size_to_bytes(limits.mem_limit)
        if mem_bytes < 16 * 1024 * 1024:
            errors.append(
                f"mem_limit={limits.mem_limit!r} is below 16m minimum "
                "(containers may OOM during init)"
            )
    except ValueError as e:
        errors.append(f"mem_limit invalid: {e}")

    # --- shm_size ------------------------------------------------------
    try:
        shm_bytes = parse_size_to_bytes(limits.shm_size)
        if shm_bytes < 1024 * 1024:
            errors.append(f"shm_size={limits.shm_size!r} is below 1m minimum")
        # shm_size should not exceed mem_limit (it's a subset of RAM).
        try:
            mem_bytes = parse_size_to_bytes(limits.mem_limit)
            if shm_bytes > mem_bytes:
                errors.append(
                    f"shm_size ({limits.shm_size}) exceeds mem_limit ({limits.mem_limit})"
                )
        except ValueError:
            pass  # already reported above
    except ValueError as e:
        errors.append(f"shm_size invalid: {e}")

    # --- cpu_quota / cpu_period ---------------------------------------
    if limits.cpu_quota < 0:
        errors.append(f"cpu_quota={limits.cpu_quota} must be >= 0")
    if limits.cpu_period <= 0:
        errors.append(f"cpu_period={limits.cpu_period} must be > 0")
    elif limits.cpu_quota > 0:
        # cpu_quota is in microseconds per cpu_period; a quota > period
        # means "more than one CPU" which is fine, but absurdly high
        # values (> 16 CPUs) are almost certainly a config mistake.
        cpus = limits.cpu_quota / limits.cpu_period
        if cpus > 16:
            errors.append(
                f"cpu_quota={limits.cpu_quota} with cpu_period={limits.cpu_period} "
                f"= {cpus:.1f} CPUs (max 16)"
            )

    # --- pids_limit ----------------------------------------------------
    if limits.pids_limit < 0:
        errors.append(f"pids_limit={limits.pids_limit} must be >= 0")
    elif 0 < limits.pids_limit < 16:
        errors.append(
            f"pids_limit={limits.pids_limit} is dangerously low (init needs ~16 procs)"
        )

    # --- ulimits -------------------------------------------------------
    if limits.ulimit_nofile < 0:
        errors.append(f"ulimit_nofile={limits.ulimit_nofile} must be >= 0")
    if limits.ulimit_nproc < 0:
        errors.append(f"ulimit_nproc={limits.ulimit_nproc} must be >= 0")
    if 0 < limits.ulimit_nproc < limits.pids_limit:
        # nproc is a per-user limit; pids_limit is a per-cgroup limit.
        # nproc < pids_limit means nproc will always hit first, making
        # pids_limit ineffective.
        errors.append(
            f"ulimit_nproc={limits.ulimit_nproc} < pids_limit={limits.pids_limit}: "
            "nproc will dominate (pids_limit ineffective)"
        )

    # --- network_mode --------------------------------------------------
    if limits.network_mode not in SUPPORTED_NETWORK_MODES:
        errors.append(
            f"network_mode={limits.network_mode!r} not in {sorted(SUPPORTED_NETWORK_MODES)}"
        )

    # --- read_only_root implications ---------------------------------
    if limits.read_only_root and limits.network_mode == "host":
        errors.append(
            "read_only_root=True with network_mode=host is unusual; "
            "host-networked containers usually need writable /etc/hosts"
        )

    return errors


__all__ = [
    "ResourceLimits",
    "parse_size_to_bytes",
    "apply_to_container_config",
    "validate_limits",
    "DEFAULT_MEM_LIMIT",
    "DEFAULT_CPU_QUOTA",
    "DEFAULT_CPU_PERIOD",
    "DEFAULT_PIDS_LIMIT",
    "DEFAULT_SHM_SIZE",
    "DEFAULT_ULIMIT_NOFILE",
    "DEFAULT_ULIMIT_NPROC",
    "DEFAULT_READ_ONLY_ROOT",
    "DEFAULT_NETWORK_MODE",
    "SUPPORTED_NETWORK_MODES",
]
