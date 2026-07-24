"""elengenix/docker/network.py — per-flow Docker network isolation.

PentAGI uses a single shared bridge network (``pentagi-network``) for
all flow containers, with port-based isolation via the deterministic
``28000 + (flow_id * 2 + i) % 2000`` port-allocation formula. It does
NOT create per-flow networks — it relies on the OS firewall + the
scraper's private/public URL routing to isolate flows from each other.

Elengenix adds an optional per-flow isolated bridge network
(``elengenix-flow-{flow_id}``) with ``Internal=True`` to provide
true L2 isolation between flows. This is exposed via two CLI flags:

* ``--network-internal`` — block internet egress; LAN-only. Implemented
  by setting ``Internal=True`` on the bridge network. Containers on an
  internal bridge cannot reach the default gateway (and thus the
  internet), but can reach each other and the host.
* ``--network-host`` — host network mode for raw-packet testing
  (nmap SYN scans, ARP spoofing, etc). Skips network creation entirely;
  the container joins the host's network namespace.

The class is async-first (``aiodocker`` is imported lazily inside
``_client()``) so the module imports cleanly without the optional
dependency installed.

Idempotency: every ``create_*`` method is safe to call multiple times
with the same arguments — it will inspect the existing network and
return its ID rather than failing on the second call. This mirrors
PentAGI's ``ensureDockerNetwork`` helper.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger("elengenix.docker.network")

# ---------------------------------------------------------------------------
# Naming + defaults
# ---------------------------------------------------------------------------

#: Prefix for all Elengenix-managed Docker networks. The flow ID is
#: appended: ``elengenix-flow-42``. This makes it easy to identify
#: Elengenix networks via ``docker network ls | grep elengenix-flow-``.
NETWORK_NAME_PREFIX: str = "elengenix-flow-"

#: Default driver. PentAGI uses ``bridge`` exclusively; we keep that as
#: the default but allow ``overlay`` for future multi-host setups.
DEFAULT_DRIVER: str = "bridge"

#: Subnet allocated to per-flow networks. We use ``172.30.0.0/16`` which
#: is in the RFC 1918 private range and unlikely to clash with the
#: default ``bridge`` network (``172.17.0.0/16``) or Docker's default
#: user-defined bridge pool (``172.18.0.0/16`` .. ``172.31.0.0/16``).
#: The per-flow subnet is ``172.30.{flow_id & 0xFF}.0/24`` — up to 256
#: concurrent isolated flows before subnet collision.
DEFAULT_SUBNET_PREFIX: str = "172.30"

#: Default gateway IP for each per-flow subnet (the ``.1`` address).
DEFAULT_GATEWAY_SUFFIX: int = 1


class DockerNetwork:
    """Per-flow Docker network isolation manager.

    All methods are coroutines; ``aiodocker`` is imported lazily so the
    module loads without the optional dependency installed.

    Usage::

        nets = DockerNetwork()
        net_id = await nets.create_isolated_network(flow_id=42, internal=True)
        await nets.connect_container(net_id, container_id, aliases=["sandbox"])
        # ... container runs ...
        await nets.disconnect_container(net_id, container_id)
        await nets.remove_network(net_id)
    """

    def __init__(self, docker_url: Optional[str] = None) -> None:
        self._docker_url = docker_url
        self._client = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Lazy client access
    # ------------------------------------------------------------------

    async def _client(self):
        """Return (cached) aiodocker.Docker client. Lazy-imported so the
        module can be AST-parsed without ``aiodocker`` installed."""
        if self._client is not None:
            return self._client
        import aiodocker

        kwargs: dict[str, Any] = {}
        if self._docker_url:
            kwargs["url"] = self._docker_url
        self._client = aiodocker.Docker(**kwargs)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def __aenter__(self) -> "DockerNetwork":
        await self._client()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Naming helpers
    # ------------------------------------------------------------------

    @staticmethod
    def network_name(flow_id: int) -> str:
        """Deterministic per-flow network name: ``elengenix-flow-{flow_id}``."""
        return f"{NETWORK_NAME_PREFIX}{int(flow_id)}"

    @staticmethod
    def subnet_for(flow_id: int) -> str:
        """Deterministic per-flow /24 subnet.

        Formula: ``172.30.{flow_id & 0xFF}.0/24`` — gives 256 distinct
        subnets before wrapping. Combined with ``Internal=True`` this
        gives true L2 isolation between flows.
        """
        octet = int(flow_id) & 0xFF
        return f"{DEFAULT_SUBNET_PREFIX}.{octet}.0/24"

    @staticmethod
    def gateway_for(flow_id: int) -> str:
        """Gateway IP for the per-flow subnet (``.1`` address)."""
        octet = int(flow_id) & 0xFF
        return f"{DEFAULT_SUBNET_PREFIX}.{octet}.{DEFAULT_GATEWAY_SUFFIX}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def create_isolated_network(
        self,
        flow_id: int,
        internal: bool = True,
        driver: str = DEFAULT_DRIVER,
    ) -> str:
        """Create (or reuse) an isolated bridge network for ``flow_id``.

        Args:
            flow_id: Flow ID — used to derive the network name and subnet.
            internal: If True (default), set ``Internal=True`` on the
                bridge — this blocks internet egress. This implements
                the ``--network-internal`` flag.
            driver: Docker network driver (default ``bridge``).

        Returns:
            The network ID (a long hex string). The friendly name is
            ``elengenix-flow-{flow_id}`` and can be resolved later via
            ``docker network inspect``.

        Idempotent: if the network already exists, returns its existing
        ID without raising. Mirrors PentAGI's ``ensureDockerNetwork``.
        """
        client = await self._client()
        name = self.network_name(flow_id)
        subnet = self.subnet_for(flow_id)
        gateway = self.gateway_for(flow_id)

        # --- idempotency: inspect first -------------------------------
        try:
            existing = await client.networks.get(name)
            info = await existing.show()
            logger.debug(
                "reusing existing network %s (id=%s) for flow %d",
                name,
                info.get("Id", "")[:12],
                flow_id,
            )
            return str(info.get("Id", name))
        except Exception:
            pass  # network doesn't exist — fall through to create

        # --- create ----------------------------------------------------
        ipam_cfg: dict[str, Any] = {
            "Driver": "default",
            "Config": [
                {
                    "Subnet": subnet,
                    "Gateway": gateway,
                }
            ],
        }
        create_kwargs: dict[str, Any] = {
            "Name": name,
            "Driver": driver,
            "Internal": bool(internal),
            "EnableIPv6": False,
            "IPAM": ipam_cfg,
            "Labels": {
                "elengenix.flow_id": str(int(flow_id)),
                "elengenix.managed": "true",
                "elengenix.internal": "true" if internal else "false",
            },
        }
        logger.info(
            "creating %sisolated network %s (subnet=%s) for flow %d",
            "internal " if internal else "",
            name,
            subnet,
            flow_id,
        )
        net = await client.networks.create(create_kwargs)
        net_info = await net.show()
        return str(net_info.get("Id", name))

    async def remove_network(self, network_id: str) -> None:
        """Remove a network by ID or name. Idempotent (no-op if missing).

        Containers must be disconnected first; Docker will refuse to
        remove a network with active endpoints. The cleanup layer is
        responsible for calling ``disconnect_container`` before this.
        """
        client = await self._client()
        try:
            net = await client.networks.get(network_id)
            await net.delete()
            logger.info("removed network %s", network_id)
        except Exception as e:
            msg = str(e).lower()
            if "no such network" in msg or "not found" in msg:
                logger.debug("network %s already gone", network_id)
                return
            logger.warning("failed to remove network %s: %s", network_id, e)
            raise

    async def connect_container(
        self,
        network_id: str,
        container_id: str,
        aliases: Optional[list[str]] = None,
        ipv4: Optional[str] = None,
    ) -> None:
        """Connect a running container to a network.

        Args:
            network_id: Network ID or name.
            container_id: Container ID or name.
            aliases: DNS aliases the container should be reachable at
                within this network (e.g. ``["sandbox", "terminal"]``).
            ipv4: Optional static IPv4 address. If omitted, Docker
                assigns the next available IP from the subnet.
        """
        client = await self._client()
        net = await client.networks.get(network_id)
        endpoint_config: dict[str, Any] = {}
        if aliases:
            endpoint_config["Aliases"] = list(aliases)
        if ipv4:
            endpoint_config["IPAMConfig"] = {"IPv4Address": ipv4}
        await net.connect({"Container": container_id, **endpoint_config})
        logger.debug(
            "connected container %s to network %s (aliases=%s)",
            container_id,
            network_id,
            aliases,
        )

    async def disconnect_container(
        self, network_id: str, container_id: str, force: bool = False
    ) -> None:
        """Disconnect a container from a network. Idempotent."""
        client = await self._client()
        net = await client.networks.get(network_id)
        try:
            await net.disconnect({"Container": container_id, "Force": bool(force)})
            logger.debug("disconnected container %s from network %s", container_id, network_id)
        except Exception as e:
            msg = str(e).lower()
            if "not connected" in msg or "no such container" in msg or "not found" in msg:
                logger.debug(
                    "container %s already disconnected from %s", container_id, network_id
                )
                return
            raise

    async def list_networks(self, flow_id: Optional[int] = None) -> list[dict[str, Any]]:
        """List Elengenix-managed networks.

        Args:
            flow_id: If given, filter to networks for that specific flow.
                If None, return ALL networks whose name starts with
                ``elengenix-flow-`` (regardless of flow).

        Returns:
            List of network-info dicts (raw aiodocker output).
        """
        client = await self._client()
        filters: dict[str, list[str]] = {"label": ["elengenix.managed=true"]}
        if flow_id is not None:
            filters["label"].append(f"elengenix.flow_id={int(flow_id)}")
        # aiodocker expects the filter dict to be JSON-encoded.
        networks = await client.networks.list(filters=filters)
        out: list[dict[str, Any]] = []
        for net in networks:
            try:
                info = await net.show()
                out.append(info)
            except Exception as e:
                logger.warning("failed to inspect network: %s", e)
        return out

    async def inspect_network(self, network_id: str) -> Optional[dict[str, Any]]:
        """Return the raw network info dict, or None if not found."""
        client = await self._client()
        try:
            net = await client.networks.get(network_id)
            return await net.show()
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Convenience: full flow-network teardown
    # ------------------------------------------------------------------

    async def teardown_flow_network(self, flow_id: int) -> None:
        """Disconnect all containers and remove the per-flow network.

        Used by ``ContainerCleanup.cleanup_flow`` to ensure no orphan
        networks are left behind. Idempotent.
        """
        name = self.network_name(flow_id)
        info = await self.inspect_network(name)
        if info is None:
            return
        # Disconnect every endpoint first.
        endpoints = (info.get("Containers") or {}).values()
        for ep in endpoints:
            ep_id = ep.get("Name") or ep.get("EndpointID") or ""
            if not ep_id:
                continue
            try:
                await self.disconnect_container(name, ep_id, force=True)
            except Exception as e:
                logger.warning(
                    "failed to disconnect container %s from flow %d network: %s",
                    ep_id,
                    flow_id,
                    e,
                )
        await self.remove_network(name)


__all__ = [
    "DockerNetwork",
    "NETWORK_NAME_PREFIX",
    "DEFAULT_DRIVER",
    "DEFAULT_SUBNET_PREFIX",
]
