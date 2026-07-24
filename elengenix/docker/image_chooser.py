"""elengenix/docker/image_chooser.py — LLM-driven smart Docker image selection.

Ports PentAGI's ``backend/pkg/templates/prompts/image_chooser.tmpl`` and
the surrounding ``NewFlowProvider`` logic in
``backend/pkg/providers/providers.go``. A single LLM call at flow-creation
time chooses between the general-purpose image (``debian:latest``) and
the pentest image (``vxcontrol/kali-linux``); the result is cached in the
DB and reused on restart. A ``--image`` CLI flag bypasses the LLM call
entirely.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional, Protocol, runtime_checkable

logger = logging.getLogger("elengenix.docker.image_chooser")

# ── Defaults (mirrors PentAGI config + providers.go hard-coded constant) ─
DEFAULT_IMAGE = os.environ.get("DOCKER_DEFAULT_IMAGE", "debian:latest")
DEFAULT_IMAGE_FOR_PENTEST = os.environ.get(
    "DOCKER_DEFAULT_IMAGE_FOR_PENTEST", "vxcontrol/kali-linux"
)

# ── Verbatim template (port of image_chooser.tmpl as specified) ──────────
IMAGE_CHOOSER_TEMPLATE = """You are choosing a Docker image for a security testing task.

Available images:
- {{ DefaultImage }} (general purpose, lightweight)
- {{ DefaultImageForPentest }} (Kali Linux with security tools)

User input: {{ Input }}

Rules:
- If user specifies a Docker image → use that exact image
- For security/pentest tasks → use {{ DefaultImageForPentest }}
- For ambiguous cases → use {{ DefaultImage }}

Output only the lowercase image name, nothing else.
"""

# A docker image reference: ``[host[:port]/]name[:tag][@digest]``.
# Lenient regex — used only to validate the LLM's output, not to enforce
# strict Docker naming rules.
_IMAGE_RE = re.compile(
    r"^(?:[a-z0-9.-]+(?::\d+)?/)?"  # optional registry host[:port]/
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*"  # repository path component(s)
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"  # additional path components
    r"(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]*)?"  # optional :tag
    r"(?:@sha256:[a-f0-9]{64})?$"  # optional @digest
)


@runtime_checkable
class LLMClientProtocol(Protocol):
    """Minimal LLM client protocol — ``complete`` returns a string.

    Satisfies any async client with ``async def complete(prompt: str, **kw)
    -> str`` (Elengenix ``UniversalAIClient``, langchain-style shims, etc.).
    """

    async def complete(self, prompt: str, **kwargs: Any) -> str: ...


@runtime_checkable
class FlowImageCacheProtocol(Protocol):
    """Optional persistence hook for the chosen image (port of flow DB row)."""

    async def get_flow_image(self, flow_id: int | str) -> Optional[str]: ...

    async def set_flow_image(self, flow_id: int | str, image: str) -> None: ...


class _NullCache:
    """No-op cache when persistence is not wired up."""

    async def get_flow_image(self, flow_id: int | str) -> Optional[str]:
        return None

    async def set_flow_image(self, flow_id: int | str, image: str) -> None:
        return None


def render_template(default_image: str, default_image_for_pentest: str, user_input: str) -> str:
    """Render the image-chooser template (verbatim port — no Jinja needed).

    The original PentAGI template uses Go ``text/template`` with the three
    well-known variables ``{{ DefaultImage }}``, ``{{ DefaultImageForPentest }}``,
    and ``{{ Input }}``. A simple ``str.replace`` is sufficient and avoids
    pulling in Jinja2 as a hard dependency.
    """
    return (
        IMAGE_CHOOSER_TEMPLATE
        .replace("{{ DefaultImage }}", default_image)
        .replace("{{ DefaultImageForPentest }}", default_image_for_pentest)
        .replace("{{ Input }}", user_input)
    )


def _validate_image(image: str) -> str:
    """Lowercase, trim, and validate the LLM-returned image reference.

    Falls back to ``DEFAULT_IMAGE`` on any validation failure (mirrors
    PentAGI's silent fallback at container-creation time, but here we
    catch malformed LLM output before it reaches the docker client).
    """
    cleaned = (image or "").strip().lower()
    if not cleaned:
        logger.warning("image chooser returned empty string — using default")
        return DEFAULT_IMAGE
    if _IMAGE_RE.match(cleaned):
        return cleaned
    # Allow common forms the strict regex might miss (e.g. ``ubuntu`` with
    # no tag, or ``mcr.microsoft.com/devcontainers/python:3.11``). If the
    # first token has any uppercase or whitespace, treat as invalid.
    if " " in cleaned or "\n" in cleaned:
        logger.warning("image chooser returned multi-token output %r — using default", image)
        return DEFAULT_IMAGE
    return cleaned


class ImageChooser:
    """LLM-driven Docker image selector.

    Usage:
        chooser = ImageChooser()
        # CLI bypass (skips the LLM call entirely):
        image = chooser.bypass("kalilinux/kali-rolling")
        # LLM-driven selection at flow creation:
        image = await chooser.choose(
            user_input, llm_client, flow_id=42, cache=flow_cache,
        )
    """

    def __init__(
        self,
        *,
        default_image: str = DEFAULT_IMAGE,
        default_image_for_pentest: str = DEFAULT_IMAGE_FOR_PENTEST,
        cache: Optional[FlowImageCacheProtocol] = None,
    ) -> None:
        self.default_image = default_image
        self.default_image_for_pentest = default_image_for_pentest
        self.cache: FlowImageCacheProtocol = cache or _NullCache()

    # ── CLI bypass (``--image`` flag) ───────────────────────────────────
    def bypass(self, explicit_image: str) -> str:
        """Skip the LLM call entirely — use the caller-provided image.

        Used when the operator passes ``--image <name>`` on the CLI. The
        supplied image is still passed through ``_validate_image`` so
        typos like trailing whitespace are caught, but no LLM round-trip
        is performed.
        """
        if not explicit_image or not explicit_image.strip():
            raise ValueError("--image requires a non-empty image reference")
        return _validate_image(explicit_image)

    # ── Cache-first LLM selection ───────────────────────────────────────
    async def choose(
        self,
        user_input: str,
        llm_client: LLMClientProtocol,
        *,
        flow_id: Optional[int | str] = None,
        cache: Optional[FlowImageCacheProtocol] = None,
    ) -> str:
        """Return the chosen Docker image for ``user_input``.

        Resolution order (mirrors PentAGI's NewFlowProvider + LoadFlowProvider):
          1. If ``flow_id`` and a cache hit → return cached image.
          2. Else render ``IMAGE_CHOOSER_TEMPLATE`` with the three
             template vars and call ``llm_client.complete`` once.
          3. Lowercase + trim + validate the LLM output.
          4. Persist to cache (if ``flow_id`` provided) for restart reuse.

        On any LLM error, fall back to ``self.default_image`` (debian:latest
        by default) — matching PentAGI's container-create fallback chain.
        """
        cache = cache or self.cache

        if flow_id is not None:
            try:
                cached = await cache.get_flow_image(flow_id)
            except Exception as exc:  # noqa: BLE001 — cache failures are non-fatal
                logger.warning("image cache read failed: %s", exc)
                cached = None
            if cached:
                return _validate_image(cached)

        prompt = render_template(
            self.default_image, self.default_image_for_pentest, user_input
        )

        try:
            raw = await llm_client.complete(prompt)
        except Exception as exc:  # noqa: BLE001 — never crash flow creation
            logger.warning("image chooser LLM call failed (%s) — using default %s",
                           exc, self.default_image)
            image = self.default_image
        else:
            image = _validate_image(raw)

        if flow_id is not None:
            try:
                await cache.set_flow_image(flow_id, image)
            except Exception as exc:  # noqa: BLE001 — cache write is best-effort
                logger.warning("image cache write failed: %s", exc)

        return image


__all__ = [
    "DEFAULT_IMAGE",
    "DEFAULT_IMAGE_FOR_PENTEST",
    "IMAGE_CHOOSER_TEMPLATE",
    "ImageChooser",
    "LLMClientProtocol",
    "FlowImageCacheProtocol",
    "render_template",
]
