"""elengenix.api — FastAPI REST API server (port of PentAGI REST surface).

This subpackage ports PentAGI's Gin-based REST API (base path ``/api/v1``,
~85 endpoints across 24 resource groups) to Python/FastAPI. It is
composed of:

* ``app``              — ``create_app()`` factory (FastAPI instance,
  middleware, exception handlers, lifespan hooks, router mounting).
* ``_models``          — shared Pydantic v2 request/response schemas
  plus the response-envelope helpers (``Envelope``, ``success_response``,
  ``error_response``, ``APIError``).
* ``_auth``            — Bearer-token (JWT HS256) + session-cookie
  authentication dependencies. Mirrors PentAGI's
  ``auth_token_required`` / ``auth_user_required`` /
  ``local_user_required`` / ``privileges_required`` middleware.
* ``routes``           — package containing one ``APIRouter`` per
  resource group (``flows``, ``auth``, ``tokens``, ``providers``,
  ``knowledge``, ``health``).

Design constraints:

* Python 3.10+, 4-space indent, line-length 100.
* Each file starts with a module docstring.
* Lazy imports of ``fastapi`` / ``pydantic`` inside ``create_app()`` so
  the package is importable for AST inspection (and so the CLI works)
  even when ``fastapi`` is not installed.
* All endpoints are ``async def`` with full type hints.
* All schemas use Pydantic v2 ``BaseModel``.
* Each module uses ``logging.getLogger("elengenix.api.<module>")``.

The response envelope mirrors PentAGI's ``response.HttpError`` catalog
(``backend/pkg/server/response/http.go``):

    {"status": "success", "data": <any>}
    {"status": "error", "code": "<code>", "msg": "<msg>", "error"?: "<orig>"}

The ``error`` field is only present when the server is running in
``develop`` mode (matches PentAGI's ``develop`` flag).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from .app import create_app


def __getattr__(name: str) -> Any:
    """Lazy attribute lookup — only imports ``fastapi`` when ``create_app``
    is actually accessed. This keeps ``import elengenix.api`` cheap and
    fastapi-free for the CLI / AST-inspection path.
    """
    if name == "create_app":
        from .app import create_app as _create_app

        return _create_app
    raise AttributeError(f"module 'elengenix.api' has no attribute {name!r}")


__all__ = ["create_app"]

__version__ = "2.0.0"
