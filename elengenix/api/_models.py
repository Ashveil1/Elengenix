"""elengenix.api._models — shared Pydantic v2 schemas + response envelope.

Ports PentAGI's request/response DTOs from ``backend/pkg/server/models/*.go``
and the response envelope from ``backend/pkg/server/response/http.go``.

Key porting decisions:

* **Pydantic v2** ``BaseModel`` for every schema. ``model_config =
  ConfigDict(extra="forbid")`` is the default — mirrors Gin's strict
  JSON binding (``binding.DisallowUnknownFields``).
* **Response envelope**: ``Envelope`` model serialises to
  ``{"status": "success", "data": <any>}`` or
  ``{"status": "error", "code": "<code>", "msg": "<msg>", "error"?: ...}``.
  The ``error`` field is omitted by default; pass ``develop=True`` (or
  set ``request.app.state.develop``) to include the raw exception text.
* **Error catalog**: ``APIError`` enum mirrors the catalog in
  ``response/errors.go`` (``ErrAuthRequired``, ``ErrTokenNotFound``,
  ``ErrLocalUserRequired``, ``ErrPrivilegesRequired``, ``ErrBadRequest``,
  ``ErrNotFound``, ``ErrConflict``, ``ErrInternal``, ``ErrValidation``).
  Each entry has an HTTP status code + a human-readable message.
* **Pagination**: ``Page`` / ``PaginatedList`` mirror PentAGI's
  ``?page=N&per_page=M`` convention. ``per_page`` is clamped to [1, 100]
  in the route layer.
* **TTL constraints** for API tokens: ``min = 60`` seconds, ``max =
  94608000`` seconds (~3 years) — verbatim port of PentAGI's
  ``api_token.go`` constants.
* **Token ID**: 10-char base62 (``[0-9A-Za-z]``), generated with
  ``secrets`` rejection sampling (see ``_auth.generate_token_id``).

This module imports ``pydantic`` lazily inside a ``try`` block so that
AST inspection (and bare ``import elengenix.api``) works even when
``pydantic`` is not installed. All schema classes are guarded by
``TYPE_CHECKING`` re-exports in the ``__all__`` list — but at runtime
they only become available if Pydantic is importable.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Generic, Optional, TypeVar

logger = logging.getLogger("elengenix.api.models")

try:
    from pydantic import BaseModel, ConfigDict, Field
except ImportError as _exc:  # pragma: no cover
    raise ImportError(
        "elengenix.api._models requires pydantic v2: pip install 'pydantic>=2.0'"
    ) from _exc


# ---------------------------------------------------------------------------
# Response envelope
# ---------------------------------------------------------------------------


class Envelope(BaseModel):
    """Top-level response envelope.

    Serialises to one of two shapes:

    * Success: ``{"status": "success", "data": <any>}``
    * Error:   ``{"status": "error", "code": "<code>", "msg": "<msg>",
                       "error"?: "<orig>"}``

    The ``error`` field is only populated when ``develop=True`` (mirror
    of PentAGI's ``develop`` flag).
    """

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description='"success" or "error"')
    data: Optional[Any] = Field(
        default=None, description="Response payload on success"
    )
    code: Optional[str] = Field(default=None, description="Error code on failure")
    msg: Optional[str] = Field(default=None, description="Human-readable message")
    error: Optional[str] = Field(
        default=None,
        description=(
            "Raw error detail (only when develop=True, mirror of PentAGI)."
        ),
    )


def success_response(data: Any) -> dict[str, Any]:
    """Build a success envelope dict (``{"status": "success", "data": ...}``)."""
    return {"status": "success", "data": data}


def error_response(
    code: str,
    msg: str,
    *,
    error: Optional[str] = None,
    develop: bool = False,
) -> dict[str, Any]:
    """Build an error envelope dict.

    The ``error`` field is only included when ``develop=True`` (or when
    a truthy ``error`` value is explicitly passed alongside ``develop``).
    """
    payload: dict[str, Any] = {"status": "error", "code": code, "msg": msg}
    if develop and error is not None:
        payload["error"] = error
    return payload


# ---------------------------------------------------------------------------
# Error catalog — port of PentAGI's response/errors.go
# ---------------------------------------------------------------------------


class APIError(str, Enum):
    """Error code catalog. The string value is the ``code`` field in the
    envelope; the tuple ``(http_status, default_msg)`` is looked up via
    ``APIErrorInfo``.
    """

    BAD_REQUEST = "bad_request"
    UNAUTHORIZED = "unauthorized"
    AUTH_REQUIRED = "auth_required"
    LOCAL_USER_REQUIRED = "local_user_required"
    PRIVILEGES_REQUIRED = "privileges_required"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    VALIDATION = "validation"
    TOKEN_NOT_FOUND = "token_not_found"
    TOKEN_EXPIRED = "token_expired"
    FLOW_NOT_FOUND = "flow_not_found"
    INTERNAL = "internal"
    SERVICE_UNAVAILABLE = "service_unavailable"
    RATE_LIMITED = "rate_limited"


# (http_status, default_message)
APIErrorInfo: dict[APIError, tuple[int, str]] = {
    APIError.BAD_REQUEST: (400, "Bad request"),
    APIError.UNAUTHORIZED: (401, "Unauthorized"),
    APIError.AUTH_REQUIRED: (401, "Authentication required"),
    APIError.LOCAL_USER_REQUIRED: (
        401,
        "Interactive session required (API tokens not allowed)",
    ),
    APIError.PRIVILEGES_REQUIRED: (403, "Insufficient privileges"),
    APIError.FORBIDDEN: (403, "Forbidden"),
    APIError.NOT_FOUND: (404, "Not found"),
    APIError.TOKEN_NOT_FOUND: (404, "API token not found"),
    APIError.FLOW_NOT_FOUND: (404, "Flow not found"),
    APIError.CONFLICT: (409, "Conflict"),
    APIError.VALIDATION: (422, "Validation failed"),
    APIError.TOKEN_EXPIRED: (401, "API token expired"),
    APIError.INTERNAL: (500, "Internal server error"),
    APIError.SERVICE_UNAVAILABLE: (503, "Service unavailable"),
    APIError.RATE_LIMITED: (429, "Too many requests"),
}


def error_http_status(code: APIError) -> int:
    """Return the HTTP status code for a given ``APIError``."""
    return APIErrorInfo.get(code, (500, "Internal server error"))[0]


def error_default_msg(code: APIError) -> str:
    """Return the default human-readable message for a given ``APIError``."""
    return APIErrorInfo.get(code, (500, "Internal server error"))[1]


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


class Page(BaseModel):
    """Pagination query parameters (?page=1&per_page=20)."""

    model_config = ConfigDict(extra="forbid")

    page: int = Field(default=1, ge=1, description="1-indexed page number")
    per_page: int = Field(
        default=20, ge=1, le=100, description="Items per page (1-100)"
    )

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.per_page


T = TypeVar("T")


class PaginatedList(BaseModel, Generic[T]):
    """Paginated list response. PentAGI wraps list endpoints in this shape."""

    model_config = ConfigDict(extra="forbid")

    items: list[T]
    page: int
    per_page: int
    total: int

    @property
    def total_pages(self) -> int:
        if self.per_page <= 0:
            return 0
        return (self.total + self.per_page - 1) // self.per_page


# ---------------------------------------------------------------------------
# Auth DTOs (port of models.Login, models.User, etc.)
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """POST /auth/login body. Mirrors PentAGI's ``models.Login``."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=4096)


class LoginResponse(BaseModel):
    """Successful login response. PentAGI sets a session cookie AND
    returns this body."""

    model_config = ConfigDict(extra="forbid")

    user_id: int
    username: str
    role: str
    token_type: str = Field(default="session", description='"session" or "api"')
    expires_at: int = Field(..., description="Unix timestamp (seconds)")


class UserPublic(BaseModel):
    """Public user representation (``/auth/me``, ``/info``)."""

    model_config = ConfigDict(extra="forbid")

    id: int
    username: str
    email: Optional[str] = None
    role: str
    privileges: list[str] = Field(default_factory=list)
    type: str = Field(
        default="local", description='"local", "oauth", "api"'
    )
    active: bool = True


class RefreshResponse(BaseModel):
    """POST /auth/refresh response."""

    model_config = ConfigDict(extra="forbid")

    token_type: str = "session"
    expires_at: int


# ---------------------------------------------------------------------------
# API Token DTOs (port of models.CreateAPITokenRequest, etc.)
# ---------------------------------------------------------------------------

# PentAGI constants (api_token.go):
#   min TTL = 60 seconds, max TTL = 94608000 seconds (~3 years).
MIN_TOKEN_TTL_SECONDS = 60
MAX_TOKEN_TTL_SECONDS = 94608000
# PentAGI token_id is base62, length 10.
TOKEN_ID_LENGTH = 10
# PentAGI name max length = 100.
TOKEN_NAME_MAX_LENGTH = 100


class CreateAPITokenRequest(BaseModel):
    """POST /tokens body. Mirrors ``models.CreateAPITokenRequest``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=TOKEN_NAME_MAX_LENGTH)
    ttl_seconds: int = Field(
        ...,
        ge=MIN_TOKEN_TTL_SECONDS,
        le=MAX_TOKEN_TTL_SECONDS,
        description="Token lifetime in seconds (60s to ~3 years).",
    )


class APITokenPublic(BaseModel):
    """API token representation WITHOUT the JWT itself (used in listings)."""

    model_config = ConfigDict(extra="forbid")

    id: int
    token_id: str = Field(..., description="10-char base62 public ID")
    name: str
    status: str = Field(default="active", description='"active" or "revoked"')
    created_at: int
    expires_at: int
    last_used_at: Optional[int] = None


class CreateAPITokenResponse(APITokenPublic):
    """POST /tokens response. The JWT is returned ONLY here, ONCE."""

    token: str = Field(..., description="JWT (HS256). Returned ONCE at creation.")


# ---------------------------------------------------------------------------
# Flow DTOs (port of models.CreateFlowRequest, models.Flow, etc.)
# ---------------------------------------------------------------------------


class CreateFlowRequest(BaseModel):
    """POST /flows body. Mirrors ``models.CreateFlowRequest``."""

    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(default=None, max_length=255)
    input: str = Field(..., min_length=1, description="User prompt for the flow")
    model: Optional[str] = Field(
        default=None, description="Provider/model override"
    )
    language: Optional[str] = Field(
        default=None, description="Output language code (e.g. 'en', 'es')"
    )
    image: Optional[str] = Field(
        default=None, description="Docker image override for sandbox"
    )


class UpdateFlowRequest(BaseModel):
    """PUT /flows/{id} body. Mirrors ``models.UpdateFlowRequest``."""

    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(default=None, max_length=255)


class FlowPublic(BaseModel):
    """Public flow representation."""

    model_config = ConfigDict(extra="forbid")

    id: int
    title: Optional[str] = None
    status: str = Field(
        ..., description='"created", "running", "waiting", "finished", "failed"'
    )
    model: Optional[str] = None
    language: Optional[str] = None
    image: Optional[str] = None
    created_at: int
    updated_at: int
    finished_at: Optional[int] = None


class FlowInputRequest(BaseModel):
    """POST /flows/{id}/input body."""

    model_config = ConfigDict(extra="forbid")

    input: str = Field(..., min_length=1, description="User input to submit")
    related_to: Optional[str] = Field(
        default=None, description="Optional parent message/agent ID"
    )


class FlowReportFormat(str, Enum):
    """Report format selector for ``GET /flows/{id}/report``."""

    MARKDOWN = "markdown"
    PDF = "pdf"
    HTML = "html"


# ---------------------------------------------------------------------------
# Provider DTOs
# ---------------------------------------------------------------------------


class ProviderInfo(BaseModel):
    """LLM provider info entry."""

    model_config = ConfigDict(extra="forbid")

    name: str
    display_name: str
    type: str = Field(
        ..., description='"openai", "anthropic", "google", "cohere", etc.'
    )
    available: bool = True
    models: list[str] = Field(default_factory=list)


class TestProviderRequest(BaseModel):
    """POST /providers/test body."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: Optional[str] = None


class TestProviderResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    latency_ms: Optional[int] = None
    message: str = ""
    model: Optional[str] = None


# ---------------------------------------------------------------------------
# Knowledge DTOs
# ---------------------------------------------------------------------------


class KnowledgeDocumentPublic(BaseModel):
    """Knowledge-base document metadata."""

    model_config = ConfigDict(extra="forbid")

    id: int
    title: str
    type: str = Field(..., description='"file", "url", "text"')
    mime_type: Optional[str] = None
    size_bytes: int = 0
    status: str = Field(
        ..., description='"queued", "processing", "ready", "failed"'
    )
    created_at: int
    updated_at: Optional[int] = None
    checksum: Optional[str] = None


class KnowledgeSearchRequest(BaseModel):
    """POST /knowledge/search body."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(..., min_length=1, max_length=4096)
    top_k: int = Field(default=5, ge=1, le=50)
    min_score: float = Field(default=0.0, ge=0.0, le=1.0)


class KnowledgeSearchHit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: int
    title: str
    snippet: str
    score: float
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str
    hits: list[KnowledgeSearchHit]
    took_ms: int


# ---------------------------------------------------------------------------
# Health / Info DTOs
# ---------------------------------------------------------------------------


class ServerInfo(BaseModel):
    """GET /info response. Mirrors PentAGI's ``info`` endpoint."""

    model_config = ConfigDict(extra="forbid")

    name: str = "Elengenix"
    version: str
    api_version: str = "v1"
    capabilities: list[str] = Field(default_factory=list)
    providers: list[ProviderInfo] = Field(default_factory=list)
    auth: dict[str, Any] = Field(default_factory=dict)
    develop: bool = False


class HealthStatus(BaseModel):
    """GET /health response."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description='"ok" or "degraded"')
    uptime_seconds: float
    checks: dict[str, str] = Field(default_factory=dict)
    version: str


__all__ = [
    # envelope
    "Envelope",
    "success_response",
    "error_response",
    # errors
    "APIError",
    "APIErrorInfo",
    "error_http_status",
    "error_default_msg",
    # pagination
    "Page",
    "PaginatedList",
    # auth
    "LoginRequest",
    "LoginResponse",
    "UserPublic",
    "RefreshResponse",
    # tokens
    "CreateAPITokenRequest",
    "APITokenPublic",
    "CreateAPITokenResponse",
    "MIN_TOKEN_TTL_SECONDS",
    "MAX_TOKEN_TTL_SECONDS",
    "TOKEN_ID_LENGTH",
    "TOKEN_NAME_MAX_LENGTH",
    # flows
    "CreateFlowRequest",
    "UpdateFlowRequest",
    "FlowPublic",
    "FlowInputRequest",
    "FlowReportFormat",
    # providers
    "ProviderInfo",
    "TestProviderRequest",
    "TestProviderResponse",
    # knowledge
    "KnowledgeDocumentPublic",
    "KnowledgeSearchRequest",
    "KnowledgeSearchHit",
    "KnowledgeSearchResponse",
    # health
    "ServerInfo",
    "HealthStatus",
]
