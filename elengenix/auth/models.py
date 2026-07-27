"""elengenix.auth.models — Pydantic models for the auth subsystem.

This module ports PentAGI's user/role/api-token GORM models
(``backend/pkg/server/models/{users,roles,api_tokens}.go``) to Pydantic v2
``BaseModel`` subclasses and provides ``make_user_hash`` — the user-hash
generator that mirrors PentAGI's ``rdb.MakeUserHash``.

Design constraints:

* Python 3.10+, 4-space indent, line-length 100.
* All fields are typed; Pydantic v2 is used (not v1 ``BaseModel``).
* No FastAPI / DB import — this module is importable for AST inspection.
* Lazy import of ``pydantic`` so the module is importable even when the
  FastAPI stack is not installed (CLI mode).

The JWT ``APITokenClaims`` model mirrors the Go struct from
``backend/pkg/server/models/api_tokens.go``::

    type APITokenClaims struct {
        TokenID string `json:"tid" validate:"required,len=10"`
        RID     uint64 `json:"rid" validate:"min=0,max=10000"`
        UID     uint64 `json:"uid" validate:"min=0,max=10000"`
        UHASH   string `json:"uhash" validate:"required"`
        jwt.RegisteredClaims  // exp, iat, sub="api_token"
    }
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("elengenix.auth.models")

# ---------------------------------------------------------------------------
# Constants (mirrors backend/pkg/server/models/{users,roles,api_tokens}.go)
# ---------------------------------------------------------------------------

# Default role ID for OAuth users (matches PentAGI's RoleUser constant).
ROLE_USER_ID: int = 2

# User types — string enum matching PentAGI's UserType (Go).
USER_TYPE_LOCAL: str = "local"
USER_TYPE_OAUTH: str = "oauth"
USER_TYPE_API: str = "api"

# User status — string enum matching PentAGI's UserStatus (Go).
USER_STATUS_CREATED: str = "created"
USER_STATUS_ACTIVE: str = "active"
USER_STATUS_BLOCKED: str = "blocked"

# API token status — string enum matching PentAGI's TokenStatus (Go).
TOKEN_STATUS_ACTIVE: str = "active"
TOKEN_STATUS_REVOKED: str = "revoked"
TOKEN_STATUS_EXPIRED: str = "expired"

# Salt used by PentAGI's rdb.MakeUserHash (Go source).
_USER_HASH_SALT: str = "248a8bd896595be1319e65c308a903c568afdb9b"


# ---------------------------------------------------------------------------
# Lazy Pydantic import
# ---------------------------------------------------------------------------

def _get_base_model() -> Any:
    """Lazy-import Pydantic v2 ``BaseModel``.

    Raises ``ImportError`` with a helpful hint if Pydantic is missing.
    """
    try:
        from pydantic import BaseModel, Field
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "elengenix.auth.models requires pydantic v2 — install with "
            "'pip install \"pydantic>=2.0\"'"
        ) from exc
    return BaseModel, Field


# ---------------------------------------------------------------------------
# User hash generation — port of PentAGI's rdb.MakeUserHash
# ---------------------------------------------------------------------------

def make_user_hash(name: str) -> str:
    """Generate a user hash from a name/email.

    This is a **byte-compatible** port of PentAGI's
    ``rdb.MakeUserHash(name)`` (Go source:
    ``backend/pkg/server/rdb/table.go:349``)::

        func MakeUserHash(name string) string {
            currentTime := time.Now().Format("2006-01-02 15:04:05.000000000")
            return MakeMD5Hash(name+currentTime, _USER_HASH_SALT)
        }

        func MakeMD5Hash(value, salt string) string {
            currentTime := time.Now().Format("2006-01-02 15:04:05.000000000")
            hash := md5.Sum([]byte(currentTime + value + salt))
            return hex.EncodeToString(hash[:])
        }

    The Go reference format ``"2006-01-02 15:04:05.000000000"`` is the
    canonical Go time layout that renders as ``YYYY-MM-DD HH:MM:SS.nnnnnnnnn``
    (nanosecond precision, padded with trailing zeros to 9 digits).

    .. note::
       The task description parenthetically notes "SHA256", but the actual
       PentAGI Go source uses **MD5** (see ``rdb.MakeMD5Hash``). To stay
       byte-compatible with the upstream Go implementation — which is the
       hard constraint — we use MD5 here. If/when PentAGI migrates the
       algorithm, this function must be updated in lockstep.

    Args:
        name: User name/email to hash.

    Returns:
        32-character lowercase hex MD5 digest.
    """
    # Go's time.Now().Format("2006-01-02 15:04:05.000000000") is the
    # equivalent of Python's strftime("%Y-%m-%d %H:%M:%S.") followed by
    # the current microsecond padded to 9 digits with trailing zeros
    # (i.e. nanosecond-format precision where the last 3 digits are
    # always zero because Python's datetime only goes to microseconds).
    now = datetime.now(timezone.utc)
    # Microseconds padded to 9 digits (nanosecond-format) — Python only
    # exposes microsecond resolution, so the last 3 digits are always 0.
    ns_str = f"{now.microsecond:06d}000"
    current_time = now.strftime("%Y-%m-%d %H:%M:%S.") + ns_str

    value = name + current_time
    salt = _USER_HASH_SALT
    payload = (current_time + value + salt).encode("utf-8")
    return hashlib.md5(payload).hexdigest()  # noqa: S324 — byte-compat with Go


# ---------------------------------------------------------------------------
# Lazy Pydantic model definitions
# ---------------------------------------------------------------------------

# We use a lazy factory pattern so that the module is importable even when
# pydantic is not installed (e.g., CLI-only environments). The first call
# to any model constructor triggers the import.

_models_cache: dict[str, Any] = {}


def _build_models() -> dict[str, Any]:
    """Build and cache Pydantic model classes on first use."""
    if _models_cache:
        return _models_cache

    BaseModel, Field = _get_base_model()

    class User(BaseModel):
        """Pydantic port of PentAGI's ``models.User`` (Go).

        Mirrors the JSON field names from the Go struct tags.
        """

        id: int = Field(default=0, ge=0, description="User primary key")
        email: str = Field(..., max_length=50, alias="mail")
        name: str = Field(default="", max_length=70)
        role_id: int = Field(default=ROLE_USER_ID, ge=0)
        type: str = Field(
            default=USER_TYPE_LOCAL,
            description="One of: local, oauth, api",
        )
        status: str = Field(
            default=USER_STATUS_CREATED,
            description="One of: created, active, blocked",
        )
        hash: str = Field(default="", description="32-char MD5 user hash")
        created_at: Optional[datetime] = None

        model_config = {"populate_by_name": True, "extra": "ignore"}

    class Role(BaseModel):
        """Pydantic port of PentAGI's ``models.Role`` (Go)."""

        id: int = Field(default=0, ge=0)
        name: str = Field(..., max_length=50)
        privileges: list[str] = Field(default_factory=list)

        model_config = {"extra": "ignore"}

    class APIToken(BaseModel):
        """Pydantic port of PentAGI's ``models.APIToken`` (Go)."""

        id: int = Field(default=0, ge=0, description="Token DB primary key")
        user_id: int = Field(..., ge=0)
        role_id: int = Field(..., ge=0)
        token_id: str = Field(..., min_length=10, max_length=10)
        name: Optional[str] = Field(default=None, max_length=100)
        ttl: int = Field(..., ge=60, le=94608000, description="TTL in seconds")
        status: str = Field(default=TOKEN_STATUS_ACTIVE)
        created_at: Optional[datetime] = None
        expires_at: Optional[datetime] = None
        last_used_at: Optional[datetime] = None

        model_config = {"extra": "ignore"}

    class APITokenClaims(BaseModel):
        """Pydantic port of PentAGI's ``models.APITokenClaims`` (Go).

        Used as JWT claims payload. Field names match the Go struct's
        JSON tags (``tid``, ``rid``, ``uid``, ``uhash``, ``exp``, ``iat``,
        ``sub``).
        """

        tid: str = Field(..., min_length=10, max_length=10, description="Token ID")
        rid: int = Field(..., ge=0, le=10000, description="Role ID")
        uid: int = Field(..., ge=0, le=10000, description="User ID")
        uhash: str = Field(..., description="User hash (MD5 hex)")
        exp: int = Field(..., description="Expiration time (Unix seconds)")
        iat: int = Field(..., description="Issued-at time (Unix seconds)")
        sub: str = Field(default="api_token")

        model_config = {"extra": "ignore"}

    _models_cache.update(
        User=User,
        Role=Role,
        APIToken=APIToken,
        APITokenClaims=APITokenClaims,
    )
    return _models_cache


def _get(name: str) -> Any:
    """Look up a cached Pydantic model class (building on first call)."""
    return _build_models()[name]


# Expose the model classes through module-level attribute access so
# ``from elengenix.auth.models import User`` works even though the class
# is built lazily on first access.

def __getattr__(name: str) -> Any:  # pragma: no cover — simple dispatch
    if name in {"User", "Role", "APIToken", "APITokenClaims"}:
        return _get(name)
    raise AttributeError(f"module 'elengenix.auth.models' has no attribute {name!r}")


def __dir__() -> list[str]:  # pragma: no cover
    return sorted(
        list(globals().keys())
        + ["User", "Role", "APIToken", "APITokenClaims"]
    )


__all__ = [
    "User",
    "Role",
    "APIToken",
    "APITokenClaims",
    "make_user_hash",
    "ROLE_USER_ID",
    "USER_TYPE_LOCAL",
    "USER_TYPE_OAUTH",
    "USER_TYPE_API",
    "USER_STATUS_CREATED",
    "USER_STATUS_ACTIVE",
    "USER_STATUS_BLOCKED",
    "TOKEN_STATUS_ACTIVE",
    "TOKEN_STATUS_REVOKED",
    "TOKEN_STATUS_EXPIRED",
]
