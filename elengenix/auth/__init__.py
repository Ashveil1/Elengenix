"""elengenix.auth — Bearer-token (JWT HS256) + OAuth2 auth subsystem.

This subpackage ports PentAGI's Go auth stack
(``backend/pkg/server/auth/*``, ``backend/pkg/server/oauth/*``, and the
auth portions of ``backend/pkg/server/services/auth.go``) to Python /
FastAPI. The port is **byte-compatible** with the upstream Go
implementation for the critical primitives:

* **JWT signing-key derivation** — PBKDF2-HMAC-SHA512, 210 000
  iterations, 32-byte output, identical password and salt strings
  (see :func:`elengenix.auth.tokens.derive_jwt_key`). Tokens issued by
  the Go PentAGI server validate in Python Elengenix and vice-versa.
* **OAuth2 state** — HMAC-SHA256-signed JSON blob with the same wire
  format ``base64url(sig || state_json)`` (see
  :func:`elengenix.auth.oauth.build_signed_state`). Allows Go ↔ Python
  interop during the migration window.
* **Token ID** — 10-character base62 with rejection sampling
  (see :func:`elengenix.auth.tokens.generate_token_id`).
* **User hash** — MD5 (matches the Go ``rdb.MakeUserHash``; see the
  note in :func:`elengenix.auth.models.make_user_hash`).

Modules:

* :mod:`elengenix.auth.models`     — Pydantic v2 ``User``, ``Role``,
  ``APIToken``, ``APITokenClaims`` + ``make_user_hash``.
* :mod:`elengenix.auth.tokens`     — JWT HS256 token management
  (issue / validate / revoke) with ``cachetools.TTLCache`` + negative
  caching.
* :mod:`elengenix.auth.sessions`   — Cookie-based sessions using
  ``itsdangerous.URLSafeTimedSerializer`` with sliding refresh.
* :mod:`elengenix.auth.middleware` — FastAPI auth dependencies
  (``try_auth``, ``auth_token_required``, ``auth_user_required``,
  ``local_user_required``, ``privileges_required``).
* :mod:`elengenix.auth.oauth`      — OAuth2 PKCE S256 GitHub + Google
  integration via ``authlib``.

Design constraints:

* Python 3.10+, 4-space indent, line-length 100.
* Each file starts with a docstring.
* All modules use ``logging.getLogger("elengenix.auth.<module>")``.
* All public APIs are fully type-hinted.
* Heavy third-party imports (``pyjwt``, ``authlib``, ``itsdangerous``,
  ``fastapi``, ``starlette``, ``httpx``, ``pydantic``) are **lazy** —
  the package is importable for AST inspection and works in CLI-only
  environments without the FastAPI stack installed.
"""

from __future__ import annotations

# Re-export the public surface from each submodule.
# Heavy objects (Pydantic models, authlib OAuth instance) are built
# lazily on first attribute access — see ``models.__getattr__`` and
# ``tokens.TokenStatusCache``.

from elengenix.auth.models import (
    APIToken,
    APITokenClaims,
    ROLE_USER_ID,
    TOKEN_STATUS_ACTIVE,
    TOKEN_STATUS_EXPIRED,
    TOKEN_STATUS_REVOKED,
    USER_STATUS_ACTIVE,
    USER_STATUS_BLOCKED,
    USER_STATUS_CREATED,
    USER_TYPE_API,
    USER_TYPE_LOCAL,
    USER_TYPE_OAUTH,
    Role,
    User,
    make_user_hash,
)
from elengenix.auth.tokens import (
    MAX_TTL_SECONDS,
    MIN_TTL_SECONDS,
    TokenStatusCache,
    derive_jwt_key,
    generate_token_id,
    issue_token,
    revoke_token,
    token_status_cache,
    validate_token,
)
from elengenix.auth.sessions import (
    DEFAULT_COOKIE_NAME,
    DEFAULT_COOKIE_PATH,
    DEFAULT_SESSION_TTL_SECONDS,
    SESSION_REFRESH_THRESHOLD_SECONDS,
    cookie_attributes,
    create_session_cookie,
    is_https_request,
    refresh_session_cookie,
    should_refresh,
    validate_session_cookie,
)
from elengenix.auth.middleware import (
    PRIVILEGE_AUTOMATION,
    AuthIdentity,
    AuthMiddlewareConfig,
    auth_token_required,
    auth_user_required,
    configure_auth_middleware,
    get_auth_config,
    local_user_required,
    lookup_permission,
    privileges_required,
    try_auth,
)
from elengenix.auth.oauth import (
    GITHUB_EMAILS_URL,
    GITHUB_SCOPES,
    GOOGLE_OIDC_DISCOVERY_URL,
    GOOGLE_SCOPES,
    NONCE_COOKIE_NAME,
    OAuthClient,
    OAuthConfig,
    OAuthRegistry,
    PROVIDER_GITHUB,
    PROVIDER_GOOGLE,
    STATE_COOKIE_NAME,
    STATE_REQUEST_TTL_SECONDS,
    authorize,
    build_signed_state,
    configure_oauth_providers,
    get_oauth_client,
    login_callback,
    oauth_registry,
    parse_signed_state,
    rand_base64_string,
    resolve_email,
)

__all__ = [
    # --- models ---
    "APIToken",
    "APITokenClaims",
    "ROLE_USER_ID",
    "Role",
    "TOKEN_STATUS_ACTIVE",
    "TOKEN_STATUS_EXPIRED",
    "TOKEN_STATUS_REVOKED",
    "USER_STATUS_ACTIVE",
    "USER_STATUS_BLOCKED",
    "USER_STATUS_CREATED",
    "USER_TYPE_API",
    "USER_TYPE_LOCAL",
    "USER_TYPE_OAUTH",
    "User",
    "make_user_hash",
    # --- tokens ---
    "MAX_TTL_SECONDS",
    "MIN_TTL_SECONDS",
    "TokenStatusCache",
    "derive_jwt_key",
    "generate_token_id",
    "issue_token",
    "revoke_token",
    "token_status_cache",
    "validate_token",
    # --- sessions ---
    "DEFAULT_COOKIE_NAME",
    "DEFAULT_COOKIE_PATH",
    "DEFAULT_SESSION_TTL_SECONDS",
    "SESSION_REFRESH_THRESHOLD_SECONDS",
    "cookie_attributes",
    "create_session_cookie",
    "is_https_request",
    "refresh_session_cookie",
    "should_refresh",
    "validate_session_cookie",
    # --- middleware ---
    "PRIVILEGE_AUTOMATION",
    "AuthIdentity",
    "AuthMiddlewareConfig",
    "auth_token_required",
    "auth_user_required",
    "configure_auth_middleware",
    "get_auth_config",
    "local_user_required",
    "lookup_permission",
    "privileges_required",
    "try_auth",
    # --- oauth ---
    "GITHUB_EMAILS_URL",
    "GITHUB_SCOPES",
    "GOOGLE_OIDC_DISCOVERY_URL",
    "GOOGLE_SCOPES",
    "NONCE_COOKIE_NAME",
    "OAuthClient",
    "OAuthConfig",
    "OAuthRegistry",
    "PROVIDER_GITHUB",
    "PROVIDER_GOOGLE",
    "STATE_COOKIE_NAME",
    "STATE_REQUEST_TTL_SECONDS",
    "authorize",
    "build_signed_state",
    "configure_oauth_providers",
    "get_oauth_client",
    "login_callback",
    "oauth_registry",
    "parse_signed_state",
    "rand_base64_string",
    "resolve_email",
]

__version__ = "1.0.0"
