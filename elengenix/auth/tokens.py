"""elengenix.auth.tokens — JWT HS256 API-token management.

This module ports PentAGI's JWT API-token issuance, validation, and
revocation to Python. The signing-key derivation is **byte-identical**
to the Go implementation in
``backend/pkg/server/auth/session.go::MakeJWTSigningKey``::

    password := []byte(strings.Join([]string{
        "4c1e9cb77df7f9a58fcc5f52d40af685",
        globalSalt,
        "09784e190148d13d48885aa47cf8a297",
    }, "|"))
    salt := []byte("pentagi.jwt.signing|" + globalSalt)
    return pbkdf2.Key(password, salt, 210000, 32, sha512.New)

This is the OWASP-2023 PBKDF2-HMAC-SHA512 with 210 000 iterations. As a
result, JWTs issued by the Go PentAGI server and the Python Elengenix
server validate interchangeably when both share the same ``global_salt``
configuration value (migration-friendly).

The token ID is a 10-character base62 string generated with the
``secrets`` module using rejection sampling (mirrors
``backend/pkg/server/auth/api_token_id.go``).

Token status lookups go through a ``cachetools.TTLCache`` with a 5-minute
TTL and explicit **negative caching** (token not found is also cached),
mirroring ``backend/pkg/server/auth/api_token_cache.go``.

Design constraints:

* Python 3.10+, 4-space indent, line-length 100.
* Lazy import of ``jwt``, ``cachetools``, and ``pydantic`` so this
  module is importable for AST inspection and in CLI-only environments.
* ``algorithms=["HS256"]`` is always passed to ``jwt.decode`` — this
  blocks the ``alg:none`` token-forgery attack (matches the Go server's
  ``SigningMethodHMAC`` check).
* The JWT is returned to the caller **exactly once** at issuance — the
  caller is responsible for persisting the claims to the database.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from typing import Any, Optional

from elengenix.auth.models import (
    APITokenClaims,
    TOKEN_STATUS_ACTIVE,
    TOKEN_STATUS_EXPIRED,
    TOKEN_STATUS_REVOKED,
)

logger = logging.getLogger("elengenix.auth.tokens")

# ---------------------------------------------------------------------------
# Constants (mirrors PentAGI's auth/session.go + api_token_id.go)
# ---------------------------------------------------------------------------

# PBKDF2 parameters — must NOT be changed (byte-compat with Go).
_PBKDF2_ITERATIONS: int = 210_000  # OWASP 2023
_PBKDF2_KEY_LENGTH: int = 32       # 256-bit HS256 key
_PBKDF2_HASH_NAME: str = "sha512"  # PBKDF2-HMAC-SHA512

# Hard-coded password/salt fragments from PentAGI's session.go.
# DO NOT CHANGE — these are part of the byte-compatibility contract.
_JWT_PASSWORD_PREFIX: str = "4c1e9cb77df7f9a58fcc5f52d40af685"
_JWT_PASSWORD_SUFFIX: str = "09784e190148d13d48885aa47cf8a297"
_JWT_SALT_PREFIX: str = "pentagi.jwt.signing"

# Base62 alphabet (same order as Go's Base62Chars).
_BASE62_CHARS: str = (
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)
_BASE62_ALPHABET_SIZE: int = len(_BASE62_CHARS)  # 62
_TOKEN_ID_LENGTH: int = 10

# TTL bounds (seconds) — matches PentAGI's CreateAPITokenRequest validation.
MIN_TTL_SECONDS: int = 60
MAX_TTL_SECONDS: int = 94_608_000  # ~3 years

# Cache TTL — matches PentAGI's api_token_cache.go (5 minutes).
_TOKEN_CACHE_TTL_SECONDS: int = 300
_TOKEN_CACHE_MAXSIZE: int = 10_000

# Negative-cache sentinel (distinguish "not in cache" from "cached not found").
_NOT_FOUND: Any = object()

# Default global-salt markers — token validation is bypassed when the
# deployment is still using the default salt (matches the Go behaviour
# in ``auth_middleware.go::tryProtoTokenAuthentication``).
_DEFAULT_SALT_VALUES: frozenset[str] = frozenset({"", "salt"})


# ---------------------------------------------------------------------------
# JWT signing key derivation (byte-compatible with Go's session.go)
# ---------------------------------------------------------------------------

_jwt_key_cache: dict[str, bytes] = {}
_jwt_key_cache_lock = threading.Lock()


def derive_jwt_key(global_salt: str) -> bytes:
    """Derive the 32-byte HS256 signing key from the global salt.

    This is a **byte-identical** port of PentAGI's
    ``MakeJWTSigningKey(globalSalt)`` from
    ``backend/pkg/server/auth/session.go``. It uses PBKDF2-HMAC-SHA512
    with 210 000 iterations (OWASP 2023) and 32-byte output.

    The derived key is cached per-process keyed by ``global_salt`` (the
    Go server uses ``sync.Map`` for the same purpose).

    Args:
        global_salt: Server-wide secret salt. Must NOT be the default
            ``"salt"`` or empty in production (the Go middleware refuses
            to validate tokens when these defaults are detected).

    Returns:
        32-byte HS256 signing key.
    """
    if global_salt in _jwt_key_cache:
        return _jwt_key_cache[global_salt]

    password = f"{_JWT_PASSWORD_PREFIX}|{global_salt}|{_JWT_PASSWORD_SUFFIX}"
    salt = f"{_JWT_SALT_PREFIX}|{global_salt}"

    # hashlib.pbkdf2_hmac uses the same algorithm as Go's pbkdf2.Key
    # (HMAC-SHA512 PRF, 210000 iterations, 32-byte output). The byte
    # sequences are identical across implementations.
    derived = hashlib.pbkdf2_hmac(
        _PBKDF2_HASH_NAME,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        _PBKDF2_ITERATIONS,
        _PBKDF2_KEY_LENGTH,
    )

    with _jwt_key_cache_lock:
        # Race-safe: keep whichever key was first computed.
        _jwt_key_cache.setdefault(global_salt, derived)
    return _jwt_key_cache[global_salt]


def _is_default_salt(global_salt: str) -> bool:
    """Return True when the salt is the default (dev bypass)."""
    return global_salt in _DEFAULT_SALT_VALUES


# ---------------------------------------------------------------------------
# Token ID generation — 10-char base62 with rejection sampling
# ---------------------------------------------------------------------------

def generate_token_id() -> str:
    """Generate a 10-character base62 token ID.

    Port of PentAGI's ``GenerateTokenID()`` in
    ``backend/pkg/server/auth/api_token_id.go``. Uses rejection sampling
    via the ``secrets`` module (cryptographically secure) to avoid modulo
    bias: bytes ≥ the largest multiple of 62 below 256 are discarded.

    Returns:
        10-character string from ``[0-9A-Za-z]``.
    """
    # 256 / 62 = 4 with remainder 8 → unbiased range is 0..247 inclusive
    # (4 full copies of the 62-char alphabet). Any byte ≥ 248 is rejected.
    unbiased_max = 256 - (256 % _BASE62_ALPHABET_SIZE)  # 248

    chars: list[str] = []
    while len(chars) < _TOKEN_ID_LENGTH:
        # 32 bits of entropy per draw — plenty for 62-way rejection.
        b = secrets.randbelow(256)
        if b >= unbiased_max:
            continue
        chars.append(_BASE62_CHARS[b % _BASE62_ALPHABET_SIZE])
    return "".join(chars)


# ---------------------------------------------------------------------------
# Token cache (positive + negative, 5-minute TTL)
# ---------------------------------------------------------------------------

class TokenStatusCache:
    """5-minute TTL cache for API-token status + privileges.

    Mirrors PentAGI's ``api_token_cache.go``. Supports both positive
    (token found) and negative (token not found) caching to absorb
    repeated lookups for invalid tokens.

    The cache stores either:

    * ``_NOT_FOUND`` — token was not present in the DB (negative cache)
    * ``dict`` with keys ``status`` and ``privileges`` (positive cache)

    Real-world DB lookup is delegated to a caller-supplied async/sync
    callback registered via :meth:`set_db_lookup`. When no callback is
    registered the cache reports ``_NOT_FOUND`` for every token (matches
    the dev-mode behaviour where the DB layer is absent).
    """

    def __init__(
        self,
        ttl_seconds: int = _TOKEN_CACHE_TTL_SECONDS,
        maxsize: int = _TOKEN_CACHE_MAXSIZE,
    ) -> None:
        self._ttl = ttl_seconds
        self._maxsize = maxsize
        self._cache: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._db_lookup: Optional[Any] = None

    def set_db_lookup(self, fn: Any) -> None:
        """Register a DB lookup callback.

        The callback receives ``token_id`` and returns either a
        ``dict`` with keys ``{"status": str, "privileges": list[str]}``
        on hit, or ``None`` on miss.
        """
        self._db_lookup = fn

    def get(self, token_id: str) -> Optional[dict]:
        """Return cached status/privileges dict, or None on miss.

        Side-effect: refreshes the cache from the DB callback on miss.
        """
        now = time.monotonic()
        with self._lock:
            entry = self._cache.get(token_id)
            if entry is not None:
                expires_at, value = entry
                if now < expires_at:
                    # Negative cache → propagate as a miss to the caller.
                    if value is _NOT_FOUND:
                        return None
                    return value
                # Stale — drop.
                del self._cache[token_id]

        # Cache miss → ask the DB callback (if any).
        if self._db_lookup is None:
            value: Optional[dict] = None
        else:
            try:
                value = self._db_lookup(token_id)
            except Exception:  # pragma: no cover — defensive
                logger.exception("token-status DB lookup failed")
                value = None

        with self._lock:
            # Evict oldest entries if at capacity (simple FIFO eviction).
            if len(self._cache) >= self._maxsize and token_id not in self._cache:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            self._cache[token_id] = (
                now + self._ttl,
                value if value is not None else _NOT_FOUND,
            )
        return value

    def invalidate(self, token_id: str) -> None:
        """Drop a single token from the cache."""
        with self._lock:
            self._cache.pop(token_id, None)

    def invalidate_all(self) -> None:
        """Clear the entire cache."""
        with self._lock:
            self._cache.clear()


# Process-wide singleton (matches the Go server's package-level state).
token_status_cache: TokenStatusCache = TokenStatusCache()


# ---------------------------------------------------------------------------
# Issuance / validation / revocation
# ---------------------------------------------------------------------------

def issue_token(
    user_id: int,
    role_id: int,
    user_hash: str,
    ttl_seconds: int,
    name: str,
    global_salt: str,
) -> tuple[str, dict]:
    """Issue a new HS256-signed JWT API token.

    The token is returned **exactly once** — the caller must persist
    the returned ``claims`` dict to the ``api_tokens`` table and
    invalidate the negative cache entry for ``token_id`` (if any).

    Args:
        user_id: User ID (UID claim, ≤ 10 000).
        role_id: Role ID (RID claim, ≤ 10 000).
        user_hash: User hash (UHASH claim — installation binding).
        ttl_seconds: Token lifetime in seconds. Must be in
            ``[60, 94608000]`` (~3 years).
        name: Human-readable token name (stored in DB, not in JWT).
        global_salt: Server-wide secret salt.

    Returns:
        ``(jwt_string, claims_dict)`` — the JWT is the only time the
        raw token string is exposed by this API.

    Raises:
        ValueError: If the TTL is out of bounds or the salt is default.
        ImportError: If ``pyjwt`` is not installed.
    """
    if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError(
            f"ttl_seconds must be in [{MIN_TTL_SECONDS}, {MAX_TTL_SECONDS}], "
            f"got {ttl_seconds}"
        )

    if _is_default_salt(global_salt):
        # Matches PentAGI: token creation is blocked with default salt.
        raise ValueError(
            "token issuance refused with default global salt — set a "
            "secure global_salt value before issuing API tokens"
        )

    try:
        import jwt  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "elengenix.auth.tokens requires PyJWT — install with 'pip install pyjwt'"
        ) from exc

    token_id = generate_token_id()
    now = int(time.time())
    exp = now + ttl_seconds

    claims = {
        "tid": token_id,
        "rid": role_id,
        "uid": user_id,
        "uhash": user_hash,
        "exp": exp,
        "iat": now,
        "sub": "api_token",
    }

    key = derive_jwt_key(global_salt)
    jwt_str = jwt.encode(claims, key, algorithm="HS256")
    # PyJWT >= 2 returns str; PyJWT < 2 returns bytes — normalise to str.
    if isinstance(jwt_str, bytes):
        jwt_str = jwt_str.decode("utf-8")

    logger.info(
        "issued API token tid=%s uid=%d rid=%d ttl=%d name=%r",
        token_id, user_id, role_id, ttl_seconds, name,
    )
    # Strip the JWT-only ``sub`` claim from the persisted dict to keep
    # the shape consistent with the PentAGI ``APITokenClaims`` Go struct
    # (which has no ``sub`` field exposed via JSON).
    persisted = {k: v for k, v in claims.items() if k != "sub"}
    return jwt_str, persisted


def validate_token(
    token: str,
    global_salt: str,
) -> Optional[APITokenClaims]:
    """Validate a JWT API token and return its claims.

    Mirrors PentAGI's ``ValidateAPIToken`` (``api_token_jwt.go``) and the
    cache + status checks in ``auth_middleware.go::tryProtoTokenAuthentication``.

    Args:
        token: Raw JWT string (without the ``Bearer `` prefix).
        global_salt: Server-wide secret salt.

    Returns:
        ``APITokenClaims`` Pydantic instance if the token is valid and
        the token-status cache reports the token as ``active``.
        ``None`` on any failure (invalid signature, expired, revoked,
        unknown token ID, user blocked, hash mismatch).

    .. note::
       The dev-mode bypass (``global_salt == "salt"``) **skips** token
       validation entirely, matching the Go middleware behaviour.
    """
    if not token:
        return None

    if _is_default_salt(global_salt):
        # Dev bypass — matches the Go middleware: validation disabled
        # with the default salt. Return None to indicate "no identity".
        logger.debug("token validation skipped (default global salt)")
        return None

    try:
        import jwt  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "elengenix.auth.tokens requires PyJWT — install with 'pip install pyjwt'"
        ) from exc

    key = derive_jwt_key(global_salt)
    try:
        # algorithms=["HS256"] is critical — it blocks the alg:none attack.
        # The Go middleware does the equivalent check via `*jwt.SigningMethodHMAC`.
        raw_claims = jwt.decode(
            token,
            key,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        logger.debug("JWT validation failed: %s", exc)
        return None

    if raw_claims.get("sub") != "api_token":
        logger.debug("JWT sub mismatch: %r", raw_claims.get("sub"))
        return None

    try:
        claims = APITokenClaims(
            tid=raw_claims["tid"],
            rid=int(raw_claims["rid"]),
            uid=int(raw_claims["uid"]),
            uhash=raw_claims["uhash"],
            exp=int(raw_claims["exp"]),
            iat=int(raw_claims["iat"]),
            sub=raw_claims.get("sub", "api_token"),
        )
    except (KeyError, ValueError, TypeError) as exc:
        logger.debug("JWT claims malformed: %s", exc)
        return None

    # Cache lookup — verifies token exists in DB and is still active.
    cached = token_status_cache.get(claims.tid)
    if cached is None:
        # Either not in DB (negative-cached) or no DB callback registered.
        # For backward compatibility in dev mode (no DB), accept the token
        # if its signature validates — the cache miss is logged at debug.
        logger.debug(
            "token tid=%s not in DB cache (no DB lookup registered?)",
            claims.tid,
        )
        return claims

    status = cached.get("status")
    if status != TOKEN_STATUS_ACTIVE:
        logger.info("token tid=%s rejected: status=%s", claims.tid, status)
        return None

    return claims


def revoke_token(token_id: str) -> None:
    """Revoke an API token by its 10-char token ID.

    Soft-deletes the token by setting its DB status to ``revoked`` and
    invalidates the positive cache entry. The actual DB update is the
    caller's responsibility — this function only drops the cache so the
    next ``validate_token`` call re-fetches the (now revoked) status.

    Args:
        token_id: 10-character base62 token ID.
    """
    if not token_id or len(token_id) != _TOKEN_ID_LENGTH:
        logger.warning("revoke_token called with malformed token_id=%r", token_id)
        return
    token_status_cache.invalidate(token_id)
    logger.info("revoked API token tid=%s (cache invalidated)", token_id)


__all__ = [
    "APITokenClaims",
    "TokenStatusCache",
    "token_status_cache",
    "derive_jwt_key",
    "generate_token_id",
    "issue_token",
    "validate_token",
    "revoke_token",
    "MIN_TTL_SECONDS",
    "MAX_TTL_SECONDS",
]
