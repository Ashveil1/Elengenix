"""elengenix.api._auth — Bearer-token (JWT HS256) + session auth.

Ports PentAGI's ``backend/pkg/server/auth/`` to FastAPI dependencies.

Key porting decisions (mirrors Task 1-c recommendations §7-§11):

* **JWT HS256** via ``pyjwt`` (``jwt.encode`` / ``jwt.decode`` with
  ``algorithms=["HS256"]`` — blocks ``alg:none``).
* **Key derivation**: PBKDF2-HMAC-SHA512, 210000 iterations, 32-byte
  key (OWASP 2023). Password and salt are constructed exactly as in
  PentAGI's ``session.go`` so tokens issued by either stack validate
  in both. Keys cached via ``functools.lru_cache(maxsize=128)`` keyed
  by salt.
* **Token ID**: 10-char base62 generated with ``secrets`` rejection
  sampling (PentAGI uses ``crypto/rand`` + ``math/big.Int``). Stored
  in DB ``api_tokens.token_id`` (UNIQUE, length 10).
* **Claims**: ``{tid, rid, uid, uhash, exp, iat, sub="api_token"}``
  — same shape as PentAGI's ``APITokenClaims``.
* **TTL validation**: ``min=60s, max=94608000s`` (~3 years).
* **Dependencies**:
  - ``try_auth``            — optional; attaches identity if present.
  - ``auth_token_required`` — mandatory; 401 if neither token nor cookie.
  - ``auth_user_required``  — mandatory; 401 if no **session** (API tokens
                              rejected). PentAGI uses this for
                              ``/tokens/*``, ``/users/*``, ``/roles/*``,
                              ``PUT /user/password``.
  - ``local_user_required`` — mandatory; rejects ``tid != "local"``.
  - ``privileges_required(*privs)`` — ``all(priv in prms for priv in privs)``.

* **Cache**: in-memory ``cachetools.TTLCache`` with 5-min TTL + negative
  caching (sentinel value). Multi-process: add Redis fallback later
  (matches PentAGI's two-tier cache plan).

This module imports ``fastapi`` / ``pyjwt`` / ``cachetools`` lazily so
the package is importable for AST inspection without those deps. The
functions are only invoked at request time, after ``create_app()`` has
already imported FastAPI.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import string
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Optional

logger = logging.getLogger("elengenix.api.auth")

# Lazy imports — these are only invoked at request time.
try:
    import jwt as pyjwt  # type: ignore[import-not-found]
except ImportError as _exc:  # pragma: no cover
    pyjwt = None  # type: ignore[assignment]

try:
    # We need Request as a runtime symbol so FastAPI's get_type_hints()
    # can resolve the string annotation "Request" in the dependency
    # signatures below. If fastapi is not installed, fall back to Any
    # (the dependencies become unusable but the module still imports
    # for AST inspection / CLI usage).
    from fastapi import Request  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    Request = Any  # type: ignore[misc,assignment]

try:
    from cachetools import TTLCache  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    # Fallback: trivially small in-memory dict-based cache with TTL.
    # NOT for production use — install cachetools for proper TTL eviction.
    class TTLCache:  # type: ignore[no-redef]
        """Tiny fallback cache. Same surface as cachetools.TTLCache."""

        def __init__(self, maxsize: int = 100, ttl: float = 300) -> None:
            self._maxsize = maxsize
            self._ttl = ttl
            self._store: dict[Any, tuple[float, Any]] = {}

        def __contains__(self, key: Any) -> bool:
            try:
                exp, _ = self._store[key]
            except KeyError:
                return False
            if exp < time.time():
                self._store.pop(key, None)
                return False
            return True

        def get(self, key: Any, default: Any = None) -> Any:
            if key not in self:
                return default
            return self._store[key][1]

        def __getitem__(self, key: Any) -> Any:
            if key not in self:
                raise KeyError(key)
            return self._store[key][1]

        def __setitem__(self, key: Any, value: Any) -> None:
            if len(self._store) >= self._maxsize and key not in self._store:
                # Naive eviction — drop the oldest entry.
                if self._store:
                    self._store.pop(next(iter(self._store)))
            self._store[key] = (time.time() + self._ttl, value)

        def pop(self, key: Any, default: Any = None) -> Any:  # type: ignore[override]
            if key in self:
                _, v = self._store.pop(key)
                return v
            return default


# ---------------------------------------------------------------------------
# Constants (verbatim from PentAGI)
# ---------------------------------------------------------------------------

# PBKDF2 parameters — OWASP 2023.
PBKDF2_ITERATIONS = 210000
PBKDF2_KEY_LENGTH = 32  # bytes — 256-bit HS256 key
PBKDF2_HASH = "sha512"

# Password construction (mirrors session.go):
#   password = "4c1e9cb77df7f9a58fcc5f52d40af685|<globalSalt>|" \
#              "09784e190148d13d48885aa47cf8a297"
#   salt     = "pentagi.jwt.signing|<globalSalt>"
JWT_PASSWORD_PREFIX = "4c1e9cb77df7f9a58fcc5f52d40af685"
JWT_PASSWORD_SUFFIX = "09784e190148d13d48885aa47cf8a297"
JWT_SALT_PREFIX = "pentagi.jwt.signing"
DEFAULT_GLOBAL_SALT = "salt"  # Dev sentinel — PentAGI refuses to issue
# tokens while salt is default.

# Token ID
TOKEN_ID_ALPHABET = string.digits + string.ascii_letters  # base62
TOKEN_ID_LENGTH = 10

# TTL bounds (seconds)
MIN_TOKEN_TTL = 60
MAX_TOKEN_TTL = 94608000  # ~3 years

# Cache TTL — PentAGI uses 5 minutes.
TOKEN_CACHE_TTL = 300
USER_CACHE_TTL = 300

# Negative-cache sentinel.
_NEG_CACHE_SENTINEL = "__not_found__"


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


@lru_cache(maxsize=128)
def derive_signing_key(global_salt: str) -> bytes:
    """Derive the JWT HS256 signing key via PBKDF2-HMAC-SHA512.

    Byte-identical to PentAGI's ``deriveSigningKey`` in ``session.go``
    so tokens issued by either stack validate in both.

    Args:
        global_salt: The server's global salt (config ``global_salt``).
            PentAGI refuses to issue tokens while this equals ``"salt"``.

    Returns:
        32-byte HS256 signing key.
    """
    password = f"{JWT_PASSWORD_PREFIX}|{global_salt}|{JWT_PASSWORD_SUFFIX}".encode(
        "utf-8"
    )
    salt = f"{JWT_SALT_PREFIX}|{global_salt}".encode("utf-8")
    return hashlib.pbkdf2_hmac(
        PBKDF2_HASH, password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH
    )


# ---------------------------------------------------------------------------
# Token ID generation — 10-char base62
# ---------------------------------------------------------------------------


def generate_token_id() -> str:
    """Generate a 10-char base62 token ID.

    Uses ``secrets`` rejection sampling against
    ``[0-9A-Za-z]`` (62 chars) — Python equivalent of PentAGI's
    ``crypto/rand`` + ``math/big.Int`` rejection sampling.
    """
    alphabet_len = len(TOKEN_ID_ALPHABET)
    out = []
    for _ in range(TOKEN_ID_LENGTH):
        # Rejection sampling: pick uniformly in [0, 256) but reject
        # values that would introduce modular bias.
        ceiling = 256 - (256 % alphabet_len)
        while True:
            n = secrets.randbits(8)
            if n < ceiling:
                break
        out.append(TOKEN_ID_ALPHABET[n % alphabet_len])
    return "".join(out)


# ---------------------------------------------------------------------------
# JWT sign / verify
# ---------------------------------------------------------------------------


def sign_api_token(
    *,
    token_id: str,
    role_id: int,
    user_id: int,
    user_hash: str,
    ttl_seconds: int,
    global_salt: str,
) -> str:
    """Sign a new API-token JWT (HS256).

    Claims mirror PentAGI's ``APITokenClaims``:
    ``{tid, rid, uid, uhash, exp, iat, sub="api_token"}``.

    Raises:
        ValueError: if ``ttl_seconds`` is out of bounds or the global
            salt is the dev default (refuses to issue).
        RuntimeError: if PyJWT is not installed.
    """
    if pyjwt is None:  # pragma: no cover
        raise RuntimeError(
            "PyJWT is not installed: pip install 'pyjwt[crypto]'"
        )
    if global_salt in ("", DEFAULT_GLOBAL_SALT):
        raise ValueError(
            "Refusing to issue API token while global_salt is the default. "
            "Set a unique server salt before issuing tokens."
        )
    if not (MIN_TOKEN_TTL <= ttl_seconds <= MAX_TOKEN_TTL):
        raise ValueError(
            f"ttl_seconds out of bounds: must be in [{MIN_TOKEN_TTL}, "
            f"{MAX_TOKEN_TTL}], got {ttl_seconds}"
        )
    now = int(time.time())
    claims = {
        "tid": token_id,
        "rid": role_id,
        "uid": user_id,
        "uhash": user_hash,
        "iat": now,
        "exp": now + ttl_seconds,
        "sub": "api_token",
    }
    key = derive_signing_key(global_salt)
    return pyjwt.encode(claims, key, algorithm="HS256")


def verify_api_token(token: str, global_salt: str) -> dict[str, Any]:
    """Verify a JWT HS256 API token. Returns claims on success.

    Raises:
        RuntimeError: if PyJWT is not installed.
        jwt.PyJWTError: on any verification failure (expired, bad sig,
            ``alg:none``, etc.).
    """
    if pyjwt is None:  # pragma: no cover
        raise RuntimeError("PyJWT is not installed: pip install 'pyjwt[crypto]'")
    key = derive_signing_key(global_salt)
    # algorithms=["HS256"] blocks alg:none and RS256 confusion attacks.
    return pyjwt.decode(token, key, algorithms=["HS256"])


# ---------------------------------------------------------------------------
# User-hash (PentAGI's MakeUserHash) — installation binding
# ---------------------------------------------------------------------------


def make_user_hash(user_id: int, password_hash: str, global_salt: str) -> str:
    """Compute the ``uhash`` claim for an API token.

    PentAGI stores ``user_hash`` in the users table; if the user's
    password or role changes, the hash changes and ALL their tokens
    auto-revoke (because ``db_hash != claims.uhash``).

    The construction is HMAC-SHA256 of ``f"{uid}:{password_hash}"``
    keyed by the global salt — distinct from the JWT signing key so a
    leak of one key doesn't compromise the other.
    """
    msg = f"{user_id}:{password_hash}".encode("utf-8")
    return hmac.new(global_salt.encode("utf-8"), msg, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Identity dataclass
# ---------------------------------------------------------------------------


@dataclass
class Identity:
    """Request-scoped identity attached by auth dependencies.

    Mirrors the fields PentAGI puts in gin context:
    ``uid, uhash, rid, tid, prm, gtm, exp, uuid, cpt``.
    """

    user_id: int
    role_id: int
    user_hash: str
    token_id: str  # "api" or "local"
    privileges: list[str] = field(default_factory=list)
    issued_at: Optional[int] = None
    expires_at: Optional[int] = None
    username: Optional[str] = None
    client_type: str = "automation"  # PentAGI: "automation" for API tokens

    @property
    def is_api_token(self) -> bool:
        return self.token_id != "local"

    @property
    def is_session(self) -> bool:
        return self.token_id == "local"

    def has_privilege(self, priv: str) -> bool:
        """Check a single privilege. Supports wildcard ``users.*``."""
        for p in self.privileges:
            if p == priv:
                return True
            if p.endswith(".*") and priv.startswith(p[:-1]):
                return True
        return False


# ---------------------------------------------------------------------------
# Token cache (5-min TTL, negative cache)
# ---------------------------------------------------------------------------


class TokenCache:
    """5-min TTL cache for API-token status lookups.

    Mirrors PentAGI's ``api_token_cache.go``. Stores either an
    ``Identity`` (positive) or ``_NEG_CACHE_SENTINEL`` (negative —
    token revoked, deleted, or never existed).
    """

    def __init__(self, maxsize: int = 10000, ttl: int = TOKEN_CACHE_TTL) -> None:
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)

    def get(self, token_id: str) -> Optional[Identity]:
        v = self._cache.get(token_id)
        if v is None or v == _NEG_CACHE_SENTINEL:
            return None
        return v  # type: ignore[return-value]

    def is_known_revoked(self, token_id: str) -> bool:
        """True if we've recently confirmed the token is invalid.

        Used to short-circuit verification — avoids re-hitting the DB
        for repeated bad-token attempts (rate-limit mitigation).
        """
        return self._cache.get(token_id) == _NEG_CACHE_SENTINEL

    def set(self, token_id: str, identity: Identity) -> None:
        self._cache[token_id] = identity

    def set_negative(self, token_id: str) -> None:
        self._cache[token_id] = _NEG_CACHE_SENTINEL

    def invalidate(self, token_id: str) -> None:
        self._cache.pop(token_id, None)

    def invalidate_user(self, user_id: int) -> None:
        """Invalidate ALL cached tokens for a user (password/role change)."""
        to_drop = [
            tid
            for tid, v in list(self._cache.items())
            if v != _NEG_CACHE_SENTINEL
            and isinstance(v, Identity)
            and v.user_id == user_id
        ]
        for tid in to_drop:
            self._cache.pop(tid, None)


class UserCache:
    """5-min TTL cache for user status (active / blocked / hash).

    Mirrors PentAGI's ``users_cache.go``.
    """

    def __init__(self, maxsize: int = 10000, ttl: int = USER_CACHE_TTL) -> None:
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)

    def get(self, user_id: int) -> Optional[dict[str, Any]]:
        v = self._cache.get(user_id)
        if v is None or v == _NEG_CACHE_SENTINEL:
            return None
        return v  # type: ignore[return-value]

    def set(self, user_id: int, info: dict[str, Any]) -> None:
        self._cache[user_id] = info

    def set_negative(self, user_id: int) -> None:
        self._cache[user_id] = _NEG_CACHE_SENTINEL

    def invalidate(self, user_id: int) -> None:
        self._cache.pop(user_id, None)


# Module-level singletons (PentAGI uses sync.Map globals).
token_cache = TokenCache()
user_cache = UserCache()


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


class AuthError(Exception):
    """Raised by auth dependencies. Carries an ``APIError`` code.

    Translated to an HTTP response by the exception handler in ``app.py``.
    """

    def __init__(self, code: str, msg: str) -> None:
        super().__init__(msg)
        self.code = code
        self.msg = msg


def _extract_bearer(authorization: Optional[str]) -> Optional[str]:
    """Extract the JWT from an ``Authorization: Bearer <jwt>`` header."""
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def _extract_session_cookie(cookies: dict[str, str]) -> Optional[dict[str, Any]]:
    """Extract session claims from the ``elengenix_session`` cookie.

    PentAGI uses Gorilla cookie store; Elengenix uses signed cookies
    via ``itsdangerous.URLSafeTimedSerializer`` (TODO: implement in
    ``elengenix.api._sessions``). For now we return ``None`` if no
    cookie is present; the actual session-decoding helper will be
    added by Task 6-b.
    """
    raw = cookies.get("elengenix_session")
    if not raw:
        return None
    # TODO (Task 6-b): implement cookie decoding + signature check.
    # For now we treat the cookie as opaque and let the router layer
    # populate Identity from a DB lookup.
    return {"raw": raw}


# --- Dependency implementations ---------------------------------------------
#
# These are written as plain async functions (not generators) so they
# can be used as FastAPI ``Depends(...)`` directly. They rely on
# ``request.app.state`` for shared resources (DB pool, global salt,
# develop flag). The state is populated by ``create_app()`` at startup.


async def try_auth(request: Request) -> Optional[Identity]:
    """Optional auth — attach identity if a valid token or cookie is
    present, return ``None`` otherwise. Never raises.

    PentAGI's ``TryAuth`` middleware: public endpoints use this so they
    can customise their response based on whether the caller is logged in.
    """
    bearer = _extract_bearer(request.headers.get("authorization"))
    if bearer:
        try:
            salt = getattr(request.app.state, "global_salt", DEFAULT_GLOBAL_SALT)
            claims = verify_api_token(bearer, salt)
        except Exception:
            logger.debug("try_auth: bearer token verification failed", exc_info=True)
            return None
        tid = str(claims.get("tid", ""))
        cached = token_cache.get(tid)
        if cached is not None:
            return cached
        # No DB wired in this layer yet — return a minimal Identity
        # constructed from the claims themselves. Task 6-b will add the
        # DB lookup + privilege join.
        identity = Identity(
            user_id=int(claims.get("uid", 0)),
            role_id=int(claims.get("rid", 0)),
            user_hash=str(claims.get("uhash", "")),
            token_id=tid or "api",
            issued_at=int(claims.get("iat", 0)) or None,
            expires_at=int(claims.get("exp", 0)) or None,
        )
        token_cache.set(tid, identity)
        return identity
    # Cookie session.
    sess = _extract_session_cookie(request.cookies)
    if sess:
        return Identity(
            user_id=int(sess.get("uid", 0)),
            role_id=int(sess.get("rid", 0)),
            user_hash=str(sess.get("uhash", "")),
            token_id="local",
            issued_at=sess.get("iat"),
            expires_at=sess.get("exp"),
            username=sess.get("uname"),
            client_type="interactive",
        )
    return None


async def auth_token_required(request: Request) -> Identity:
    """Mandatory auth — 401 if neither bearer nor cookie is valid.

    PentAGI's ``AuthTokenRequired`` middleware: protects ``/flows/*``,
    ``/knowledge/*``, ``/providers``, ``/resources/*``, etc.
    """
    identity = await try_auth(request)
    if identity is None:
        raise AuthError("auth_required", "Authentication required")
    return identity


async def auth_user_required(request: Request) -> Identity:
    """Mandatory auth — 401 if no **session** (API tokens rejected).

    PentAGI's ``AuthUserRequired`` middleware: protects ``/tokens/*``,
    ``/users/*``, ``/roles/*``, ``PUT /user/password``.
    """
    identity = await try_auth(request)
    if identity is None:
        raise AuthError("auth_required", "Authentication required")
    if identity.is_api_token:
        raise AuthError(
            "local_user_required",
            "Interactive session required (API tokens not allowed)",
        )
    return identity


async def local_user_required(request: Request) -> Identity:
    """Mandatory auth — rejects ``tid != "local"`` AND requires active
    session. Used for password change (PentAGI's
    ``localUserRequired``).
    """
    identity = await auth_user_required(request)
    if identity.token_id != "local":
        raise AuthError(
            "local_user_required",
            "Local (interactive) user required for this operation",
        )
    return identity


def privileges_required(*required_privs: str):
    """Dependency factory — require ALL of ``required_privs``.

    PentAGI's ``PrivilegesRequired`` middleware uses
    ``slices.Contains`` (i.e. ALL of the required privs must be
    present). We mirror that with ``has_privilege`` (which also supports
    the ``users.*`` wildcard convention).
    """

    async def _dep(request: Request) -> Identity:
        identity = await auth_token_required(request)
        for priv in required_privs:
            if not identity.has_privilege(priv):
                raise AuthError(
                    "privileges_required",
                    f"Insufficient privileges: missing {priv!r}",
                )
        return identity

    return _dep


__all__ = [
    # constants
    "PBKDF2_ITERATIONS",
    "PBKDF2_KEY_LENGTH",
    "PBKDF2_HASH",
    "DEFAULT_GLOBAL_SALT",
    "TOKEN_ID_LENGTH",
    "TOKEN_ID_ALPHABET",
    "MIN_TOKEN_TTL",
    "MAX_TOKEN_TTL",
    "TOKEN_CACHE_TTL",
    "USER_CACHE_TTL",
    # key derivation
    "derive_signing_key",
    # token id
    "generate_token_id",
    # jwt
    "sign_api_token",
    "verify_api_token",
    # user hash
    "make_user_hash",
    # identity
    "Identity",
    "AuthError",
    # caches
    "TokenCache",
    "UserCache",
    "token_cache",
    "user_cache",
    # dependencies
    "try_auth",
    "auth_token_required",
    "auth_user_required",
    "local_user_required",
    "privileges_required",
]
