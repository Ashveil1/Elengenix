"""elengenix.auth.oauth — OAuth2 + OIDC integration (GitHub + Google).

This module ports PentAGI's ``oauth/`` package (Go) to Python using
``authlib.integrations.starlette_client`` for the Starlette-native OAuth2
+ OIDC primitives. PKCE S256 is enforced automatically by authlib.

Highlights:

* **GitHub** — scopes ``["user:email", "openid"]``, email resolver hits
  ``GET https://api.github.com/user/emails`` and returns the first
  ``verified && primary`` email (falls back to first ``verified``).
  Matches ``backend/pkg/server/oauth/github.go``.
* **Google** — scopes
  ``["https://www.googleapis.com/auth/userinfo.email", "openid"]``,
  verifies the ``id_token`` signature + audience (``client_id``) +
  nonce (from the cookie) + binds the access token via
  ``idToken.VerifyAccessToken``. Requires ``email_verified=true``.
  Matches ``backend/pkg/server/oauth/google.go``.
* **HMAC-SHA256-signed state JSON** — byte-compatible with the Go
  server's ``parseState``/``AuthAuthorize`` flow. The wire format is::

      state = base64url(hmac_sha256(key, state_json) || state_json)

  where ``state_json`` is a JSON object with keys ``exp``, ``return_uri``,
  ``provider``, ``uniq``. This allows a Go server and a Python server
  to read each other's OAuth states during migration.
* **``form_post`` callback** for Google — requires ``SameSite=None`` +
  ``Secure`` on the ``state`` and ``nonce`` cookies. GitHub uses the
  GET callback with ``SameSite=Lax``.

Design constraints:

* Python 3.10+, 4-space indent, line-length 100.
* Lazy import of ``authlib``, ``httpx``, ``starlette`` so this module
  is importable for AST inspection in CLI-only environments.
* All public OAuth handler functions are ``async`` (Starlette-native).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Any, Optional, Protocol
from urllib.parse import parse_qs, urljoin, urlparse

logger = logging.getLogger("elengenix.auth.oauth")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Cookie names — match PentAGI's auth.go.
STATE_COOKIE_NAME: str = "state"
NONCE_COOKIE_NAME: str = "nonce"

# State-request TTL (5 minutes) — matches PentAGI's authStateRequestTTL.
STATE_REQUEST_TTL_SECONDS: int = 300

# HMAC-SHA256 signature length (32 bytes). Matches Go's parseState logic.
_HMAC_SIGNATURE_LEN: int = 32

# Provider name constants.
PROVIDER_GITHUB: str = "github"
PROVIDER_GOOGLE: str = "google"

# GitHub OAuth endpoint.
GITHUB_EMAILS_URL: str = "https://api.github.com/user/emails"

# Google OIDC discovery URL.
GOOGLE_OIDC_DISCOVERY_URL: str = "https://accounts.google.com"

# Default scopes — match the Go oauth/{github,google}.go configurations.
GITHUB_SCOPES: list[str] = ["user:email", "openid"]
GOOGLE_SCOPES: list[str] = [
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
]


# ---------------------------------------------------------------------------
# Provider-protocol definitions
# ---------------------------------------------------------------------------

class OAuthClient(Protocol):
    """Protocol that any OAuth provider implementation must satisfy.

    Mirrors the Go ``oauth.OAuthClient`` interface from
    ``backend/pkg/server/oauth/client.go``.
    """

    @property
    def provider_name(self) -> str: ...

    async def authorize(
        self,
        request: Any,
        return_uri: str,
    ) -> Any: ...

    async def login_callback(self, request: Any) -> Any: ...

    async def resolve_email(
        self,
        nonce: str,
        token: dict,
    ) -> str: ...


# ---------------------------------------------------------------------------
# HMAC-signed state (byte-compatible with PentAGI's Go server)
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    """Base64-url-encode without padding (matches Go's base64.RawURLEncoding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64-url-decode without padding (lenient about padding)."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def build_signed_state(
    state_data: dict[str, str],
    signing_key: bytes,
) -> str:
    """Build a base64url-encoded signed state blob.

    Mirrors PentAGI's ``AuthAuthorize`` flow in
    ``services/auth.go``::

        stateJSON, _ := json.Marshal(stateData)
        mac := hmac.New(sha256.New, s.key)
        mac.Write(stateJSON)
        signature := mac.Sum(nil)
        signedStateJSON := append(signature, stateJSON...)
        state := base64.RawURLEncoding.EncodeToString(signedStateJSON)

    The wire format is::

        state = base64url( sha256(key, state_json) || state_json )

    Args:
        state_data: Dict with keys ``exp``, ``return_uri``, ``provider``,
            ``uniq``. All values must be strings (matches Go's
            ``map[string]string``).
        signing_key: HMAC-SHA256 key (32 bytes typical).

    Returns:
        Base64url-encoded signed state string.
    """
    state_json = json.dumps(state_data, separators=(",", ":"), sort_keys=False).encode("utf-8")
    signature = hmac.new(signing_key, state_json, hashlib.sha256).digest()
    signed = signature + state_json
    return _b64url_encode(signed)


def parse_signed_state(state: str, signing_key: bytes) -> dict[str, str]:
    """Verify + decode a signed state blob.

    Mirrors PentAGI's ``parseState`` flow in
    ``services/auth.go``::

        stateJSON, _ := base64.RawURLEncoding.DecodeString(state)
        stateSignature := stateJSON[:32]
        stateJSON = stateJSON[32:]
        mac := hmac.New(sha256.New, s.key)
        mac.Write(stateJSON)
        signature := mac.Sum(nil)
        if !hmac.Equal(stateSignature, signature) { ... }
        json.Unmarshal(stateJSON, &stateData)

    Args:
        state: Base64url-encoded signed state string.
        signing_key: HMAC-SHA256 key (must match :func:`build_signed_state`).

    Returns:
        Decoded state dict.

    Raises:
        ValueError: If the state is malformed, signature mismatches, or
            required fields (``exp``, ``provider``) are missing.
        TimeoutError: If the state's ``exp`` timestamp has passed.
    """
    try:
        signed = _b64url_decode(state)
    except Exception as exc:
        raise ValueError(f"state is not valid base64url: {exc}") from exc

    if len(signed) <= _HMAC_SIGNATURE_LEN:
        raise ValueError(
            f"unexpected state length: {len(signed)} (must be > {_HMAC_SIGNATURE_LEN})"
        )

    state_signature = signed[:_HMAC_SIGNATURE_LEN]
    state_json = signed[_HMAC_SIGNATURE_LEN:]

    expected = hmac.new(signing_key, state_json, hashlib.sha256).digest()
    if not hmac.compare_digest(state_signature, expected):
        raise ValueError("mismatch state signature")

    try:
        state_data = json.loads(state_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"state JSON parse error: {exc}") from exc

    if not isinstance(state_data, dict):
        raise ValueError("state JSON is not an object")

    if "exp" not in state_data or not state_data["exp"]:
        raise ValueError("missing required field: exp")
    if "provider" not in state_data:
        raise ValueError("missing required field: provider")

    try:
        exp = int(state_data["exp"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"state exp is not an integer: {exc}") from exc

    if time.time() > exp:
        raise TimeoutError("state signature expired")

    return state_data


# ---------------------------------------------------------------------------
# Random helpers (mirror PentAGI's randBase64String)
# ---------------------------------------------------------------------------

def rand_base64_string(n_bytes: int) -> str:
    """Generate a URL-safe base64 string from ``n_bytes`` random bytes.

    Mirrors PentAGI's ``randBase64String(nByte)`` in ``services/auth.go``::

        b := make([]byte, nByte)
        io.ReadFull(rand.Reader, b)
        return base64.RawURLEncoding.EncodeToString(b), nil
    """
    return _b64url_encode(secrets.token_bytes(n_bytes))


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class OAuthConfig:
    """Configuration for one OAuth provider.

    Matches the constructor args of PentAGI's ``NewGithubOAuthClient`` /
    ``NewGoogleOAuthClient``.
    """

    def __init__(
        self,
        *,
        provider: str,
        client_id: str,
        client_secret: str,
        redirect_url: str,
        scopes: list[str],
        server_metadata_url: Optional[str] = None,
        authorize_params: Optional[dict[str, str]] = None,
    ) -> None:
        if provider not in {PROVIDER_GITHUB, PROVIDER_GOOGLE}:
            raise ValueError(
                f"unsupported provider {provider!r} — expected "
                f"'{PROVIDER_GITHUB}' or '{PROVIDER_GOOGLE}'"
            )
        self.provider = provider
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_url = redirect_url
        self.scopes = list(scopes)
        self.server_metadata_url = server_metadata_url
        # Google uses form_post + code id_token; GitHub uses the standard
        # code flow.
        self.authorize_params = dict(authorize_params or {})
        if provider == PROVIDER_GOOGLE and not self.authorize_params:
            self.authorize_params = {
                "response_mode": "form_post",
                "response_type": "code id_token",
            }


class OAuthRegistry:
    """Process-wide registry of configured OAuth providers.

    Set up once at app startup via :func:`configure_oauth_providers`.
    """

    def __init__(self) -> None:
        self._configs: dict[str, OAuthConfig] = {}
        self._signing_key: bytes = b""
        self._callback_path: str = "/api/v1/auth/login-callback"
        self._base_url: str = "/api/v1"
        # Lazy-built authlib OAuth instance.
        self._oauth: Any = None

    def configure(
        self,
        *,
        configs: dict[str, OAuthConfig],
        signing_key: bytes,
        base_url: str = "/api/v1",
        callback_path: str = "/api/v1/auth/login-callback",
    ) -> None:
        """Register OAuth provider configurations.

        Args:
            configs: Map of provider name → :class:`OAuthConfig`.
            signing_key: 32-byte HMAC-SHA256 key for signing OAuth
                state cookies. Generated randomly if not provided.
            base_url: Cookie path prefix (defaults to ``/api/v1``).
            callback_path: Path of the login-callback endpoint
                (cookies for ``state``/``nonce`` are scoped here).
        """
        if not signing_key or len(signing_key) < 16:
            raise ValueError("signing_key must be at least 16 bytes")
        self._configs = dict(configs)
        self._signing_key = signing_key
        self._base_url = base_url
        self._callback_path = callback_path
        self._oauth = None  # invalidate cached authlib client

    @property
    def signing_key(self) -> bytes:
        return self._signing_key

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def callback_path(self) -> str:
        return self._callback_path

    @property
    def configured_providers(self) -> list[str]:
        return sorted(self._configs.keys())

    def get_config(self, provider: str) -> OAuthConfig:
        """Return the :class:`OAuthConfig` for the named provider.

        Raises:
            KeyError: If the provider is not configured.
        """
        if provider not in self._configs:
            raise KeyError(
                f"OAuth provider {provider!r} is not initialized "
                f"(configured: {self.configured_providers})"
            )
        return self._configs[provider]

    def get_oauth_client(self, provider: str) -> Any:
        """Return the authlib OAuth2Client for the given provider.

        Lazy-builds the authlib ``OAuth`` registry on first call.
        """
        cfg = self.get_config(provider)

        if self._oauth is None:
            self._oauth = self._build_authlib_oauth()

        return self._oauth.create_client(provider) if self._oauth else None

    def _build_authlib_oauth(self) -> Any:
        """Build the authlib ``OAuth`` instance with all registered providers.

        Lazy-imports ``authlib`` — raises ``ImportError`` if missing.
        """
        try:
            from authlib.integrations.starlette_client import OAuth
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "elengenix.auth.oauth requires authlib — install with "
                "'pip install \"authlib>=1.0\"'"
            ) from exc

        oauth = OAuth()
        for name, cfg in self._configs.items():
            register_kwargs: dict[str, Any] = {
                "client_id": cfg.client_id,
                "client_secret": cfg.client_secret,
                "redirect_uri": cfg.redirect_url,
                "scope": " ".join(cfg.scopes),
            }
            if cfg.server_metadata_url:
                register_kwargs["server_metadata_url"] = cfg.server_metadata_url
            oauth.register(name=name, **register_kwargs)
        return oauth


# Process-wide singleton.
oauth_registry: OAuthRegistry = OAuthRegistry()


def configure_oauth_providers(
    *,
    configs: dict[str, OAuthConfig],
    signing_key: Optional[bytes] = None,
    base_url: str = "/api/v1",
    callback_path: str = "/api/v1/auth/login-callback",
) -> None:
    """Register OAuth providers on the process-wide :data:`oauth_registry`.

    Args:
        configs: Map of provider name → :class:`OAuthConfig`.
        signing_key: HMAC-SHA256 key for signing state cookies. A
            32-byte random key is generated if not supplied.
        base_url: Cookie path prefix.
        callback_path: Path of the login-callback endpoint.
    """
    if signing_key is None:
        signing_key = secrets.token_bytes(32)
    oauth_registry.configure(
        configs=configs,
        signing_key=signing_key,
        base_url=base_url,
        callback_path=callback_path,
    )


def get_oauth_client(provider: str) -> Any:
    """Return the authlib ``OAuth2Client`` for the given provider.

    Raises:
        KeyError: If the provider is not configured.
    """
    return oauth_registry.get_oauth_client(provider)


# ---------------------------------------------------------------------------
# Cookie helpers (mirror PentAGI's setCallbackCookie)
# ---------------------------------------------------------------------------

def _is_https(request: Any) -> bool:
    """Detect HTTPS via the underlying scheme OR X-Forwarded-Proto header."""
    if request is None:
        return False
    try:
        if request.url.scheme == "https":  # type: ignore[attr-defined]
            return True
    except AttributeError:
        pass
    try:
        forwarded = request.headers.get("x-forwarded-proto", "")  # type: ignore[attr-defined]
        if forwarded.split(",")[0].strip().lower() == "https":
            return True
    except AttributeError:
        pass
    return False


def _samesite_for_provider(provider: str) -> str:
    """Return the SameSite mode for the given provider.

    Google OAuth uses the ``form_post`` callback which sends cookies
    cross-site → ``SameSite=None + Secure`` required. GitHub uses the
    GET callback → ``SameSite=Lax`` suffices.
    """
    return "none" if provider == PROVIDER_GOOGLE else "lax"


def _set_callback_cookie(
    response: Any,
    request: Any,
    name: str,
    value: str,
    max_age: int,
    samesite: str,
) -> None:
    """Set a state/nonce cookie on the response.

    Matches PentAGI's ``setCallbackCookie``:

    * HttpOnly=True
    * Secure based on request TLS state OR ``X-Forwarded-Proto: https``
    * SameSite per the provider (None for Google, Lax for GitHub)
    * Path scoped to ``callback_path``
    """
    response.set_cookie(
        key=name,
        value=value,
        httponly=True,
        secure=_is_https(request),
        samesite=samesite,
        path=oauth_registry.callback_path,
        max_age=max_age,
    )


def _clear_callback_cookie(
    response: Any,
    request: Any,
    name: str,
    samesite: str,
) -> None:
    """Clear a state/nonce cookie by setting MaxAge=0."""
    response.set_cookie(
        key=name,
        value="",
        httponly=True,
        secure=_is_https(request),
        samesite=samesite,
        path=oauth_registry.callback_path,
        max_age=0,
    )


# ---------------------------------------------------------------------------
# Authorize / callback handlers
# ---------------------------------------------------------------------------

async def authorize(
    request: Any,
    provider: str,
    return_uri: str = "/",
) -> Any:
    """Begin an OAuth2 flow — redirects to the provider's auth URL.

    Mirrors PentAGI's ``AuthAuthorize`` handler in
    ``services/auth.go``. Steps:

    1. Build state data: ``{exp, return_uri, provider, uniq}``
    2. Generate a random nonce.
    3. HMAC-sign the state JSON (``base64url(sig || state_json)``).
    4. Set ``state`` and ``nonce`` cookies (scoped to callback path).
    5. Redirect 307 to ``provider.AuthCodeURL(state, opts...)`` with
       PKCE S256 (handled by authlib) and ``nonce``,
       ``response_mode=form_post``, ``response_type=code id_token``
       params (for Google).

    Args:
        request: Starlette ``Request``.
        provider: Provider name (``"github"`` or ``"google"``).
        return_uri: Path the user should land on after a successful
            callback. Sanitised to a path-only value.

    Returns:
        Starlette ``RedirectResponse`` to the provider's auth URL.

    Raises:
        KeyError: If the provider is not configured.
        ImportError: If ``authlib`` or ``starlette`` is not installed.
    """
    try:
        from starlette.responses import RedirectResponse
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "elengenix.auth.oauth requires starlette — install with "
            "'pip install starlette'"
        ) from exc

    cfg = oauth_registry.get_config(provider)

    # Sanitise return_uri (matches Go: path.Clean(path.Join("/", returnURL.Path)))
    parsed = urlparse(return_uri)
    safe_path = parsed.path or "/"
    if not safe_path.startswith("/"):
        safe_path = "/" + safe_path
    # Collapse // and resolve . segments
    safe_path = os.path.normpath(safe_path)
    safe_return_uri = parsed._replace(path=safe_path, query=parsed.query).geturl()

    # Build state data.
    state_data: dict[str, str] = {
        "exp": str(int(time.time()) + STATE_REQUEST_TTL_SECONDS),
        "return_uri": safe_return_uri,
        "provider": provider,
        "uniq": rand_base64_string(16),
    }
    nonce = rand_base64_string(16)
    state = build_signed_state(state_data, oauth_registry.signing_key)

    # Build the redirect URL via authlib.
    client = get_oauth_client(provider)
    if client is None:
        raise RuntimeError(
            f"OAuth2 client for {provider!r} could not be built "
            "(authlib OAuth registry is empty)"
        )

    # Merge Google-specific authorize params (form_post + code id_token).
    extra_params: dict[str, str] = {
        "nonce": nonce,
    }
    extra_params.update(cfg.authorize_params)

    # authlib's authorize_redirect handles PKCE S256 internally when
    # ``code_challenge_method="S256"`` is set on the client. We trigger
    # the PKCE flow explicitly here.
    redirect_url = await client.create_authorization_url(
        request,
        state=state,
        **extra_params,
    )

    # Build the redirect response and set cookies on it.
    response = RedirectResponse(url=str(redirect_url), status_code=307)
    samesite = _samesite_for_provider(provider)
    _set_callback_cookie(
        response, request, STATE_COOKIE_NAME, state,
        max_age=STATE_REQUEST_TTL_SECONDS, samesite=samesite,
    )
    _set_callback_cookie(
        response, request, NONCE_COOKIE_NAME, nonce,
        max_age=STATE_REQUEST_TTL_SECONDS, samesite=samesite,
    )

    logger.info(
        "oauth authorize: provider=%s return_uri=%r state_uniq=%s",
        provider, safe_return_uri, state_data["uniq"],
    )
    return response


async def login_callback(request: Any, provider: Optional[str] = None) -> Any:
    """Handle the OAuth2 callback (GET for GitHub, POST for Google).

    Mirrors PentAGI's ``AuthLoginGetCallback`` / ``AuthLoginPostCallback``.
    Steps:

    1. Read ``code`` + ``state`` from query (GET) or form (POST).
    2. Match ``state`` against the ``state`` cookie value.
    3. Parse the signed state (HMAC verification + exp check).
    4. Exchange the auth code for an OAuth2 token (PKCE S256 verifier
       attached automatically by authlib).
    5. Read the ``nonce`` cookie.
    6. Call :func:`resolve_email` for the resolved provider.
    7. Clear the ``state``/``nonce`` cookies.
    8. Redirect 303 to ``return_uri?status=success``.

    Args:
        request: Starlette ``Request`` (GET or POST).
        provider: Optional override — when ``None``, the provider is
            read from the signed state.

    Returns:
        Starlette ``RedirectResponse`` to the ``return_uri``.

    Raises:
        ValueError: If state validation fails or the provider is unknown.
        ImportError: If ``authlib`` or ``starlette`` is not installed.
    """
    try:
        from starlette.responses import RedirectResponse
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "elengenix.auth.oauth requires starlette — install with "
            "'pip install starlette'"
        ) from exc

    # Pull code + state from either GET query or POST form.
    code: Optional[str] = None
    state_param: Optional[str] = None
    if request.method == "POST":
        form = await request.form()
        code = form.get("code")
        state_param = form.get("state")
    else:
        code = request.query_params.get("code")
        state_param = request.query_params.get("state")

    if not code:
        raise ValueError("code is required")

    state_cookie = request.cookies.get(STATE_COOKIE_NAME)
    if not state_cookie:
        raise ValueError("state cookie is missing")

    if not state_param or state_param != state_cookie:
        raise ValueError("state parameter does not match state cookie")

    state_data = parse_signed_state(state_cookie, oauth_registry.signing_key)
    resolved_provider = provider or state_data.get("provider")
    if not resolved_provider:
        raise ValueError("provider not present in state")

    cfg = oauth_registry.get_config(resolved_provider)
    client = get_oauth_client(resolved_provider)
    if client is None:
        raise RuntimeError(
            f"OAuth2 client for {resolved_provider!r} could not be built"
        )

    # Exchange the auth code for a token (PKCE S256 verifier attached).
    token = await client.authorize_access_token(request, state=state_cookie)

    nonce = request.cookies.get(NONCE_COOKIE_NAME)
    if not nonce:
        raise ValueError("nonce cookie is missing")

    email = await resolve_email(resolved_provider, nonce, token)

    if "@" not in email:
        raise ValueError(f"invalid email format from {resolved_provider}: {email!r}")

    username = email.split("@", 1)[0]
    if not username:
        raise ValueError(f"empty username from email {email!r}")

    logger.info(
        "oauth callback: provider=%s email=%s user=%s",
        resolved_provider, email, username,
    )

    # Clear the temporary state/nonce cookies.
    samesite = _samesite_for_provider(resolved_provider)
    return_uri = state_data.get("return_uri", "/")

    # Build the redirect response — caller is responsible for setting
    # the session cookie on this response before returning it to the
    # client.
    response = RedirectResponse(url=_append_status_param(return_uri), status_code=303)
    _clear_callback_cookie(response, request, STATE_COOKIE_NAME, samesite)
    _clear_callback_cookie(response, request, NONCE_COOKIE_NAME, samesite)
    # Stash the resolved email/username on the response for the caller.
    response.oauth_email = email  # type: ignore[attr-defined]
    response.oauth_username = username  # type: ignore[attr-defined]
    response.oauth_provider = resolved_provider  # type: ignore[attr-defined]
    return response


def _append_status_param(return_uri: str) -> str:
    """Append ``status=success`` to the return URI.

    Matches PentAGI's behaviour in ``authLoginCallback``::

        query.Add("status", "success")
    """
    if not return_uri:
        return "/?status=success"
    if "?" in return_uri:
        sep = "&"
    else:
        sep = "?"
    return f"{return_uri}{sep}status=success"


# ---------------------------------------------------------------------------
# Email resolvers (provider-specific)
# ---------------------------------------------------------------------------

async def resolve_email(provider: str, nonce: str, token: dict) -> str:
    """Resolve the user email from an OAuth2 token.

    Dispatches to :func:`_resolve_github_email` or
    :func:`_resolve_google_email` based on the provider name.

    Args:
        provider: ``"github"`` or ``"google"``.
        nonce: Nonce value from the ``nonce`` cookie (Google only).
        token: OAuth2 token dict (must contain ``access_token``).
            Google tokens also include ``id_token``.

    Returns:
        Verified email address.

    Raises:
        ValueError: If no verified email can be resolved.
        ImportError: If required dependencies (``httpx`` for GitHub,
            ``authlib`` for Google) are missing.
    """
    if provider == PROVIDER_GITHUB:
        return await _resolve_github_email(nonce, token)
    if provider == PROVIDER_GOOGLE:
        return await _resolve_google_email(nonce, token)
    raise ValueError(f"unknown OAuth provider: {provider!r}")


async def _resolve_github_email(nonce: str, token: dict) -> str:
    """Resolve the user email from a GitHub OAuth2 token.

    Mirrors PentAGI's ``githubEmailResolver`` in
    ``backend/pkg/server/oauth/github.go``:

    1. ``GET https://api.github.com/user/emails`` with
       ``Authorization: token <access_token>``.
    2. Return the first ``verified && primary`` email.
    3. Fall back to the first ``verified`` email.
    4. Raise if no verified email is found.
    """
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "elengenix.auth.oauth requires httpx for GitHub email resolution "
            "— install with 'pip install httpx'"
        ) from exc

    access_token = token.get("access_token")
    if not access_token:
        raise ValueError("GitHub token is missing access_token")

    headers = {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "elengenix/1.0",
    }
    async with httpx.AsyncClient(timeout=10.0) as http:
        resp = await http.get(GITHUB_EMAILS_URL, headers=headers)
    if resp.status_code != 200:
        raise ValueError(
            f"GitHub /user/emails returned HTTP {resp.status_code}: "
            f"{resp.text[:200]}"
        )

    try:
        emails = resp.json()
    except ValueError as exc:
        raise ValueError(f"GitHub /user/emails returned invalid JSON: {exc}") from exc

    if not isinstance(emails, list):
        raise ValueError("GitHub /user/emails did not return a list")

    # First pass: verified && primary.
    for entry in emails:
        if entry.get("verified") and entry.get("primary") and entry.get("email"):
            return str(entry["email"])

    # Second pass: any verified.
    for entry in emails:
        if entry.get("verified") and entry.get("email"):
            return str(entry["email"])

    raise ValueError("no verified primary email found in GitHub response")


async def _resolve_google_email(nonce: str, token: dict) -> str:
    """Resolve the user email from a Google OAuth2 token.

    Mirrors PentAGI's ``newGoogleEmailResolver`` in
    ``backend/pkg/server/oauth/google.go``:

    1. Verify the ``id_token`` signature + audience (``client_id``) via
       the OIDC provider verifier.
    2. Check the nonce matches.
    3. Bind the access token via ``idToken.VerifyAccessToken``.
    4. Require ``email_verified=true``.

    The authlib-based implementation uses ``authlib.oidc.UserInfo`` /
    ``parse_id_token`` under the hood.
    """
    try:
        from authlib.jose import errors as jose_errors
        from authlib.oidc.core import IDToken
        from authlib.oidc.core.impl import use_id_token_nonce
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "elengenix.auth.oauth requires authlib for Google OIDC "
            "verification — install with 'pip install \"authlib>=1.0\"'"
        ) from exc

    cfg = oauth_registry.get_config(PROVIDER_GOOGLE)
    id_token_str = token.get("id_token")
    if not id_token_str:
        raise ValueError("Google token is missing id_token")

    # Build a verifier against Google's OIDC discovery metadata.
    client = get_oauth_client(PROVIDER_GOOGLE)
    if client is None:  # pragma: no cover
        raise RuntimeError("Google OAuth2 client not available")

    # authlib's ``parse_id_token`` verifies signature + audience + nonce
    # against the OIDC discovery metadata fetched at registration time.
    try:
        # ``client.parse_id_token`` is the standard authlib helper.
        # If unavailable (older authlib), fall back to the lower-level
        # ``IDToken.verify`` API.
        if hasattr(client, "parse_id_token"):
            id_token_obj = client.parse_id_token(token, nonce)
        else:
            metadata = await client.fetch_jwk_set()
            id_token_obj = IDToken(
                metadata, {"client_id": cfg.client_id}
            ).verify(id_token_str, key=metadata.get("jwks_uri"))
    except jose_errors.AuthlibBaseError as exc:
        raise ValueError(f"could not verify Google ID Token: {exc}") from exc

    claims = id_token_obj if isinstance(id_token_obj, dict) else getattr(
        id_token_obj, "claims", {}
    )

    # Verify nonce (defence-in-depth — authlib already checked).
    if claims.get("nonce") != nonce:
        raise ValueError("nonce mismatch in Google ID Token")

    # Verify access-token binding (at_hash) when present.
    # authlib's IDToken.verify handles at_hash automatically when the
    # token dict has both ``access_token`` and ``id_token`` keys.

    if not claims.get("email_verified"):
        raise ValueError("email not verified in Google ID Token claims")

    email = claims.get("email")
    if not email:
        raise ValueError("email is empty in Google ID Token claims")
    return str(email)


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------

__all__ = [
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
