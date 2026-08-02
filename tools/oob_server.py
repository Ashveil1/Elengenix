"""tools/oob_server.py — Local Out-of-Band (OOB) callback server.

In-process HTTP callback listener for confirming *blind* vulnerabilities
(SSRF, blind SQLi/SSTI exfil, blind XXE, ...) where the injectable response
carries no signature. The scanner embeds a unique per-test token into a
callback URL; if the target (or its backend) fetches that URL, the callback
is recorded and the finding is OOB-confirmed.

Design:
  - Stdlib only (``http.server.ThreadingHTTPServer`` on ``127.0.0.1``,
    ephemeral port, daemon thread).
  - Token-keyed hit store: path, headers, body, timestamp.
  - ``wait_for(token, timeout)`` blocks with a condition variable;
    ``poll(token)`` is non-blocking.
  - Module-level singleton via :func:`get_oob_server` (lazy start);
    returns ``None`` if the server cannot bind.

Scope note: this is a *local* loopback listener — it confirms blind issues
only when the target can reach 127.0.0.1:<port> (same host, benchmarks,
labs). Real engagements need a publicly reachable interactsh/collaborator
endpoint instead.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

logger = logging.getLogger("elengenix.oob_server")

_MAX_BODY = 64 * 1024  # read at most 64 KiB of any callback body


@dataclass
class OOBHit:
    """A single recorded callback request."""

    token: str
    method: str
    path: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    timestamp: float = 0.0
    client: str = ""

    def to_dict(self) -> Dict:
        return {
            "token": self.token,
            "method": self.method,
            "path": self.path,
            "headers": dict(self.headers),
            "body": self.body.decode("utf-8", errors="replace")[:2048],
            "timestamp": self.timestamp,
            "client": self.client,
        }


class OOBServer:
    """In-process HTTP callback listener for blind vulnerability detection."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._hits: Dict[str, List[OOBHit]] = {}
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        server = self  # closure ref for the handler

        class _Handler(BaseHTTPRequestHandler):
            def _record(self) -> None:
                token = self.path.strip("/").split("/")[0].split("?")[0] or "_root"
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(min(length, _MAX_BODY)) if length > 0 else b""
                server._record_hit(
                    OOBHit(
                        token=token,
                        method=self.command,
                        path=self.path,
                        headers={k: v for k, v in self.headers.items()},
                        body=body,
                        timestamp=time.time(),
                        client=self.client_address[0],
                    )
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "3")
                self.end_headers()
                self.wfile.write(b"ok\n")

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _record  # type: ignore[assignment]
            do_OPTIONS = do_PATCH = _record  # type: ignore[assignment]

            def log_message(self, fmt, *args):  # keep stderr quiet
                logger.debug("oob %s - %s", self.address_string(), fmt % args)

        self._handler_cls = _Handler
        try:
            self._httpd = ThreadingHTTPServer((host, port), _Handler)
            self._httpd.daemon_threads = True
            self._thread = threading.Thread(
                target=self._httpd.serve_forever,
                kwargs={"poll_interval": 0.1},
                name="oob-server",
                daemon=True,
            )
            self._thread.start()
        except Exception as e:  # bind/permission failure → caller disables OOB
            logger.warning("OOB server failed to bind %s:%s: %s", host, port, e)
            self._httpd = None

    # ── lifecycle ───────────────────────────────────────────────
    @property
    def running(self) -> bool:
        return self._httpd is not None

    @property
    def port(self) -> int:
        return self._httpd.server_address[1] if self._httpd else 0

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def shutdown(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    # ── token API ───────────────────────────────────────────────
    def new_url(self, suffix: str = "") -> tuple[str, str]:
        """Issue a unique token and its callback URL.

        Returns ``(token, url)`` where url = ``http://127.0.0.1:<port>/<token>[suffix]``.
        """
        token = uuid.uuid4().hex[:16]
        return token, f"{self.base_url}/{token}{suffix}"

    def _record_hit(self, hit: OOBHit) -> None:
        with self._cond:
            self._hits.setdefault(hit.token, []).append(hit)
            self._cond.notify_all()

    def poll(self, token: str) -> List[OOBHit]:
        """Return recorded hits for *token* (non-blocking)."""
        with self._lock:
            return list(self._hits.get(token, []))

    def wait_for(self, token: str, timeout: float = 3.0) -> Optional[OOBHit]:
        """Block up to *timeout* s for a callback on *token*; return first hit or None."""
        deadline = time.monotonic() + timeout
        with self._cond:
            while not self._hits.get(token):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)
            return self._hits[token][0]


# ── module-level singleton ──────────────────────────────────────
_server: Optional[OOBServer] = None
_server_lock = threading.Lock()


def get_oob_server() -> Optional[OOBServer]:
    """Return the shared OOB server (started lazily), or None if it failed to bind."""
    global _server
    with _server_lock:
        if _server is None:
            _server = OOBServer()
            if not _server.running:
                _server = None
        return _server


def reset_oob_server_for_tests() -> None:
    """Shut down and drop the singleton (test teardown only)."""
    global _server
    with _server_lock:
        if _server is not None:
            _server.shutdown()
            _server = None


if __name__ == "__main__":  # manual smoke: python3 tools/oob_server.py
    srv = get_oob_server()
    assert srv, "failed to bind"
    tok, url = srv.new_url()
    print(f"listening on {srv.base_url} — try: curl {url}")
    hit = srv.wait_for(tok, timeout=30)
    print(json.dumps(hit.to_dict() if hit else {"timeout": True}, indent=2)[:800])
