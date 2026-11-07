"""tests/vulnerable_target/hard_target.py

A HARDER, NOISIER deliberately-vulnerable Flask app for testing Elengenix's
discrimination under noise — distinct from the canonical 10-vuln target
(app.py), which measures *completeness*. This target measures *precision on a
noisier surface + detection of real-world classes the 10-vuln set never
exercised*:

  REAL vulnerabilities (ground truth):
    1. Host Header Injection   -> /reset
       Builds a password-reset link from the attacker-controlled Host header.
       A canary Host echoed into the response body is a deterministic proof.
    2. Weak / hardcoded JWT secret -> /api/jwt/verify
       Verifies HS256 JWTs with the weak secret "supersecret" and (importantly)
       REJECTS alg=none. So a naive "jwt endpoint == alg=none vuln" check
       misses it; Elengenix must forge an admin token with the weak secret.

  DECOYS (look vulnerable, are not — a naive substring scanner false-positives,
  Elengenix's canary/signal detectors resist):
    - /search?q=     reflects the param but HTML-ESCAPES it  -> not XSS.
    - /download?file= reflects the param but does NO traversal -> not LFI.
    - /api/config    returns a config JSON containing a STRONG (random) jwt
       secret in plaintext -> not a weak-secret vuln (can't be forged).

  STEALTH mode (ELENGENIX_BENCH_STEALTH=1): the index is an opaque service
  page — no endpoint list, no vuln hints. The agent must discover the
  endpoints itself AND discriminate real vulns from decoys.

Never deploy to production. For local scanner testing ONLY.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import base64

import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)

STEALTH = os.environ.get("ELENGENIX_BENCH_STEALTH", "").strip().lower() in (
    "1", "true", "yes", "on",
)

# A genuinely STRONG (random) JWT secret, embedded in /api/config to make the
# "leaked secret" decoy realistic. It is NOT in the hunter's weak-secret list,
# so a weak-secret detector must NOT fire on it.
STRONG_JWT_SECRET = "9f8a7c6b5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a"

# The REAL (weak) secret the /api/jwt/verify endpoint actually signs with.
WEAK_JWT_SECRET = "supersecret"


def _b64u(d: dict) -> str:
    return base64.urlsafe_b64encode(
        __import__("json").dumps(d, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


@app.route("/")
def index():
    if STEALTH:
        return jsonify({"status": "ok", "service": "elengenix-hard-target"})
    return jsonify(
        {
            "app": "Elengenix Hard (Noisy) Test Target",
            "warning": "FOR LOCAL TESTING ONLY - DO NOT EXPOSE",
        }
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ── REAL VULN 1: Host Header Injection (password-reset link) ─────────────────
@app.route("/reset")
def reset():
    # VULNERABLE: builds the reset URL from the attacker-controlled Host header
    # instead of a canonical host. A canary Host is echoed into the body.
    host = request.headers.get("Host", "example.com")
    token = "t-" + hashlib.sha256(host.encode()).hexdigest()[:16]
    return (
        f'Your password reset link: http://{host}/api/password/reset?token={token}'
    ), 200, {"Content-Type": "text/html"}


# ── REAL VULN 2: Weak / hardcoded JWT secret (rejects alg=none) ─────────────
@app.route("/api/jwt/verify", methods=["POST"])
def jwt_verify():
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")
    try:
        # Rejects alg=none (so the alg=none detector does NOT fire); only HS256
        # is accepted — but signed with a WEAK secret, so tokens can be forged.
        payload = jwt.decode(
            token,
            WEAK_JWT_SECRET,
            algorithms=["HS256"],
            options={"verify_exp": False, "verify_iat": False, "verify_nbf": False},
        )
        return jsonify({"valid": True, "claims": payload})
    except jwt.InvalidAlgorithmError:
        return jsonify({"valid": False, "error": "invalid algorithm"}), 401
    except Exception as e:  # bad signature / malformed
        return jsonify({"valid": False, "error": str(e)[:120]}), 401


# ── DECOY 1: reflected XSS param, but HTML-escaped (NOT exploitable) ─────────
@app.route("/search")
def search():
    from markupsafe import escape

    q = request.args.get("q", "")
    # Looks like a reflected sink, but the value is escaped -> no XSS.
    return (
        f'<html><body><p>Results for: {escape(q)}</p></body></html>'
    ), 200, {"Content-Type": "text/html"}


# ── DECOY 2: reflected "file" param, but no traversal (NOT exploitable) ──────
@app.route("/download")
def download():
    f = request.args.get("file", "")
    # Looks like a file endpoint, but the value is only echoed as JSON metadata
    # (no filesystem access) -> no LFI/path traversal.
    return jsonify({"requested": f, "status": "not found"}), 404


# ── DECOY 3: config leaks a STRONG secret (NOT a weak-secret vuln) ──────────
@app.route("/api/config")
def config():
    # Looks like a secret leak, but the embedded JWT secret is strong/random ->
    # a weak-secret detector must not fire (it can't be forged).
    return jsonify(
        {
            "service": "elengenix-hard-target",
            "version": "2.0.0",
            "jwt": {"algorithm": "HS256", "secret": STRONG_JWT_SECRET},
            "features": {"reset": True},
        }
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5556))
    print(f"Starting HARD (noisy) vulnerable target on port {port}")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
