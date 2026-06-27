"""tests/vulnerable_target/app.py

DELIBERATELY VULNERABLE Flask application for testing Elengenix scanners.

Contains intentional vulnerabilities for testing detection capabilities:
    1. SQL Injection (login form via /login)
    2. Reflected XSS (search via /search)
    3. Stored XSS (comments via /comments)
    4. IDOR/BOLA (user profile via /api/user/<id>)
    5. Mass Assignment (registration via /register with role=admin)
    6. SSTI (template via /render)
    7. JWT alg=none (auth via /api/jwt/verify)
    8. Prototype pollution (JSON merge via /api/merge)
    9. Race condition (coupon redemption via /api/coupon/redeem)
   10. Path traversal (file download via /download)

Run: python3 app.py
Default port: 5555 (configurable via PORT env var)

NEVER deploy this to production. NEVER expose to internet.
For local scanner testing ONLY.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time

import jwt
from flask import Flask, jsonify, make_response, render_template_string, request

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey-12345"  # INTENTIONALLY WEAK
DB_PATH = "/tmp/elengenix_vuln.db"

# ═══════════════════════════════════════════════════════════════════════════
# DB SETUP
# ═══════════════════════════════════════════════════════════════════════════


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS comments;
        DROP TABLE IF EXISTS coupons;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 100.0
        );
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            content TEXT
        );
        CREATE TABLE coupons (
            id INTEGER PRIMARY KEY,
            code TEXT UNIQUE,
            used INTEGER DEFAULT 0,
            value REAL DEFAULT 50.0
        );
        INSERT INTO users (username, password, email, role, balance) VALUES
            ('alice', 'alice123', 'alice@test.com', 'user', 100.0),
            ('bob',   'bob123',   'bob@test.com',   'user', 50.0),
            ('admin', 'admin123', 'admin@test.com', 'admin', 1000.0);
        INSERT INTO coupons (code, used, value) VALUES
            ('WELCOME50', 0, 50.0),
            ('SAVE10',    0, 10.0);
    """
    )
    conn.commit()
    conn.close()


_init_db()


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ═══════════════════════════════════════════════════════════════════════════
# VULN 1: SQL Injection — login form (string concatenation)
# ═══════════════════════════════════════════════════════════════════════════


@app.route("/login", methods=["POST"])
def login_sqli():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # VULNERABLE: direct string concatenation
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = _db()
    row = conn.execute(query).fetchone()
    conn.close()
    if row:
        # Set session cookie properly
        session_id = f"session_{row['id']}_{hashlib.md5(username.encode()).hexdigest()[:8]}"
        resp = make_response(
            jsonify(
                {
                    "status": "ok",
                    "user": dict(row),
                    "token": session_id,
                }
            )
        )
        resp.set_cookie("session_id", session_id, httponly=False, samesite="Lax")
        return resp
    return jsonify({"status": "fail", "query": query}), 401  # echoes query (debug leak)


# ═══════════════════════════════════════════════════════════════════════════
# VULN 2: Reflected XSS — search
# ═══════════════════════════════════════════════════════════════════════════


@app.route("/search")
def search_xss():
    q = request.args.get("q", "")
    # VULNERABLE: raw string interpolation
    html = f"<html><body>Search results for: {q}</body></html>"
    return html, 200, {"Content-Type": "text/html"}


# ═══════════════════════════════════════════════════════════════════════════
# VULN 3: Stored XSS — comments
# ═══════════════════════════════════════════════════════════════════════════


@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        c = request.form.get("content", "")
        conn = _db()
        conn.execute("INSERT INTO comments (user_id, content) VALUES (1, ?)", (c,))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})
    conn = _db()
    rows = conn.execute("SELECT * FROM comments").fetchall()
    conn.close()
    # VULNERABLE: rendered without escaping
    html = "<html><body><h1>Comments</h1>"
    for r in rows:
        html += f"<div class='comment'>{r['content']}</div>"
    html += "</body></html>"
    return html, 200, {"Content-Type": "text/html"}


# ═══════════════════════════════════════════════════════════════════════════
# VULN: Authenticated BOLA — /api/user/<id> accessible to any logged-in user
# ═══════════════════════════════════════════════════════════════════════════


@app.route("/api/user/<int:user_id>")
def user_profile_idor(user_id):
    # Check session cookie OR Authorization header
    auth_header = request.headers.get("Authorization", "")
    session_id = request.cookies.get("session_id", "")
    if not auth_header and not session_id:
        return jsonify({"error": "unauthenticated"}), 401
    # VULNERABLE: no ownership check — any logged-in user can see any user
    conn = _db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if row:
        return jsonify(dict(row))
    return jsonify({"error": "not found"}), 404


# ═══════════════════════════════════════════════════════════════════════════
# VULN 5: Mass Assignment — registration accepts role parameter
# ═══════════════════════════════════════════════════════════════════════════


@app.route("/register", methods=["POST"])
def register_mass_assign():
    data = request.get_json() or {}
    # VULNERABLE: blindly assigns all fields including role
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    role = data.get("role", "user")  # attacker can set role=admin
    balance = data.get("balance", 100.0)  # attacker can set balance=99999
    try:
        conn = _db()
        conn.execute(
            "INSERT INTO users (username, password, email, role, balance) VALUES (?,?,?,?,?)",
            (username, password, email, role, balance),
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "ok", "role": role, "balance": balance})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════════════
# VULN 6: SSTI — template injection
# ═══════════════════════════════════════════════════════════════════════════


@app.route("/render")
def render_ssti():
    tpl = request.args.get("template", "Hello {{ name }}")
    name = request.args.get("name", "World")
    # VULNERABLE: user-controlled template string
    return render_template_string(tpl, name=name), 200, {"Content-Type": "text/html"}


# ═══════════════════════════════════════════════════════════════════════════
# VULN 7: JWT alg=none acceptance
# ═══════════════════════════════════════════════════════════════════════════


@app.route("/api/jwt/verify", methods=["POST"])
def jwt_verify():
    token = request.get_json().get("token", "")
    try:
        # VULNERABLE: algorithms not pinned — accepts alg=none
        payload = jwt.decode(
            token, options={"verify_signature": False}, algorithms=["HS256", "RS256", "none"]
        )
        return jsonify({"valid": True, "payload": payload})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 401


@app.route("/api/jwt/issue")
def jwt_issue():
    token = jwt.encode({"user": "alice", "role": "user"}, "secret", algorithm="HS256")
    return jsonify({"token": token})


# ═══════════════════════════════════════════════════════════════════════════
# VULN 8: Prototype pollution — JSON merge
# ═══════════════════════════════════════════════════════════════════════════


@app.route("/api/merge", methods=["POST"])
def proto_pollution():
    # VULNERABLE: naive deep merge with __proto__
    def merge(target, source):
        for k, v in source.items():
            if k == "__proto__":
                # Naive handling — accepts the keys
                pass
            if isinstance(v, dict) and isinstance(target.get(k), dict):
                merge(target[k], v)
            else:
                target[k] = v
        return target

    data = request.get_json() or {}
    result = merge({}, data)
    return jsonify({"merged": result})


# ═══════════════════════════════════════════════════════════════════════════
# VULN 9: Race condition — single-use coupon
# ═══════════════════════════════════════════════════════════════════════════


@app.route("/api/coupon/redeem", methods=["POST"])
def coupon_redeem():
    code = request.get_json().get("code", "")
    conn = _db()
    # VULNERABLE: TOCTOU — read then write without lock
    row = conn.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
    if not row or row["used"]:
        conn.close()
        return jsonify({"error": "invalid or used"}), 400
    time.sleep(0.05)  # makes race easier to exploit
    conn.execute("UPDATE coupons SET used=1 WHERE code=?", (code,))
    conn.commit()
    conn.close()
    return jsonify({"redeemed": code, "value": row["value"]})


# ═══════════════════════════════════════════════════════════════════════════
# VULN 10: Path traversal — file download
# ═══════════════════════════════════════════════════════════════════════════


@app.route("/download")
def download_traversal():
    fname = request.args.get("file", "readme.txt")
    # VULNERABLE: no path sanitization
    base = "/tmp/elengenix_files/"
    os.makedirs(base, exist_ok=True)
    # Create a benign file for testing
    safe_file = os.path.join(base, "readme.txt")
    if not os.path.exists(safe_file):
        with open(safe_file, "w") as f:
            f.write("Welcome to Elengenix Test Files\n")
    # Concatenate and return — vulnerable to ../../etc/passwd
    try:
        full = os.path.join(base, fname)
        # Block obvious traversal — wait, NO, we INTENTIONALLY allow it for testing
        with open(full, "r") as f:
            return f.read(), 200, {"Content-Type": "text/plain"}
    except Exception as e:
        return jsonify({"error": str(e), "attempted": fname}), 400


# ═══════════════════════════════════════════════════════════════════════════
# HEALTH & INFO
# ═══════════════════════════════════════════════════════════════════════════


@app.route("/")
def index():
    return jsonify(
        {
            "app": "Elengenix Vulnerable Test Target",
            "version": "1.0.0",
            "vulnerabilities": [
                "SQL Injection: POST /login",
                "Reflected XSS: GET /search?q=",
                "Stored XSS: POST /comments",
                "IDOR: GET /api/user/<id>",
                "Mass Assignment: POST /register",
                "SSTI: GET /render?template=",
                "JWT alg=none: POST /api/jwt/verify",
                "Prototype Pollution: POST /api/merge",
                "Race Condition: POST /api/coupon/redeem",
                "Path Traversal: GET /download?file=",
            ],
            "warning": "FOR LOCAL TESTING ONLY — DO NOT EXPOSE",
        }
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5555))
    print(f"Starting vulnerable target on port {port}")
    print("  Endpoints: see GET /")
    print("  WARNING: deliberately vulnerable, LOCAL TESTING ONLY")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
