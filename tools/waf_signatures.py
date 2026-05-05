"""tools/waf_signatures.py

Centralized WAF signature database.

All WAF detection logic across the framework should import from here
instead of maintaining separate signature dictionaries.
"""

WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "__cfduid", "cloudflare", "cf-cache-status"],
        "body": ["cloudflare", "cf-browser-verification", "ray id"],
        "cookies": ["__cfduid", "cf_clearance"],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "awselb", "x-amz-cf-id", "x-amzn-remapped"],
        "body": ["aws waf", "requestid"],
        "cookies": [],
    },
    "modsecurity": {
        "headers": ["server: mod_security", "server: modsecurity", "x-powered-by: mod_security"],
        "body": ["mod_security", "modsecurity", "not acceptable"],
        "cookies": [],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai", "x-cache: akamai"],
        "body": ["akamaighost", "akamai", "access denied"],
        "cookies": ["akamai"],
    },
    "incapsula": {
        "headers": ["x-iinfo", "x-cdn", "incap_ses"],
        "body": ["incapsula", "incident id", "support.incapsula.com"],
        "cookies": ["incap_ses", "visid_incap", "nlbi_"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
        "body": ["sucuri", "cloudproxy", "denied by sucuri"],
        "cookies": ["sucuri_cloudproxy"],
    },
    "fortinet": {
        "headers": ["fortigate", "fortiweb"],
        "body": ["fortigate", "fortiweb", "fortinet"],
        "cookies": [],
    },
    "f5_bigip": {
        "headers": ["x-f5", "bigip", "x-wa-info", "ts"],
        "body": ["bigip", "f5", "denied by policy"],
        "cookies": ["bigipserver", "f5"],
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn", "imperva"],
        "body": ["imperva", "incapsula", "denied by imperva"],
        "cookies": [],
    },
    "datadog": {
        "headers": ["x-datadog", "dd-trace-id"],
        "body": [],
        "cookies": [],
    },
}


def detect_waf_from_response(headers: dict, body: str = "",
                             cookies: dict = None) -> tuple:
    """
    Detect WAF from HTTP response characteristics.

    Args:
        headers: Response headers dict
        body: Response body text
        cookies: Response cookies dict

    Returns:
        (waf_name, confidence) or (None, 0.0)
    """
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    header_str = " ".join(f"{k}:{v}" for k, v in headers_lower.items())
    body_lower = (body or "").lower()[:2000]
    cookies_lower = {k.lower(): v.lower() for k, v in (cookies or {}).items()}

    best_match = None
    best_confidence = 0.0

    for waf_name, sigs in WAF_SIGNATURES.items():
        confidence = 0.0
        matches = 0

        for sig in sigs.get("headers", []):
            sig_lower = sig.lower()
            for hk, hv in headers_lower.items():
                if sig_lower in hk or sig_lower in hv:
                    matches += 1
                    break

        for sig in sigs.get("body", []):
            if sig.lower() in body_lower:
                matches += 1

        for sig in sigs.get("cookies", []):
            sig_lower = sig.lower()
            for ck in cookies_lower:
                if sig_lower in ck:
                    matches += 1
                    break

        if matches > 0:
            total_sigs = len(sigs.get("headers", [])) + len(sigs.get("body", [])) + len(sigs.get("cookies", []))
            confidence = min(1.0, 0.4 + (0.3 * matches / max(1, total_sigs)) + (0.3 if matches >= 2 else 0))

        if confidence > best_confidence:
            best_confidence = confidence
            best_match = waf_name

    if best_match and best_confidence >= 0.5:
        return best_match, best_confidence
    return None, 0.0
