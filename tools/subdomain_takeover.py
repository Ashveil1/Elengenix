"""tools/subdomain_takeover.py — Subdomain Takeover Detection

Checks if discovered subdomains point to unclaimed cloud resources.
A subdomain takeover occurs when a DNS record (CNAME) points to an
external service (S3, Heroku, Azure, GitHub Pages, etc.) that has
been deprovisioned, allowing an attacker to claim it.

Technique:
  1. Resolve the subdomain's CNAME chain
  2. Check if the CNAME target matches known vulnerable services
  3. Verify if the resource is actually unclaimed (HTTP fingerprint)
"""

import logging
import re
import socket
import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("elengenix.subdomain_takeover")

_TIMEOUT = 8

# ─────────────────────────────────────────────────
# Fingerprint Database
# Each entry: service_name -> {cname_patterns, http_fingerprints, severity}
# ─────────────────────────────────────────────────

TAKEOVER_SIGNATURES = {
    "aws_s3": {
        "cname_patterns": [r"\.s3\.amazonaws\.com$", r"\.s3[-\.].*\.amazonaws\.com$"],
        "http_fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "high",
        "service": "AWS S3",
    },
    "github_pages": {
        "cname_patterns": [r"\.github\.io$"],
        "http_fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/)",
        ],
        "severity": "high",
        "service": "GitHub Pages",
    },
    "heroku": {
        "cname_patterns": [r"\.herokuapp\.com$", r"\.herokussl\.com$"],
        "http_fingerprints": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app",
            "no-such-app",
        ],
        "severity": "high",
        "service": "Heroku",
    },
    "azure_websites": {
        "cname_patterns": [r"\.azurewebsites\.net$", r"\.cloudapp\.azure\.com$"],
        "http_fingerprints": [
            "404 Web Site not found",
            "Error 404 - Web app not found",
        ],
        "severity": "high",
        "service": "Azure App Service",
    },
    "azure_blob": {
        "cname_patterns": [r"\.blob\.core\.windows\.net$"],
        "http_fingerprints": [
            "BlobNotFound",
            "The specified container does not exist",
            "ContainerNotFound",
        ],
        "severity": "high",
        "service": "Azure Blob Storage",
    },
    "shopify": {
        "cname_patterns": [r"\.myshopify\.com$"],
        "http_fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step left",
        ],
        "severity": "medium",
        "service": "Shopify",
    },
    "tumblr": {
        "cname_patterns": [r"\.tumblr\.com$"],
        "http_fingerprints": [
            "There's nothing here",
            "Whatever you were looking for doesn't currently exist",
        ],
        "severity": "medium",
        "service": "Tumblr",
    },
    "wordpress": {
        "cname_patterns": [r"\.wordpress\.com$"],
        "http_fingerprints": ["Do you want to register"],
        "severity": "medium",
        "service": "WordPress.com",
    },
    "ghost": {
        "cname_patterns": [r"\.ghost\.io$"],
        "http_fingerprints": ["The thing you were looking for is no longer here"],
        "severity": "medium",
        "service": "Ghost",
    },
    "surge": {
        "cname_patterns": [r"\.surge\.sh$"],
        "http_fingerprints": ["project not found"],
        "severity": "medium",
        "service": "Surge.sh",
    },
    "fastly": {
        "cname_patterns": [r"\.fastly\.net$", r"\.fastlylb\.net$"],
        "http_fingerprints": ["Fastly error: unknown domain"],
        "severity": "high",
        "service": "Fastly CDN",
    },
    "pantheon": {
        "cname_patterns": [r"\.pantheonsite\.io$"],
        "http_fingerprints": ["404 error unknown site", "The gods are wise"],
        "severity": "medium",
        "service": "Pantheon",
    },
    "netlify": {
        "cname_patterns": [r"\.netlify\.app$", r"\.netlify\.com$"],
        "http_fingerprints": ["Not Found - Request ID"],
        "severity": "medium",
        "service": "Netlify",
    },
    "fly_io": {
        "cname_patterns": [r"\.fly\.dev$"],
        "http_fingerprints": ["404 Not Found"],
        "severity": "medium",
        "service": "Fly.io",
    },
    "aws_elastic_beanstalk": {
        "cname_patterns": [r"\.elasticbeanstalk\.com$"],
        "http_fingerprints": ["404 Not Found"],
        "severity": "high",
        "service": "AWS Elastic Beanstalk",
    },
    "zendesk": {
        "cname_patterns": [r"\.zendesk\.com$"],
        "http_fingerprints": ["Help Center Closed", "this help center no longer exists"],
        "severity": "medium",
        "service": "Zendesk",
    },
    "google_cloud_storage": {
        "cname_patterns": [r"\.storage\.googleapis\.com$", r"c\.storage\.googleapis\.com$"],
        "http_fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "severity": "high",
        "service": "Google Cloud Storage",
    },
}


# ─────────────────────────────────────────────────
# Core Functions
# ─────────────────────────────────────────────────

def resolve_cname(domain: str) -> Optional[str]:
    """Resolve the CNAME record for a domain using DNS."""
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "CNAME", domain],
            capture_output=True, text=True, timeout=5
        )
        cname = result.stdout.strip().rstrip(".")
        if cname:
            return cname
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: try socket
    try:
        answers = socket.getaddrinfo(domain, None)
        if answers:
            return answers[0][4][0]
    except socket.gaierror:
        pass

    return None


def check_http_fingerprint(domain: str, fingerprints: List[str]) -> Tuple[bool, str]:
    """Check if a domain's HTTP response matches takeover fingerprints."""
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{domain}",
                timeout=_TIMEOUT,
                headers={"User-Agent": "Elengenix-Security-Scanner/3.0"},
                verify=False,
                allow_redirects=True,
            )
            body = resp.text[:5000]

            for fp in fingerprints:
                if fp.lower() in body.lower():
                    return True, fp

        except requests.exceptions.SSLError:
            continue
        except Exception:
            continue

    return False, ""


def check_single_subdomain(subdomain: str) -> Optional[Dict]:
    """
    Check a single subdomain for takeover vulnerability.
    Returns a finding dict if vulnerable, None otherwise.
    """
    # Clean the subdomain
    subdomain = subdomain.strip().lower()
    if subdomain.startswith("http"):
        subdomain = urlparse(subdomain).hostname or subdomain

    # Step 1: Resolve CNAME
    cname = resolve_cname(subdomain)

    if not cname:
        return None

    # Step 2: Check if CNAME matches any known vulnerable service
    for service_id, sig in TAKEOVER_SIGNATURES.items():
        for pattern in sig["cname_patterns"]:
            if re.search(pattern, cname, re.IGNORECASE):
                # Step 3: Verify with HTTP fingerprint
                is_vulnerable, matched_fp = check_http_fingerprint(
                    subdomain, sig["http_fingerprints"]
                )

                if is_vulnerable:
                    return {
                        "title": f"Subdomain Takeover: {subdomain} → {sig['service']}",
                        "description": (
                            f"Subdomain '{subdomain}' has a CNAME pointing to "
                            f"{sig['service']} ({cname}), but the resource is unclaimed.\n"
                            f"HTTP fingerprint match: '{matched_fp}'\n\n"
                            f"An attacker can claim this resource and serve "
                            f"malicious content under the trusted domain."
                        ),
                        "severity": sig["severity"],
                        "type": "subdomain_takeover",
                        "subdomain": subdomain,
                        "cname": cname,
                        "service": sig["service"],
                        "fingerprint": matched_fp,
                    }
                else:
                    # CNAME matches but resource exists — still noteworthy
                    logger.info(
                        f"{subdomain} → {cname} ({sig['service']}): "
                        f"CNAME match but resource exists"
                    )

    return None


def check_subdomains(subdomains: List[str]) -> List[Dict]:
    """
    Check a list of subdomains for takeover vulnerabilities.

    Args:
        subdomains: List of subdomain strings

    Returns:
        List of vulnerability findings
    """
    findings = []

    for sub in subdomains:
        try:
            result = check_single_subdomain(sub)
            if result:
                findings.append(result)
                print(f"    [TAKEOVER] {sub} → {result['service']} (VULNERABLE!)")
            else:
                logger.debug(f"No takeover for {sub}")
        except Exception as e:
            logger.error(f"Takeover check error for {sub}: {e}")

    return findings
