"""
tools/base_scanner.py — Python-based Vulnerability Scanner
- HTTP probe and vulnerability detection
- Returns parsed findings list
"""

from __future__ import annotations

import logging
import os
import re
from typing import Dict, List

import requests

logger = logging.getLogger("elengenix.base_scanner")


def run_vuln_scan(
    target_url: str,
    timeout: int = 30,
) -> List[Dict]:
    """
    Run Python-based vulnerability scan against a target.
    Returns a list of parsed finding dicts.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    findings = []

    # Common vulnerability checks
    checks = [
        ("/.env", "Environment file exposed", "high"),
        ("/.git", "Git repository exposed", "high"),
        ("/admin", "Admin panel exposed", "medium"),
        ("/robots.txt", "Robots.txt with sensitive paths", "low"),
        ("/sitemap.xml", "Sitemap with sensitive URLs", "low"),
        ("/server-status", "Apache server-status exposed", "medium"),
        ("/server-info", "Apache server-info exposed", "medium"),
        ("/wp-config.php.bak", "WordPress config backup", "critical"),
        ("/.htaccess", "HTACCESS file exposed", "medium"),
        ("/web.config", "IIS config exposed", "medium"),
        ("/phpinfo.php", "PHP info exposed", "medium"),
        ("/.DS_Store", "macOS metadata file exposed", "low"),
        ("/crossdomain.xml", "Cross-domain policy file", "low"),
        ("/clientaccesspolicy.xml", "Silverlight policy file", "low"),
    ]

    for path, description, severity in checks:
        try:
            url = f"{target_url.rstrip('/')}{path}"
            response = requests.get(url, timeout=5, verify=False, allow_redirects=False)

            if response.status_code == 200 and len(response.text) > 50:
                findings.append(
                    {
                        "name": description,
                        "severity": severity.upper(),
                        "url": url,
                        "details": f"Status: {response.status_code}, Size: {len(response.text)} bytes",
                    }
                )
        except requests.exceptions.RequestException:
            continue
        except Exception as e:
            logger.debug(f"Error checking {path}: {e}")
            continue

    return findings


def _parse_output(output_file: str) -> List[Dict]:
    """Legacy function for backward compatibility."""
    findings = []
    if not os.path.exists(output_file):
        return findings
    try:
        with open(output_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                m = re.match(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)", line)
                if m:
                    findings.append(
                        {
                            "name": m.group(1),
                            "severity": m.group(2).upper(),
                            "url": m.group(3),
                            "details": line,
                        }
                    )
    except Exception as e:
        logger.warning(f"Could not parse output: {e}")
    return findings


# Backward compatibility alias
run_nuclei_scan = run_vuln_scan
