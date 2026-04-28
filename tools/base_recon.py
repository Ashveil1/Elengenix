"""
tools/base_recon.py — Subdomain & URL Enumeration (v2.0.0)
- Subfinder + Waybackurls + GAU (if available)
- Python-native deduplication & sorting
- Returns path to unique subdomains file
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger("elengenix.base_recon")

def run_subdomain_enum(domain: str, output_dir: str) -> str:
 """
 Discovers subdomains using available tools and deduplicates results.
 Returns path to the unique subdomains file.
 """
 logger.info(f"Starting subdomain enumeration for: {domain}")
 Path(output_dir).mkdir(parents=True, exist_ok=True)

 raw_file = os.path.join(output_dir, f"{domain}_raw.txt")
 unique_file = os.path.join(output_dir, f"{domain}_subs.txt")

 raw_lines: list[str] = []

 # 1. Subfinder
 if shutil.which("subfinder"):
 try:
 result = subprocess.run(
 ["subfinder", "-d", domain, "-silent"],
 capture_output=True, text=True, timeout=120,
 )
 if result.stdout.strip():
 raw_lines.extend(result.stdout.splitlines())
 logger.info(f"Subfinder: {len(result.stdout.splitlines())} results")
 except subprocess.TimeoutExpired:
 logger.warning("Subfinder timed out.")
 except Exception as e:
 logger.error(f"Subfinder error: {e}")
 else:
 raw_lines.append(domain)
 logger.warning("subfinder not found — using base domain only.")

 # 2. Waybackurls (extract hostnames)
 if shutil.which("waybackurls"):
 try:
 result = subprocess.run(
 ["waybackurls", domain],
 capture_output=True, text=True, timeout=60,
 )
 for url in result.stdout.splitlines():
 host = _extract_host(url)
 if host and domain in host:
 raw_lines.append(host)
 except Exception as e:
 logger.warning(f"waybackurls error: {e}")

 # 3. GAU
 if shutil.which("gau"):
 try:
 result = subprocess.run(
 ["gau", "--subs", domain],
 capture_output=True, text=True, timeout=60,
 )
 for url in result.stdout.splitlines():
 host = _extract_host(url)
 if host and domain in host:
 raw_lines.append(host)
 except Exception as e:
 logger.warning(f"gau error: {e}")

 # Deduplicate & sort
 unique = sorted({line.strip().lower() for line in raw_lines if line.strip()})

 with open(unique_file, "w", encoding="utf-8") as f:
 f.write("\n".join(unique))

 logger.info(f"Unique subdomains: {len(unique)} → {unique_file}")
 return unique_file

def _extract_host(url: str) -> str:
 try:
 from urllib.parse import urlparse
 return urlparse(url).netloc.split(":")[0]
 except Exception:
 return ""

if __name__ == "__main__":
 import sys
 if len(sys.argv) > 1:
 out = run_subdomain_enum(sys.argv[1], "reports/test_recon")
 print(f"Saved to: {out}")
