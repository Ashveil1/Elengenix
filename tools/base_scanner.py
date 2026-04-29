"""
tools/base_scanner.py — Nuclei Vulnerability Scanner Wrapper (v2.0.0)
- Severity filtering
- Auto-skips if nuclei not installed
- Returns parsed findings list
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import List, Dict

logger = logging.getLogger("elengenix.base_scanner")

def run_nuclei_scan(
 target_file: str,
 output_dir: str,
 severity: str = "low,medium,high,critical",
 timeout: int = 300,
) -> List[Dict]:
 """
 Runs nuclei against a targets file.
 Returns a list of parsed finding dicts.
 """
 if not shutil.which("nuclei"):
 logger.warning("nuclei not installed — skipping scan.")
 return []

 if not os.path.exists(target_file):
 logger.error(f"Target file not found: {target_file}")
 return []

 output_file = os.path.join(output_dir, "nuclei_results.txt")
 cmd = [
 "nuclei",
 "-l", target_file,
 "-o", output_file,
 "-severity", severity,
 "-silent",
 "-no-color",
 ]

 logger.info(f"Running nuclei: {' '.join(cmd)}")
 try:
 subprocess.run(cmd, timeout=timeout, capture_output=True, check=False)
 except subprocess.TimeoutExpired:
 logger.warning(f"nuclei timed out after {timeout}s.")
 except Exception as e:
 logger.error(f"nuclei error: {e}")
 return []

 return _parse_output(output_file)

def _parse_output(output_file: str) -> List[Dict]:
 findings = []
 if not os.path.exists(output_file):
 return findings
 try:
 with open(output_file, "r", encoding="utf-8") as f:
 for line in f:
 line = line.strip()
 m = re.match(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)", line)
 if m:
 findings.append({
 "name": m.group(1),
 "severity": m.group(2).upper(),
 "url": m.group(3),
 "details": line,
 })
 except Exception as e:
 logger.warning(f"Could not parse nuclei output: {e}")
 return findings
