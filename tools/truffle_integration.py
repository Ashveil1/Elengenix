"""
tools/truffle_integration.py — Secret Detection (v1.0.0)
- TruffleHog: Find credentials, API keys, secrets in code
- Scans Git history, files, and URLs
- Deep inspection capability
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Union

from tools.tool_registry import BaseTool, ToolCategory, ToolMetadata, ToolResult, ToolPriority, register_tool

@register_tool(ToolMetadata(
 name="trufflehog",
 category=ToolCategory.SECRETS,
 priority=ToolPriority.HIGH,
 binary_name="trufflehog",
 description="Find credentials, API keys, and secrets in code and Git history",
 timeout_seconds=600,
 supports_list_input=True,
))
class TrufflehogTool(BaseTool):
 """TruffleHog secret detection integration."""
 
 # High-entropy patterns and verified secrets only
 SEVERITY_MAP = {
 "AWS": "critical",
 "GitHub": "critical",
 "Slack": "high",
 "PrivateKey": "critical",
 "APIKey": "high",
 "Password": "medium",
 }
 
 async def execute(
 self, 
 target: Union[str, List[str]], 
 report_dir: Path,
 semaphore: asyncio.Semaphore,
 scan_type: str = "filesystem", # filesystem, git, docker
 **kwargs
 ) -> ToolResult:
 """
 Execute trufflehog secret scan.
 
 Args:
 target: Path to scan or URL
 report_dir: Output directory
 semaphore: Rate limiter
 scan_type: Type of scan to perform
 """
 start_time = time.time()
 
 output_file = report_dir / "trufflehog_results.json"
 
 # Build command based on scan type
 if scan_type == "git":
 cmd = [
 "trufflehog", "git", target,
 "--json",
 "--only-verified", # Only show verified secrets
 ]
 elif scan_type == "docker":
 cmd = [
 "trufflehog", "docker", target,
 "--json",
 "--only-verified",
 ]
 else: # filesystem (default)
 if isinstance(target, list):
 # Scan multiple paths
 target = target[0] if target else "."
 
 cmd = [
 "trufflehog", "filesystem", target,
 "--json",
 "--only-verified",
 "--include-detectors", "all", # Use all detectors
 ]
 
 # Run with output redirection
 stdout_file = report_dir / "trufflehog_raw.json"
 
 async with semaphore:
 try:
 with open(stdout_file, "w") as f:
 proc = await asyncio.create_subprocess_exec(
 *cmd,
 stdout=f,
 stderr=asyncio.subprocess.PIPE
 )
 _, stderr = await asyncio.wait_for(
 proc.communicate(),
 timeout=self.metadata.timeout_seconds
 )
 except asyncio.TimeoutError:
 proc.kill()
 stderr = b"Timeout exceeded"
 
 execution_time = time.time() - start_time
 
 # Parse findings
 findings = []
 
 if stdout_file.exists():
 try:
 for line in stdout_file.read_text().strip().split('\n'):
 if not line:
 continue
 try:
 data = json.loads(line)
 detector = data.get("DetectorName", "Unknown")
 verified = data.get("Verified", False)
 
 # Determine severity
 severity = self.SEVERITY_MAP.get(detector, "medium")
 if not verified:
 severity = "low" # Unverified secrets are lower priority
 
 finding = {
 "type": "secret",
 "severity": severity,
 "detector": detector,
 "verified": verified,
 "file": data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
 "line": data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
 "raw": data.get("Raw", ""), # Redacted in final report for security
 "redacted": data.get("Redacted", ""),
 "cwe": "CWE-798", # Use of Hard-coded Credentials
 }
 findings.append(finding)
 except json.JSONDecodeError:
 continue
 except Exception as e:
 
 # Generate summary
 verified_count = sum(1 for f in findings if f.get("verified"))
 critical_count = sum(1 for f in findings if f.get("severity") == "critical")
 
 output_summary = f"Found {len(findings)} secrets ({verified_count} verified, {critical_count} critical)"
 
 return ToolResult(
 success=True,
 tool_name=self.metadata.name,
 category=self.metadata.category,
 output=output_summary + "\n" + stderr.decode() if stderr else output_summary,
 findings=findings,
 execution_time=execution_time,
 raw_output_file=stdout_file if stdout_file.exists() else None,
 )
 
 async def scan_js_files(
 self,
 report_dir: Path,
 semaphore: asyncio.Semaphore
 ) -> ToolResult:
 """Scan JavaScript files for secrets."""
 # Look for downloaded JS files
 js_dirs = [
 report_dir / "js_files",
 report_dir / "downloads",
 report_dir.parent / "downloads",
 ]
 
 for js_dir in js_dirs:
 if js_dir.exists():
 return await self.execute(
 str(js_dir), 
 report_dir, 
 semaphore, 
 scan_type="filesystem"
 )
 
 return ToolResult(
 success=False,
 tool_name=self.metadata.name,
 category=self.metadata.category,
 error_message="No JavaScript files directory found",
 )
 
 async def scan_target_directory(
 self,
 target_dir: Path,
 report_dir: Path,
 semaphore: asyncio.Semaphore
 ) -> ToolResult:
 """Scan a specific directory for secrets."""
 if not target_dir.exists():
 return ToolResult(
 success=False,
 tool_name=self.metadata.name,
 category=self.metadata.category,
 error_message=f"Directory not found: {target_dir}",
 )
 
 return await self.execute(
 str(target_dir),
 report_dir,
 semaphore,
 scan_type="filesystem"
 )

# Quick test
if __name__ == "__main__":
 from tools.tool_registry import registry
 
 tool = registry.get_tool("trufflehog")
 if tool:
 print(f"[+] TruffleHog tool registered: {tool.is_available}")
 if not tool.is_available:
 print("[!] trufflehog binary not found. Install with:")
 print(" curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh")
 else:
 print("[!] Failed to register trufflehog")
