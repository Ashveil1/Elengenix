"""
tools/dalfox_integration.py — XSS Scanner Integration (v1.0.0)
- Dalfox: Powerful XSS scanning and parameter analysis
- Finds reflected parameters, DOM XSS, stored XSS
- Generates PoC automatically
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Union

from tools.tool_registry import BaseTool, ToolCategory, ToolMetadata, ToolResult, ToolPriority, register_tool

@register_tool(ToolMetadata(
 name="dalfox",
 category=ToolCategory.EXPLOITATION,
 priority=ToolPriority.HIGH,
 binary_name="dalfox",
 description="Powerful XSS scanner with automatic PoC generation",
 timeout_seconds=600,
 supports_list_input=True,
))
class DalfoxTool(BaseTool):
 """Dalfox XSS scanner integration."""
 
 async def execute(
 self, 
 target: Union[str, List[str]], 
 report_dir: Path,
 semaphore: asyncio.Semaphore,
 scan_mode: str = "url", # url, file, pipe
 **kwargs
 ) -> ToolResult:
 """
 Execute dalfox XSS scan.
 
 Args:
 target: URL to scan or path to URL list
 report_dir: Directory for output files
 semaphore: Async semaphore for rate limiting
 scan_mode: 'url' for single URL, 'file' for URL list
 """
 start_time = time.time()
 
 output_file = report_dir / "dalfox_results.json"
 
 # Build command based on mode
 if scan_mode == "file" or isinstance(target, list):
 # Multiple URLs
 if isinstance(target, list):
 url_file = report_dir / "dalfox_urls.txt"
 url_file.write_text('\n'.join(target))
 target = str(url_file)
 
 cmd = [
 "dalfox", "file", target,
 "--format", "json",
 "--output", str(output_file),
 "--silence",
 "--worker", "10",
 "--only-poc", # Only show confirmed XSS
 ]
 else:
 # Single URL
 cmd = [
 "dalfox", "url", target,
 "--format", "json",
 "--output", str(output_file),
 "--silence",
 "--worker", "5",
 "--only-poc",
 ]
 
 stdout, stderr, rc = await self._run_subprocess(cmd, semaphore=semaphore)
 execution_time = time.time() - start_time
 
 # Parse findings
 findings = []
 if output_file.exists():
 try:
 content = output_file.read_text()
 # Dalfox outputs one JSON object per line
 for line in content.strip().split('\n'):
 if line:
 try:
 data = json.loads(line)
 finding = {
 "type": "xss",
 "severity": "high",
 "url": data.get("url", ""),
 "parameter": data.get("param", ""),
 "poc": data.get("poc", ""),
 "method": data.get("method", "GET"),
 "evidence": data.get("evidence", ""),
 "cwe": "CWE-79",
 }
 findings.append(finding)
 except json.JSONDecodeError:
 continue
 except Exception as e:
 pass
 
 # Also check for results in stdout if file is empty
 if not findings and stdout:
 # Parse stdout for any inline results
 if "[POC]" in stdout:
 for line in stdout.split('\n'):
 if "[POC]" in line:
 findings.append({
 "type": "xss",
 "severity": "high",
 "evidence": line,
 "cwe": "CWE-79",
 })
 
 success = len(findings) > 0 or rc == 0
 
 return ToolResult(
 success=success,
 tool_name=self.metadata.name,
 category=self.metadata.category,
 output=stdout + stderr,
 findings=findings,
 execution_time=execution_time,
 raw_output_file=output_file if output_file.exists() else None,
 error_message=stderr if rc != 0 and not findings else None,
 )
 
 async def scan_with_httpx_feed(
 self,
 report_dir: Path,
 semaphore: asyncio.Semaphore
 ) -> ToolResult:
 """Scan URLs from httpx output automatically."""
 httpx_file = report_dir / "live_hosts.json"
 
 if not httpx_file.exists():
 return ToolResult(
 success=False,
 tool_name=self.metadata.name,
 category=self.metadata.category,
 error_message="No httpx output found. Run httpx first.",
 )
 
 # Extract URLs from httpx JSON output
 urls = []
 try:
 for line in httpx_file.read_text().strip().split('\n'):
 if line:
 data = json.loads(line)
 url = data.get("url", "")
 status = data.get("status_code", 0)
 # Only scan live endpoints that might have forms/parameters
 if url and status in [200, 301, 302, 403, 500]:
 urls.append(url)
 except Exception as e:
 return ToolResult(
 success=False,
 tool_name=self.metadata.name,
 category=self.metadata.category,
 error_message=f"Failed to parse httpx output: {e}",
 )
 
 if not urls:
 return ToolResult(
 success=False,
 tool_name=self.metadata.name,
 category=self.metadata.category,
 error_message="No valid URLs found in httpx output",
 )
 
 # Run dalfox on extracted URLs
 return await self.execute(urls, report_dir, semaphore, scan_mode="file")

# Quick test
if __name__ == "__main__":
 import sys
 from tools.tool_registry import registry
 
 tool = registry.get_tool("dalfox")
 if tool:
 print(f"[+] Dalfox tool registered: {tool.is_available}")
 if not tool.is_available:
 print("[!] dalfox binary not found. Install with: go install github.com/hahwul/dalfox/v2@latest")
 else:
 print("[!] Failed to register dalfox")
