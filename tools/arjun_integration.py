"""
tools/arjun_integration.py — HTTP Parameter Discovery (v1.0.0)
- Arjun: HTTP parameter discovery suite
- Finds hidden parameters, query parameters, form parameters
- Essential for API testing and parameter pollution attacks
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Union

from tools.tool_registry import BaseTool, ToolCategory, ToolMetadata, ToolResult, ToolPriority, register_tool

@register_tool(ToolMetadata(
 name="arjun",
 category=ToolCategory.API,
 priority=ToolPriority.MEDIUM,
 binary_name="arjun",
 description="HTTP parameter discovery suite for finding hidden parameters",
 timeout_seconds=300,
 supports_list_input=True,
))
class ArjunTool(BaseTool):
 """Arjun parameter discovery integration."""
 
 async def execute(
 self, 
 target: Union[str, List[str]], 
 report_dir: Path,
 semaphore: asyncio.Semaphore,
 method: str = "GET",
 **kwargs
 ) -> ToolResult:
 """
 Execute arjun parameter discovery.
 
 Args:
 target: URL or file containing URLs
 report_dir: Directory for output
 semaphore: Rate limiter
 method: HTTP method (GET, POST, JSON)
 """
 start_time = time.time()
 
 output_file = report_dir / "arjun_results.json"
 
 # Check if target is a file or URL
 if isinstance(target, list):
 # Write URLs to file
 url_file = report_dir / "arjun_urls.txt"
 url_file.write_text('\n'.join(target))
 target = str(url_file)
 
 # Check if target is a file path
 target_path = Path(target)
 is_file = target_path.exists() and target_path.is_file()
 
 if is_file:
 cmd = [
 "arjun", "-i", target,
 "-oJ", str(output_file),
 "-m", method.lower(),
 "-oT", str(report_dir / "arjun_results.txt"), # Also save text format
 ]
 else:
 cmd = [
 "arjun", "-u", target,
 "-oJ", str(output_file),
 "-m", method.lower(),
 "-oT", str(report_dir / "arjun_results.txt"),
 ]
 
 stdout, stderr, rc = await self._run_subprocess(cmd, semaphore=semaphore)
 execution_time = time.time() - start_time
 
 # Parse findings
 findings = []
 
 # Try JSON output first
 if output_file.exists():
 try:
 data = json.loads(output_file.read_text())
 for result in data.get("results", []):
 url = result.get("url", "")
 params_found = result.get("params", [])
 
 for param in params_found:
 findings.append({
 "type": "hidden_parameter",
 "severity": "medium",
 "url": url,
 "parameter": param.get("name", ""),
 "method": method,
 "value": param.get("value", ""),
 "cwe": "CWE-200", # Information Exposure
 })
 except (json.JSONDecodeError, KeyError) as e:
 
 # Fallback to text parsing
 text_file = report_dir / "arjun_results.txt"
 if not findings and text_file.exists():
 content = text_file.read_text()
 for line in content.split('\n'):
 if "|" in line and "Parameter" in line:
 parts = line.split("|")
 if len(parts) >= 3:
 findings.append({
 "type": "hidden_parameter",
 "severity": "medium",
 "url": parts[0].strip(),
 "parameter": parts[1].strip(),
 "evidence": line,
 })
 
 return ToolResult(
 success=rc == 0 or len(findings) > 0,
 tool_name=self.metadata.name,
 category=self.metadata.category,
 output=stdout + stderr,
 findings=findings,
 execution_time=execution_time,
 raw_output_file=output_file if output_file.exists() else None,
 )
 
 async def discover_on_urls(
 self,
 urls: List[str],
 report_dir: Path,
 semaphore: asyncio.Semaphore,
 methods: List[str] = None
 ) -> List[ToolResult]:
 """Run parameter discovery on multiple URLs with multiple methods."""
 if methods is None:
 methods = ["GET", "POST", "JSON"]
 
 results = []
 
 for method in methods:
 result = await self.execute(urls, report_dir, semaphore, method=method)
 results.append(result)
 
 return results

# Quick test
if __name__ == "__main__":
 from tools.tool_registry import registry
 
 tool = registry.get_tool("arjun")
 if tool:
 print(f"[+] Arjun tool registered: {tool.is_available}")
 if not tool.is_available:
 print("[!] arjun binary not found. Install with: pip install arjun")
 else:
 print("[!] Failed to register arjun")
