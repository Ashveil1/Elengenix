"""
tools/ffuf_integration.py — Fast Web Fuzzer (v1.0.0)
- FFUF: Fast web fuzzer for directory and parameter discovery
- Custom wordlist support with AI-generated lists
- Recursive directory fuzzing
- Parameter fuzzing (GET/POST)
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Union

from tools.tool_registry import BaseTool, ToolCategory, ToolMetadata, ToolResult, ToolPriority, register_tool

@register_tool(ToolMetadata(
 name="ffuf",
 category=ToolCategory.FUZZING,
 priority=ToolPriority.MEDIUM,
 binary_name="ffuf",
 description="Fast web fuzzer for directory and parameter discovery",
 timeout_seconds=300,
))
class FfufTool(BaseTool):
 """FFUF web fuzzer integration."""
 
 # Default wordlist paths (can be overridden)
 DEFAULT_WORDLISTS = {
 "common": "wordlists/common.txt",
 "directories": "wordlists/directory-list-2.3-medium.txt",
 "api": "wordlists/api-endpoints.txt",
 "parameters": "wordlists/parameters.txt",
 }
 
 # Status codes to consider successful
 SUCCESS_CODES = [200, 204, 301, 302, 307, 308, 401, 403, 405]
 
 async def execute(
 self, 
 target: str, 
 report_dir: Path,
 semaphore: asyncio.Semaphore,
 fuzz_mode: str = "directory", # directory, vhost, parameter
 wordlist: Path = None,
 extensions: str = "php,html,js,txt,json,xml",
 **kwargs
 ) -> ToolResult:
 """
 Execute ffuf fuzzer.
 
 Args:
 target: Target URL with FUZZ keyword (e.g., http://target/FUZZ)
 report_dir: Output directory
 semaphore: Rate limiter
 fuzz_mode: Type of fuzzing to perform
 wordlist: Path to wordlist file
 extensions: Comma-separated file extensions to test
 """
 start_time = time.time()
 
 output_file = report_dir / f"ffuf_{fuzz_mode}_results.json"
 
 # Ensure target has FUZZ keyword
 if "FUZZ" not in target:
 if fuzz_mode == "directory":
 target = f"{target.rstrip('/')}/FUZZ"
 elif fuzz_mode == "vhost":
 target = target
 elif fuzz_mode == "parameter":
 target = f"{target}?FUZZ=value"
 
 # Get wordlist
 if wordlist is None:
 wordlist = self._get_default_wordlist(fuzz_mode, report_dir)
 
 if not wordlist or not wordlist.exists():
 return ToolResult(
 success=False,
 tool_name=self.metadata.name,
 category=self.metadata.category,
 error_message=f"Wordlist not found: {wordlist}",
 )
 
 # Build command
 cmd = [
 "ffuf",
 "-u", target,
 "-w", str(wordlist),
 "-o", str(output_file),
 "-of", "json",
 "-s", # Silent mode
 "-mc", ",".join(map(str, self.SUCCESS_CODES)),
 "-t", "50", # Threads
 ]
 
 # Add extensions for directory fuzzing
 if fuzz_mode == "directory" and extensions:
 cmd.extend(["-e", f".{extensions.replace(',', ',.')}"])
 
 # Virtual host mode
 if fuzz_mode == "vhost":
 cmd.extend(["-H", f"Host: FUZZ.{target}"])
 
 # Follow redirects
 cmd.append("-r")
 
 stdout, stderr, rc = await self._run_subprocess(cmd, semaphore=semaphore)
 execution_time = time.time() - start_time
 
 # Parse findings
 findings = []
 
 if output_file.exists():
 try:
 data = json.loads(output_file.read_text())
 results = data.get("results", [])
 
 for result in results:
 url = result.get("url", "")
 status = result.get("status", 0)
 length = result.get("length", 0)
 words = result.get("words", 0)
 
 # Determine severity based on status and content
 severity = "info"
 if status == 200:
 severity = "medium" if length > 0 else "low"
 elif status in [401, 403]:
 severity = "medium" # Protected resource
 
 finding = {
 "type": f"ffuf_{fuzz_mode}",
 "severity": severity,
 "url": url,
 "status": status,
 "length": length,
 "words": words,
 "redirectlocation": result.get("redirectlocation", ""),
 "resultfile": result.get("resultfile", ""),
 "cwe": "CWE-200" if status == 200 else None,
 }
 findings.append(finding)
 except (json.JSONDecodeError, KeyError) as e:
 
 return ToolResult(
 success=rc == 0 or len(findings) > 0,
 tool_name=self.metadata.name,
 category=self.metadata.category,
 output=stdout + stderr,
 findings=findings,
 execution_time=execution_time,
 raw_output_file=output_file if output_file.exists() else None,
 )
 
 def _get_default_wordlist(self, fuzz_mode: str, report_dir: Path) -> Path:
 """Get default wordlist for fuzz mode."""
 # Try to find wordlist in common locations
 possible_paths = [
 Path(__file__).parent.parent / "wordlists" / f"{fuzz_mode}.txt",
 Path(__file__).parent.parent / "wordlists" / "common.txt",
 Path("/usr/share/wordlists/dirb/common.txt"),
 Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
 report_dir.parent / "wordlists" / f"{fuzz_mode}.txt",
 ]
 
 for path in possible_paths:
 if path.exists():
 return path
 
 return None
 
 async def fuzz_from_httpx(
 self,
 report_dir: Path,
 semaphore: asyncio.Semaphore,
 wordlist: Path = None
 ) -> List[ToolResult]:
 """Run directory fuzzing on all live hosts from httpx output."""
 httpx_file = report_dir / "live_hosts.json"
 
 if not httpx_file.exists():
 return []
 
 # Extract URLs
 urls = []
 try:
 for line in httpx_file.read_text().strip().split('\n'):
 if line:
 data = json.loads(line)
 url = data.get("url", "")
 status = data.get("status_code", 0)
 # Only fuzz 200 OK endpoints
 if url and status == 200:
 urls.append(url)
 except Exception:
 
 if not urls:
 return []
 
 # Limit to first 5 URLs to avoid long scans
 urls = urls[:5]
 
 results = []
 for url in urls:
 result = await self.execute(
 url, 
 report_dir, 
 semaphore,
 fuzz_mode="directory",
 wordlist=wordlist
 )
 results.append(result)
 
 return results
 
 async def generate_wordlist_from_js(
 self,
 js_analyzer_output: Path,
 output_file: Path
 ) -> Path:
 """Generate wordlist from JS analyzer endpoints."""
 if not js_analyzer_output.exists():
 return None
 
 # Extract unique paths/endpoints from JS analysis
 words = set()
 try:
 content = js_analyzer_output.read_text()
 # Simple extraction - can be enhanced
 for line in content.split('\n'):
 if '/' in line and not line.startswith('#'):
 parts = line.split('/')
 for part in parts:
 if part and len(part) > 2:
 words.add(part)
 except Exception:
 
 if words:
 output_file.write_text('\n'.join(sorted(words)))
 return output_file
 
 return None

# Quick test
if __name__ == "__main__":
 from tools.tool_registry import registry
 
 tool = registry.get_tool("ffuf")
 if tool:
 print(f"[+] FFUF tool registered: {tool.is_available}")
 if not tool.is_available:
 print("[!] ffuf binary not found. Install with: go install github.com/ffuf/ffuf@latest")
 else:
 print("[!] Failed to register ffuf")
