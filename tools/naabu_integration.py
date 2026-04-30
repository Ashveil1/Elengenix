"""
tools/naabu_integration.py — Fast Port Scanner (v1.0.0)
- Naabu: Fast port scanner using SYN/CONNECT
- SYN Scan, Service Discovery, CDN/WAF bypass
- Integrates with nmap for service detection
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Union

from tools.tool_registry import BaseTool, ToolCategory, ToolMetadata, ToolResult, ToolPriority, register_tool


@register_tool(ToolMetadata(
    name="naabu",
    category=ToolCategory.NETWORK,
    priority=ToolPriority.HIGH,
    binary_name="naabu",
    description="Fast port scanner with SYN/CONNECT support and service discovery",
    timeout_seconds=300,
))
class NaabuTool(BaseTool):
    """Naabu port scanner integration."""
    
    # Common web ports + interesting ports
    DEFAULT_PORTS = [
        "80", "443", "8080", "8443", "3000", "5000", "8000", "9000",
        "21", "22", "23", "25", "53", "110", "143", "3306", "5432",
        "6379", "27017", "9200", "9300",
    ]
    
    async def execute(
        self, 
        target: Union[str, List[str]], 
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        scan_type: str = "connect",  # syn, connect
        ports: List[str] = None,
        **kwargs
    ) -> ToolResult:
        """
        Execute naabu port scan.
        
        Args:
            target: Host to scan
            report_dir: Output directory
            semaphore: Rate limiter
            scan_type: 'syn' (requires root) or 'connect'
            ports: List of ports to scan (default: common web ports)
        """
        start_time = time.time()
        
        output_file = report_dir / "naabu_results.json"
        
        # Determine port range
        if ports is None:
            port_str = ",".join(self.DEFAULT_PORTS)
        else:
            port_str = ",".join(ports)
        
        # Build command
        cmd = [
            "naabu",
            "-host", target if isinstance(target, str) else target[0],
            "-p", port_str,
            "-json", "-o", str(output_file),
        ]
        
        # Scan type (SYN requires root)
        if scan_type == "syn":
            cmd.append("-scan-all-ips")
        else:
            cmd.append("-s")  # Simple connect scan
        
        # Enable nmap integration for service detection if available
        if kwargs.get("nmap_service_detection", False):
            cmd.extend(["-nmap-cli", "nmap -sV -sS"])
        
        stdout, stderr, rc = await self._run_subprocess(cmd, semaphore=semaphore)
        execution_time = time.time() - start_time
        
        # Parse findings
        findings = []
        
        if output_file.exists():
            try:
                for line in output_file.read_text().strip().split('\n'):
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        finding = {
                            "type": "open_port",
                            "severity": "info",
                            "host": data.get("host", ""),
                            "port": data.get("port", 0),
                            "ip": data.get("ip", ""),
                            "protocol": "tcp",
                        }
                        
                        # Adjust severity based on port
                        port = data.get("port", 0)
                        if port in [22, 3389, 5900]:  # RDP/VNC/SSH
                            finding["severity"] = "medium"
                        elif port in [3306, 5432, 6379, 27017]:  # Databases
                            finding["severity"] = "high"
                        elif port in [21, 23, 25, 110, 143]:  # Old protocols
                            finding["severity"] = "medium"
                        
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
            except Exception as e:
                pass
        
        # Also parse stdout if file is empty
        if not findings and stdout:
            for line in stdout.split('\n'):
                if "open" in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            port = int(parts[-1])
                            findings.append({
                                "type": "open_port",
                                "severity": "info",
                                "port": port,
                                "evidence": line,
                            })
                        except ValueError:
                            pass
        
        return ToolResult(
            success=rc == 0 or len(findings) > 0,
            tool_name=self.metadata.name,
            category=self.metadata.category,
            output=stdout + stderr,
            findings=findings,
            execution_time=execution_time,
            raw_output_file=output_file if output_file.exists() else None,
        )
    
    async def scan_with_subdomains(
        self,
        report_dir: Path,
        semaphore: asyncio.Semaphore
    ) -> ToolResult:
        """Scan all subdomains discovered by subfinder."""
        subdomains_file = report_dir / "subdomains.txt"
        
        if not subdomains_file.exists():
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message="No subdomains file found. Run subfinder first.",
            )
        
        # Read subdomains
        subdomains = [
            line.strip() 
            for line in subdomains_file.read_text().split('\n') 
            if line.strip()
        ]
        
        if not subdomains:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message="No subdomains found in file",
            )
        
        # Scan first subdomain or all depending on scope
        # For efficiency, scan just the main domain and a few key subdomains
        targets = subdomains[:10]  # Limit to first 10
        
        all_findings = []
        start_time = time.time()
        
        for target in targets:
            result = await self.execute(target, report_dir, semaphore)
            all_findings.extend(result.findings)
        
        execution_time = time.time() - start_time
        
        return ToolResult(
            success=len(all_findings) > 0,
            tool_name=self.metadata.name,
            category=self.metadata.category,
            output=f"Scanned {len(targets)} subdomains",
            findings=all_findings,
            execution_time=execution_time,
        )


# Quick test
if __name__ == "__main__":
    from tools.tool_registry import registry
    
    tool = registry.get_tool("naabu")
    if tool:
        print(f"[+] Naabu tool registered: {tool.is_available}")
        if not tool.is_available:
            print("[!] naabu binary not found. Install with: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
    else:
        print("[!] Failed to register naabu")
