"""tools/auto_detector.py

Auto-Detector - Smart input detection for easiest UX.

Purpose:
- Auto-detect what the user wants to do from their input
- Route to appropriate module without user memorizing commands
- Smart file type detection
- URL pattern matching
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


class AutoDetector:
    """
    Smart detector that figures out what module to use based on input.
    """

    @staticmethod
    def detect(target: str) -> Dict[str, Any]:
        """
        Detect what type of input and recommend action.
        Returns: {"action": str, "module": str, "confidence": float, "explanation": str}
        """
        target = target.strip()
        
        # Check if it's a file path
        if Path(target).exists():
            return AutoDetector._detect_file(target)
        
        # Check if it's a URL
        if target.startswith(("http://", "https://")):
            return AutoDetector._detect_url(target)
        
        # Check if it's a domain/IP
        if AutoDetector._is_domain_or_ip(target):
            return {
                "action": "recon",
                "module": "recon",
                "confidence": 0.9,
                "explanation": f"'{target}' looks like a domain or IP address. Running reconnaissance...",
            }
        
        # Check if it's hex data (for protocol analysis)
        if re.match(r'^[0-9a-fA-F\s]+$', target) and len(target.replace(' ', '')) > 20:
            return {
                "action": "ai",
                "module": "ai",
                "confidence": 0.85,
                "explanation": "Input looks like hex data. Switching to AI mode for guided protocol analysis...",
            }
        
        # Default to AI mode
        return {
            "action": "ai",
            "module": "ai",
            "confidence": 0.5,
            "explanation": f"Not sure what '{target}' is. Switching to AI assistant mode...",
        }

    @staticmethod
    def _detect_file(path: str) -> Dict[str, Any]:
        """Detect file type and recommend module."""
        p = Path(path)
        ext = p.suffix.lower()
        
        # JSON files
        if ext == '.json':
            # Try to detect JSON content type
            try:
                content = p.read_text(encoding='utf-8', errors='ignore')[:5000]
                data = json.loads(content)
                
                # Check for findings/scans format
                if isinstance(data, list) and len(data) > 0:
                    if any(k in str(data[0]) for k in ['severity', 'type', 'finding']):
                        return {
                            "action": "ai",
                            "module": "ai",
                            "confidence": 0.95,
                            "explanation": f"JSON findings detected: {p.name}. Opening AI mode for analysis and prioritization...",
                        }
                
                # Check for Burp/mobile format
                if isinstance(data, dict):
                    if any(k in data for k in ['endpoints', 'requests', 'responses']):
                        return {
                            "action": "ai",
                            "module": "ai",
                            "confidence": 0.9,
                            "explanation": f"API export detected: {p.name}. Opening AI mode for focused API analysis...",
                        }
                
                return {
                    "action": "json_analysis",
                    "module": "ai",
                    "confidence": 0.7,
                    "explanation": f"JSON file detected: {p.name}. Analyzing content...",
                }
            except Exception:
                pass
        
        # Cloud/Terraform files
        if ext in ['.tf', '.tfvars', '.yml', '.yaml']:
            return {
                "action": "ai",
                "module": "ai",
                "confidence": 0.9,
                "explanation": f"Infrastructure-as-code file detected: {p.name}. Opening AI mode for cloud security review...",
            }
        
        # Source code
        if ext in ['.py', '.js', '.java', '.go', '.ts', '.php']:
            return {
                "action": "sast",
                "module": "sast",
                "confidence": 0.95,
                "explanation": f"Source code file detected: {p.name}. Running SAST...",
            }
        
        # Log files
        if ext in ['.log', '.txt'] or 'log' in p.name.lower():
            return {
                "action": "ai",
                "module": "ai",
                "confidence": 0.85,
                "explanation": f"Log file detected: {p.name}. Opening AI mode for security log analysis...",
            }
        
        # Protocol/hex dump
        if ext in ['.pcap', '.cap', '.hex', '.bin']:
            return {
                "action": "ai",
                "module": "ai",
                "confidence": 0.9,
                "explanation": f"Binary capture detected: {p.name}. Opening AI mode for protocol triage...",
            }
        
        # Targets list (for swarm)
        if p.name.lower() in ['targets.txt', 'urls.txt', 'domains.txt']:
            return {
                "action": "ai",
                "module": "ai",
                "confidence": 0.95,
                "explanation": f"Targets list detected: {p.name}. Opening AI mode for controlled multi-target planning...",
            }
        
        # OpenAPI schema
        if any(k in p.name.lower() for k in ['openapi', 'swagger', 'api.json', 'api.yaml']):
            return {
                "action": "ai",
                "module": "ai",
                "confidence": 0.95,
                "explanation": f"OpenAPI schema detected: {p.name}. Opening AI mode for API surface review...",
            }
        
        # Default file
        return {
            "action": "file_analysis",
            "module": "ai",
            "confidence": 0.6,
            "explanation": f"File detected: {p.name}. Analyzing with AI...",
        }

    @staticmethod
    def _detect_url(url: str) -> Dict[str, Any]:
        """Detect URL type and recommend module."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # API endpoints
        if '/api/' in path or path.endswith(('.json', '.xml')):
            return {
                "action": "bola",
                "module": "bola",
                "confidence": 0.85,
                "explanation": f"API endpoint detected: {url}. Testing for BOLA/IDOR...",
            }
        
        # Admin panels
        if any(k in path for k in ['/admin', '/dashboard', '/panel', '/manage']):
            return {
                "action": "admin_test",
                "module": "ai",
                "confidence": 0.8,
                "explanation": f"Admin panel detected: {url}. Scanning for misconfigurations...",
            }
        
        # OpenAPI schema URL
        if any(k in url.lower() for k in ['openapi', 'swagger', 'api-docs']):
            return {
                "action": "ai",
                "module": "ai",
                "confidence": 0.95,
                "explanation": f"OpenAPI docs detected: {url}. Opening AI mode for schema review...",
            }
        
        # Default web scan
        return {
            "action": "waf",
            "module": "waf",
            "confidence": 0.8,
            "explanation": f"Web URL detected: {url}. Testing for WAF and vulnerabilities...",
        }

    @staticmethod
    def _is_domain_or_ip(target: str) -> bool:
        """Check if target is a domain or IP address."""
        # IP pattern
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, target):
            return True
        
        # Domain pattern (simple)
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$'
        if re.match(domain_pattern, target):
            return True
        
        return False


class SmartWizard:
    """
    Interactive wizard that guides users step-by-step.
    """

    QUESTIONS = {
        "start": {
            "question": "What do you want to do? (Select one)",
            "options": [
                ("Scan a website/domain for vulnerabilities", "scan"),
                ("Test for specific bug (BOLA, XSS, WAF bypass)", "specific"),
                ("Analyze a file (logs, code, API export, findings)", "file"),
                ("Chat with AI assistant", "ai"),
                ("Generate professional PDF report", "report"),
            ]
        },
        "scan_type": {
            "question": "Choose scan type:",
            "options": [
                ("Reconnaissance - Discover subdomains, ports, technologies", "recon"),
                ("Web vulnerabilities - XSS, WAF bypass, injection", "waf"),
                ("Bug bounty - BOLA/IDOR, access control testing", "bola"),
                ("Cloud security - Terraform, AWS, configuration files", "cloud"),
                ("Source code - Python, JS, Java, Go vulnerabilities", "sast"),
            ]
        },
        "file_type": {
            "question": "What type of file are you analyzing?",
            "options": [
                ("Mobile API - Burp export, API collection", "mobile"),
                ("Security logs - SIEM, firewall, alerts", "soc"),
                ("Cloud config - Terraform, CloudFormation, AWS", "cloud"),
                ("Source code - .py, .js, .java, .go files", "sast"),
                ("Findings/results - JSON scan results", "predict"),
                ("Network data - PCAP, hex dump, protocol capture", "proto"),
                ("Not sure - Let Elengenix auto-detect", "auto"),
            ]
        },
        "specific_type": {
            "question": "Which vulnerability type to test?",
            "options": [
                ("BOLA/IDOR - Broken access control, ID enumeration", "bola"),
                ("WAF/XSS - Web firewall bypass, cross-site scripting", "waf"),
                ("Protocols - MQTT, Modbus, gRPC, IoT/ICS", "proto"),
                ("Red Team - EDR evasion, AV bypass (authorized only)", "evasion"),
            ]
        },
    }

    @staticmethod
    def get_wizard_step(step_id: str) -> Dict[str, Any]:
        """Get wizard step configuration."""
        return SmartWizard.QUESTIONS.get(step_id, {})


class CommandSimplifier:
    """
    Simplifies command usage with smart shortcuts.
    """

    SHORTCUTS = {
        # Single word shortcuts
        "bb": "bola",           # Bug bounty
        "scan": "ai",           # Smart scan
        "check": "recon",       # Quick check
        "test": "waf",          # Test vulnerabilities
        "hack": "ai",           # AI mode
        "learn": "ai",          # AI mode
        "help": "menu",         # Show menu
        
        # File-based shortcuts
        "report": "report",     # Generate report
        "pdf": "report",        # PDF report
        
        # Special modes
        "red": "evasion",       # Red team
        "team": "evasion",      # Red team
        "swarm": "swarm",       # Multi-target
        "batch": "swarm",       # Batch mode
    }

    @staticmethod
    def simplify(command: str) -> str:
        """Simplify a command to its canonical form."""
        return CommandSimplifier.SHORTCUTS.get(command.lower(), command)

    @staticmethod
    def get_help_text() -> str:
        """Get organized help text by category."""
        return """
[bold cyan]╔══════════════════════════════════════════════════════════════════════╗[/bold cyan]
[bold cyan]║[/bold cyan]                    [bold yellow]ELENGENIX[/bold yellow]  —  [bold white]COMMAND REFERENCE[/bold white]                  [bold cyan]║[/bold cyan]
[bold cyan]╚══════════════════════════════════════════════════════════════════════╝[/bold cyan]

  [bold yellow]SMART MODE[/bold yellow] [dim](just type a target — Elengenix auto-routes):[/dim]
  [dim]─────────────────────────────────────────────────────────[/dim]
    [cyan]elengenix[/cyan] example.com            [dim]->[/dim]  [green]Reconnaissance[/green]
    [cyan]elengenix[/cyan] https://api.x.com/     [dim]->[/dim]  [green]BOLA / WAF workflow[/green]
    [cyan]elengenix[/cyan] findings.json          [dim]->[/dim]  [green]AI-assisted analysis[/green]
    [cyan]elengenix[/cyan] myapp.py               [dim]->[/dim]  [green]SAST static scan[/green]
    [cyan]elengenix[/cyan] terraform/             [dim]->[/dim]  [green]Cloud security review[/green]

[dim]┌─────────────────────┬──────────────────────────────────────────────┐[/dim]
│  [bold cyan]AI & AGENT[/bold cyan]         │                                              │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [cyan]elengenix cli[/cyan]      │  [white]Gemini-style CLI session (prompt_toolkit)[/white]   │
│  [cyan]elengenix universal[/cyan]│  [white]Autonomous agent mode (open-ended tasks)[/white]    │
│  [cyan]elengenix autonomous[/cyan] <target>                                      │
│                     │  [white]Fully autonomous AI scan[/white]                    │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [bold cyan]RECONNAISSANCE[/bold cyan]     │                                              │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [cyan]elengenix recon[/cyan] <domain>          [white]Asset discovery + correlation[/white]   │
│  [cyan]elengenix scan[/cyan] <target>           [white]Full scan pipeline[/white]              │
│  [cyan]elengenix bounty[/cyan] [program]        [white]Bug bounty intel & predictor[/white]    │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [bold cyan]EXPLOITATION[/bold cyan]       │                                              │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [cyan]elengenix bola[/cyan] <url>              [white]BOLA / IDOR differential tests[/white]  │
│  [cyan]elengenix waf[/cyan] <url>               [white]WAF detection & XSS bypass[/white]      │
│  [cyan]elengenix evasion[/cyan]                 [white]EDR / AV evasion framework[/white]      │
│  [cyan]elengenix research[/cyan] <CVE|type>     [white]CVE research + PoC generator[/white]    │
│  [cyan]elengenix poc[/cyan] <vuln-type>         [white]Generate custom exploit PoC[/white]     │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [bold cyan]ANALYSIS[/bold cyan]           │                                              │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [cyan]elengenix sast[/cyan] <file|dir>         [white]Source code static analysis[/white]     │
│  [cyan]elengenix cloud[/cyan] <file|dir>        [white]Terraform / IaC / cloud review[/white]  │
│  [cyan]elengenix mobile[/cyan] <target>         [white]Mobile API analysis & fuzzing[/white]   │
│  [cyan]elengenix soc[/cyan] [logfile]           [white]Security log & SIEM analysis[/white]    │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [bold cyan]REPORTS & MEMORY[/bold cyan]   │                                              │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [cyan]elengenix report[/cyan] [findings]       [white]Generate HTML/PDF report[/white]        │
│  [cyan]elengenix memory[/cyan]                  [white]View & search AI memory[/white]         │
│  [cyan]elengenix history[/cyan]                 [white]Browse past scan sessions[/white]       │
│  [cyan]elengenix dashboard[/cyan]               [white]Launch live web dashboard[/white]       │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [bold cyan]SYSTEM[/bold cyan]             │                                              │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [cyan]elengenix doctor[/cyan]                  [white]System health & tool check[/white]      │
│  [cyan]elengenix configure[/cyan]               [white]Set AI keys, Telegram, H1[/white]       │
│  [cyan]elengenix gateway[/cyan]                 [white]Start Telegram bot[/white]              │
│  [cyan]elengenix arsenal[/cyan]                 [white]Manual tool selector[/white]            │
│  [cyan]elengenix menu[/cyan]                    [white]Interactive categorized menu[/white]     │
│  [cyan]elengenix cve-update[/cyan]              [white]Refresh local CVE database[/white]       │
│  [cyan]elengenix update[/cyan]                  [white]Update via git pull[/white]             │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [bold cyan]SHORTCUTS[/bold cyan]          │                                              │
[dim]├─────────────────────┼──────────────────────────────────────────────┤[/dim]
│  [cyan]bb[/cyan] <url>           [dim]->[/dim]  [green]bola[/green]     [cyan]check[/cyan] <domain>  [dim]->[/dim]  [green]recon[/green]        │
│  [cyan]test[/cyan] <url>         [dim]->[/dim]  [green]waf[/green]      [cyan]red[/cyan]              [dim]->[/dim]  [green]evasion[/green]      │
│  [cyan]hack / ai[/cyan]          [dim]->[/dim]  [green]ai chat[/green]  [cyan]pdf[/cyan] <file>       [dim]->[/dim]  [green]report[/green]       │
[dim]└─────────────────────┴──────────────────────────────────────────────┘[/dim]
"""
