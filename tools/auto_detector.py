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
                "action": "protocol",
                "module": "proto",
                "confidence": 0.85,
                "explanation": "Input looks like hex data. Analyzing as network protocol...",
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
                            "action": "analyze_findings",
                            "module": "predict",
                            "confidence": 0.95,
                            "explanation": f"JSON file with findings detected: {p.name}. Running bounty prediction...",
                        }
                
                # Check for Burp/mobile format
                if isinstance(data, dict):
                    if any(k in data for k in ['endpoints', 'requests', 'responses']):
                        return {
                            "action": "mobile_api",
                            "module": "mobile",
                            "confidence": 0.9,
                            "explanation": f"API export detected: {p.name}. Running mobile API analysis...",
                        }
                
                return {
                    "action": "json_analysis",
                    "module": "ai",
                    "confidence": 0.7,
                    "explanation": f"JSON file detected: {p.name}. Analyzing content...",
                }
            except:
        
        # Cloud/Terraform files
        if ext in ['.tf', '.tfvars', '.yml', '.yaml']:
            return {
                "action": "cloud_scan",
                "module": "cloud",
                "confidence": 0.9,
                "explanation": f"Infrastructure-as-code file detected: {p.name}. Scanning for misconfigurations...",
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
                "action": "soc_analysis",
                "module": "soc",
                "confidence": 0.85,
                "explanation": f"Log file detected: {p.name}. Analyzing for threats...",
            }
        
        # Protocol/hex dump
        if ext in ['.pcap', '.cap', '.hex', '.bin']:
            return {
                "action": "protocol",
                "module": "proto",
                "confidence": 0.9,
                "explanation": f"Binary/hex file detected: {p.name}. Analyzing protocol...",
            }
        
        # Targets list (for swarm)
        if p.name.lower() in ['targets.txt', 'urls.txt', 'domains.txt']:
            return {
                "action": "swarm",
                "module": "swarm",
                "confidence": 0.95,
                "explanation": f"Targets list detected: {p.name}. Running multi-target swarm...",
            }
        
        # OpenAPI schema
        if any(k in p.name.lower() for k in ['openapi', 'swagger', 'api.json', 'api.yaml']):
            return {
                "action": "schema",
                "module": "schema",
                "confidence": 0.95,
                "explanation": f"OpenAPI schema detected: {p.name}. Analyzing API surface...",
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
                "action": "bola_test",
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
                "action": "schema",
                "module": "schema",
                "confidence": 0.95,
                "explanation": f"OpenAPI docs detected: {url}. Analyzing schema...",
            }
        
        # Default web scan
        return {
            "action": "web_scan",
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
            "question": "🚀 What do you want to do? (Select one)",
            "options": [
                ("🔍 Scan a website/domain for vulnerabilities", "scan"),
                ("🐛 Test for specific bug (BOLA, XSS, WAF bypass)", "specific"),
                ("📁 Analyze a file (logs, code, API export, findings)", "file"),
                ("🤖 Chat with AI assistant", "ai"),
                ("📊 Generate professional PDF report", "report"),
            ]
        },
        "scan_type": {
            "question": "🔍 Choose scan type:",
            "options": [
                ("🔎 Reconnaissance - Discover subdomains, ports, tech", "recon"),
                ("🛡️ Web vulnerabilities - XSS, WAF bypass, injection", "waf"),
                ("🎯 Bug bounty - BOLA/IDOR, access control testing", "bola"),
                ("☁️ Cloud security - Terraform, AWS, config files", "cloud"),
                ("💻 Source code - Python, JS, Java, Go vulnerabilities", "sast"),
            ]
        },
        "file_type": {
            "question": "📁 What type of file are you analyzing?",
            "options": [
                ("📱 Mobile API - Burp Suite export, API collection", "mobile"),
                ("🔐 Security logs - SIEM, firewall, alerts (SOC analysis)", "soc"),
                ("☁️ Cloud config - Terraform, CloudFormation, AWS", "cloud"),
                ("💻 Source code - .py, .js, .java, .go files", "sast"),
                ("📊 Findings/results - JSON scan results to analyze", "predict"),
                ("🔌 Network data - PCAP, hex dump, protocol capture", "proto"),
                ("❓ Not sure - Let Elengenix auto-detect", "auto"),
            ]
        },
        "specific_type": {
            "question": "🐛 Which vulnerability type to test?",
            "options": [
                ("🎯 BOLA/IDOR - Broken access control, ID enumeration", "bola"),
                ("🛡️ WAF/XSS - Web firewall bypass, cross-site scripting", "waf"),
                ("🔌 Protocols - MQTT, Modbus, gRPC, IoT/ICS", "proto"),
                ("🔴 Red Team - EDR evasion, AV bypass (Auth only)", "evasion"),
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
╔══════════════════════════════════════════════════════════════════╗
║                    🚀 ELENGENIX - COMMAND GUIDE                   ║
╚══════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────┐
│  🎯 SMART MODE (Auto-Detect) - Just type anything!              │
├──────────────────────────────────────────────────────────────────┤
│  elengenix example.com              → Auto reconnaissance       │
│  elengenix https://api.x.com        → Auto API testing          │
│  elengenix findings.json            → Auto bounty analysis      │
│  elengenix myapp.py                 → Auto code scan            │
│  elengenix terraform/               → Auto cloud scan           │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  ⚡ QUICK SHORTCUTS (One word = One action)                      │
├──────────────────────────────────────────────────────────────────┤
│  elengenix bb <url>                 → Bug bounty (BOLA)         │
│  elengenix check <domain>           → Quick recon               │
│  elengenix test <url>               → Test WAF/XSS              │
│  elengenix red                      → Red team tools            │
│  elengenix pdf <file>               → Generate report           │
│  elengenix ai                       → AI assistant                │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  📋 FULL COMMANDS (Explicit control)                            │
├──────────────────────────────────────────────────────────────────┤
│  Offensive Testing:                                             │
│    elengenix bola <url>             BOLA/IDOR testing           │
│    elengenix waf <url>              WAF/XSS scanner           │
│    elengenix evasion                EDR/AV evasion (Red Team) │
│                                                                 │
│  Reconnaissance:                                                │
│    elengenix recon <domain>         Asset discovery             │
│    elengenix scan <target>          Full scan pipeline          │
│                                                                 │
│  Analysis & Reports:                                            │
│    elengenix report <findings>      Generate PDF report         │
│    elengenix menu                   Interactive wizard          │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  💡 EXAMPLES                                                      │
├──────────────────────────────────────────────────────────────────┤
│  # Quick start - just type the target                          │
│  elengenix target.com                                             │
│                                                                   │
│  # Bug bounty mode                                               │
│  elengenix bb https://api.target.com                            │
│                                                                   │
│  # Analyze file                                                  │
│  elengenix burp_export.json                                     │
│                                                                   │
│  # Ask AI anything                                               │
│  elengenix ai                                                     │
│  > Help me scan target.com for vulnerabilities                 │
└──────────────────────────────────────────────────────────────────┘

For detailed help: elengenix menu
"""
