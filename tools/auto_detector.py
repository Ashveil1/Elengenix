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
                pass
        
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
            "question": "What do you want to do?",
            "options": [
                ("🔍 Scan a target (website/domain/IP)", "scan"),
                ("🐛 Test for specific bug (BOLA, XSS, etc.)", "specific"),
                ("📁 Analyze a file (logs, code, API export)", "file"),
                ("🤖 AI assistant mode (ask anything)", "ai"),
                ("📊 Generate report from findings", "report"),
            ]
        },
        "scan_type": {
            "question": "What type of scan?",
            "options": [
                ("🔎 Reconnaissance (discover assets)", "recon"),
                ("🛡️ Web scan (find vulnerabilities)", "waf"),
                ("🎯 Full bug bounty scan (comprehensive)", "bola"),
                ("☁️ Cloud infrastructure scan", "cloud"),
                ("💻 Source code scan (SAST)", "sast"),
            ]
        },
        "file_type": {
            "question": "What type of file?",
            "options": [
                ("📱 Mobile API export (Burp, etc.)", "mobile"),
                ("🔐 Log file (SOC analysis)", "soc"),
                ("☁️ Cloud config (Terraform, etc.)", "cloud"),
                ("💻 Source code (Python, JS, etc.)", "sast"),
                ("📊 Findings JSON (analyze/predict)", "predict"),
                ("🔌 Protocol/hex dump", "proto"),
                ("❓ Not sure, auto-detect", "auto"),
            ]
        },
        "specific_type": {
            "question": "What vulnerability to test for?",
            "options": [
                ("🎯 BOLA/IDOR (broken access control)", "bola"),
                ("🛡️ WAF bypass/XSS", "waf"),
                ("🔌 Protocol analysis (MQTT, Modbus)", "proto"),
                ("🔴 Red Team/EDR evasion", "evasion"),
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
        """Get simplified help text."""
        return """
🚀 ELENGENIX - Quick Start (Easiest Commands)

Just type what you want:

  elengenix <target>           Auto-detect and scan
  elengenix <file>             Auto-detect file type and analyze
  elengenix ai                 Ask the AI anything
  elengenix menu               Interactive wizard

Quick Shortcuts:
  elengenix bb <url>           Bug bounty scan (BOLA)
  elengenix scan <url>         Smart scan everything
  elengenix check <domain>     Quick reconnaissance
  elengenix test <url>         Test for WAF/XSS
  elengenix red                Red team tools
  elengenix pdf <findings>     Generate report

Examples:
  elengenix example.com
  elengenix https://api.example.com/users
  elengenix burp_export.json
  elengenix terraform/

For help: elengenix help
For wizard: elengenix menu
"""
