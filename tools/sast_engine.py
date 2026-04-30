"""tools/sast_engine.py

Static Application Security Testing (SAST) Engine.

Purpose:
- Analyze source code for security vulnerabilities
- Support Python, JavaScript/TypeScript, Java, Go
- Detect injection flaws, secrets, weak crypto, etc.
- Generate findings with line numbers and remediation
- Integrate with agent loop for code-assisted pentest

Input: Source code files or repository path
Output: Vulnerability findings with fix suggestions
"""

from __future__ import annotations

import ast
import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("elengenix.sast")


@dataclass
class CodeVulnerability:
    """Represents a code vulnerability finding."""
    vuln_id: str
    file_path: str
    line_number: int
    column: int
    vuln_type: str  # sqli, xss, hardcoded_secret, weak_crypto, etc.
    severity: str  # critical, high, medium, low
    confidence: float
    description: str
    code_snippet: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None


class PatternBasedScanner:
    """Pattern-based vulnerability scanner for multiple languages."""
    
    # Language-specific patterns
    PATTERNS = {
        'python': {
            'sql_injection': [
                (r'execute\s*\(\s*["\'].*?%s.*?["\']\s*%', 'CWE-89', 'Potential SQL injection with string formatting'),
                (r'execute\s*\(\s*["\'].*?\+.*?\+.*?["\']\s*\)', 'CWE-89', 'Potential SQL injection with concatenation'),
                (r'\.format\s*\(.*\)', 'CWE-89', 'Potential format string injection'),
                (r'f["\'].*?\{.*?\}.*?["\']', 'CWE-89', 'Potential f-string SQL injection in query'),
            ],
            'command_injection': [
                (r'os\.system\s*\(', 'CWE-78', 'Command injection risk with os.system'),
                (r'subprocess\.call\s*\(\s*shell\s*=\s*True', 'CWE-78', 'Subprocess with shell=True is dangerous'),
                (r'eval\s*\(', 'CWE-95', 'Dangerous eval() usage'),
                (r'exec\s*\(', 'CWE-95', 'Dangerous exec() usage'),
            ],
            'hardcoded_secret': [
                (r'password\s*=\s*["\'][^"\']+["\']', 'CWE-798', 'Hardcoded password'),
                (r'secret\s*=\s*["\'][^"\']{8,}["\']', 'CWE-798', 'Hardcoded secret'),
                (r'api_key\s*=\s*["\'][^"\']{10,}["\']', 'CWE-798', 'Hardcoded API key'),
                (r'aws_access_key_id\s*=\s*["\']', 'CWE-798', 'Hardcoded AWS credentials'),
                (r'token\s*=\s*["\']eyJ[a-zA-Z0-9_-]*\.eyJ', 'CWE-798', 'Hardcoded JWT token'),
            ],
            'weak_crypto': [
                (r'md5\s*\(', 'CWE-327', 'Weak MD5 hash algorithm'),
                (r'sha1\s*\(', 'CWE-327', 'Weak SHA1 hash algorithm'),
                (r'DES\b', 'CWE-327', 'Weak DES encryption'),
                (r'ECB\b', 'CWE-327', 'ECB mode is insecure'),
                (r'random\.random\s*\(', 'CWE-338', 'Not cryptographically secure random'),
            ],
            'insecure_deserialization': [
                (r'pickle\.loads?\s*\(', 'CWE-502', 'Insecure pickle deserialization'),
                (r'yaml\.load\s*\(', 'CWE-502', 'Insecure YAML load (use safe_load)'),
                (r'\.loads?\s*\(.*\beval\b', 'CWE-502', 'Deserialization with eval'),
            ],
            'xss': [
                (r'render_template_string', 'CWE-79', 'Potential XSS with template string'),
                (r'Markup\s*\(', 'CWE-79', 'Markup() bypasses auto-escaping'),
                (r'\.html\s*=.*\+', 'CWE-79', 'Direct HTML assignment'),
            ],
            'path_traversal': [
                (r'open\s*\(\s*.*\+.*\)', 'CWE-22', 'Potential path traversal'),
                (r'\.read\s*\(\s*.*request', 'CWE-22', 'Reading from user input'),
            ],
        },
        'javascript': {
            'sql_injection': [
                (r'query\s*\(\s*["\'].*\$\{', 'CWE-89', 'Template literal in SQL query'),
                (r'\.query\s*\(\s*.*\+', 'CWE-89', 'String concatenation in query'),
            ],
            'xss': [
                (r'innerHTML\s*=\s*', 'CWE-79', 'XSS via innerHTML'),
                (r'document\.write\s*\(', 'CWE-79', 'XSS via document.write'),
                (r'eval\s*\(', 'CWE-94', 'Dangerous eval()'),
                (r'new\s+Function\s*\(', 'CWE-94', 'Dynamic code execution'),
            ],
            'hardcoded_secret': [
                (r'password\s*[=:]\s*["\'][^"\']+["\']', 'CWE-798', 'Hardcoded password'),
                (r'apiKey\s*[=:]\s*["\'][^"\']{10,}["\']', 'CWE-798', 'Hardcoded API key'),
                (r'secret\s*[=:]\s*["\'][^"\']{8,}["\']', 'CWE-798', 'Hardcoded secret'),
            ],
            'insecure_random': [
                (r'Math\.random\s*\(\)', 'CWE-338', 'Not cryptographically secure'),
            ],
            'proto_pollution': [
                (r'\[\s*["\']__proto__["\']\s*\]', 'CWE-1321', 'Prototype pollution risk'),
            ],
        },
        'java': {
            'sql_injection': [
                (r'executeQuery\s*\(\s*".*\+', 'CWE-89', 'SQL concatenation'),
                (r'String\.format.*SELECT', 'CWE-89', 'Formatted SQL query'),
            ],
            'hardcoded_secret': [
                (r'String\s+password\s*=\s*"[^"]+"', 'CWE-798', 'Hardcoded password'),
                (r'String\s+secret\s*=\s*"[^"]{8,}"', 'CWE-798', 'Hardcoded secret'),
            ],
            'weak_crypto': [
                (r'MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)', 'CWE-327', 'Weak MD5'),
                (r'MessageDigest\.getInstance\s*\(\s*"SHA1"\s*\)', 'CWE-327', 'Weak SHA1'),
            ],
            'deserialization': [
                (r'ObjectInputStream', 'CWE-502', 'Java deserialization risk'),
            ],
        },
        'go': {
            'sql_injection': [
                (r'Query\s*\(.*fmt\.Sprintf', 'CWE-89', 'Formatted SQL query'),
                (r'Query\s*\(.*\+.*\+', 'CWE-89', 'Concatenated SQL query'),
            ],
            'hardcoded_secret': [
                (r'const\s+\w*password\w*\s*=\s*["\'][^"\']+["\']', 'CWE-798', 'Hardcoded password'),
            ],
            'weak_crypto': [
                (r'md5\.Sum', 'CWE-327', 'Weak MD5 hash'),
                (r'sha1\.Sum', 'CWE-327', 'Weak SHA1 hash'),
            ],
        },
    }

    def scan_file(self, file_path: Path) -> List[CodeVulnerability]:
        """Scan a single file for vulnerabilities."""
        findings = []
        
        # Determine language from extension
        lang = self._detect_language(file_path)
        if not lang or lang not in self.PATTERNS:
            return findings
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            patterns = self.PATTERNS[lang]
            
            for vuln_type, pattern_list in patterns.items():
                for pattern, cwe, description in pattern_list:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        # Calculate line number
                        line_num = content[:match.start()].count('\n') + 1
                        col = match.start() - content.rfind('\n', 0, match.start())
                        
                        # Get code snippet
                        snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                        
                        # Calculate severity
                        severity = self._calculate_severity(vuln_type)
                        
                        findings.append(CodeVulnerability(
                            vuln_id=f"{vuln_type}:{file_path.name}:{line_num}",
                            file_path=str(file_path),
                            line_number=line_num,
                            column=col,
                            vuln_type=vuln_type,
                            severity=severity,
                            confidence=0.75,
                            description=description,
                            code_snippet=snippet[:100],
                            remediation=self._get_remediation(vuln_type),
                            cwe_id=cwe,
                            owasp_category=self._get_owasp_category(vuln_type),
                        ))
            
        except Exception as e:
            logger.debug(f"Failed to scan {file_path}: {e}")
        
        return findings
    
    def _detect_language(self, file_path: Path) -> Optional[str]:
        """Detect programming language from file extension."""
        ext = file_path.suffix.lower()
        mapping = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'javascript',
            '.tsx': 'javascript',
            '.java': 'java',
            '.go': 'go',
        }
        return mapping.get(ext)
    
    def _calculate_severity(self, vuln_type: str) -> str:
        """Calculate severity based on vulnerability type."""
        critical_types = ['sql_injection', 'command_injection', 'hardcoded_secret', 
                         'insecure_deserialization', 'deserialization']
        high_types = ['xss', 'weak_crypto', 'path_traversal', 'eval_danger']
        
        if vuln_type in critical_types:
            return 'critical'
        elif vuln_type in high_types:
            return 'high'
        elif vuln_type in ['insecure_random']:
            return 'medium'
        return 'low'
    
    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type."""
        remediations = {
            'sql_injection': 'Use parameterized queries/prepared statements. Never concatenate user input into SQL.',
            'command_injection': 'Avoid shell=True. Use subprocess with list arguments. Validate all inputs.',
            'hardcoded_secret': 'Move secrets to environment variables, secret managers, or config files outside version control.',
            'weak_crypto': 'Use strong algorithms: SHA-256 or better for hashing, AES-256-GCM for encryption.',
            'xss': 'Use context-aware output encoding. Implement Content Security Policy (CSP).',
            'insecure_deserialization': 'Use safe deserialization methods. Validate and sanitize input before deserializing.',
            'path_traversal': 'Validate and sanitize file paths. Use allowlists for permitted directories.',
            'eval_danger': 'Avoid eval(). Use safer alternatives like ast.literal_eval for literals only.',
            'insecure_random': 'Use cryptographically secure random: secrets.token_bytes in Python, crypto.randomBytes in Node.js',
        }
        return remediations.get(vuln_type, 'Review code and apply security best practices.')
    
    def _get_owasp_category(self, vuln_type: str) -> Optional[str]:
        """Map vulnerability to OWASP Top 10 category."""
        mapping = {
            'sql_injection': 'A03:2021 - Injection',
            'command_injection': 'A03:2021 - Injection',
            'xss': 'A03:2021 - Injection',
            'hardcoded_secret': 'A07:2021 - Identification and Authentication Failures',
            'weak_crypto': 'A02:2021 - Cryptographic Failures',
            'insecure_deserialization': 'A08:2021 - Software and Data Integrity Failures',
            'path_traversal': 'A01:2021 - Broken Access Control',
            'insecure_random': 'A02:2021 - Cryptographic Failures',
        }
        return mapping.get(vuln_type)


class SASTEngine:
    """
    Main SAST engine that orchestrates scanning.
    """
    
    def __init__(self):
        self.pattern_scanner = PatternBasedScanner()
        self.findings: List[CodeVulnerability] = []
    
    def scan_repository(self, repo_path: Path, exclude_patterns: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Scan entire repository for vulnerabilities.
        
        Args:
            repo_path: Path to source code repository
            exclude_patterns: List of glob patterns to exclude (e.g., ['*/test/*', '*.min.js'])
        """
        if not repo_path.exists():
            return {"error": f"Repository path not found: {repo_path}"}
        
        exclude_patterns = exclude_patterns or ['*/test/*', '*/tests/*', '*.min.js', '*/node_modules/*', '*/venv/*', '*/__pycache__/*']
        
        supported_extensions = {'.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go'}
        
        all_findings = []
        files_scanned = 0
        
        for file_path in repo_path.rglob('*'):
            # Skip excluded patterns
            skip = False
            str_path = str(file_path)
            for pattern in exclude_patterns:
                pattern_clean = pattern.replace('*/', '').replace('*', '')
                if pattern_clean in str_path:
                    skip = True
                    break
            
            if skip:
                continue
            
            if file_path.suffix in supported_extensions:
                findings = self.pattern_scanner.scan_file(file_path)
                all_findings.extend(findings)
                if findings or True:  # Count all scanned files
                    files_scanned += 1
        
        self.findings = all_findings
        return self._generate_report(files_scanned)
    
    def _generate_report(self, files_scanned: int) -> Dict[str, Any]:
        """Generate SAST scan report."""
        severity_counts = {}
        vuln_types = {}
        files_affected = set()
        
        for finding in self.findings:
            sev = finding.severity
            vtype = finding.vuln_type
            
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
            files_affected.add(finding.file_path)
        
        return {
            "files_scanned": files_scanned,
            "files_with_vulns": len(files_affected),
            "total_vulnerabilities": len(self.findings),
            "severity_distribution": severity_counts,
            "vulnerability_types": vuln_types,
            "critical_vulnerabilities": [
                {
                    "id": v.vuln_id,
                    "file": v.file_path,
                    "line": v.line_number,
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "cwe": v.cwe_id,
                    "description": v.description,
                    "code": v.code_snippet,
                    "fix": v.remediation,
                    "owasp": v.owasp_category,
                }
                for v in self.findings if v.severity in ['critical', 'high']
            ],
        }


def format_sast_report(report: Dict[str, Any]) -> str:
    """Format SAST report for display."""
    lines = []
    lines.append("=" * 60)
    lines.append("STATIC APPLICATION SECURITY TESTING (SAST) REPORT")
    lines.append("=" * 60)
    
    if "error" in report:
        lines.append(f"\nError: {report['error']}")
        return "\n".join(lines)
    
    lines.append(f"\nFiles Scanned: {report.get('files_scanned', 0)}")
    lines.append(f"Files with Vulnerabilities: {report.get('files_with_vulns', 0)}")
    lines.append(f"Total Vulnerabilities: {report.get('total_vulnerabilities', 0)}")
    
    lines.append("\n[Severity Distribution]")
    for sev, count in report.get('severity_distribution', {}).items():
        lines.append(f"  {sev.upper()}: {count}")
    
    lines.append("\n[Vulnerability Types]")
    for vtype, count in report.get('vulnerability_types', {}).items():
        lines.append(f"  {vtype}: {count}")
    
    lines.append("\n[Critical/High Vulnerabilities]")
    for vuln in report.get('critical_vulnerabilities', [])[:10]:
        lines.append(f"\n  {vuln['type'].upper()} ({vuln['severity']})")
        lines.append(f"  File: {vuln['file']}:{vuln['line']}")
        if vuln.get('cwe'):
            lines.append(f"  CWE: {vuln['cwe']}")
        if vuln.get('owasp'):
            lines.append(f"  OWASP: {vuln['owasp']}")
        lines.append(f"  Code: {vuln['code'][:60]}...")
        lines.append(f"  Fix: {vuln['fix'][:80]}...")
    
    lines.append("\n" + "=" * 60)
    return "\n".join(lines)
