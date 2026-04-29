"""tools/mobile_api_tester.py

Mobile API Testing Module for iOS/Android Application Security.

Purpose:
- Analyze mobile app API endpoints (REST/GraphQL)
- Test for mobile-specific vulnerabilities
- Certificate pinning bypass detection
- API key/token extraction patterns
- Analyze protobuf/gRPC endpoints
- Deep link validation

Input: API spec, proxy logs (Burp/OWASP ZAP), or mobile app binary
Output: Mobile API security report with findings
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("elengenix.mobile_api")

@dataclass
class APIEndpoint:
 """Represents a mobile API endpoint."""
 url: str
 method: str
 headers: Dict[str, str]
 parameters: List[Dict[str, Any]]
 auth_type: Optional[str] = None # bearer, api_key, oauth, none
 response_schema: Optional[Dict[str, Any]] = None
 mobile_specific: bool = False
 deep_link: Optional[str] = None
 protobuf_detected: bool = False
 

@dataclass
class MobileFinding:
 """Mobile API security finding."""
 finding_id: str
 endpoint: str
 finding_type: str # hardcoded_key, weak_auth, pin_bypass, data_leak, etc.
 severity: str # critical, high, medium, low, info
 confidence: float
 description: str
 evidence: Dict[str, Any]
 remediation: str

class MobileAPITester:
 """
 Mobile application API security testing engine.
 """

 # Patterns for mobile-specific vulnerabilities
 HARDCODED_KEY_PATTERNS = [
 r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
 r'api[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
 r'auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
 r'Bearer\s+([a-zA-Z0-9_-]{20,})',
 r'aws_access_key_id["\']?\s*[:=]\s*["\'](AKIA[0-9A-Z]{16})["\']',
 r'firebase[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{100,})["\']',
 r'stripe[_-]?key["\']?\s*[:=]\s*["\'](sk_[a-zA-Z0-9_-]{20,})["\']',
 ]
 
 WEAK_AUTH_INDICATORS = [
 r'authorization:\s*basic\s+([a-zA-Z0-9+/=]+)',
 r'api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_-]{10,20})["\']?',
 r'password["\']?\s*[:=]\s*["\'][^"\']{1,8}["\']',
 ]
 
 SENSITIVE_FIELDS = [
 'password', 'ssn', 'credit_card', 'cvv', 'pin', 'dob', 'birthdate',
 'phone', 'email', 'address', 'gps', 'location', 'latitude', 'longitude',
 'device_id', 'imei', 'mac_address', 'serial_number', 'udid'
 ]
 
 MOBILE_HEADERS = [
 'x-device-id', 'x-device-type', 'x-os-version', 'x-app-version',
 'x-platform', 'user-agent', 'x-fingerprint', 'x-session-id'
 ]

 def __init__(self, target_url: Optional[str] = None):
 self.target_url = target_url
 self.endpoints: List[APIEndpoint] = []
 self.findings: List[MobileFinding] = []
 self.certificate_pinned: Optional[bool] = None

 def parse_burp_export(self, file_path: Path) -> List[APIEndpoint]:
 """Parse Burp Suite export (XML or JSON)."""
 endpoints = []
 try:
 if file_path.suffix == '.json':
 with open(file_path, 'r') as f:
 data = json.load(f)
 for item in data:
 endpoint = self._parse_burp_item(item)
 if endpoint:
 endpoints.append(endpoint)
 # Note: XML parsing would require additional dependency
 except Exception as e:
 logger.error(f"Failed to parse Burp export: {e}")
 return endpoints

 def _parse_burp_item(self, item: Dict[str, Any]) -> Optional[APIEndpoint]:
 """Parse single Burp item."""
 try:
 url = item.get('url', '')
 method = item.get('method', 'GET')
 request_headers = item.get('request', {}).get('headers', {})
 
 # Check if mobile-specific
 is_mobile = any(
 h.lower() in [header.lower() for header in request_headers.keys()]
 for h in self.MOBILE_HEADERS
 )
 
 # Detect auth type
 auth_type = None
 auth_header = request_headers.get('Authorization', '')
 if auth_header.startswith('Bearer '):
 auth_type = 'bearer'
 elif auth_header.startswith('Basic '):
 auth_type = 'basic'
 elif 'api-key' in request_headers or 'x-api-key' in request_headers:
 auth_type = 'api_key'
 
 # Parse parameters
 params = []
 if '?' in url:
 parsed = urlparse(url)
 query_params = parse_qs(parsed.query)
 for key, values in query_params.items():
 params.append({
 'name': key,
 'value': values[0] if values else '',
 'location': 'query'
 })
 
 return APIEndpoint(
 url=url,
 method=method,
 headers=request_headers,
 parameters=params,
 auth_type=auth_type,
 mobile_specific=is_mobile,
 )
 except Exception:
 return None

 def analyze_endpoint(self, endpoint: APIEndpoint) -> List[MobileFinding]:
 """Analyze single endpoint for vulnerabilities."""
 findings = []
 
 # Check for hardcoded keys in URL/parameters
 all_text = f"{endpoint.url} {json.dumps(endpoint.parameters)}"
 
 for pattern in self.HARDCODED_KEY_PATTERNS:
 matches = re.finditer(pattern, all_text, re.IGNORECASE)
 for match in matches:
 findings.append(MobileFinding(
 finding_id=f"hardcoded_key:{hash(match.group(0)) % 1000000:06d}",
 endpoint=endpoint.url,
 finding_type="hardcoded_api_key",
 severity="critical",
 confidence=0.9,
 description=f"Potential hardcoded API key detected in request",
 evidence={
 "pattern_matched": pattern[:50],
 "location": "url_or_parameter",
 "endpoint": endpoint.url,
 },
 remediation="Remove hardcoded keys. Use secure key management (Android Keystore, iOS Keychain) or fetch from server.",
 ))
 
 # Check for weak authentication
 if endpoint.auth_type == 'basic':
 findings.append(MobileFinding(
 finding_id=f"weak_auth:{hash(endpoint.url) % 1000000:06d}",
 endpoint=endpoint.url,
 finding_type="weak_authentication",
 severity="high",
 confidence=0.85,
 description="Basic authentication detected in mobile API",
 evidence={"auth_type": "basic", "endpoint": endpoint.url},
 remediation="Replace Basic Auth with OAuth 2.0, JWT, or API keys with TLS 1.3",
 ))
 
 # Check for missing certificate pinning indicators
 if endpoint.mobile_specific and self.certificate_pinned is None:
 findings.append(MobileFinding(
 finding_id=f"pin_check:{hash(endpoint.url) % 1000000:06d}",
 endpoint=endpoint.url,
 finding_type="certificate_pinning_check_needed",
 severity="medium",
 confidence=0.6,
 description="Mobile API without verified certificate pinning",
 evidence={"endpoint": endpoint.url, "mobile_headers": True},
 remediation="Implement certificate pinning (TrustKit for iOS, OkHttp CertificatePinner for Android).",
 ))
 
 # Check for sensitive data in parameters
 for param in endpoint.parameters:
 param_name_lower = param.get('name', '').lower()
 for sensitive in self.SENSITIVE_FIELDS:
 if sensitive in param_name_lower:
 findings.append(MobileFinding(
 finding_id=f"sensitive_param:{hash(param_name_lower) % 1000000:06d}",
 endpoint=endpoint.url,
 finding_type="sensitive_data_exposure",
 severity="high",
 confidence=0.75,
 description=f"Sensitive field '{param.get('name')}' sent in URL parameters",
 evidence={"parameter": param.get('name'), "endpoint": endpoint.url},
 remediation="Move sensitive data to request body (POST) or headers with encryption.",
 ))
 
 return findings

 def check_deep_links(self, manifest_content: str) -> List[MobileFinding]:
 """Analyze Android manifest or iOS plist for deep link vulnerabilities."""
 findings = []
 
 # Android deep links
 deep_link_pattern = r'<data\s+android:scheme=["\']([^"\']+)["\']\s+android:host=["\']([^"\']+)["\']'
 matches = re.finditer(deep_link_pattern, manifest_content)
 
 for match in matches:
 scheme = match.group(1)
 host = match.group(2)
 
 # Check for insecure schemes
 if scheme in ['http', 'ftp']:
 findings.append(MobileFinding(
 finding_id=f"deeplink:{hash(match.group(0)) % 1000000:06d}",
 endpoint=f"{scheme}://{host}",
 finding_type="insecure_deep_link",
 severity="high",
 confidence=0.8,
 description=f"Insecure scheme '{scheme}' in deep link",
 evidence={"scheme": scheme, "host": host},
 remediation="Use https:// scheme for deep links. Validate all incoming deep link data.",
 ))
 
 # Check for wildcard hosts
 if '*' in host or host == '':
 findings.append(MobileFinding(
 finding_id=f"deeplink_wildcard:{hash(match.group(0)) % 1000000:06d}",
 endpoint=f"{scheme}://{host}",
 finding_type="wildcard_deep_link",
 severity="medium",
 confidence=0.7,
 description=f"Wildcard host in deep link: {host}",
 evidence={"host": host, "scheme": scheme},
 remediation="Avoid wildcard hosts. Explicitly define allowed hosts.",
 ))
 
 return findings

 def analyze_protobuf_patterns(self, request_body: bytes) -> Optional[MobileFinding]:
 """Detect protobuf/gRPC in request body."""
 # Protobuf wire format indicators
 # Field number << 3 | wire_type pattern
 if len(request_body) > 10:
 # Check for common protobuf patterns
 protobuf_indicators = [
 request_body[0] & 0x07 in [0, 2, 5], # Valid wire types
 ]
 
 if all(protobuf_indicators):
 return MobileFinding(
 finding_id=f"protobuf:{hash(request_body[:20]) % 1000000:06d}",
 endpoint="protobuf_detected",
 finding_type="protobuf_api_detected",
 severity="info",
 confidence=0.6,
 description="Protocol Buffers detected in API communication",
 evidence={"body_prefix": request_body[:20].hex()},
 remediation="Ensure protobuf schemas are not exposed. Validate all deserialized data.",
 )
 return None

 def run_full_analysis(self, endpoints: Optional[List[APIEndpoint]] = None) -> Dict[str, Any]:
 """Run complete mobile API security analysis."""
 if endpoints:
 self.endpoints = endpoints
 
 all_findings: List[MobileFinding] = []
 
 for endpoint in self.endpoints:
 findings = self.analyze_endpoint(endpoint)
 all_findings.extend(findings)
 
 # Generate report
 severity_counts = {}
 finding_types = {}
 
 for finding in all_findings:
 sev = finding.severity
 ftype = finding.finding_type
 severity_counts[sev] = severity_counts.get(sev, 0) + 1
 finding_types[ftype] = finding_types.get(ftype, 0) + 1
 
 self.findings = all_findings
 
 return {
 "total_endpoints": len(self.endpoints),
 "mobile_endpoints": len([e for e in self.endpoints if e.mobile_specific]),
 "total_findings": len(all_findings),
 "severity_distribution": severity_counts,
 "finding_types": finding_types,
 "critical_findings": [
 {
 "id": f.finding_id,
 "type": f.finding_type,
 "endpoint": f.endpoint,
 "severity": f.severity,
 "description": f.description,
 "remediation": f.remediation,
 }
 for f in all_findings if f.severity in ['critical', 'high']
 ],
 }

def format_mobile_report(report: Dict[str, Any]) -> str:
 """Format mobile API analysis report for display."""
 lines = []
 lines.append("=" * 60)
 lines.append("MOBILE API SECURITY ANALYSIS")
 lines.append("=" * 60)
 
 lines.append(f"\nTotal Endpoints: {report.get('total_endpoints', 0)}")
 lines.append(f"Mobile-Specific: {report.get('mobile_endpoints', 0)}")
 lines.append(f"Total Findings: {report.get('total_findings', 0)}")
 
 lines.append("\n[Severity Distribution]")
 for sev, count in report.get('severity_distribution', {}).items():
 lines.append(f" {sev.upper()}: {count}")
 
 lines.append("\n[Finding Types]")
 for ftype, count in report.get('finding_types', {}).items():
 lines.append(f" {ftype}: {count}")
 
 lines.append("\n[Critical/High Findings]")
 for finding in report.get('critical_findings', [])[:10]:
 lines.append(f"\n {finding['type'].upper()}")
 lines.append(f" Endpoint: {finding['endpoint']}")
 lines.append(f" Severity: {finding['severity']}")
 lines.append(f" Description: {finding['description']}")
 lines.append(f" Fix: {finding['remediation'][:80]}...")
 
 lines.append("\n" + "=" * 60)
 return "\n".join(lines)
