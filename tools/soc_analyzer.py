"""tools/soc_analyzer.py

SOC Analyzer & Alert Triage Engine.

Purpose:
- Parse and analyze security logs/alerts (syslog, JSON, CSV)
- Triage alerts by severity, confidence, and impact
- Correlate alerts with threat intelligence
- Generate detection rules (Sigma format)
- Provide actionable incident response recommendations

Input: Log files or alert streams
Output: Triage report + detection rules + response playbook
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import Counter

logger = logging.getLogger("elengenix.soc")

@dataclass
class Alert:
 """Normalized security alert."""
 alert_id: str
 timestamp: str
 source: str # Source system (e.g., "suricata", "wazuh", "crowdsec")
 alert_type: str # e.g., "malware", "intrusion", "recon", "privilege_escalation"
 severity: str # critical, high, medium, low, info
 confidence: float # 0.0-1.0
 src_ip: Optional[str] = None
 dst_ip: Optional[str] = None
 src_port: Optional[int] = None
 dst_port: Optional[int] = None
 user: Optional[str] = None
 process: Optional[str] = None
 command: Optional[str] = None
 hash_md5: Optional[str] = None
 hash_sha256: Optional[str] = None
 domain: Optional[str] = None
 url: Optional[str] = None
 signature: Optional[str] = None
 raw_data: Dict[str, Any] = field(default_factory=dict)
 ioc_matches: List[str] = field(default_factory=list)

@dataclass
class TriageResult:
 """Result of alert triage."""
 alert: Alert
 priority_score: float # Calculated priority
 category: str # true_positive, false_positive, needs_investigation
 recommended_action: str
 related_alerts: List[str]
 threat_actor: Optional[str] = None
 campaign: Optional[str] = None

@dataclass
class DetectionRule:
 """Generated detection rule (Sigma format)."""
 title: str
 logsource: Dict[str, str]
 detection: Dict[str, Any]
 tags: List[str]
 level: str # critical, high, medium, low
 description: str
 references: List[str] = field(default_factory=list)

class SOCAnalyzer:
 """
 Security Operations Center alert analyzer and triage engine.
 """

 # Known threat actor signatures in alerts
 THREAT_ACTOR_SIGNATURES = {
 "apt28": ["fancy bear", "apt28", "sofacy", "sednit"],
 "apt29": ["cozy bear", "apt29", "the dukes"],
 "lazarus": ["lazarus", "hidden cobra", "guardians of peace"],
 "fin7": ["fin7", "carbanak", "anunak"],
 "emotet": ["emotet", "heodo"],
 "trickbot": ["trickbot", "trickster"],
 "cobalt_strike": ["cobalt strike", "beacon"],
 }

 # Severity mapping
 SEVERITY_WEIGHTS = {
 "critical": 10.0,
 "high": 7.0,
 "medium": 4.0,
 "low": 2.0,
 "info": 1.0,
 }

 def __init__(self, ioc_db: Optional[Dict[str, Any]] = None):
 self.ioc_db = ioc_db or {}
 self.alerts: List[Alert] = []
 self.iocs_seen: Set[str] = set()

 def parse_syslog(self, log_line: str) -> Optional[Alert]:
 """Parse syslog format alert."""
 try:
 # Common syslog pattern
 match = re.match(
 r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s+(.+)$",
 log_line
 )
 if not match:
 return None

 timestamp_str, hostname, process, message = match.groups()
 timestamp = datetime.strptime(
 f"{datetime.now().year} {timestamp_str}",
 "%Y %b %d %H:%M:%S"
 ).isoformat()

 # Extract severity from message
 severity = "info"
 if any(kw in message.lower() for kw in ["critical", "alert"]):
 severity = "critical"
 elif any(kw in message.lower() for kw in ["error", "high"]):
 severity = "high"
 elif any(kw in message.lower() for kw in ["warning", "medium"]):
 severity = "medium"
 elif any(kw in message.lower() for kw in ["low"]):
 severity = "low"

 # Extract IPs if present
 ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
 src_ip = ips[0] if ips else None
 dst_ip = ips[1] if len(ips) > 1 else None

 alert_id = f"syslog:{hash(log_line) % 1000000:06d}"

 return Alert(
 alert_id=alert_id,
 timestamp=timestamp,
 source=process,
 alert_type="system",
 severity=severity,
 confidence=0.6,
 src_ip=src_ip,
 dst_ip=dst_ip,
 raw_data={"message": message, "hostname": hostname},
 )

 except Exception as e:
 logger.debug(f"Syslog parse failed: {e}")
 return None

 def parse_json_alert(self, json_data: Dict[str, Any], source: str) -> Optional[Alert]:
 """Parse JSON format alert (common in modern SIEMs)."""
 try:
 # Handle various JSON formats
 alert_id = json_data.get("alert_id") or json_data.get("id") or f"json:{hash(str(json_data)) % 1000000:06d}"
 timestamp = json_data.get("timestamp") or json_data.get("@timestamp") or datetime.utcnow().isoformat()
 severity = (json_data.get("severity") or json_data.get("level") or "medium").lower()
 
 # Normalize severity
 if severity in ["emergency", "critical", "alert"]:
 severity = "critical"
 elif severity in ["error", "high"]:
 severity = "high"
 elif severity in ["warning", "notice", "medium"]:
 severity = "medium"
 elif severity in ["info", "low", "debug"]:
 severity = "low"

 # Extract network info
 src_ip = json_data.get("src_ip") or json_data.get("source_ip") or json_data.get("src")
 dst_ip = json_data.get("dst_ip") or json_data.get("dest_ip") or json_data.get("dst")
 src_port = json_data.get("src_port") or json_data.get("sport")
 dst_port = json_data.get("dst_port") or json_data.get("dport")

 # Convert ports to int if string
 if isinstance(src_port, str):
 src_port = int(src_port) if src_port.isdigit() else None
 if isinstance(dst_port, str):
 dst_port = int(dst_port) if dst_port.isdigit() else None

 # Determine alert type
 alert_type = "unknown"
 signature = json_data.get("signature") or json_data.get("rule_name") or ""
 if any(kw in signature.lower() for kw in ["malware", "trojan", "virus"]):
 alert_type = "malware"
 elif any(kw in signature.lower() for kw in ["intrusion", "exploit", "attack", "cve"]):
 alert_type = "intrusion"
 elif any(kw in signature.lower() for kw in ["recon", "scan", "probe"]):
 alert_type = "recon"
 elif any(kw in signature.lower() for kw in ["privilege", "escalation", "sudo", "admin"]):
 alert_type = "privilege_escalation"
 elif any(kw in signature.lower() for kw in ["data", "exfil", "leak", "theft"]):
 alert_type = "data_exfiltration"

 return Alert(
 alert_id=alert_id,
 timestamp=timestamp,
 source=source,
 alert_type=alert_type,
 severity=severity,
 confidence=json_data.get("confidence", 0.7),
 src_ip=src_ip,
 dst_ip=dst_ip,
 src_port=src_port,
 dst_port=dst_port,
 user=json_data.get("user") or json_data.get("username"),
 process=json_data.get("process") or json_data.get("proc_name"),
 command=json_data.get("command") or json_data.get("cmdline"),
 hash_md5=json_data.get("md5") or json_data.get("hash_md5"),
 hash_sha256=json_data.get("sha256") or json_data.get("hash_sha256"),
 domain=json_data.get("domain") or json_data.get("fqdn"),
 url=json_data.get("url") or json_data.get("uri"),
 signature=signature,
 raw_data=json_data,
 )

 except Exception as e:
 logger.debug(f"JSON parse failed: {e}")
 return None

 def check_ioc(self, alert: Alert) -> List[str]:
 """Check alert against IOC database."""
 matches = []
 
 checks = [
 ("ip", alert.src_ip),
 ("ip", alert.dst_ip),
 ("domain", alert.domain),
 ("hash", alert.hash_md5),
 ("hash", alert.hash_sha256),
 ("url", alert.url),
 ]
 
 for ioc_type, value in checks:
 if value and value in self.ioc_db.get(ioc_type, {}):
 matches.append(f"{ioc_type}:{value}")
 
 return matches

 def identify_threat_actor(self, alert: Alert) -> Tuple[Optional[str], Optional[str]]:
 """Identify potential threat actor from alert signatures."""
 text_to_check = " ".join([
 alert.signature or "",
 alert.raw_data.get("message", ""),
 str(alert.raw_data),
 ]).lower()

 for actor, signatures in self.THREAT_ACTOR_SIGNATURES.items():
 if any(sig in text_to_check for sig in signatures):
 return actor, "signature_match"
 
 return None, None

 def calculate_priority(self, alert: Alert) -> float:
 """Calculate priority score for alert."""
 base_score = self.SEVERITY_WEIGHTS.get(alert.severity, 1.0)
 
 # Confidence weight
 confidence_weight = alert.confidence
 
 # IOC match bonus
 ioc_bonus = len(alert.ioc_matches) * 2.0
 
 # Threat actor bonus
 actor_bonus = 3.0 if alert.ioc_matches else 0.0
 
 # Lateral movement indicators
 lateral_bonus = 0.0
 if alert.alert_type in ["privilege_escalation", "lateral_movement"]:
 lateral_bonus = 2.0
 
 # Data exfiltration
 exfil_bonus = 0.0
 if alert.alert_type == "data_exfiltration":
 exfil_bonus = 4.0

 total = (base_score * confidence_weight) + ioc_bonus + actor_bonus + lateral_bonus + exfil_bonus
 return round(min(10.0, total), 2)

 def triage_alert(self, alert: Alert) -> TriageResult:
 """Triage single alert."""
 # Check IOCs
 alert.ioc_matches = self.check_ioc(alert)
 
 # Identify threat actor
 threat_actor, campaign = self.identify_threat_actor(alert)
 
 # Calculate priority
 priority = self.calculate_priority(alert)
 
 # Determine category
 if alert.ioc_matches:
 category = "true_positive"
 elif alert.confidence > 0.8 and alert.severity in ["critical", "high"]:
 category = "needs_investigation"
 elif alert.confidence < 0.4:
 category = "false_positive_likely"
 else:
 category = "needs_investigation"
 
 # Recommended action
 if category == "true_positive":
 action = "Immediate containment recommended. Check for lateral movement."
 elif category == "needs_investigation":
 action = "Investigate immediately. Collect additional logs and context."
 elif category == "false_positive_likely":
 action = "Review and tune rule. Likely benign activity."
 else:
 action = "Monitor and investigate if pattern continues."

 return TriageResult(
 alert=alert,
 priority_score=priority,
 category=category,
 recommended_action=action,
 related_alerts=[], # Would be filled by correlation engine
 threat_actor=threat_actor,
 campaign=campaign,
 )

 def correlate_alerts(self, triage_results: List[TriageResult]) -> List[TriageResult]:
 """Correlate alerts to find related activity."""
 # Group by common indicators
 ip_to_alerts: Dict[str, List[str]] = {}
 user_to_alerts: Dict[str, List[str]] = {}
 
 for result in triage_results:
 alert = result.alert
 
 if alert.src_ip:
 if alert.src_ip not in ip_to_alerts:
 ip_to_alerts[alert.src_ip] = []
 ip_to_alerts[alert.src_ip].append(alert.alert_id)
 
 if alert.user:
 if alert.user not in user_to_alerts:
 user_to_alerts[alert.user] = []
 user_to_alerts[alert.user].append(alert.alert_id)
 
 # Update related alerts
 for result in triage_results:
 alert = result.alert
 related = set()
 
 if alert.src_ip and alert.src_ip in ip_to_alerts:
 related.update(ip_to_alerts[alert.src_ip])
 if alert.user and alert.user in user_to_alerts:
 related.update(user_to_alerts[alert.user])
 
 related.discard(alert.alert_id) # Remove self
 result.related_alerts = list(related)
 
 return triage_results

 def generate_sigma_rule(self, alert: Alert) -> Optional[DetectionRule]:
 """Generate Sigma detection rule from alert."""
 if alert.confidence < 0.6:
 return None # Don't generate rules for low confidence
 
 logsource = {"product": "generic", "service": alert.source}
 
 # Build detection logic
 detection: Dict[str, Any] = {"condition": "selection"}
 selection: Dict[str, Any] = {}
 
 if alert.signature:
 selection["Signature|contains"] = alert.signature[:50] # Truncate for readability
 
 if alert.src_ip:
 selection["SourceIP"] = alert.src_ip
 
 if alert.dst_ip:
 selection["DestinationIP"] = alert.dst_ip
 
 if alert.process:
 selection["Image|contains"] = alert.process.lower()
 
 if alert.command:
 cmd_keywords = alert.command.split()[:3] # First 3 words
 selection["CommandLine|contains|all"] = cmd_keywords

 detection["selection"] = selection

 # Determine level
 level = alert.severity
 if alert.alert_type in ["privilege_escalation", "data_exfiltration"]:
 level = "high"

 return DetectionRule(
 title=f"{alert.alert_type.replace('_', ' ').title()} - {alert.source}",
 logsource=logsource,
 detection=detection,
 tags=[alert.alert_type, alert.source, "auto-generated"],
 level=level,
 description=f"Auto-generated rule for {alert.alert_type} detected by {alert.source}",
 references=[],
 )

 def analyze_log_file(self, file_path: Path, source_hint: Optional[str] = None) -> Dict[str, Any]:
 """Analyze a log file and return comprehensive report."""
 if not file_path.exists():
 return {"error": f"File not found: {file_path}"}

 source = source_hint or file_path.stem
 parsed_alerts: List[Alert] = []
 
 # Try to detect format
 with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
 first_lines = [f.readline() for _ in range(5)]
 
 # Determine format
 is_json = any(line.strip().startswith(("{", "[")) for line in first_lines if line.strip())
 
 with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
 for line_num, line in enumerate(f, 1):
 line = line.strip()
 if not line:
 continue
 
 alert = None
 
 if is_json:
 try:
 json_data = json.loads(line)
 alert = self.parse_json_alert(json_data, source)
 except json.JSONDecodeError:
 else:
 # Try syslog
 alert = self.parse_syslog(line)
 
 if alert:
 parsed_alerts.append(alert)

 # Triage all alerts
 triage_results = [self.triage_alert(a) for a in parsed_alerts]
 
 # Correlate
 triage_results = self.correlate_alerts(triage_results)
 
 # Generate rules for high-confidence alerts
 rules = []
 for result in triage_results:
 if result.category in ["true_positive", "needs_investigation"] and result.priority_score >= 6.0:
 rule = self.generate_sigma_rule(result.alert)
 if rule:
 rules.append(rule)

 # Summary statistics
 severity_counts = Counter([r.alert.severity for r in triage_results])
 type_counts = Counter([r.alert.alert_type for r in triage_results])
 category_counts = Counter([r.category for r in triage_results])
 
 # Top priority alerts
 top_alerts = sorted(triage_results, key=lambda x: x.priority_score, reverse=True)[:10]
 
 return {
 "total_alerts": len(parsed_alerts),
 "severity_distribution": dict(severity_counts),
 "type_distribution": dict(type_counts),
 "category_distribution": dict(category_counts),
 "top_priority_alerts": [
 {
 "id": r.alert.alert_id,
 "type": r.alert.alert_type,
 "severity": r.alert.severity,
 "priority": r.priority_score,
 "src_ip": r.alert.src_ip,
 "threat_actor": r.threat_actor,
 "action": r.recommended_action,
 }
 for r in top_alerts
 ],
 "generated_rules": [
 {
 "title": r.title,
 "level": r.level,
 "tags": r.tags,
 }
 for r in rules
 ],
 "ioc_matches_found": sum(1 for r in triage_results if r.alert.ioc_matches),
 "threat_actors_identified": list(set(r.threat_actor for r in triage_results if r.threat_actor)),
 }

def format_soc_report(report: Dict[str, Any]) -> str:
 """Format SOC analysis report for display."""
 lines = []
 lines.append("=" * 60)
 lines.append("SOC ALERT ANALYSIS REPORT")
 lines.append("=" * 60)
 
 lines.append(f"\nTotal Alerts Analyzed: {report.get('total_alerts', 0)}")
 
 lines.append("\n[Severity Distribution]")
 for sev, count in report.get('severity_distribution', {}).items():
 lines.append(f" {sev.upper()}: {count}")
 
 lines.append("\n[Alert Categories]")
 for cat, count in report.get('category_distribution', {}).items():
 lines.append(f" {cat}: {count}")
 
 lines.append("\n[Top Priority Alerts]")
 for alert in report.get('top_priority_alerts', [])[:5]:
 lines.append(f"\n ID: {alert['id']}")
 lines.append(f" Type: {alert['type']} | Severity: {alert['severity']} | Priority: {alert['priority']}")
 if alert.get('threat_actor'):
 lines.append(f" Threat Actor: {alert['threat_actor']}")
 lines.append(f" Action: {alert['action']}")
 
 if report.get('threat_actors_identified'):
 lines.append("\n[Threat Actors Identified]")
 for actor in report['threat_actors_identified']:
 lines.append(f" - {actor}")
 
 if report.get('generated_rules'):
 lines.append(f"\n[Detection Rules Generated: {len(report['generated_rules'])}]")
 for rule in report['generated_rules'][:3]:
 lines.append(f" - {rule['title']} ({rule['level']})")
 
 lines.append("\n" + "=" * 60)
 return "\n".join(lines)
