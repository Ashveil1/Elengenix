"""tools/protocol_analyzer.py

Network Protocol Analyzer for IoT/ICS Testing.

Purpose:
- Analyze non-HTTP protocols: MQTT, Modbus, CoAP
- gRPC/Protobuf decoding and analysis
- Binary protocol structure detection
- Protocol-specific vulnerability detection
- Fuzzing vector identification

Input: PCAP files, network captures, or live protocol streams
Output: Protocol analysis report with security findings
"""

from __future__ import annotations

import json
import logging
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from enum import Enum

logger = logging.getLogger("elengenix.protocol_analyzer")

class ProtocolType(Enum):
 MQTT = "mqtt"
 MODBUS = "modbus"
 COAP = "coap"
 GRPC = "grpc"
 PROTOBUF = "protobuf"
 UNKNOWN_BINARY = "unknown_binary"

@dataclass
class ProtocolPacket:
 """Represents a parsed protocol packet."""
 timestamp: float
 src_addr: Tuple[str, int]
 dst_addr: Tuple[str, int]
 protocol: ProtocolType
 raw_data: bytes
 parsed_payload: Optional[Dict[str, Any]] = None
 flags: Set[str] = field(default_factory=set)
 anomalies: List[str] = field(default_factory=list)

@dataclass
class ProtocolFinding:
 """Protocol security finding."""
 finding_id: str
 protocol: ProtocolType
 finding_type: str
 severity: str
 confidence: float
 description: str
 packet_ref: Optional[str] = None
 evidence: Dict[str, Any] = field(default_factory=dict)
 remediation: str = ""
 cwe_id: Optional[str] = None

class MQTTAnalyzer:
 """
 MQTT (Message Queuing Telemetry Transport) analyzer for IoT.
 Common in IoT devices, smart home, industrial sensors.
 """
 
 # MQTT packet types
 PACKET_TYPES = {
 1: "CONNECT",
 2: "CONNACK",
 3: "PUBLISH",
 4: "PUBACK",
 5: "PUBREC",
 6: "PUBREL",
 7: "PUBCOMP",
 8: "SUBSCRIBE",
 9: "SUBACK",
 10: "UNSUBSCRIBE",
 11: "UNSUBACK",
 12: "PINGREQ",
 13: "PINGRESP",
 14: "DISCONNECT",
 15: "AUTH",
 }
 
 def is_mqtt(self, data: bytes) -> bool:
 """Check if data looks like MQTT packet."""
 if len(data) < 2:
 return False
 # First byte: packet type (upper nibble)
 packet_type = (data[0] >> 4) & 0x0F
 return 1 <= packet_type <= 15
 
 def parse_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
 """Parse MQTT packet structure."""
 if len(data) < 2:
 return None
 
 try:
 first_byte = data[0]
 packet_type_num = (first_byte >> 4) & 0x0F
 flags = first_byte & 0x0F
 
 packet_type = self.PACKET_TYPES.get(packet_type_num, "UNKNOWN")
 
 # Variable length decode (remaining length)
 remaining_length = 0
 multiplier = 1
 idx = 1
 while idx < len(data):
 byte = data[idx]
 remaining_length += (byte & 0x7F) * multiplier
 multiplier *= 128
 idx += 1
 if not (byte & 0x80):
 break
 
 result = {
 "packet_type": packet_type,
 "packet_type_num": packet_type_num,
 "flags": flags,
 "remaining_length": remaining_length,
 "header_length": idx,
 }
 
 # Parse payload for specific packet types
 payload_start = idx
 if packet_type == "CONNECT" and len(data) > payload_start:
 result["payload"] = self._parse_connect(data[payload_start:])
 elif packet_type == "PUBLISH" and len(data) > payload_start:
 result["payload"] = self._parse_publish(data[payload_start:], flags)
 elif packet_type == "SUBSCRIBE" and len(data) > payload_start:
 result["payload"] = self._parse_subscribe(data[payload_start:])
 
 return result
 
 except Exception as e:
 logger.debug(f"MQTT parse error: {e}")
 return None
 
 def _parse_connect(self, data: bytes) -> Dict[str, Any]:
 """Parse MQTT CONNECT packet payload."""
 try:
 idx = 0
 # Protocol name length
 proto_len = struct.unpack("!H", data[idx:idx+2])[0]
 idx += 2
 proto_name = data[idx:idx+proto_len].decode('utf-8', errors='ignore')
 idx += proto_len
 
 # Protocol level
 proto_level = data[idx]
 idx += 1
 
 # Connect flags
 connect_flags = data[idx]
 idx += 1
 
 # Keep alive
 keep_alive = struct.unpack("!H", data[idx:idx+2])[0]
 idx += 2
 
 # Client ID
 client_id_len = struct.unpack("!H", data[idx:idx+2])[0]
 idx += 2
 client_id = data[idx:idx+client_id_len].decode('utf-8', errors='ignore')
 idx += client_id_len
 
 result = {
 "protocol_name": proto_name,
 "protocol_level": proto_level,
 "client_id": client_id,
 "keep_alive": keep_alive,
 "clean_session": bool(connect_flags & 0x02),
 "will_flag": bool(connect_flags & 0x04),
 "will_qos": (connect_flags >> 3) & 0x03,
 "will_retain": bool(connect_flags & 0x20),
 "password_flag": bool(connect_flags & 0x40),
 "username_flag": bool(connect_flags & 0x80),
 }
 
 # Username
 if result["username_flag"] and len(data) > idx:
 try:
 user_len = struct.unpack("!H", data[idx:idx+2])[0]
 idx += 2
 result["username"] = data[idx:idx+user_len].decode('utf-8', errors='ignore')
 idx += user_len
 except:
 pass
 
 # Password
 if result["password_flag"] and len(data) > idx:
 try:
 pass_len = struct.unpack("!H", data[idx:idx+2])[0]
 idx += 2
 result["password"] = data[idx:idx+pass_len].decode('utf-8', errors='ignore')
 except:
 pass
 
 return result
 
 except Exception as e:
 return {"error": str(e), "partial": True}
 
 def _parse_publish(self, data: bytes, flags: int) -> Dict[str, Any]:
 """Parse MQTT PUBLISH packet payload."""
 try:
 idx = 0
 topic_len = struct.unpack("!H", data[idx:idx+2])[0]
 idx += 2
 topic = data[idx:idx+topic_len].decode('utf-8', errors='ignore')
 idx += topic_len
 
 # QoS level from flags
 qos = (flags >> 1) & 0x03
 retain = bool(flags & 0x01)
 
 result = {
 "topic": topic,
 "qos": qos,
 "retain": retain,
 "dup": bool(flags & 0x08),
 }
 
 # Message ID if QoS > 0
 if qos > 0 and len(data) > idx:
 try:
 msg_id = struct.unpack("!H", data[idx:idx+2])[0]
 idx += 2
 result["message_id"] = msg_id
 except:
 pass
 
 # Payload
 if len(data) > idx:
 payload = data[idx:]
 result["payload_length"] = len(payload)
 # Try to decode as text
 try:
 result["payload_text"] = payload.decode('utf-8', errors='ignore')[:200]
 except:
 result["payload_hex"] = payload[:50].hex()
 
 return result
 
 except Exception as e:
 return {"error": str(e)}
 
 def _parse_subscribe(self, data: bytes) -> Dict[str, Any]:
 """Parse MQTT SUBSCRIBE packet payload."""
 try:
 idx = 0
 # Message ID
 msg_id = struct.unpack("!H", data[idx:idx+2])[0]
 idx += 2
 
 topics = []
 while idx < len(data):
 topic_len = struct.unpack("!H", data[idx:idx+2])[0]
 idx += 2
 topic = data[idx:idx+topic_len].decode('utf-8', errors='ignore')
 idx += topic_len
 
 if idx < len(data):
 qos = data[idx] & 0x03
 idx += 1
 topics.append({"topic": topic, "qos": qos})
 
 return {
 "message_id": msg_id,
 "topics": topics,
 }
 
 except Exception as e:
 return {"error": str(e)}
 
 def analyze_security(self, packet_data: bytes) -> List[ProtocolFinding]:
 """Analyze MQTT packet for security issues."""
 findings = []
 
 parsed = self.parse_packet(packet_data)
 if not parsed:
 return findings
 
 # Check for authentication issues
 if parsed["packet_type"] == "CONNECT":
 payload = parsed.get("payload", {})
 
 # No authentication
 if not payload.get("username_flag") and not payload.get("password_flag"):
 findings.append(ProtocolFinding(
 finding_id=f"mqtt:no_auth:{hash(packet_data[:20])}",
 protocol=ProtocolType.MQTT,
 finding_type="missing_authentication",
 severity="high",
 confidence=0.9,
 description="MQTT connection without username/password authentication",
 evidence={"client_id": payload.get("client_id"), "protocol_level": payload.get("protocol_level")},
 remediation="Enable MQTT authentication. Require username/password or client certificates.",
 cwe_id="CWE-306",
 ))
 
 # Weak protocol version (MQTT 3.1 is old)
 if payload.get("protocol_level", 4) < 4:
 findings.append(ProtocolFinding(
 finding_id=f"mqtt:old_version:{hash(packet_data[:20])}",
 protocol=ProtocolType.MQTT,
 finding_type="outdated_protocol",
 severity="medium",
 confidence=0.8,
 description=f"Old MQTT protocol version: {payload.get('protocol_name')}",
 evidence={"protocol_name": payload.get("protocol_name"), "protocol_level": payload.get("protocol_level")},
 remediation="Upgrade to MQTT v5.0 with enhanced security features.",
 cwe_id="CWE-1104",
 ))
 
 # Hardcoded credentials detection (if we can see them)
 if payload.get("username") and payload.get("password"):
 if len(payload["password"]) < 8 or payload["password"] in ["123456", "password", "admin"]:
 findings.append(ProtocolFinding(
 finding_id=f"mqtt:weak_creds:{hash(packet_data[:20])}",
 protocol=ProtocolType.MQTT,
 finding_type="weak_credentials",
 severity="critical",
 confidence=0.85,
 description="Weak or default MQTT credentials detected",
 evidence={"username": payload.get("username")},
 remediation="Use strong, unique passwords. Implement certificate-based authentication.",
 cwe_id="CWE-798",
 ))
 
 # Check for sensitive topics in PUBLISH
 if parsed["packet_type"] == "PUBLISH":
 payload = parsed.get("payload", {})
 topic = payload.get("topic", "")
 
 sensitive_patterns = ["command", "control", "config", "password", "key", "token", "auth"]
 if any(pattern in topic.lower() for pattern in sensitive_patterns):
 findings.append(ProtocolFinding(
 finding_id=f"mqtt:sensitive_topic:{hash(packet_data[:20])}",
 protocol=ProtocolType.MQTT,
 finding_type="sensitive_topic",
 severity="medium",
 confidence=0.7,
 description=f"Sensitive topic detected: {topic}",
 evidence={"topic": topic, "qos": payload.get("qos")},
 remediation="Restrict access to sensitive topics. Use topic ACLs. Enable encryption (TLS).",
 cwe_id="CWE-284",
 ))
 
 # Check for wildcard subscriptions (potential DoS)
 if "#" in topic or "+" in topic:
 findings.append(ProtocolFinding(
 finding_id=f"mqtt:wildcard:{hash(packet_data[:20])}",
 protocol=ProtocolType.MQTT,
 finding_type="wildcard_subscription",
 severity="low",
 confidence=0.6,
 description=f"MQTT wildcard subscription detected: {topic}",
 evidence={"topic": topic},
 remediation="Review wildcard usage. May lead to information disclosure or DoS.",
 cwe_id="CWE-400",
 ))
 
 return findings

class ModbusAnalyzer:
 """
 Modbus protocol analyzer for Industrial Control Systems (ICS/SCADA).
 Common in industrial automation, building management systems.
 """
 
 FUNCTION_CODES = {
 0x01: "Read Coils",
 0x02: "Read Discrete Inputs",
 0x03: "Read Holding Registers",
 0x04: "Read Input Registers",
 0x05: "Write Single Coil",
 0x06: "Write Single Register",
 0x0F: "Write Multiple Coils",
 0x10: "Write Multiple Registers",
 0x16: "Mask Write Register",
 0x17: "Read/Write Multiple Registers",
 0x08: "Diagnostics",
 0x11: "Report Slave ID",
 }
 
 def is_modbus_tcp(self, data: bytes) -> bool:
 """Check if data looks like Modbus TCP packet."""
 if len(data) < 7:
 return False
 # MBAP header: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1)
 protocol_id = struct.unpack("!H", data[2:4])[0]
 return protocol_id == 0 # Modbus protocol ID is 0
 
 def parse_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
 """Parse Modbus TCP packet."""
 if len(data) < 7:
 return None
 
 try:
 # MBAP Header
 transaction_id = struct.unpack("!H", data[0:2])[0]
 protocol_id = struct.unpack("!H", data[2:4])[0]
 length = struct.unpack("!H", data[4:6])[0]
 unit_id = data[6]
 
 result = {
 "transaction_id": transaction_id,
 "protocol_id": protocol_id,
 "length": length,
 "unit_id": unit_id,
 }
 
 # PDU starts at byte 7
 if len(data) > 7:
 pdu = data[7:]
 function_code = pdu[0]
 result["function_code"] = function_code
 result["function_name"] = self.FUNCTION_CODES.get(function_code, "Unknown")
 
 # Parse PDU based on function code
 if len(pdu) > 1:
 if function_code in [0x01, 0x02, 0x03, 0x04]: # Read functions
 if len(pdu) >= 5:
 result["start_address"] = struct.unpack("!H", pdu[1:3])[0]
 result["quantity"] = struct.unpack("!H", pdu[3:5])[0]
 
 elif function_code in [0x05, 0x06]: # Write single
 if len(pdu) >= 5:
 result["address"] = struct.unpack("!H", pdu[1:3])[0]
 result["value"] = struct.unpack("!H", pdu[3:5])[0]
 
 elif function_code == 0x08: # Diagnostics
 if len(pdu) >= 3:
 result["sub_function"] = struct.unpack("!H", pdu[1:3])[0]
 
 return result
 
 except Exception as e:
 logger.debug(f"Modbus parse error: {e}")
 return None
 
 def analyze_security(self, packet_data: bytes) -> List[ProtocolFinding]:
 """Analyze Modbus packet for security issues."""
 findings = []
 
 parsed = self.parse_packet(packet_data)
 if not parsed:
 return findings
 
 # Check for write operations (potential unauthorized control)
 function_code = parsed.get("function_code", 0)
 write_functions = [0x05, 0x06, 0x0F, 0x10, 0x16, 0x17]
 
 if function_code in write_functions:
 findings.append(ProtocolFinding(
 finding_id=f"modbus:write_op:{hash(packet_data[:20])}",
 protocol=ProtocolType.MODBUS,
 finding_type="write_operation",
 severity="high",
 confidence=0.85,
 description=f"Modbus write operation: {parsed.get('function_name')}",
 evidence={
 "function_code": function_code,
 "function_name": parsed.get("function_name"),
 "unit_id": parsed.get("unit_id"),
 "address": parsed.get("address") or parsed.get("start_address"),
 },
 remediation="Implement authentication and authorization for write operations. Use secure Modbus (TLS).",
 cwe_id="CWE-306",
 ))
 
 # Check for unit ID 0 (broadcast) - potential DoS
 if parsed.get("unit_id") == 0:
 findings.append(ProtocolFinding(
 finding_id=f"modbus:broadcast:{hash(packet_data[:20])}",
 protocol=ProtocolType.MODBUS,
 finding_type="broadcast_message",
 severity="medium",
 confidence=0.7,
 description="Modbus broadcast message (Unit ID 0) detected",
 evidence={"function_code": function_code, "unit_id": 0},
 remediation="Restrict broadcast usage. Implement rate limiting.",
 cwe_id="CWE-400",
 ))
 
 # Large read quantity (potential information disclosure)
 quantity = parsed.get("quantity", 0)
 if quantity > 100:
 findings.append(ProtocolFinding(
 finding_id=f"modbus:large_read:{hash(packet_data[:20])}",
 protocol=ProtocolType.MODBUS,
 finding_type="large_data_request",
 severity="low",
 confidence=0.6,
 description=f"Large Modbus read request: {quantity} registers/coils",
 evidence={"quantity": quantity, "start_address": parsed.get("start_address")},
 remediation="Limit read quantities. Implement access controls per register range.",
 cwe_id="CWE-200",
 ))
 
 return findings

class ProtobufAnalyzer:
 """
 Protocol Buffers (protobuf) and gRPC analyzer.
 Common in microservices, mobile APIs, modern distributed systems.
 """
 
 # Wire types
 WIRE_TYPES = {
 0: "Varint",
 1: "64-bit",
 2: "Length-delimited",
 3: "Start group",
 4: "End group",
 5: "32-bit",
 }
 
 def is_protobuf(self, data: bytes) -> bool:
 """Heuristic check for protobuf data."""
 if len(data) < 3:
 return False
 
 # Check for valid protobuf wire format patterns
 try:
 idx = 0
 field_count = 0
 while idx < len(data) and field_count < 5:
 if data[idx] == 0:
 return False # Invalid tag
 
 wire_type = data[idx] & 0x07
 if wire_type not in self.WIRE_TYPES:
 return False
 
 # Try to parse field number and advance
 field_num = data[idx] >> 3
 if field_num == 0:
 return False
 
 idx += 1
 
 # Handle varint (common for field tags > 15)
 if data[idx - 1] & 0x80:
 while idx < len(data) and data[idx - 1] & 0x80:
 idx += 1
 
 # Skip value based on wire type
 if wire_type == 0: # Varint
 while idx < len(data) and data[idx] & 0x80:
 idx += 1
 idx += 1
 elif wire_type == 1: # 64-bit
 idx += 8
 elif wire_type == 2: # Length-delimited
 if idx >= len(data):
 return False
 length = data[idx]
 idx += 1
 if length & 0x80: # Varint length
 while idx < len(data) and data[idx - 1] & 0x80:
 idx += 1
 # Decode actual length (simplified)
 length = data[idx - 1] & 0x7F
 idx += length
 elif wire_type == 5: # 32-bit
 idx += 4
 else:
 return False
 
 field_count += 1
 
 return field_count > 0 and field_count < 100
 
 except:
 return False
 
 def parse_protobuf(self, data: bytes, max_depth: int = 3) -> List[Dict[str, Any]]:
 """Parse protobuf message structure (best effort without schema)."""
 fields = []
 idx = 0
 
 try:
 while idx < len(data) and max_depth > 0:
 if idx >= len(data):
 break
 
 tag = data[idx]
 wire_type = tag & 0x07
 field_number = tag >> 3
 idx += 1
 
 # Handle extended field numbers
 if tag & 0x80:
 field_number = (field_number << 7) | (data[idx] & 0x7F)
 idx += 1
 while data[idx - 1] & 0x80 and idx < len(data):
 field_number = (field_number << 7) | (data[idx] & 0x7F)
 idx += 1
 
 field_info = {
 "field_number": field_number,
 "wire_type": wire_type,
 "wire_type_name": self.WIRE_TYPES.get(wire_type, "Unknown"),
 "offset": idx - 1,
 }
 
 # Parse value
 if wire_type == 0: # Varint
 value = 0
 shift = 0
 while idx < len(data):
 byte = data[idx]
 idx += 1
 value |= (byte & 0x7F) << shift
 if not (byte & 0x80):
 break
 shift += 7
 field_info["value"] = value
 
 elif wire_type == 1: # 64-bit
 if idx + 8 <= len(data):
 value = struct.unpack("<Q", data[idx:idx+8])[0]
 field_info["value"] = value
 field_info["as_double"] = struct.unpack("<d", data[idx:idx+8])[0]
 idx += 8
 
 elif wire_type == 2: # Length-delimited
 length = 0
 shift = 0
 while idx < len(data):
 byte = data[idx]
 idx += 1
 length |= (byte & 0x7F) << shift
 if not (byte & 0x80):
 break
 shift += 7
 
 field_info["length"] = length
 if idx + length <= len(data):
 payload = data[idx:idx+length]
 field_info["raw_payload"] = payload[:50].hex()
 
 # Try to decode as string
 try:
 text = payload.decode('utf-8')
 if all(c.isprintable() or c.isspace() for c in text):
 field_info["as_string"] = text[:100]
 except:
 pass
 
 # Check for nested protobuf
 if length > 2 and self.is_protobuf(payload):
 field_info["nested"] = self.parse_protobuf(payload, max_depth - 1)
 
 idx += length
 
 elif wire_type == 5: # 32-bit
 if idx + 4 <= len(data):
 value = struct.unpack("<I", data[idx:idx+4])[0]
 field_info["value"] = value
 field_info["as_float"] = struct.unpack("<f", data[idx:idx+4])[0]
 idx += 4
 
 fields.append(field_info)
 
 except Exception as e:
 fields.append({"error": str(e), "offset": idx})
 
 return fields
 
 def analyze_grpc_metadata(self, headers: Dict[str, str]) -> List[ProtocolFinding]:
 """Analyze gRPC headers for security issues."""
 findings = []
 
 # Check for gRPC-Web (less secure than native gRPC)
 if 'grpc-web' in headers.get('content-type', ''):
 findings.append(ProtocolFinding(
 finding_id=f"grpc:web_mode:{hash(str(headers))}",
 protocol=ProtocolType.GRPC,
 finding_type="grpc_web_mode",
 severity="low",
 confidence=0.7,
 description="gRPC-Web detected (may have CORS/security implications)",
 evidence={"content_type": headers.get('content-type')},
 remediation="Use native gRPC with TLS for production. Review CORS policies.",
 cwe_id="CWE-942",
 ))
 
 # Check for missing deadline/timeout
 if 'grpc-timeout' not in headers and 'deadline' not in str(headers).lower():
 findings.append(ProtocolFinding(
 finding_id=f"grpc:no_timeout:{hash(str(headers))}",
 protocol=ProtocolType.GRPC,
 finding_type="missing_timeout",
 severity="low",
 confidence=0.6,
 description="gRPC request without explicit timeout/deadline",
 evidence={},
 remediation="Always set gRPC deadlines to prevent resource exhaustion.",
 cwe_id="CWE-400",
 ))
 
 return findings
 
 def detect_secrets_in_protobuf(self, data: bytes) -> List[ProtocolFinding]:
 """Detect potential secrets in protobuf payload."""
 findings = []
 
 # Common secret patterns in protobuf
 secret_patterns = [
 (rb'token["\']?\s*:\s*["\']?([a-zA-Z0-9_-]{20,})', "token"),
 (rb'key["\']?\s*:\s*["\']?([a-zA-Z0-9_-]{20,})', "api_key"),
 (rb'secret["\']?\s*:\s*["\']?([a-zA-Z0-9_-]{20,})', "secret"),
 (rb'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*', "jwt_token"),
 (rb'AKIA[0-9A-Z]{16}', "aws_access_key"),
 ]
 
 for pattern, secret_type in secret_patterns:
 matches = list(re.finditer(pattern, data))
 for match in matches:
 findings.append(ProtocolFinding(
 finding_id=f"grpc:secret:{secret_type}:{match.start()}",
 protocol=ProtocolType.GRPC,
 finding_type=f"exposed_{secret_type}",
 severity="critical",
 confidence=0.8,
 description=f"Potential {secret_type} exposed in protobuf/gRPC message",
 evidence={"offset": match.start(), "type": secret_type},
 remediation="Remove secrets from gRPC messages. Use secure credential management.",
 cwe_id="CWE-798",
 ))
 
 return findings

class ProtocolAnalyzer:
 """
 Main protocol analyzer that orchestrates all protocol scanners.
 """
 
 def __init__(self):
 self.mqtt = MQTTAnalyzer()
 self.modbus = ModbusAnalyzer()
 self.protobuf = ProtobufAnalyzer()
 self.packets: List[ProtocolPacket] = []
 self.findings: List[ProtocolFinding] = []
 
 def detect_protocol(self, data: bytes, src_port: int = 0, dst_port: int = 0) -> ProtocolType:
 """Detect protocol type from packet data and ports."""
 
 # Port-based hints
 port_hints = {
 1883: ProtocolType.MQTT,
 8883: ProtocolType.MQTT, # MQTT over TLS
 502: ProtocolType.MODBUS,
 80: ProtocolType.GRPC, # gRPC-Web
 443: ProtocolType.GRPC, # gRPC over TLS
 }
 
 if src_port in port_hints or dst_port in port_hints:
 hint = port_hints.get(src_port) or port_hints.get(dst_port)
 if hint:
 return hint
 
 # Content-based detection
 if self.mqtt.is_mqtt(data):
 return ProtocolType.MQTT
 
 if self.modbus.is_modbus_tcp(data):
 return ProtocolType.MODBUS
 
 if self.protobuf.is_protobuf(data):
 # Could be gRPC or pure protobuf
 return ProtocolType.PROTOBUF
 
 return ProtocolType.UNKNOWN_BINARY
 
 def analyze_packet(self, data: bytes, src_addr: Tuple[str, int], dst_addr: Tuple[str, int], 
 timestamp: float = 0.0) -> ProtocolPacket:
 """Analyze a single packet."""
 
 protocol = self.detect_protocol(data, src_addr[1], dst_addr[1])
 
 packet = ProtocolPacket(
 timestamp=timestamp,
 src_addr=src_addr,
 dst_addr=dst_addr,
 protocol=protocol,
 raw_data=data,
 )
 
 # Parse based on protocol
 if protocol == ProtocolType.MQTT:
 packet.parsed_payload = self.mqtt.parse_packet(data)
 findings = self.mqtt.analyze_security(data)
 self.findings.extend(findings)
 
 elif protocol == ProtocolType.MODBUS:
 packet.parsed_payload = self.modbus.parse_packet(data)
 findings = self.modbus.analyze_security(data)
 self.findings.extend(findings)
 
 elif protocol in [ProtocolType.PROTOBUF, ProtocolType.GRPC]:
 packet.parsed_payload = {
 "fields": self.protobuf.parse_protobuf(data),
 "is_protobuf": True,
 }
 findings = self.protobuf.detect_secrets_in_protobuf(data)
 self.findings.extend(findings)
 
 self.packets.append(packet)
 return packet
 
 def analyze_hex_dump(self, hex_data: str) -> Dict[str, Any]:
 """Analyze hex dump string."""
 try:
 data = bytes.fromhex(hex_data.replace(' ', '').replace('\n', ''))
 except:
 return {"error": "Invalid hex data"}
 
 protocol = self.detect_protocol(data)
 
 return {
 "protocol": protocol.value,
 "length": len(data),
 "hex_preview": data[:50].hex(),
 "analysis": self._analyze_binary(data, protocol),
 }
 
 def _analyze_binary(self, data: bytes, protocol: ProtocolType) -> Dict[str, Any]:
 """Deep analysis of binary data."""
 analysis = {
 "entropy": self._calculate_entropy(data),
 "printable_ratio": sum(1 for b in data if 32 <= b <= 126) / len(data) if data else 0,
 "null_bytes": data.count(0),
 "common_patterns": [],
 }
 
 # Look for common patterns
 patterns = {
 b'\x00\x00\x00\x00': "null_padding",
 b'{': "json_start",
 b'<?xml': "xml_start",
 b'PK\x03\x04': "zip_file",
 b'%PDF': "pdf_file",
 }
 
 for pattern, name in patterns.items():
 if pattern in data:
 analysis["common_patterns"].append(name)
 
 return analysis
 
 def _calculate_entropy(self, data: bytes) -> float:
 """Calculate Shannon entropy of data."""
 if not data:
 return 0.0
 
 from math import log2
 
 counts = {}
 for byte in data:
 counts[byte] = counts.get(byte, 0) + 1
 
 entropy = 0.0
 length = len(data)
 for count in counts.values():
 if count > 0:
 p = count / length
 entropy -= p * log2(p)
 
 return round(entropy, 2)
 
 def generate_fuzzing_hints(self) -> List[Dict[str, Any]]:
 """Generate fuzzing vectors based on analyzed protocols."""
 hints = []
 
 for finding in self.findings:
 if finding.severity in ['critical', 'high']:
 hints.append({
 "target": finding.protocol.value,
 "vulnerability": finding.finding_type,
 "suggested_fuzz_vectors": self._get_fuzz_vectors(finding.protocol, finding.finding_type),
 })
 
 return hints
 
 def _get_fuzz_vectors(self, protocol: ProtocolType, vuln_type: str) -> List[str]:
 """Get protocol-specific fuzzing vectors."""
 vectors = {
 ProtocolType.MQTT: {
 "missing_authentication": ["\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00"], # CONNECT no auth
 "wildcard_subscription": ["\x82\x07\x00\x01\x00\x02#\x00", "\x82\x07\x00\x01\x00\x02+\x00"],
 },
 ProtocolType.MODBUS: {
 "write_operation": ["\x00\x00\x00\x00\x00\x06\x01\x06\x00\x01\x00\xff"], # Write register
 "broadcast_message": ["\x00\x00\x00\x00\x00\x06\x00\x06\x00\x01\x00\xff"], # Unit ID 0
 },
 ProtocolType.GRPC: {
 "exposed_token": ["grpc-timeout: 1S", "grpc-encoding: gzip"],
 },
 }
 
 return vectors.get(protocol, {}).get(vuln_type, [])
 
 def generate_report(self) -> Dict[str, Any]:
 """Generate comprehensive protocol analysis report."""
 protocol_counts = {}
 severity_counts = {}
 
 for packet in self.packets:
 p = packet.protocol.value
 protocol_counts[p] = protocol_counts.get(p, 0) + 1
 
 for finding in self.findings:
 s = finding.severity
 severity_counts[s] = severity_counts.get(s, 0) + 1
 
 return {
 "total_packets": len(self.packets),
 "protocol_distribution": protocol_counts,
 "total_findings": len(self.findings),
 "severity_distribution": severity_counts,
 "critical_findings": [
 {
 "id": f.finding_id,
 "protocol": f.protocol.value,
 "type": f.finding_type,
 "severity": f.severity,
 "description": f.description,
 "cwe": f.cwe_id,
 "remediation": f.remediation,
 }
 for f in self.findings if f.severity in ['critical', 'high']
 ],
 "fuzzing_hints": self.generate_fuzzing_hints(),
 }

def format_protocol_report(report: Dict[str, Any]) -> str:
 """Format protocol analysis report for display."""
 lines = []
 lines.append("=" * 60)
 lines.append("PROTOCOL ANALYSIS REPORT (IoT/ICS/gRPC)")
 lines.append("=" * 60)
 
 lines.append(f"\nTotal Packets Analyzed: {report.get('total_packets', 0)}")
 lines.append(f"Total Findings: {report.get('total_findings', 0)}")
 
 lines.append("\n[Protocol Distribution]")
 for proto, count in report.get('protocol_distribution', {}).items():
 lines.append(f" {proto.upper()}: {count} packets")
 
 lines.append("\n[Severity Distribution]")
 for sev, count in report.get('severity_distribution', {}).items():
 lines.append(f" {sev.upper()}: {count}")
 
 lines.append("\n[Critical/High Findings]")
 for finding in report.get('critical_findings', [])[:10]:
 lines.append(f"\n [{finding['protocol'].upper()}] {finding['type']}")
 lines.append(f" Severity: {finding['severity']}")
 lines.append(f" CWE: {finding.get('cwe', 'N/A')}")
 lines.append(f" {finding['description'][:80]}...")
 lines.append(f" Fix: {finding['remediation'][:60]}...")
 
 hints = report.get('fuzzing_hints', [])
 if hints:
 lines.append(f"\n[Fuzzing Vectors Generated: {len(hints)}]")
 for hint in hints[:5]:
 lines.append(f" - {hint['target']}: {hint['vulnerability']}")
 
 lines.append("\n" + "=" * 60)
 return "\n".join(lines)
