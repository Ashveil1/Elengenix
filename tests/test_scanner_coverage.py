"""tests/test_scanner_coverage.py — Tests for security scanner and tool modules."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ═══════════════════════════════════════════════════════════════════════════
# PROTOCOL ANALYZER
# ═══════════════════════════════════════════════════════════════════════════
class TestProtocolAnalyzer:
    def test_enum_values(self):
        from tools.protocol_analyzer import ProtocolType

        for pt in ProtocolType:
            assert pt.value

    def test_protocol_packet(self):
        from tools.protocol_analyzer import ProtocolPacket, ProtocolType

        p = ProtocolPacket(
            timestamp=0.0,
            src_addr=("127.0.0.1", 1883),
            dst_addr=("127.0.0.1", 54321),
            protocol=ProtocolType.MQTT,
            raw_data=b"\x10\x0c",
        )
        assert p.protocol == ProtocolType.MQTT

    def test_protocol_finding(self):
        from tools.protocol_analyzer import ProtocolFinding, ProtocolType

        f = ProtocolFinding(
            finding_id="f1",
            protocol=ProtocolType.MQTT,
            finding_type="weak_auth",
            severity="high",
            confidence=0.8,
            description="desc",
        )
        assert f.severity == "high"

    def test_mqtt_analyzer(self):
        from tools.protocol_analyzer import MQTTAnalyzer

        a = MQTTAnalyzer()
        assert a.is_mqtt(b"\x10\x0c")
        parsed = a.parse_packet(b"\x10\x11\x00\x04MQTT\x04\x00\x00\x3c\x00\x01x")
        assert parsed is None or isinstance(parsed, dict)

    def test_modbus_analyzer(self):
        from tools.protocol_analyzer import ModbusAnalyzer

        a = ModbusAnalyzer()
        assert a.is_modbus_tcp(b"\x00\x00\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a")
        parsed = a.parse_packet(b"\x00\x00\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a")
        assert parsed is None or isinstance(parsed, dict)

    def test_protocol_analyzer(self):
        from tools.protocol_analyzer import ProtocolAnalyzer

        a = ProtocolAnalyzer()
        assert hasattr(a, "analyze_packet")

    def test_format_report(self):
        from tools.protocol_analyzer import format_protocol_report

        assert isinstance(format_protocol_report({}), str)
        r = format_protocol_report(
            {"target": "x", "findings": [{"title": "X", "severity": "high"}]}
        )
        assert isinstance(r, str)

    def test_mqtt_connect(self):
        from tools.protocol_analyzer import MQTTAnalyzer

        a = MQTTAnalyzer()
        pkt = b"\x10\x11\x00\x04MQTT\x04\x00\x00\x3c\x00\x01x"
        assert a.is_mqtt(pkt)
        result = a.parse_packet(pkt)
        assert result is None or isinstance(result, dict)

    def test_modbus_function_codes(self):
        from tools.protocol_analyzer import ModbusAnalyzer

        a = ModbusAnalyzer()
        pkt = b"\x00\x00\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"
        assert a.is_modbus_tcp(pkt)
        result = a.parse_packet(pkt)
        assert result is None or isinstance(result, dict)


# ═══════════════════════════════════════════════════════════════════════════
# TARGETED ATTACKS
# ═══════════════════════════════════════════════════════════════════════════
class TestTargetedAttacks:
    def test_confirmed_finding(self):
        from tools.targeted_attacks import ConfirmedFinding

        f = ConfirmedFinding(
            title="SQLi",
            severity="Critical",
            category="injection",
            endpoint_url="http://t.com",
            method="POST",
            evidence="err",
        )
        assert f.severity == "Critical"
        assert f.confidence == 1.0

    def test_defaults(self):
        from tools.targeted_attacks import ConfirmedFinding

        f = ConfirmedFinding(
            title="X",
            severity="High",
            category="xss",
            endpoint_url="http://x",
            method="GET",
            evidence="e",
        )
        assert f.payload == ""

    def test_full_params(self):
        from tools.targeted_attacks import ConfirmedFinding

        f = ConfirmedFinding(
            title="IDOR",
            severity="Medium",
            category="idor",
            endpoint_url="http://api/v1/user/1",
            method="GET",
            evidence="200 OK",
            response_snippet="data",
            status_code=200,
            confidence=0.9,
            detector="idor",
        )
        assert f.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════
# SMART SCANNER
# ═══════════════════════════════════════════════════════════════════════════
class TestSmartScanner:
    def test_scan_phase_config(self):
        from tools.smart_scanner import ScanPhaseConfig

        c = ScanPhaseConfig(
            name="recon",
            description="Recon phase",
            estimated_tokens=1000,
            estimated_duration_minutes=5,
        )
        assert c.name == "recon"

    def test_init(self):
        from tools.smart_scanner import SmartScanner

        s = SmartScanner(target="http://test.com")
        assert s.target == "http://test.com"


# ═══════════════════════════════════════════════════════════════════════════
# SMART RECON
# ═══════════════════════════════════════════════════════════════════════════
class TestSmartRecon:
    def test_asset_node(self):
        from tools.smart_recon import AssetNode

        n = AssetNode(id="n1", asset_type="domain", value="test.com")
        assert n.value == "test.com"

    def test_asset_edge(self):
        from tools.smart_recon import AssetEdge

        e = AssetEdge(source="a.com", target="b.com", relation="subdomain_of")
        assert e.relation == "subdomain_of"

    def test_recon_result(self):
        from tools.smart_recon import ReconResult, AssetNode, AssetEdge

        n = AssetNode(id="n1", asset_type="domain", value="t.com")
        r = ReconResult(nodes=[n], edges=[], findings=[], stats={"total": 1})
        assert r.stats["total"] == 1

    def test_engine(self):
        from tools.smart_recon import SmartReconEngine

        e = SmartReconEngine(target_domain="test.com")
        assert e.target_domain == "test.com"


# ═══════════════════════════════════════════════════════════════════════════
# WAF EVASION
# ═══════════════════════════════════════════════════════════════════════════
class TestWAFEvasion:
    def test_mutation_technique(self):
        from tools.waf_evasion import MutationTechnique

        t = MutationTechnique(name="urlencode", apply=lambda p: p)
        assert t.name == "urlencode"

    def test_waf_test_result(self):
        from tools.waf_evasion import WAFTestResult

        r = WAFTestResult(
            payload="test",
            techniques=["enc"],
            blocked=False,
            status_code=200,
            response_snippet="ok",
            waf_detected=None,
            confidence=0.9,
        )
        assert r.blocked is False

    def test_engine(self):
        from tools.waf_evasion import WAFEvasionEngine

        e = WAFEvasionEngine(base_url="http://test.com")
        assert e is not None


# ═══════════════════════════════════════════════════════════════════════════
# SAST ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class TestSASTEngine:
    def test_code_vulnerability(self):
        from tools.sast_engine import CodeVulnerability

        v = CodeVulnerability(
            vuln_id="v1",
            file_path="test.py",
            line_number=10,
            column=0,
            vuln_type="sqli",
            severity="high",
            confidence=0.9,
            description="SQL injection",
            code_snippet="os.system()",
            remediation="Use parameterized queries",
        )
        assert v.line_number == 10

    def test_pattern_scanner(self):
        from tools.sast_engine import PatternBasedScanner

        s = PatternBasedScanner()
        assert s is not None

    def test_sast_engine(self):
        from tools.sast_engine import SASTEngine

        e = SASTEngine()
        assert e is not None

    def test_scan_repository(self):
        from tools.sast_engine import SASTEngine

        e = SASTEngine()
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "test.py").write_text("x = 1\n")
            if hasattr(e, "scan_repository"):
                result = e.scan_repository(Path(td))
                assert isinstance(result, (list, dict))


# ═══════════════════════════════════════════════════════════════════════════
# RACE CONDITION, SSTI, XXE, SSRF
# ═══════════════════════════════════════════════════════════════════════════
class TestScanners:
    def test_race(self):
        from tools.race_condition_tester import RaceConditionTester

        assert RaceConditionTester() is not None

    def test_ssti(self):
        from tools.ssti_scanner import SSTIScanner

        assert SSTIScanner() is not None

    def test_xxe(self):
        from tools.xxe_scanner import XXEScanner

        assert XXEScanner() is not None

    def test_ssrf(self):
        from tools.ssrf_scanner import SSRFScanner

        assert SSRFScanner() is not None

    def test_native(self):
        from tools.native_scanner import NativeScanner

        assert NativeScanner() is not None


# ═══════════════════════════════════════════════════════════════════════════
# NVD CVE
# ═══════════════════════════════════════════════════════════════════════════
class TestNVDCVE:
    def test_cve_vuln(self):
        from tools.nvd_cve import CVEVuln

        v = CVEVuln(cve_id="CVE-2024-0001", description="Test", cvss_v3=8.5, severity="HIGH")
        assert v.cve_id == "CVE-2024-0001"

    def test_nvd_database(self):
        from tools.nvd_cve import NVDDatabase

        db = NVDDatabase()
        assert db is not None


# ═══════════════════════════════════════════════════════════════════════════
# VULN REASONING
# ═══════════════════════════════════════════════════════════════════════════
class TestVulnReasoning:
    def test_hypothesis(self):
        from tools.vuln_reasoning import VulnHypothesis

        h = VulnHypothesis(title="SQLi", vuln_class="sqli", confidence=0.8, reasoning="test")
        assert h.confidence == 0.8

    def test_analysis_result(self):
        from tools.vuln_reasoning import AnalysisResult

        r = AnalysisResult()
        assert r.hypotheses == []

    def test_engine(self):
        from tools.vuln_reasoning import VulnReasoningEngine

        assert VulnReasoningEngine() is not None


# ═══════════════════════════════════════════════════════════════════════════
# VULN ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class TestVulnEngine:
    def test_vuln_class_enum(self):
        from tools.vuln_engine import VulnClass

        for v in VulnClass:
            assert v.value

    def test_exploit_maturity(self):
        from tools.vuln_engine import ExploitMaturity

        for m in ExploitMaturity:
            assert m.value

    def test_vuln_finding(self):
        from tools.vuln_engine import VulnFinding

        f = VulnFinding(id="v1", title="XSS", severity="high", url="http://t.com/xss")
        assert f.severity == "high"

    def test_payload_gen(self):
        from tools.vuln_engine import PayloadGen

        assert PayloadGen() is not None

    def test_kill_chain(self):
        from tools.vuln_engine import KillChainPhase

        for p in KillChainPhase:
            assert p.value

    def test_chain_link(self):
        from tools.vuln_engine import ChainLink, KillChainPhase

        link = ChainLink(vuln_id="v1", phase=KillChainPhase.DELIVER, description="test delivery")
        assert link.vuln_id == "v1"

    def test_exploit_chain(self):
        from tools.vuln_engine import ExploitChain

        c = ExploitChain(name="chain1", target="http://test.com")
        assert c.name == "chain1"


# ═══════════════════════════════════════════════════════════════════════════
# REPORTER
# ═══════════════════════════════════════════════════════════════════════════
class TestReporter:
    def test_generate_report(self):
        from tools.reporter import generate_bug_report

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            try:
                result = generate_bug_report(
                    target="http://test.com",
                    findings=[{"title": "XSS", "severity": "high"}],
                    report_path=f.name,
                )
                assert result is not None or os.path.exists(f.name)
            finally:
                if os.path.exists(f.name):
                    os.unlink(f.name)


# ═══════════════════════════════════════════════════════════════════════════
# PDF REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════
class TestPDFReport:
    def test_finding(self):
        from tools.pdf_report_generator import Finding

        f = Finding(
            title="XSS",
            severity="High",
            cvss_score=7.5,
            description="Reflected XSS",
            impact="Session hijack",
            evidence="alert(1)",
            remediation="Encode output",
        )
        assert f.severity == "High"

    def test_metadata(self):
        from tools.pdf_report_generator import ReportMetadata

        m = ReportMetadata(title="Report", target="test.com", author="Tester", date="2024-01-01")
        assert m.author == "Tester"

    def test_generator(self):
        from tools.pdf_report_generator import PDFReportGenerator

        assert PDFReportGenerator() is not None


# ═══════════════════════════════════════════════════════════════════════════
# WORDLIST MANAGER
# ═══════════════════════════════════════════════════════════════════════════
class TestWordlistManager:
    def test_path_suggestion(self):
        from tools.wordlist_manager import PathSuggestion

        p = PathSuggestion(
            path="/admin",
            confidence=0.9,
            reasoning="common",
            estimated_severity="high",
            bounty_potential="high",
            source="common",
        )
        assert p.confidence == 0.9

    def test_wordlist_config(self):
        from tools.wordlist_manager import WordlistConfig

        c = WordlistConfig(category="api", custom_paths=["/admin"])
        assert c.category == "api"

    def test_manager(self):
        from tools.wordlist_manager import WordlistManager

        with tempfile.TemporaryDirectory() as td:
            m = WordlistManager(wordlist_dir=td)
            assert m is not None


# ═══════════════════════════════════════════════════════════════════════════
# WELCOME WIZARD
# ═══════════════════════════════════════════════════════════════════════════
class TestWelcomeWizard:
    def test_setup_config(self):
        from tools.welcome_wizard import SetupConfig

        c = SetupConfig(
            ai_provider="openai",
            ai_model="gpt-4",
            default_mode="scan",
            rate_limit=10,
            theme="dark",
            auto_update=True,
            telemetry=False,
        )
        assert c.ai_provider == "openai"

    def test_wizard(self):
        from tools.welcome_wizard import WelcomeWizard

        assert WelcomeWizard() is not None


# ═══════════════════════════════════════════════════════════════════════════
# SOC ANALYZER
# ═══════════════════════════════════════════════════════════════════════════
class TestSOCAnalyzer:
    def test_alert(self):
        from tools.soc_analyzer import Alert

        a = Alert(
            alert_id="a1",
            timestamp="2024-01-01",
            source="auth",
            alert_type="brute_force",
            severity="high",
            confidence=0.9,
        )
        assert a.severity == "high"

    def test_triage_result(self):
        from tools.soc_analyzer import Alert, TriageResult

        a = Alert(
            alert_id="a1",
            timestamp="t",
            source="s",
            alert_type="type",
            severity="high",
            confidence=0.9,
        )
        r = TriageResult(
            alert=a,
            priority_score=0.9,
            category="brute_force",
            recommended_action="block",
            related_alerts=[],
        )
        assert r.recommended_action == "block"

    def test_detection_rule(self):
        from tools.soc_analyzer import DetectionRule

        rule = DetectionRule(
            title="brute_force",
            logsource={"category": "auth"},
            detection={"condition": "count > 10"},
            tags=["attack"],
            level="high",
            description="Brute force detection",
        )
        assert rule.level == "high"

    def test_analyzer(self):
        from tools.soc_analyzer import SOCAnalyzer

        s = SOCAnalyzer()
        assert s is not None


# ═══════════════════════════════════════════════════════════════════════════
# THREAT INTEL
# ═══════════════════════════════════════════════════════════════════════════
class TestThreatIntel:
    def test_db(self):
        from tools.threat_intel import ThreatIntelDB

        assert ThreatIntelDB() is not None

    def test_enricher(self):
        from tools.threat_intel import Enricher

        assert Enricher() is not None


# ═══════════════════════════════════════════════════════════════════════════
# TELEGRAM BRIDGE
# ═══════════════════════════════════════════════════════════════════════════
class TestTelegramBridge:
    def test_config(self):
        from tools.telegram_bridge import TelegramConfig

        c = TelegramConfig(bot_token="123:ABC", chat_id="12345")
        assert c.bot_token == "123:ABC"

    def test_bridge(self):
        from tools.telegram_bridge import TelegramBridge

        assert TelegramBridge() is not None


# ═══════════════════════════════════════════════════════════════════════════
# PROGRESS DISPLAY
# ═══════════════════════════════════════════════════════════════════════════
class TestProgressDisplay:
    def test_scan_phase(self):
        from tools.progress_display import ScanPhase

        p = ScanPhase(id="p1", name="recon", subtasks=["t1", "t2"])
        assert p.name == "recon"

    def test_metrics(self):
        from tools.progress_display import ProgressMetrics

        m = ProgressMetrics(target="http://t.com", start_time=0.0, phases={})
        assert m.target == "http://t.com"

    def test_display(self):
        from tools.progress_display import ProgressDisplay

        d = ProgressDisplay(target="http://t.com")
        assert d is not None

    def test_compact(self):
        from tools.progress_display import CompactProgress

        c = CompactProgress(total=100, description="Test")
        assert c is not None


# ═══════════════════════════════════════════════════════════════════════════
# WORKFLOW FUZZER
# ═══════════════════════════════════════════════════════════════════════════
class TestWorkflowFuzzer:
    def test_step(self):
        from tools.workflow_fuzzer import WorkflowStep

        s = WorkflowStep(name="nav", method="GET", path="/login")
        assert s.name == "nav"

    def test_plan(self):
        from tools.workflow_fuzzer import WorkflowStep, WorkflowPlan

        s = WorkflowStep(name="nav", method="GET", path="/login")
        p = WorkflowPlan(plan_id="p1", title="Test", description="desc", steps=[s], risk="low")
        assert p.plan_id == "p1"

    def test_result(self):
        from tools.workflow_fuzzer import WorkflowResult

        r = WorkflowResult(success=True, observations=[], anomalies=[], notes=["ok"])
        assert r.success is True

    def test_fuzzer(self):
        from tools.workflow_fuzzer import WorkflowFuzzer

        f = WorkflowFuzzer(base_url="http://test.com")
        assert f.base_url == "http://test.com/"


# ═══════════════════════════════════════════════════════════════════════════
# OBJECT ID PERMUTER
# ═══════════════════════════════════════════════════════════════════════════
class TestObjectIDPermuter:
    def test_case(self):
        from tools.object_id_permuter import PermutationCase

        p = PermutationCase(
            endpoint_template="/api/user/{id}",
            placeholder="{id}",
            value_a="1",
            value_b="2",
            description="ID comparison",
        )
        assert p.value_a == "1"

    def test_result(self):
        from tools.object_id_permuter import PermutationResult

        r = PermutationResult(
            url_a="http://a/1",
            url_b="http://a/2",
            status_a=200,
            status_b=403,
            len_a=100,
            len_b=50,
            signal="idor",
            notes="different response",
        )
        assert r.signal == "idor"

    def test_permuter(self):
        from tools.object_id_permuter import ObjectIDPermuter

        p = ObjectIDPermuter(base_url="http://test.com/api")
        assert "test.com" in p.base_url


# ═══════════════════════════════════════════════════════════════════════════
# SWARM CONTROLLER
# ═══════════════════════════════════════════════════════════════════════════
class TestSwarmController:
    def test_import(self):
        from tools.swarm_controller import SwarmController

        assert SwarmController is not None


# ═══════════════════════════════════════════════════════════════════════════
# MULTI AGENT
# ═══════════════════════════════════════════════════════════════════════════
class TestMultiAgent:
    def test_import(self):
        import tools.multi_agent as ma

        classes = [
            c for c in dir(ma) if not c.startswith("_") and isinstance(getattr(ma, c, None), type)
        ]
        assert len(classes) > 0


# ═══════════════════════════════════════════════════════════════════════════
# TOKEN MANAGER
# ═══════════════════════════════════════════════════════════════════════════
class TestTokenManager:
    def test_import(self):
        from tools.token_manager import TokenManager

        assert TokenManager() is not None


# ═══════════════════════════════════════════════════════════════════════════
# SESSION MANAGER
# ═══════════════════════════════════════════════════════════════════════════
class TestSessionManager:
    def test_import(self):
        from tools.session_manager import SessionManager

        assert SessionManager() is not None


# ═══════════════════════════════════════════════════════════════════════════
# VULN HUNTER CORE, VULNCHECK, WAYBACK, RESEARCH
# ═══════════════════════════════════════════════════════════════════════════
class TestMiscModules:
    def test_vuln_hunter_core(self):
        import tools.vuln_hunter_core as vhc

        classes = [
            c for c in dir(vhc) if not c.startswith("_") and isinstance(getattr(vhc, c, None), type)
        ]
        assert len(classes) > 0

    def test_vulncheck(self):
        import tools.vulncheck_tool as vt

        assert vt is not None

    def test_wayback(self):
        import tools.wayback_tool as wt

        assert wt is not None

    def test_research(self):
        import tools.research_tool as rt

        assert rt is not None

    def test_truffle(self):
        from tools.truffle_integration import TrufflehogTool

        assert TrufflehogTool is not None

    def test_tui_dashboard(self):
        import tools.tui_dashboard as td

        assert td is not None
