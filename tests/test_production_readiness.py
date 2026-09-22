"""Production-readiness regressions from the offline / no-API-key audit.

Every test here corresponds to a real failure found by running the CLI the
way a brand-new `pip install` user would (no keys, no wizard state):

- welcome wizard re-nagging users whose config.yaml was written by
  ``configure`` (ai section only, no wizard section),
- doctor reporting "config.yaml not found" while the AI stack found it fine,
- print primitives crashing on dynamic text containing bracket sequences,
- engine-method mismatches that made sast/cloud/mobile/soc fail silently,
- target-bearing commands hijacked by auto-detect instead of their handlers.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestWizardGating:
    def test_ai_only_config_counts_as_configured(self, tmp_path, monkeypatch):
        """ai.active_provider without a wizard section must NOT re-trigger
        the first-run wizard on every invocation."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "ai:\n  active_provider: openai\n  providers:\n    openai:\n      model: gpt-4o\n"
        )
        monkeypatch.setenv("ELENGENIX_CONFIG", str(cfg))
        from tools.welcome_wizard import WelcomeWizard

        saved = WelcomeWizard.get_saved_config()
        assert saved is not None
        assert saved.ai_provider == "openai"
        assert saved.first_run_complete is True

    def test_empty_config_is_still_first_run(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("# nothing yet\n")
        monkeypatch.setenv("ELENGENIX_CONFIG", str(cfg))
        monkeypatch.setattr("elengenix.paths.ELENGENIX_HOME", tmp_path / "home")
        monkeypatch.chdir(tmp_path)
        from tools.welcome_wizard import WelcomeWizard

        assert WelcomeWizard.get_saved_config() is None


class TestDoctorConfigResolution:
    def test_honors_elengenix_config_env(self, tmp_path, monkeypatch):
        """doctor must resolve config via elengenix.paths.find_config(), the
        same order the AI stack uses ($ELENGENIX_CONFIG -> home -> cwd)."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "ai:\n  active_provider: openai\n  providers:\n    openai:\n      model: gpt-4o\n"
        )
        monkeypatch.setenv("ELENGENIX_CONFIG", str(cfg))
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        from tools.doctor import _check_config

        ok, msg = _check_config()
        # Key is absent in this test env: doctor must still FIND the config
        # and complain about the key, never about "config.yaml not found".
        assert "not found" not in msg.lower()
        assert "openai" in msg
        assert ok == ("API key" not in msg)

    def test_missing_config_reports_configure_hint(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ELENGENIX_CONFIG", str(tmp_path / "nope.yaml"))
        monkeypatch.setattr("elengenix.paths.ELENGENIX_HOME", tmp_path / "home")
        monkeypatch.chdir(tmp_path)
        from tools.doctor import _check_config

        ok, msg = _check_config()
        assert ok is False
        assert "configure" in msg


class TestPrintPrimitivesMarkupSafety:
    """Dynamic text with bracket sequences must never raise MarkupError."""

    @pytest.mark.parametrize("fn_name", ["print_info", "print_error", "print_success", "print_warning"])
    def test_bracket_text_does_not_crash(self, fn_name):
        from cli import ui_components

        fn = getattr(ui_components, fn_name)
        # Would previously raise MarkupError for [multimodal] / [Errno ...]
        fn("finding [multimodal] cmd_injection at [Errno 2] /etc/passwd")

    def test_strip_markup_helper(self):
        from cli.ui_components import _strip_markup

        assert _strip_markup("[bold]x[/bold] [multimodal] y") == "x  y"


class TestEngineMethodContract:
    """Handlers must call methods that exist — a mismatch previously made
    sast/cloud/mobile/soc fail silently (or with a confusing error)."""

    def test_sast_engine_scan_repository(self, tmp_path):
        from tools.sast_engine import SASTEngine

        f = tmp_path / "vuln.py"
        f.write_text("import os\nos.system(input())\n")
        report = SASTEngine().scan_repository(tmp_path)
        assert isinstance(report.get("critical_vulnerabilities"), list)

    def test_cloud_scanner_scan_directory(self, tmp_path):
        from tools.cloud_scanner import CloudScanner

        (tmp_path / "bad.tf").write_text(
            'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}\n'
        )
        report = CloudScanner().scan_directory(tmp_path)
        assert "error" not in report
        assert isinstance(report.get("critical_findings"), list)

    def test_mobile_tester_run_full_analysis(self):
        from tools.mobile_api_tester import MobileAPITester

        report = MobileAPITester().run_full_analysis()
        assert isinstance(report.get("critical_findings"), list)
        assert "total_findings" in report

    def test_soc_analyzer_analyze_log_file(self, tmp_path):
        from tools.soc_analyzer import SOCAnalyzer

        log = tmp_path / "auth.log"
        log.write_text("Jan 12 03:14:22 web01 sshd[2411]: Failed password for admin from 203.0.113.66 port 51234 ssh2\n")
        report = SOCAnalyzer().analyze_log_file(log)
        assert "error" not in report
        assert "total_alerts" in report


class TestExplicitCommandsRouting:
    def test_target_commands_are_never_hijacked_by_autodetect(self):
        """Every target-bearing command with a dedicated handler must be in
        main.py's explicit_commands set, else auto-detect steals it."""
        tree = ast.parse((REPO_ROOT / "main.py").read_text())
        found = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "explicit_commands" for t in node.targets
            ):
                found = {
                    e.value for e in node.value.elts if isinstance(e, ast.Constant)
                }
        assert found is not None, "explicit_commands set not found in main.py"
        for cmd in (
            "scan", "hack", "tui", "hunt", "recon", "sast", "cloud", "mobile",
            "soc", "bola", "waf", "report", "pdf", "pd", "scan-report",
            "research", "poc", "autonomous", "vuln-hunt", "compliance",
            "dashboard", "bounty",
        ):
            assert cmd in found, f"{cmd} missing from explicit_commands → auto-detect hijack"
