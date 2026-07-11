"""tests/test_export_fix.py — Tests for export_to_html XSS escaping and export_to_svg output."""

import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tui.export import export_to_html, export_to_svg


def test_export_to_html_escapes_xss():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "test.html")
        data = {
            "target": "<script>alert('xss')</script>",
            "findings": [
                {
                    "title": "<img src=x onerror=alert(1)>",
                    "severity": "HIGH",
                    "location": "javascript:void(0)",
                    "timestamp": "2025-01-01",
                }
            ],
            "risk_score": 75,
            "total_findings": 1,
            "critical": 0,
            "high": 1,
        }
        result = export_to_html(data, output_path)
        assert result == output_path
        content = open(output_path).read()
        # Raw script tag should be escaped in the target line
        assert "<script>" not in content.split("Target:")[1].split("</div>")[0]
        assert "&lt;script&gt;" in content
        # Finding title should be escaped
        assert "&lt;img" in content


def test_export_to_html_writes_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "report.html")
        data = {"target": "example.com", "findings": []}
        export_to_html(data, output_path)
        assert os.path.exists(output_path)
        content = open(output_path).read()
        assert "ELENGENIX" in content


def test_export_to_svg_returns_svg():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "report.svg")
        data = {
            "target": "example.com",
            "risk_score": 50,
            "findings": [{"title": "Test Finding", "severity": "HIGH", "location": "/api"}],
        }
        result = export_to_svg(data, output_path)
        assert result.endswith(".svg")
        assert os.path.exists(result)


def test_export_to_svg_no_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "empty.svg")
        data = {"target": "example.com", "risk_score": 0, "findings": []}
        result = export_to_svg(data, output_path)
        assert result.endswith(".svg")
        assert os.path.exists(result)
