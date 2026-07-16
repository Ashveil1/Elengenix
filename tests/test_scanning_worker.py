"""Tests for elengenix/scanning/worker.py — Worker base class."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from elengenix.scanning.worker import WorkerResult, BaseWorker


class TestWorkerResult:
    """Tests for WorkerResult dataclass."""

    def test_default_values(self):
        """Test default field values."""
        result = WorkerResult(success=True, worker_name="test")
        assert result.success is True
        assert result.worker_name == "test"
        assert result.output == ""
        assert result.findings == []
        assert result.error == ""
        assert result.metadata == {}
        assert result.duration_seconds == 0.0

    def test_with_all_fields(self):
        """Test with all fields provided."""
        result = WorkerResult(
            success=False,
            worker_name="scanner",
            output="scan output",
            findings=[{"vuln": "xss"}],
            error="timeout",
            metadata={"tool": "nmap"},
            duration_seconds=5.5,
        )
        assert result.success is False
        assert result.worker_name == "scanner"
        assert result.output == "scan output"
        assert result.findings == [{"vuln": "xss"}]
        assert result.error == "timeout"
        assert result.metadata == {"tool": "nmap"}
        assert result.duration_seconds == 5.5

    def test_to_dict_truncates_output(self):
        """to_dict should truncate long output."""
        long_output = "x" * 5000
        result = WorkerResult(success=True, worker_name="test", output=long_output)
        d = result.to_dict()
        assert len(d["output"]) == 3000

    def test_to_dict_truncates_findings(self):
        """to_dict should truncate findings list."""
        many_findings = [{"id": i} for i in range(50)]
        result = WorkerResult(success=True, worker_name="test", findings=many_findings)
        d = result.to_dict()
        assert len(d["findings"]) == 20

    def test_to_dict_rounds_duration(self):
        """Duration should be rounded to 2 decimal places."""
        result = WorkerResult(success=True, worker_name="test", duration_seconds=3.14159)
        d = result.to_dict()
        assert d["duration_s"] == 3.14


class ConcreteWorker(BaseWorker):
    """Concrete implementation for testing."""

    def run(self, target: str, params: dict = None) -> WorkerResult:
        return WorkerResult(
            success=True,
            worker_name=self.name,
            output=f"scanned {target}",
            findings=[{"target": target}],
        )


class TestBaseWorker:
    """Tests for BaseWorker abstract class."""

    def test_init_sets_attributes(self):
        """Init should set name, description, timeout."""
        worker = ConcreteWorker(name="TestWorker", description="A test worker", timeout_seconds=60)
        assert worker.name == "TestWorker"
        assert worker.description == "A test worker"
        assert worker.timeout_seconds == 60
        assert worker.logger is not None

    def test_init_defaults(self):
        """Init with default values."""
        worker = ConcreteWorker(name="DefaultWorker")
        assert worker.description == ""
        assert worker.timeout_seconds == 300

    def test_run_abstract(self):
        """Subclass must implement run()."""
        worker = ConcreteWorker(name="Test")
        result = worker.run("example.com")
        assert isinstance(result, WorkerResult)
        assert result.success is True
        assert "example.com" in result.output

    def test_timed_run_success(self):
        """_timed_run should measure duration on success."""
        worker = ConcreteWorker(name="TimedWorker")
        result = worker._timed_run("example.com")
        assert result.success is True
        assert result.duration_seconds > 0
        assert result.duration_seconds < 1.0  # should be fast

    def test_timed_run_exception(self):
        """_timed_run should catch exceptions and return error result."""

        class FailingWorker(BaseWorker):
            def run(self, target: str, params: dict = None) -> WorkerResult:
                raise ValueError("boom")

        worker = FailingWorker(name="FailWorker")
        result = worker._timed_run("example.com")
        assert result.success is False
        assert result.error == "boom"
        assert result.duration_seconds > 0

    def test_execute_logs_and_returns_result(self, caplog):
        """execute() should log start and completion."""
        worker = ConcreteWorker(name="ExecuteWorker")
        with caplog.at_level("INFO"):
            result = worker.execute("example.com")
        assert "Starting on example.com" in caplog.text
        assert "[OK]" in caplog.text or "[FAIL]" in caplog.text
        assert result.success is True

    def test_execute_passes_params(self):
        """execute() should pass params to _timed_run."""

        class ParamWorker(BaseWorker):
            def run(self, target: str, params: dict = None) -> WorkerResult:
                return WorkerResult(
                    success=True,
                    worker_name=self.name,
                    output=f"target={target}, params={params}",
                )

        worker = ParamWorker(name="ParamWorker")
        result = worker.execute("example.com", {"depth": "deep"})
        assert "depth" in result.output
        assert "deep" in result.output

    def test_repr(self):
        """__repr__ should show worker name."""
        worker = ConcreteWorker(name="ReprWorker")
        assert repr(worker) == "<Worker:ReprWorker>"


class TestWorkerResultEdgeCases:
    """Edge case tests for WorkerResult."""

    def test_to_dict_empty_metadata(self):
        """to_dict with empty metadata."""
        result = WorkerResult(success=True, worker_name="test", metadata={})
        d = result.to_dict()
        assert d["metadata"] == {}

    def test_to_dict_none_duration(self):
        """to_dict with 0 duration."""
        result = WorkerResult(success=True, worker_name="test", duration_seconds=0)
        d = result.to_dict()
        assert d["duration_s"] == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])