"""Tests for tools/safe_exec.py retry/backoff wrapper.

The AI agent runs real network commands. Transient failures (timeouts,
connection resets, DNS blips) used to fail the whole mission. The new
``execute_with_retry`` wrapper retries transient failures with exponential
backoff and returns deterministic failures immediately.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tools.safe_exec import (
    _is_retryable,
    execute_safely,
    execute_with_retry,
)


def _ok(stdout: str = "ok") -> dict:
    return {"success": True, "stdout": stdout, "stderr": "", "exit_code": 0, "error": ""}


def _fail(err: str, stderr: str = "") -> dict:
    return {"success": False, "stdout": "", "stderr": stderr, "exit_code": 1, "error": err}


# ===================================================================
# _is_retryable
# ===================================================================


class TestIsRetryable:
    def test_success_is_not_retryable(self):
        assert _is_retryable(_ok()) is False

    def test_timeout_is_retryable(self):
        assert _is_retryable(_fail("Command timed out after 300s.")) is True

    def test_connection_reset_is_retryable(self):
        assert _is_retryable(_fail("connection reset by peer")) is True

    def test_dns_failure_is_retryable(self):
        assert _is_retryable(_fail("could not resolve host")) is True

    def test_command_not_found_is_NOT_retryable(self):
        # Deterministic failure — retrying wastes budget
        assert _is_retryable(_fail("command not found")) is False

    def test_permission_denied_is_NOT_retryable(self):
        assert _is_retryable(_fail("permission denied")) is False

    def test_empty_error_with_failure_is_retryable(self):
        # Conservative: unknown failure → retry once
        assert _is_retryable(_fail("")) is True


# ===================================================================
# execute_with_retry
# ===================================================================


class TestExecuteWithRetry:
    def test_success_first_try_no_retry(self):
        with patch("tools.safe_exec.execute_safely", return_value=_ok()) as mock_exec:
            result = execute_with_retry("echo hi", max_retries=2)
        assert mock_exec.call_count == 1
        assert result["success"] is True
        assert result["attempts"] == 1

    def test_retries_on_transient_failure(self):
        with patch("tools.safe_exec.execute_safely",
                   side_effect=[_fail("timed out"), _ok()]) as mock_exec:
            with patch("time.sleep"):  # don't actually sleep
                result = execute_with_retry("curl http://x", max_retries=2, backoff_base=0.01)
        assert mock_exec.call_count == 2
        assert result["success"] is True
        assert result["attempts"] == 2

    def test_no_retry_on_deterministic_failure(self):
        with patch("tools.safe_exec.execute_safely",
                   return_value=_fail("command not found")) as mock_exec:
            result = execute_with_retry("nonexistent_cmd", max_retries=2)
        assert mock_exec.call_count == 1
        assert result["success"] is False
        assert result["attempts"] == 1

    def test_gives_up_after_max_retries(self):
        with patch("tools.safe_exec.execute_safely",
                   return_value=_fail("connection reset")) as mock_exec:
            with patch("time.sleep"):
                result = execute_with_retry("curl http://x", max_retries=2, backoff_base=0.01)
        assert mock_exec.call_count == 3  # 1 initial + 2 retries
        assert result["success"] is False
        assert result["attempts"] == 3

    def test_exponential_backoff_called(self):
        sleep_delays = []
        def fake_sleep(d):
            sleep_delays.append(d)

        with patch("tools.safe_exec.execute_safely",
                   side_effect=[_fail("timeout"), _fail("timeout"), _ok()]):
            with patch("time.sleep", side_effect=fake_sleep):
                result = execute_with_retry("curl http://x", max_retries=2, backoff_base=0.5)

        # Backoff: 0.5 * 2^0 = 0.5, 0.5 * 2^1 = 1.0
        assert sleep_delays == [0.5, 1.0]
        assert result["success"] is True

    def test_zero_retries_works(self):
        with patch("tools.safe_exec.execute_safely", return_value=_ok()) as mock_exec:
            result = execute_with_retry("echo hi", max_retries=0)
        assert mock_exec.call_count == 1
        assert result["attempts"] == 1

    def test_returns_attempts_field(self):
        with patch("tools.safe_exec.execute_safely", return_value=_ok()):
            result = execute_with_retry("echo hi", max_retries=2)
        assert "attempts" in result

    def test_preserves_underlying_result_shape(self):
        with patch("tools.safe_exec.execute_safely", return_value=_ok("hello")):
            result = execute_with_retry("echo hi", max_retries=2)
        assert result["stdout"] == "hello"
        assert result["exit_code"] == 0

    def test_real_shell_pipe_works(self):
        """Tool composition (nmap | grep) must work via shell=True."""
        result = execute_with_retry("echo hello world | grep hello", max_retries=0)
        assert result["success"] is True
        assert "hello" in result["stdout"]
