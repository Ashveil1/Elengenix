"""Tests for elengenix/scanning/helpers.py — utility functions."""
from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock

from elengenix.scanning.helpers import (
    _get_now_context,
    _thai_month_name,
    _get_memory_profile_context,
    _strip_code_fences,
    _scan_balanced,
    _repair_json,
    extract_json,
    _extract_json_object,
    _extract_target_from_text,
    _safe_operation,
)


# ===================================================================
# _get_now_context
# ===================================================================


class TestGetNowContext:
    def test_returns_string(self):
        ctx = _get_now_context()
        assert isinstance(ctx, str)
        assert len(ctx) > 0

    def test_contains_time_indicators(self):
        ctx = _get_now_context()
        assert "20" in ctx  # year


# ===================================================================
# _thai_month_name
# ===================================================================


class TestThaiMonthName:
    def test_january(self):
        assert "มกราคม" in _thai_month_name(1)

    def test_december(self):
        assert "ธันวาคม" in _thai_month_name(12)

    def test_invalid_month(self):
        assert _thai_month_name(13) == "13"

    def test_zero_month(self):
        assert _thai_month_name(0) == "0"

    def test_negative_month(self):
        assert _thai_month_name(-1) == "-1"


# ===================================================================
# _get_memory_profile_context
# ===================================================================


class TestGetMemoryProfileContext:
    @patch("elengenix.scanning.helpers.read_memory")
    def test_with_profile(self, mock_read):
        mock_read.return_value = {"user_name": "Alice", "role": "tester"}
        result = _get_memory_profile_context()
        assert "USER PROFILE" in result
        assert "Alice" in result
        assert "tester" in result

    @patch("elengenix.scanning.helpers.read_memory")
    def test_empty_profile(self, mock_read):
        mock_read.return_value = {}
        result = _get_memory_profile_context()
        assert result == ""

    @patch("elengenix.scanning.helpers.read_memory")
    def test_no_profile(self, mock_read):
        mock_read.return_value = None
        result = _get_memory_profile_context()
        assert result == ""

    @patch("elengenix.scanning.helpers.read_memory")
    def test_profile_with_none(self, mock_read):
        mock_read.return_value = None
        result = _get_memory_profile_context()
        assert result == ""


# ===================================================================
# _strip_code_fences
# ===================================================================


class TestStripCodeFences:
    def test_json_fence(self):
        text = "```json\n{\"key\": \"value\"}\n```"
        result = _strip_code_fences(text)
        assert result == '{"key": "value"}'

    def test_plain_fence(self):
        text = "```\nhello world\n```"
        result = _strip_code_fences(text)
        assert result == "hello world"

    def test_no_fence(self):
        text = "plain text"
        result = _strip_code_fences(text)
        assert result == "plain text"

    def test_empty_string(self):
        assert _strip_code_fences("") == ""

    def test_multiple_fences(self):
        text = "```json\n{\"a\": 1}\n```\ntext\n```json\n{\"b\": 2}\n```"
        result = _strip_code_fences(text)
        assert result == '{"a": 1}'  # only first

    def test_json_uppercase(self):
        text = "```JSON\n{\"x\": 1}\n```"
        result = _strip_code_fences(text)
        assert result == '{"x": 1}'


# ===================================================================
# _scan_balanced
# ===================================================================


class TestScanBalanced:
    def test_simple_brace(self):
        result = _scan_balanced("{hello}", "{", "}")
        assert result == "{hello}"

    def test_nested_braces(self):
        result = _scan_balanced("{outer{inner}}", "{", "}")
        assert result == "{outer{inner}}"

    def test_no_balanced(self):
        result = _scan_balanced("abc", "{", "}")
        assert result is None

    def test_string_aware(self):
        # Braces inside strings should not affect nesting
        text = '{"key": "value with { inside}"}'
        result = _scan_balanced(text, "{", "}")
        assert result is not None
        assert "key" in result

    def test_unclosed(self):
        result = _scan_balanced("{unclosed", "{", "}")
        assert result is None

    def test_extra_close(self):
        result = _scan_balanced("}{", "{", "}")
        assert result is None or "}" not in result


# ===================================================================
# _repair_json
# ===================================================================


class TestRepairJson:
    def test_already_valid(self):
        result = _repair_json('{"a": 1}')
        assert json.loads(result)

    def test_smart_quotes(self):
        result = _repair_json('{"a": \u201cvalue\u201d}')
        assert '"value"' in result

    def test_trailing_comma(self):
        result = _repair_json('{"a": 1,}')
        assert json.loads(result) == {"a": 1}

    def test_single_quotes_not_handled(self):
        # _repair_json doesn't handle single-quote -> double-quote conversion
        result = _repair_json("{'a': 1}")
        assert "'" in result  # left as-is

    def test_empty(self):
        result = _repair_json("")
        assert isinstance(result, str)

    def test_nested_trailing_comma(self):
        result = _repair_json('{"a": {"b": 2,}}')
        assert json.loads(result) == {"a": {"b": 2}}


# ===================================================================
# _try_loads
# ===================================================================



# ===================================================================
# extract_json
# ===================================================================


class TestExtractJson:
    def test_direct_object(self):
        result = extract_json('{"a": 1}')
        assert result == {"a": 1}

    def test_in_json_fence(self):
        result = extract_json("```json\n{\"a\": 1}\n```")
        assert result == {"a": 1}

    def test_in_plain_fence(self):
        result = extract_json("```\n{\"a\": 1}\n```")
        assert result == {"a": 1}

    def test_with_surrounding_text(self):
        result = extract_json("Here is the result: {\"a\": 1} done.")
        assert result == {"a": 1}

    def test_nested_extraction(self):
        result = extract_json("Thought: {\"a\": {\"b\": [1, 2]}}")
        assert result == {"a": {"b": [1, 2]}}

    def test_expect_array(self):
        result = extract_json('[1, 2, 3]', expect='array')
        assert result == [1, 2, 3]

    def test_expect_array_in_fence(self):
        result = extract_json("```json\n[1, 2, 3]\n```", expect='array')
        assert result == [1, 2, 3]

    def test_repaired_smart_quotes(self):
        result = extract_json('{"a": \u201cval\u201d}')
        assert result == {"a": "val"}

    def test_repaired_trailing_comma(self):
        result = extract_json('{"a": 1,}')
        assert result == {"a": 1}

    def test_invalid_returns_none(self):
        result = extract_json("not json at all")
        assert result is None

    def test_empty_string(self):
        assert extract_json("") is None

    def test_with_repair_client(self):
        client = MagicMock()
        chat_resp = MagicMock()
        chat_resp.content = '{"a": 2}'
        client.chat.return_value = chat_resp
        result = extract_json("garbage", repair_client=client)
        assert result == {"a": 2}
        client.chat.assert_called_once()

    def test_repair_client_fails(self):
        client = MagicMock()
        client.chat.side_effect = Exception("broken")
        result = extract_json("garbage", repair_client=client)
        assert result is None

    def test_expect_array_but_object_returns_none(self):
        result = extract_json('{"a": 1}', expect='array')
        # Should try to find an array, fall back to None
        assert result is None or result == {"a": 1}


# ===================================================================
# _extract_json_object
# ===================================================================


class TestExtractJsonObject:
    def test_simple_object(self):
        result = _extract_json_object('{"a": 1}')
        assert result == {"a": 1}

    def test_in_text(self):
        result = _extract_json_object("found: {\"a\": 1} end")
        assert result == {"a": 1}

    def test_no_object(self):
        assert _extract_json_object("no json here") is None

    def test_empty(self):
        assert _extract_json_object("") is None


# ===================================================================
# _extract_target_from_text
# ===================================================================


class TestExtractTargetFromText:
    def test_picks_last_nonstop_word(self):
        result = _extract_target_from_text("scan example.com")
        assert result == "example.com"

    def test_appends_dot_com(self):
        result = _extract_target_from_text("scan example")
        assert result == "example.com"

    def test_empty_text(self):
        result = _extract_target_from_text("")
        assert result == ""

    def test_all_stop_words(self):
        result = _extract_target_from_text("scan for bug")
        assert result == ""

    def test_short_word_not_appended(self):
        result = _extract_target_from_text("scan ab")
        assert result == "ab"  # len(t) < 3, no .com appended

    def test_normal_case(self):
        result = _extract_target_from_text("I want to scan example.com")
        assert "example.com" in result


# ===================================================================
# _safe_operation
# ===================================================================


class TestSafeOperation:
    def test_success(self):
        result = _safe_operation("test_op", lambda: 42)
        assert result == 42

    def test_exception_without_default(self):
        def failing():
            raise ValueError("oops")
        result = _safe_operation("fail_op", failing)
        assert result is None

    def test_exception_with_default(self):
        def failing():
            raise ValueError("oops")
        result = _safe_operation("fail_op", failing, default=-1)
        assert result == -1

    def test_none_function(self):
        result = _safe_operation("none_op", None)
        assert result is None

    def test_with_args(self):
        result = _safe_operation("add", lambda x, y: x + y, 1, 2)
        assert result == 3

    def test_with_kwargs(self):
        result = _safe_operation("add_kw", lambda a, b=0: a + b, 1, b=5)
        assert result == 6
