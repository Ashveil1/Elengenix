"""Tests for elengenix/scanning/intent.py — AI-driven intent classification."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, Mock, patch
from elengenix.scanning.intent import (
    _fast_path_classify,
    _ai_classify,
    analyze_intent,
    _CASUAL_PATTERN,
    _SCAN_PATTERN,
    _RESEARCH_PATTERN,
)


class TestCasualPattern:
    """Tests for _CASUAL_PATTERN regex."""

    @pytest.mark.parametrize("query", [
        "hi",
        "hello",
        "hey",
        "hiya",
        "yo",
        "sup",
        "howdy",
        "greetings",
        "who are you",
        "what are you",
        "what can you do",
        "what's your name",
        "what is your name",
        "help me",
        "help",
        "how are you",
        # Thai greetings from regex (Unicode escapes decoded):
        # สวัสดี = สวัสดี
        # หวัดดี = หวัดดี
        # ว่าไง = ว่าไง
        # ไง = ไง
        # ดี = ดี
        "สวัสดี",
        "หวัดดี",
        "ว่าไง",
        "ไง",
        "ดี",
        "HELLO",
        "Hello",
        "Hey.",
        "Who are you?",
        "What can you do?",
    ])
    def test_casual_pattern_matches(self, query):
        assert _CASUAL_PATTERN.match(query) is not None, f"Failed for: {query}"

    @pytest.mark.parametrize("query", [
        "scan example.com",
        "pentest google.com",
        "today's score",
        "latest news",
        "explain SQL injection",
        "what is XSS",
        "",
        "  help  ",
        "Hi there!",  # contains extra text beyond pattern
        "hi there",   # contains extra text
        # These Thai strings are NOT in the regex pattern
        "ครับ",
        "สบายดีไหม",
        "ขอบคุณ",
        "หวัดดีครับ",
        "หวัดดีค่ะ",
    ])
    def test_casual_pattern_no_match(self, query):
        assert _CASUAL_PATTERN.match(query) is None, f"Unexpectedly matched: {query}"


class TestScanPattern:
    """Tests for _SCAN_PATTERN regex."""

    @pytest.mark.parametrize("query", [
        "scan example.com",
        "pentest google.com",
        "hack test.local",
        "attack 192.168.1.1",
        "recon mysite.org",
        "hunt bugbounty.net",
        "audit api.example.com",
        "fuzz target.io",
        "SCAN EXAMPLE.COM",
        "Scan https://example.com",
        "pentest http://test.local",
    ])
    def test_scan_pattern_matches(self, query):
        assert _SCAN_PATTERN.search(query) is not None, f"Failed for: {query}"

    @pytest.mark.parametrize("query", [
        "scan",
        "pentest",
        "who are you",
        "today's score",
        "explain SQL injection",
        "",
        "scan localhost",  # no TLD
        "scan test",  # no TLD
    ])
    def test_scan_pattern_no_match(self, query):
        assert _SCAN_PATTERN.search(query) is None, f"Unexpectedly matched: {query}"


class TestResearchPattern:
    """Tests for _RESEARCH_PATTERN regex."""

    @pytest.mark.parametrize("query", [
        "today's score",
        "today's news",
        "today's weather",
        "today's price",
        "today's rate",
        "today's match",
        "today's game",
        "latest news",
        "latest update",
        "latest score",
        "latest price",
        "current price",
        "current rate",
        "current weather",
        "current score",
        "stock price",
        "tomorrow's weather",
        # Thai research terms from regex: ราคาวันนี้, ข่าววันนี้, ผลบอล
        "ราคาวันนี้",
        "ข่าววันนี้",
        "ผลบอล",
    ])
    def test_research_pattern_matches(self, query):
        assert _RESEARCH_PATTERN.search(query) is not None, f"Failed for: {query}"

    @pytest.mark.parametrize("query", [
        "what is SQL injection",
        "explain XSS",
        "scan example.com",
        "hi",
        "",
        "yesterday's news",  # not today/tomorrow
    ])
    def test_research_pattern_no_match(self, query):
        assert _RESEARCH_PATTERN.search(query) is None, f"Unexpectedly matched: {query}"


class TestFastPathClassify:
    """Tests for _fast_path_classify function."""

    def test_empty_query_returns_casual(self):
        assert _fast_path_classify("") == "casual"
        assert _fast_path_classify("   ") == "casual"

    def test_casual_queries(self):
        assert _fast_path_classify("hello") == "casual"
        assert _fast_path_classify("who are you") == "casual"
        assert _fast_path_classify("help") == "casual"
        # Thai greetings from the regex
        assert _fast_path_classify("สวัสดี") == "casual"
        assert _fast_path_classify("หวัดดี") == "casual"
        assert _fast_path_classify("ว่าไง") == "casual"
        assert _fast_path_classify("ไง") == "casual"
        assert _fast_path_classify("ดี") == "casual"

    def test_scan_queries(self):
        assert _fast_path_classify("scan example.com") == "scan"
        assert _fast_path_classify("pentest google.com") == "scan"
        assert _fast_path_classify("attack test.local") == "scan"
        assert _fast_path_classify("recon api.site.org") == "scan"

    def test_research_queries(self):
        assert _fast_path_classify("today's score") == "research"
        assert _fast_path_classify("latest news") == "research"
        assert _fast_path_classify("current price") == "research"
        assert _fast_path_classify("stock price") == "research"
        assert _fast_path_classify("tomorrow's weather") == "research"
        # Thai research terms from regex
        assert _fast_path_classify("ราคาวันนี้") == "research"
        assert _fast_path_classify("ข่าววันนี้") == "research"
        assert _fast_path_classify("ผลบอล") == "research"

    def test_short_thai_text_is_casual(self):
        """Short Thai-only text that doesn't match research should be casual."""
        # These are the exact Thai strings in _CASUAL_PATTERN
        assert _fast_path_classify("ไง") == "casual"
        assert _fast_path_classify("ดี") == "casual"
        # 555 is digits, not Thai chars, so doesn't match thai_only regex
        # These are NOT in casual pattern, but are short Thai-only (<=12 chars)
        assert _fast_path_classify("ขอบคุณ") == "casual"
        assert _fast_path_classify("ครับ") == "casual"
        assert _fast_path_classify("ว่าไง") == "casual"
        assert _fast_path_classify("สบายดีไหม") == "casual"

    def test_longer_thai_text_returns_none(self):
        """Thai text longer than 12 chars should return None (needs AI)."""
        long_thai = "นี่คือข้อความภาษาไทยที่ยาวพอสมควร"
        assert _fast_path_classify(long_thai) is None

    def test_ambiguous_queries_return_none(self):
        """Ambiguous queries should return None to trigger AI classification."""
        assert _fast_path_classify("what is SQL injection") is None
        assert _fast_path_classify("explain XSS to me") is None
        assert _fast_path_classify("how does authentication work") is None
        assert _fast_path_classify("tell me about vulnerabilities") is None
        assert _fast_path_classify("security advice") is None


class TestAiClassify:
    """Tests for _ai_classify function."""

    def test_returns_casual_on_none_response(self):
        """If AI returns None, default to security_chat."""
        client = Mock()
        client.chat.return_value.content = None
        result = _ai_classify(client, "ambiguous query")
        assert result == "security_chat"

    def test_returns_matching_intent_from_response(self):
        """Should extract valid intent from AI response."""
        client = Mock()
        client.chat.return_value.content = "scan"
        result = _ai_classify(client, "scan example.com")
        assert result == "scan"

        client.chat.return_value.content = "research"
        result = _ai_classify(client, "today's news")
        assert result == "research"

        client.chat.return_value.content = "casual"
        result = _ai_classify(client, "hi")
        assert result == "casual"

        client.chat.return_value.content = "security_chat"
        result = _ai_classify(client, "what is xss")
        assert result == "security_chat"

    def test_case_insensitive_intent_matching(self):
        """Should match intent case-insensitively."""
        client = Mock()
        client.chat.return_value.content = "SCAN"
        result = _ai_classify(client, "query")
        assert result == "scan"

        client.chat.return_value.content = "Security_Chat"
        result = _ai_classify(client, "query")
        assert result == "security_chat"

    def test_intent_embedded_in_text(self):
        """Should find intent word embedded in response text."""
        client = Mock()
        client.chat.return_value.content = "The intent is clearly scan because..."
        result = _ai_classify(client, "query")
        assert result == "scan"

        client.chat.return_value.content = "I think this is security_chat"
        result = _ai_classify(client, "query")
        assert result == "security_chat"

    def test_returns_security_chat_on_exception(self):
        """On any exception, default to security_chat."""
        client = Mock()
        client.chat.side_effect = Exception("API error")
        result = _ai_classify(client, "query")
        assert result == "security_chat"

    def test_calls_ai_with_correct_messages(self):
        """Should call AI client with system prompt and user query."""
        client = Mock()
        client.chat.return_value.content = "scan"
        _ai_classify(client, "scan test.com")
        client.chat.assert_called_once()
        call_args = client.chat.call_args[0][0]
        assert len(call_args) == 2
        assert call_args[0].role == "system"
        assert call_args[1].role == "user"
        assert call_args[1].content == "scan test.com"


class TestAnalyzeIntent:
    """Tests for analyze_intent public function."""

    def test_fast_path_casual(self):
        """Casual queries should use fast path."""
        client = Mock()
        result = analyze_intent(client, "hello")
        assert result == "casual"
        client.chat.assert_not_called()

    def test_fast_path_scan(self):
        """Scan queries should use fast path."""
        client = Mock()
        result = analyze_intent(client, "scan example.com")
        assert result == "scan"
        client.chat.assert_not_called()

    def test_fast_path_research(self):
        """Research queries should use fast path."""
        client = Mock()
        result = analyze_intent(client, "today's score")
        assert result == "research"
        client.chat.assert_not_called()

    def test_ai_path_for_ambiguous(self):
        """Ambiguous queries should use AI classification."""
        client = Mock()
        client.chat.return_value.content = "security_chat"
        result = analyze_intent(client, "what is SQL injection")
        assert result == "security_chat"
        client.chat.assert_called_once()

    def test_ai_path_for_security_questions(self):
        """Security knowledge questions should use AI."""
        client = Mock()
        client.chat.return_value.content = "security_chat"
        result = analyze_intent(client, "explain how XSS works")
        assert result == "security_chat"
        client.chat.assert_called_once()

    def test_logs_debug_on_fast_path(self, caplog):
        """Should log debug message on fast path."""
        client = Mock()
        with caplog.at_level("DEBUG"):
            analyze_intent(client, "scan example.com")
        assert "Intent fast-path" in caplog.text
        assert "scan" in caplog.text


class TestThaiTextHandling:
    """Tests for Thai text handling."""

    def test_short_thai_is_casual(self):
        """Short Thai-only text should be classified as casual."""
        # These are exact strings from _CASUAL_PATTERN
        assert _fast_path_classify("ไง") == "casual"
        assert _fast_path_classify("ดี") == "casual"
        # These are short Thai-only strings (<=12 chars) not in casual pattern
        assert _fast_path_classify("ขอบคุณ") == "casual"
        assert _fast_path_classify("ครับ") == "casual"
        assert _fast_path_classify("ว่าไง") == "casual"
        assert _fast_path_classify("สบายดีไหม") == "casual"

    def test_long_thai_requires_ai(self):
        """Longer Thai text should require AI classification."""
        long_thai = "ผมต้องการขอคำแนะนำเกี่ยวกับความปลอดภัยของเว็บไซต์"
        assert _fast_path_classify(long_thai) is None

    def test_mixed_thai_english_requires_ai(self):
        """Mixed Thai/English with scan command matches scan pattern first (by design)."""
        # The scan pattern matches "scan example.com" regardless of Thai text after
        assert _fast_path_classify("scan example.com กรุณา") == "scan"
        # But mixed text without scan/research/casual patterns needs AI
        assert _fast_path_classify("what is this กรุณา") is None
        assert _fast_path_classify("explain XSS กรุณา") is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])