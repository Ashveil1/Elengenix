"""tests/test_agent_council.py — Unit tests for TeamAegis v2 AgentCouncil."""

import json
from unittest.mock import MagicMock


from agents.agent_council import AgentCouncil, CouncilMessage, MessageType, SharedInbox
from agents.critic_agent import CriticAgent
from agents.specialist_agent import _heuristic_findings
from agents.strategist_agent import StrategistAgent, _extract_json
from agents.worker_base import BaseWorker, WorkerResult

# ── Fixtures ──────────────────────────────────────────────────────────────────


class _FakeResponse:
    """Mimics AIClientManager.chat() response."""

    def __init__(self, content: str):
        self.content = content


class _FakeClient:
    """Minimal fake AI client."""

    def __init__(self, response: str = ""):
        self._response = response

    def chat(self, messages, **kwargs):
        return _FakeResponse(self._response)


# ── WorkerResult ───────────────────────────────────────────────────────────────


class TestWorkerResult:
    def test_to_dict_fields(self):
        wr = WorkerResult(
            success=True,
            worker_name="TestWorker",
            output="hello",
            findings=[{"type": "test", "severity": "info"}],
            error="",
            duration_seconds=1.23,
        )
        d = wr.to_dict()
        assert d["success"] is True
        assert d["worker"] == "TestWorker"
        assert d["duration_s"] == 1.23
        assert len(d["findings"]) == 1

    def test_output_truncated(self):
        long_output = "x" * 5000
        wr = WorkerResult(success=True, worker_name="w", output=long_output)
        d = wr.to_dict()
        assert len(d["output"]) <= 3000


# ── BaseWorker ─────────────────────────────────────────────────────────────────


class ConcreteWorker(BaseWorker):
    """Minimal concrete worker for testing."""

    def run(self, target, params=None):
        return WorkerResult(success=True, worker_name=self.name, output=f"done:{target}")


class FailingWorker(BaseWorker):
    """Worker that raises an exception."""

    def run(self, target, params=None):
        raise RuntimeError("worker kaboom")


class TestBaseWorker:
    def test_execute_success(self):
        w = ConcreteWorker("TestWorker")
        result = w.execute("example.com")
        assert result.success
        assert "example.com" in result.output
        assert result.duration_seconds >= 0

    def test_execute_exception_caught(self):
        w = FailingWorker("FailWorker")
        result = w.execute("example.com")
        assert not result.success
        assert "kaboom" in result.error

    def test_repr(self):
        w = ConcreteWorker("MyWorker")
        assert "MyWorker" in repr(w)


# ── SharedInbox ────────────────────────────────────────────────────────────────


class TestSharedInbox:
    def test_post_and_get(self):
        inbox = SharedInbox()
        msg = CouncilMessage(
            msg_type=MessageType.STATUS,
            sender="test",
            recipient="council",
            payload={"data": "hello"},
        )
        inbox.post(msg)
        received = inbox.get(timeout=0.1)
        assert received is not None
        assert received.sender == "test"

    def test_get_empty_returns_none(self):
        inbox = SharedInbox()
        assert inbox.get(timeout=0.05) is None

    def test_drain_multiple(self):
        inbox = SharedInbox()
        for i in range(5):
            inbox.post(
                CouncilMessage(
                    msg_type=MessageType.STATUS,
                    sender="test",
                    recipient="all",
                    payload={"i": i},
                )
            )
        msgs = inbox.drain(limit=3)
        assert len(msgs) == 3

    def test_history(self):
        inbox = SharedInbox()
        msg = CouncilMessage(
            msg_type=MessageType.PLAN,
            sender="strategist",
            recipient="council",
            payload={},
        )
        inbox.post(msg)
        _ = inbox.get(timeout=0.1)  # consume from queue
        history = inbox.history(last_n=5)
        assert len(history) >= 1

    def test_pending_count(self):
        inbox = SharedInbox()
        assert inbox.pending_count == 0
        inbox.post(CouncilMessage(msg_type=MessageType.STATUS, sender="a", recipient="b"))
        assert inbox.pending_count == 1


# ── CouncilMessage ─────────────────────────────────────────────────────────────


class TestCouncilMessage:
    def test_auto_msg_id(self):
        msg = CouncilMessage(
            msg_type=MessageType.PLAN,
            sender="strategist",
            recipient="council",
        )
        assert msg.msg_id  # non-empty

    def test_to_dict(self):
        msg = CouncilMessage(
            msg_type=MessageType.RESULT,
            sender="specialist",
            recipient="council",
            payload={"output": "hello"},
        )
        d = msg.to_dict()
        assert d["type"] == "result"
        assert d["from"] == "specialist"
        assert d["payload"]["output"] == "hello"


# ── _extract_json (Strategist) ─────────────────────────────────────────────────


class TestExtractJson:
    def test_plain_json_list(self):
        text = '[{"description": "task1", "phase": "recon"}]'
        result = _extract_json(text)
        assert isinstance(result, list)
        assert result[0]["description"] == "task1"

    def test_markdown_fenced(self):
        text = '```json\n[{"description": "task2"}]\n```'
        result = _extract_json(text)
        assert isinstance(result, list)

    def test_invalid_returns_empty(self):
        result = _extract_json("not json at all")
        assert result == []


# ── _heuristic_findings (Specialist) ──────────────────────────────────────────


class TestHeuristicFindings:
    def test_secret_detected(self):
        output = "Found API_KEY=abc123xyz in response"
        findings = _heuristic_findings(output, "curl example.com")
        assert any(f["type"] == "potential_secret" for f in findings)

    def test_url_extraction(self):
        output = "Redirecting to https://example.com/admin\nhttps://example.com/api"
        findings = _heuristic_findings(output, "curl example.com")
        assert any(f["type"] == "urls_extracted" for f in findings)

    def test_sql_error_detected(self):
        output = "You have an error in your SQL syntax near 'id=1'"
        findings = _heuristic_findings(output, "sqlmap example.com")
        assert any(f["type"] == "sql_error_detected" for f in findings)

    def test_no_findings_clean_output(self):
        output = "200 OK\nContent-Type: text/html\n<html>Hello World</html>"
        findings = _heuristic_findings(output, "curl example.com")
        # May be empty or have only URL finding
        for f in findings:
            assert f.get("type") in ("urls_extracted", "extracted_url")


# ── StrategistAgent ─────────────────────────────────────────────────────────────


class TestStrategistAgent:
    def test_plan_returns_list(self):
        plan_json = '[{"description": "Run subfinder", "phase": "recon", "risk": "low"}]'
        client = _FakeClient(plan_json)
        agent = StrategistAgent(client=client, enable_workers=False)
        inbox = SharedInbox()
        tasks = agent.plan("test objective", "example.com", inbox)
        assert isinstance(tasks, list)
        assert len(tasks) >= 1

    def test_plan_posts_to_inbox(self):
        plan_json = '[{"description": "Run subfinder", "phase": "recon", "risk": "low"}]'
        client = _FakeClient(plan_json)
        agent = StrategistAgent(client=client, enable_workers=False)
        inbox = SharedInbox()
        agent.plan("test", "example.com", inbox)
        assert inbox.pending_count >= 1

    def test_vote_approve(self):
        client = _FakeClient("approve")
        agent = StrategistAgent(client=client, enable_workers=False)
        result = agent.vote({"description": "Run nmap", "risk": "medium"}, [], "example.com")
        assert result == "approve"

    def test_vote_deny(self):
        client = _FakeClient("deny this action")
        agent = StrategistAgent(client=client, enable_workers=False)
        result = agent.vote({"description": "Run sqlmap", "risk": "critical"}, [], "example.com")
        assert result == "deny"

    def test_vote_fails_gracefully(self):
        client = MagicMock()
        client.chat.side_effect = RuntimeError("API down")
        agent = StrategistAgent(client=client, enable_workers=False)
        result = agent.vote({"description": "x", "risk": "high"}, [], "target.com")
        assert result == "approve"  # default on error

    def test_no_client_returns_empty(self):
        agent = StrategistAgent(client=None, enable_workers=False)
        inbox = SharedInbox()
        tasks = agent.plan("test", "example.com", inbox)
        assert tasks == []


# ── CriticAgent ────────────────────────────────────────────────────────────────


class TestCriticAgent:
    def test_review_confirmed(self):
        verdicts = json.dumps(
            [
                {
                    "index": 0,
                    "verdict": "confirmed",
                    "cvss": 8.5,
                    "confidence": "high",
                    "notes": "Patch immediately",
                }
            ]
        )
        client = _FakeClient(verdicts)
        agent = CriticAgent(client=client, enable_workers=False)
        inbox = SharedInbox()
        findings = [
            {"type": "xss", "severity": "high", "title": "XSS found", "description": "alert(1)"}
        ]
        results = agent.review(findings, "example.com", inbox)
        assert len(results) == 1
        assert results[0]["verdict"] == "confirmed"
        assert results[0]["cvss"] == 8.5

    def test_review_false_positive(self):
        verdicts = json.dumps(
            [
                {
                    "index": 0,
                    "verdict": "false_positive",
                    "cvss": 0.0,
                    "confidence": "high",
                    "notes": "Expected behavior",
                }
            ]
        )
        client = _FakeClient(verdicts)
        agent = CriticAgent(client=client, enable_workers=False)
        inbox = SharedInbox()
        findings = [{"type": "info", "severity": "info", "title": "Info", "description": "ok"}]
        results = agent.review(findings, "example.com", inbox)
        assert results[0]["verdict"] == "false_positive"

    def test_review_empty_findings(self):
        client = _FakeClient("[]")
        agent = CriticAgent(client=client, enable_workers=False)
        inbox = SharedInbox()
        results = agent.review([], "example.com", inbox)
        assert results == []

    def test_vote_deny_default_on_error(self):
        client = MagicMock()
        client.chat.side_effect = RuntimeError("timeout")
        agent = CriticAgent(client=client, enable_workers=False)
        result = agent.vote({"description": "x", "risk": "critical"}, [], "target.com")
        assert result == "deny"  # Critic is conservative


# ── AgentCouncil ───────────────────────────────────────────────────────────────


class TestAgentCouncil:
    def _make_council(self, plan_json, exec_result, review_json):
        """Build a council with mocked agents."""
        strategist = MagicMock()
        strategist.model_label = "TestStrategist"
        strategist.plan.return_value = json.loads(plan_json) if plan_json else []
        strategist.replan.return_value = []
        strategist.vote.return_value = "approve"
        strategist.total_tokens_used = 100

        specialist = MagicMock()
        specialist.model_label = "TestSpecialist"
        specialist.execute_task.return_value = exec_result
        specialist.total_tokens_used = 200

        critic = MagicMock()
        critic.model_label = "TestCritic"
        critic.review.return_value = json.loads(review_json) if review_json else []
        critic.total_tokens_used = 150

        council = AgentCouncil(
            strategist=strategist,
            specialist=specialist,
            critic=critic,
            target="example.com",
            max_rounds=5,
        )
        return council

    def test_run_returns_string(self):
        plan = '[{"description": "Run subfinder", "phase": "recon", "risk": "low"}]'
        exec_r = WorkerResult(success=True, worker_name="spec", output="out", findings=[])
        council = self._make_council(plan, exec_r, "[]")
        report = council.run("Test objective")
        assert isinstance(report, str)
        assert "TeamAegis" in report

    def test_run_includes_findings_in_report(self):
        plan = '[{"description": "Scan", "phase": "scanning", "risk": "low"}]'
        exec_r = WorkerResult(
            success=True,
            worker_name="spec",
            output="vuln found",
            findings=[{"type": "xss", "severity": "high", "title": "XSS", "description": "alert"}],
        )
        review = json.dumps(
            [
                {
                    "verdict": "confirmed",
                    "finding": {
                        "type": "xss",
                        "severity": "high",
                        "title": "XSS",
                        "description": "alert",
                    },
                    "cvss": 8.0,
                    "confidence": "high",
                    "notes": "Fix it",
                }
            ]
        )
        council = self._make_council(plan, exec_r, review)
        report = council.run("Find bugs")
        assert "XSS" in report or "confirmed" in report.lower() or "8.0" in report

    def test_deliberation_denied_skips_task(self):
        plan = '[{"description": "sqlmap attack", "phase": "exploit", "risk": "critical"}]'
        exec_r = WorkerResult(success=True, worker_name="spec", output="", findings=[])
        council = self._make_council(plan, exec_r, "[]")
        # Both deny -> strict majority deny -> task blocked
        council.strategist.vote.return_value = "deny"
        council.critic.vote.return_value = "deny"
        council.risk_threshold = "high"

        council.run("Critical exploit test")
        council.specialist.execute_task.assert_not_called()

    def test_deliberation_tie_defaults_to_deny(self):
        """Tie vote (1 approve, 1 deny) must block the task — conservative default."""
        plan = '[{"description": "risky scan", "phase": "exploit", "risk": "high"}]'
        exec_r = WorkerResult(success=True, worker_name="spec", output="", findings=[])
        council = self._make_council(plan, exec_r, "[]")
        # Tie: strategist approve, critic deny -> strict majority = deny
        council.strategist.vote.return_value = "approve"
        council.critic.vote.return_value = "deny"
        council.risk_threshold = "high"

        council.run("Tie vote test")
        # Task must be blocked
        council.specialist.execute_task.assert_not_called()

    def test_deliberation_both_approve_executes(self):
        """Both approve -> task proceeds."""
        plan = '[{"description": "safe scan", "phase": "recon", "risk": "high"}]'
        exec_r = WorkerResult(success=True, worker_name="spec", output="ok", findings=[])
        council = self._make_council(plan, exec_r, "[]")
        council.strategist.vote.return_value = "approve"
        council.critic.vote.return_value = "approve"
        council.risk_threshold = "high"

        council.run("Both approve test")
        council.specialist.execute_task.assert_called_once()

    def test_empty_plan_uses_default(self):
        exec_r = WorkerResult(success=True, worker_name="spec", output="", findings=[])
        council = self._make_council("[]", exec_r, "[]")
        report = council.run("empty plan test")
        # Should still produce a report (default plan used)
        assert isinstance(report, str)

    def test_token_usage_in_report(self):
        plan = '[{"description": "recon", "phase": "recon", "risk": "low"}]'
        exec_r = WorkerResult(success=True, worker_name="spec", output="", findings=[])
        council = self._make_council(plan, exec_r, "[]")
        report = council.run("Token test")
        assert "Tokens" in report or "Resource" in report


# ── HybridAgent council mode ────────────────────────────────────────────────────


class TestHybridAgentCouncilMode:
    def test_council_mode_activated_with_separate_clients(self):
        from agents.hybrid_agent import HybridAgent

        client_a = _FakeClient("[]")
        client_b = _FakeClient("{}")
        client_c = _FakeClient("[]")
        agent = HybridAgent(
            client=client_a,
            strategist_client=client_a,
            specialist_client=client_b,
            critic_client=client_c,
        )
        assert agent._use_council is True

    def test_legacy_mode_with_single_client(self):
        from agents.hybrid_agent import HybridAgent

        client = _FakeClient("[]")
        agent = HybridAgent(client=client)
        assert agent._use_council is False

    def test_partial_clients_activates_council(self):
        from agents.hybrid_agent import HybridAgent

        client = _FakeClient("[]")
        agent = HybridAgent(client=client, strategist_client=client)
        assert agent._use_council is True
