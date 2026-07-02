"""tests/test_adaptive_planner.py — Tests for AdaptivePlanner module."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.adaptive_planner import AdaptivePlanner, ActionType


def test_rank_targets():
    planner = AdaptivePlanner()
    targets = [
        {"url": "http://test.com/api/users", "type": "api_endpoint"},
        {"url": "http://test.com/static/style.css", "type": "static"},
        {"url": "http://test.com/login", "type": "auth"},
    ]
    ranked = planner.rank_targets(targets)
    assert len(ranked) == 3
    # api_endpoint and auth should be rank 5, static should be rank 1
    assert ranked[0]["rank"] >= ranked[-1]["rank"]
    # First should be auth or api_endpoint (rank 5)
    assert ranked[0]["rank"] == 5


def test_rank_targets_unknown_type():
    planner = AdaptivePlanner()
    targets = [{"url": "http://test.com/unknown", "type": "custom_thing"}]
    ranked = planner.rank_targets(targets)
    assert ranked[0]["rank"] == 2  # default for unknown types


def test_decide_next_initial():
    planner = AdaptivePlanner()
    state = {"findings": [], "tried_paths": [], "budget_remaining": 1.0}
    decision = planner.decide_next(state)
    assert decision["action"] == ActionType.RECON.value


def test_decide_next_high_severity():
    planner = AdaptivePlanner()
    state = {
        "findings": [{"type": "XSS", "severity": "HIGH"}],
        "tried_paths": [],
        "budget_remaining": 1.0,
    }
    decision = planner.decide_next(state)
    assert decision["action"] == ActionType.ESCALATE.value


def test_decide_next_critical_severity():
    planner = AdaptivePlanner()
    state = {
        "findings": [{"type": "SQLi", "severity": "CRITICAL"}],
        "tried_paths": [],
        "budget_remaining": 1.0,
    }
    decision = planner.decide_next(state)
    assert decision["action"] == ActionType.ESCALATE.value


def test_decide_next_medium_chain():
    planner = AdaptivePlanner()
    state = {
        "findings": [
            {"type": "IDOR", "severity": "MEDIUM"},
            {"type": "info_disclosure", "severity": "MEDIUM"},
        ],
        "tried_paths": [],
        "budget_remaining": 1.0,
    }
    decision = planner.decide_next(state)
    assert decision["action"] == ActionType.CHAIN.value


def test_decide_next_budget_low():
    planner = AdaptivePlanner()
    state = {
        "findings": [],
        "tried_paths": [],
        "budget_remaining": 0.05,
    }
    decision = planner.decide_next(state)
    assert decision["action"] == ActionType.REPORT.value


def test_should_stop_budget_depleted():
    planner = AdaptivePlanner()
    state = {"budget_remaining": 0.01, "steps": 10, "max_steps": 100}
    assert planner.should_stop(state) is True


def test_should_stop_max_steps():
    planner = AdaptivePlanner()
    state = {"budget_remaining": 0.5, "steps": 100, "max_steps": 100}
    assert planner.should_stop(state) is True


def test_should_stop_continue():
    planner = AdaptivePlanner()
    state = {"budget_remaining": 0.5, "steps": 10, "max_steps": 100}
    assert planner.should_stop(state) is False
