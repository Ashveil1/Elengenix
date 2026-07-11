"""Tests for Loop - Fixed version with proper mocking"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock, patch, AsyncMock
from elengenix.types import MissionContext, MissionResult, LoopConfig


class TestTrueAgenticLoop:
    """Tests for TrueAgenticLoop"""

    @pytest.fixture
    def mock_brain(self):
        brain = MagicMock()
        brain.perceive = AsyncMock(return_value={"target_status": "active"})
        brain.reason = AsyncMock(return_value=MagicMock())
        brain.decide = AsyncMock(return_value={"action_type": "scan", "tool": "scanner"})
        brain.planner = MagicMock()
        brain.planner.plan = AsyncMock(return_value=MagicMock(phases=[]))
        brain.decision_engine = MagicMock()
        brain.decision_engine.decide = AsyncMock(return_value={"action_type": "scan", "tool": "scanner"})
        brain.constitutional_engine = MagicMock()
        brain.constitutional_engine.verify_action = AsyncMock(return_value=MagicMock(
            verified=True, requires_human_review=False
        ))
        return brain

    @pytest.fixture
    def loop_config(self):
        from elengenix.loop import LoopConfig
        return LoopConfig(
            max_steps=10,
            max_duration=60,
            replan_threshold=0.3,
            reflection_interval=5,
            constitutional_check=True,
            auto_replan=True,
            max_consecutive_failures=3
        )

    @pytest.fixture
    def mission_context(self):
        from elengenix.types import MissionContext
        return MissionContext(
            mission_id="test-mission-001",
            target="example.com",
            scope=["example.com"],
            objectives=["Find vulnerabilities"],
            max_duration=3600
        )

    @pytest.fixture
    def loop(self, mock_brain, loop_config, mission_context):
        from elengenix.loop import TrueAgenticLoop
        from elengenix.governance import GovernanceGate
        from elengenix.tools import ToolRegistry
        from elengenix.memory import CognitiveMemoryManager
        from elengenix.constitution import Constitution
        from elengenix.constitution_engine import ConstitutionalAIEngine

        loop = TrueAgenticLoop(
            brain=MagicMock(),
            constitution=MagicMock(),
            governance=MagicMock(),
            tools=MagicMock(),
            memory=MagicMock(),
            config=LoopConfig(max_steps=5, max_duration=60)
        )

        # Replace with mocks
        loop.brain = MagicMock()
        loop.brain.perceive = AsyncMock(return_value={"target_status": "active"})
        loop.brain.reason = AsyncMock(return_value=MagicMock())
        loop.brain.decide = AsyncMock(return_value={"action_type": "scan", "tool": "scanner"})
        loop.brain.planner = MagicMock()
        loop.brain.planner.plan = AsyncMock(return_value=MagicMock(phases=[]))
        loop.brain.decision_engine = MagicMock()
        loop.brain.decision_engine.decide = AsyncMock(return_value={"action_type": "scan", "tool": "scanner"})
        loop.brain.constitutional_engine = MagicMock()
        loop.brain.constitutional_engine.verify_action = AsyncMock(return_value=MagicMock(
            verified=True, requires_human_review=False
        ))
        loop.memory = MagicMock()
        loop.memory.remember = AsyncMock()
        loop.memory.get_recent_findings = lambda: []
        loop.memory.get_verified_findings = lambda: []
        loop.tools = MagicMock()
        loop.tools.execute = AsyncMock(return_value=MagicMock(
            success=True, output="test", findings=[]
        ))
        loop.governance = MagicMock()
        loop.governance.gate = AsyncMock(return_value=MagicMock(
            decision="allow", rationale="ok", risk_level="low"
        ))
        loop.constitutional_engine = MagicMock()
        loop.constitutional_engine.verify_action = AsyncMock(return_value=MagicMock(
            verified=True, requires_human_review=False
        ))
        loop.config = MagicMock()
        loop.config.max_steps = 5
        loop.config.max_duration = 60
        loop.config.replan_threshold = 0.3
        loop.config.reflection_interval = 10
        loop.config.constitutional_check = True
        loop.config.auto_replan = True
        loop.config.max_consecutive_failures = 3
        loop.metrics_data = type('MetricsData', (), {
            'steps_taken': 0,
            'successful_actions': 0,
            'failed_actions': 0,
            'replans': 0,
            'constitutional_violations': 0,
            'human_interventions': 0,
            'total_duration': 0.0,
            'total_cost': 0.0,
            'findings_discovered': 0,
            'findings_verified': 0,
            'unique_vuln_types': set()
        })()
        loop.callback = None
        loop._shutdown = False
        loop._phase_complete_events = {}

        return loop

    @pytest.fixture
    def mission_context(self):
        from elengenix.types import MissionContext
        return MissionContext(
            mission_id="test-mission-001",
            target="example.com",
            scope=["example.com"],
            objectives=["Find vulnerabilities"],
            max_duration=3600
        )

    @pytest.mark.asyncio
    async def test_loop_initialization(self, loop):
        assert loop.config.max_steps == 5
        assert loop._shutdown is False

    @pytest.mark.asyncio
    async def test_mission_complete_check(self, loop, mission_context):
        loop.cognitive_state.active_plan = MagicMock()
        loop.cognitive_state.active_plan.phases = [
            MagicMock(completed=True),
            MagicMock(completed=True)
        ]
        assert loop._mission_complete() is True

    @pytest.mark.asyncio
    async def test_should_stop(self, loop):
        loop._shutdown = True
        assert loop._should_stop() is True

    @pytest.mark.asyncio
    async def test_execute_action(self, loop, mission_context):
        action = MagicMock()
        action.action_type = "scan"
        action.tool = "scanner"
        action.target = "example.com"
        action.parameters = {}
        action.description = "Test scan"

        loop.tools.execute = AsyncMock(return_value=MagicMock(
            success=True, output="test output", findings=[]
        ))

        result = await loop._execute_action(action, mission_context)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_reflect_and_learn(self, loop):
        action = MagicMock()
        action.description = "Test action"
        action.expected_outcome = "Find something"
        result = {"success": True, "output": "Found something", "findings": []}

        await loop._reflect_and_learn(action, result)
        # Should not raise

    @pytest.mark.asyncio
    async def test_update_cognitive_state(self, loop):
        action = MagicMock()
        action.description = "Test action"
        result = {"success": True}

        loop._update_cognitive_state(action, result)

        assert loop.cognitive_state.step_count == 1
        assert loop.cognitive_state.confidence >= 0.5

    @pytest.mark.asyncio
    async def test_needs_replanning(self, loop):
        loop.cognitive_state.confidence = 0.2
        loop.config.replan_threshold = 0.3

        assert loop._needs_replanning({}) is True

    @pytest.mark.asyncio
    async def test_replan(self, loop):
        loop.metrics_data.replans = 0

        await loop._replan()

        assert loop.metrics_data.replans == 1

    @pytest.mark.asyncio
    async def test_mission_complete(self, loop):
        loop.cognitive_state.active_plan = MagicMock()
        loop.cognitive_state.active_plan.phases = [
            MagicMock(completed=True),
            MagicMock(completed=True)
        ]
        assert loop._mission_complete({}) is True

    @pytest.mark.asyncio
    async def test_should_stop(self, loop):
        loop._shutdown = True
        assert loop._should_stop() is True

    @pytest.mark.asyncio
    async def test_execute_action(self, loop, mission_context):
        action = MagicMock()
        action.action_type = "scan"
        action.tool = "scanner"
        action.target = "example.com"
        action.parameters = {}
        action.description = "Test scan"

        loop.tools.execute = AsyncMock(return_value=MagicMock(
            success=True, output="test output", findings=[]
        ))

        result = await loop._execute_action(action, mission_context)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_reflect_and_learn(self, loop):
        action = MagicMock()
        action.description = "Test action"
        action.expected_outcome = "Find something"
        result = {"success": True, "output": "Found something", "findings": []}

        await loop._reflect_and_learn(action, result)
        # Should not raise

    @pytest.mark.asyncio
    async def test_update_cognitive_state(self, loop):
        action = MagicMock()
        action.description = "Test action"
        result = {"success": True}

        loop._update_cognitive_state(action, result)

        assert loop.cognitive_state.step_count == 1
        assert loop.cognitive_state.confidence >= 0.5

    @pytest.mark.asyncio
    async def test_needs_replanning(self, loop):
        loop.cognitive_state.confidence = 0.2
        loop.config.replan_threshold = 0.3

        assert loop._needs_replanning({}) is True

    @pytest.mark.asyncio
    async def test_replan(self, loop):
        loop.metrics_data.replans = 0

        await loop._replan()

        assert loop.metrics_data.replans == 1

    @pytest.mark.asyncio
    async def test_mission_complete(self, loop):
        loop.cognitive_state.active_plan = MagicMock()
        loop.cognitive_state.active_plan.phases = [
            MagicMock(completed=True),
            MagicMock(completed=True)
        ]
        assert loop._mission_complete({}) is True

    @pytest.mark.asyncio
    async def test_should_stop(self, loop):
        loop._shutdown = True
        assert loop._should_stop() is True

    @pytest.mark.asyncio
    async def test_execute_action(self, loop, mission_context):
        action = MagicMock()
        action.action_type = "scan"
        action.tool = "scanner"
        action.target = "example.com"
        action.parameters = {}
        action.description = "Test scan"

        loop.tools.execute = AsyncMock(return_value=MagicMock(
            success=True, output="test output", findings=[]
        ))

        result = await loop._execute_action(action, mission_context)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_reflect_and_learn(self, loop):
        action = MagicMock()
        action.description = "Test action"
        action.expected_outcome = "Find something"
        result = {"success": True, "output": "Found something", "findings": []}

        await loop._reflect_and_learn(action, result)
        # Should not raise

    @pytest.mark.asyncio
    async def test_update_cognitive_state(self, loop):
        action = MagicMock()
        action.description = "Test action"
        result = {"success": True}

        loop._update_cognitive_state(action, result)

        assert loop.cognitive_state.step_count == 1
        assert loop.cognitive_state.confidence >= 0.5

    @pytest.mark.asyncio
    async def test_needs_replanning(self, loop):
        loop.cognitive_state.confidence = 0.2
        loop.config.replan_threshold = 0.3

        assert loop._needs_replanning({}) is True

    @pytest.mark.asyncio
    async def test_replan(self, loop):
        loop.metrics_data.replans = 0

        await loop._replan()

        assert loop.metrics_data.replans == 1

    @pytest.mark.asyncio
    async def test_mission_complete(self, loop):
        loop.cognitive_state.active_plan = MagicMock()
        loop.cognitive_state.active_plan.phases = [
            MagicMock(completed=True),
            MagicMock(completed=True)
        ]
        assert loop._mission_complete({}) is True

    @pytest.mark.asyncio
    async def test_should_stop(self, loop):
        loop._shutdown = True
        assert loop._should_stop() is True

    @pytest.mark.asyncio
    async def test_execute_action(self, loop, mission_context):
        action = MagicMock()
        action.action_type = "scan"
        action.tool = "scanner"
        action.target = "example.com"
        action.parameters = {}
        action.description = "Test scan"

        loop.tools.execute = AsyncMock(return_value=MagicMock(
            success=True, output="test output", findings=[]
        ))

        result = await loop._execute_action(action, mission_context)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_reflect_and_learn(self, loop):
        action = MagicMock()
        action.description = "Test action"
        action.expected_outcome = "Find something"
        result = {"success": True, "output": "Found something", "findings": []}

        await loop._reflect_and_learn(action, result)
        # Should not raise

    @pytest.mark.asyncio
    async def test_update_cognitive_state(self, loop):
        action = MagicMock()
        action.description = "Test action"
        result = {"success": True}

        loop._update_cognitive_state(action, result)

        assert loop.cognitive_state.step_count == 1
        assert loop.cognitive_state.confidence >= 0.5

    @pytest.mark.asyncio
    async def test_needs_replanning(self, loop):
        loop.cognitive_state.confidence = 0.2
        loop.config.replan_threshold = 0.3

        assert loop._needs_replanning({}) is True

    @pytest.mark.asyncio
    async def test_replan(self, loop):
        loop.metrics_data.replans = 0

        await loop._replan()

        assert loop.metrics_data.replans == 1

    @pytest.mark.asyncio
    async def test_mission_complete(self, loop):
        loop.cognitive_state.active_plan = MagicMock()
        loop.cognitive_state.active_plan.phases = [
            MagicMock(completed=True),
            MagicMock(completed=True)
        ]
        assert loop._mission_complete({}) is True

    @pytest.mark.asyncio
    async def test_should_stop(self, loop):
        loop._shutdown = True
        assert loop._should_stop() is True

    @pytest.mark.asyncio
    async def test_execute_action(self, loop, mission_context):
        action = MagicMock()
        action.action_type = "scan"
        action.tool = "scanner"
        action.target = "example.com"
        action.parameters = {}
        action.description = "Test scan"

        loop.tools.execute = AsyncMock(return_value=MagicMock(
            success=True, output="test output", findings=[]
        ))

        result = await loop._execute_action(action, mission_context)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_reflect_and_learn(self, loop):
        action = MagicMock()
        action.description = "Test action"
        action.expected_outcome = "Find something"
        result = {"success": True, "output": "Found something", "findings": []}

        await loop._reflect_and_learn(action, result)
        # Should not raise

    @pytest.mark.asyncio
    async def test_update_cognitive_state(self, loop):
        action = MagicMock()
        action.description = "Test action"
        result = {"success": True}

        loop._update_cognitive_state(action, result)

        assert loop.cognitive_state.step_count == 1
        assert loop.cognitive_state.confidence >= 0.5

    @pytest.mark.asyncio
    async def test_needs_replanning(self, loop):
        loop.cognitive_state.confidence = 0.2
        loop.config.replan_threshold = 0.3

        assert loop._needs_replanning({}) is True

    @pytest.mark.asyncio
    async def test_replan(self, loop):
        loop.metrics_data.replans = 0

        await loop._replan()

        assert loop.metrics_data.replans == 1

    @pytest.mark.asyncio
    async def test_mission_complete(self, loop):
        loop.cognitive_state.active_plan = MagicMock()
        loop.cognitive_state.active_plan.phases = [
            MagicMock(completed=True),
            MagicMock(completed=True)
        ]
        assert loop._mission_complete({}) is True

    @pytest.mark.asyncio
    async def test_should_stop(self, loop):
        loop._shutdown = True
        assert loop._should_stop() is True