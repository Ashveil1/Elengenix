"""
agents/redteam/base.py — REDTEAM Agent Communication Protocol (ACP)

Base classes for the autonomous REDTEAM multi-agent system.
Implements the Agent Communication Protocol for inter-agent coordination.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger("elengenix.redteam")


class AgentRole(Enum):
    """REDTEAM agent roles"""
    CAPTAIN = "captain"
    RECON = "recon"
    PLANNER = "planner"
    SCANNER = "scanner"
    EXPLOITER = "exploiter"
    VERIFIER = "verifier"
    REPORTER = "reporter"
    INTEL = "intel"


class MessageType(Enum):
    """ACP message types"""
    TASK = "task"
    RESULT = "result"
    INTEL = "intel"
    ALERT = "alert"
    DECISION = "decision"
    HEARTBEAT = "heartbeat"
    PHASE_CHANGE = "phase_change"


class MissionPhase(Enum):
    """Mission lifecycle phases"""
    INIT = "init"
    RECON = "recon"
    PLANNING = "planning"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    VERIFICATION = "verification"
    REPORTING = "reporting"
    COMPLETE = "complete"
    ABORTED = "aborted"


@dataclass
class AgentMessage:
    """ACP message envelope"""
    from_agent: str
    to_agent: str
    message_type: MessageType
    payload: Dict[str, Any]
    priority: int = 3  # 1=critical, 2=high, 3=normal, 4=low
    correlation_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    requires_response: bool = False


@dataclass
class AgentStatus:
    """Agent runtime status"""
    role: AgentRole
    status: str = "idle"  # idle, busy, error, offline
    current_task: Optional[str] = None
    metrics: Dict[str, float] = field(default_factory=dict)
    last_heartbeat: float = field(default_factory=lambda: datetime.now().timestamp())
    error_count: int = 0


class MessageBus:
    """ACP - Agent Communication Protocol message bus"""

    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = {}
        self.message_log: List[AgentMessage] = []
        self._lock = asyncio.Lock()

    def subscribe(self, agent_name: str, handler: Callable[[AgentMessage], Any]):
        """Subscribe agent to messages"""
        if agent_name not in self.subscribers:
            self.subscribers[agent_name] = []
        self.subscribers[agent_name].append(handler)

    def unsubscribe(self, agent_name: str, handler: Callable):
        """Unsubscribe agent from messages"""
        if agent_name in self.subscribers:
            self.subscribers[agent_name] = [h for h in self.subscribers[agent_name] if h != handler]

    async def publish(self, message: AgentMessage):
        """Publish message to subscribers"""
        async with self._lock:
            self.message_log.append(message)
            logger.debug(f"ACP: {message.from_agent} → {message.to_agent} [{message.message_type.value}]")

        targets = []
        if message.to_agent == "all":
            targets = list(self.subscribers.keys())
        elif message.to_agent in self.subscribers:
            targets = [message.to_agent]

        # Deliver to all handlers for target agents
        tasks = []
        for agent_name in targets:
            if agent_name in self.subscribers:
                for handler in self.subscribers[agent_name]:
                    tasks.append(asyncio.create_task(self._safe_deliver(handler, message)))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_deliver(self, handler: Callable, message: AgentMessage):
        """Safely deliver message to handler"""
        try:
            if asyncio.iscoroutinefunction(handler):
                await handler(message)
            else:
                handler(message)
        except Exception as e:
            logger.error(f"ACP delivery error: {e}")

    def get_recent_messages(self, count: int = 50) -> List[AgentMessage]:
        """Get recent messages for dashboard"""
        return self.message_log[-count:]


class RedTeamAgent(ABC):
    """Base class for all REDTEAM agents"""

    def __init__(self, name: str, role: AgentRole, message_bus: MessageBus):
        self.name = name
        self.role = role
        self.bus = message_bus
        self.state: Dict[str, Any] = {}
        self.metrics: Dict[str, float] = {}
        self._running = False
        self._shutdown_event = asyncio.Event()

        # Subscribe to messages
        self.bus.subscribe(name, self._handle_message)
        self.bus.subscribe("all", self._handle_message)

    @abstractmethod
    async def initialize(self, mission_context: Dict[str, Any]) -> None:
        """Called at mission start with full context"""
        pass

    @abstractmethod
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific task"""
        pass

    async def _handle_message(self, msg: AgentMessage):
        """Route incoming messages to appropriate handlers"""
        if msg.message_type == MessageType.TASK:
            try:
                result = await self.execute_task(msg.payload)
                await self.send_result(msg.correlation_id, result, msg.from_agent)
            except Exception as e:
                logger.error(f"[{self.name}] Task execution error: {e}")
                await self.send_result(msg.correlation_id, {"error": str(e)}, msg.from_agent)
        elif msg.message_type == MessageType.INTEL:
            try:
                await self.process_intel(msg.payload)
            except Exception as e:
                logger.error(f"[{self.name}] Intel processing error: {e}")
        elif msg.message_type == MessageType.DECISION:
            try:
                await self.process_decision(msg.payload)
            except Exception as e:
                logger.error(f"[{self.name}] Decision processing error: {e}")
        elif msg.message_type == MessageType.PHASE_CHANGE:
            try:
                await self.on_phase_change(msg.payload)
            except Exception as e:
                logger.error(f"[{self.name}] Phase change error: {e}")
        elif msg.message_type == MessageType.HEARTBEAT:
            self._update_heartbeat()

    def _update_heartbeat(self):
        """Update last heartbeat timestamp"""
        self.metrics["last_heartbeat"] = time.time()

    async def send_task(self, to_agent: str, task: Dict[str, Any], priority: int = 3, requires_response: bool = True):
        """Send task to another agent"""
        await self.bus.publish(AgentMessage(
            from_agent=self.name,
            to_agent=to_agent,
            message_type=MessageType.TASK,
            payload=task,
            priority=priority,
            requires_response=requires_response
        ))

    async def send_intel(self, intel: Dict[str, Any], to_agent: str = "all", priority: int = 2):
        """Share intelligence with other agents"""
        await self.bus.publish(AgentMessage(
            from_agent=self.name,
            to_agent=to_agent,
            message_type=MessageType.INTEL,
            payload=intel,
            priority=priority
        ))

    async def send_result(self, correlation_id: str, result: Dict[str, Any], to_agent: str = "captain"):
        """Send task result back"""
        await self.bus.publish(AgentMessage(
            from_agent=self.name,
            to_agent=to_agent,
            message_type=MessageType.RESULT,
            payload=result,
            correlation_id=correlation_id,
            priority=2
        ))

    async def send_alert(self, alert: Dict[str, Any], to_agent: str = "captain", priority: int = 1):
        """Send alert to captain"""
        await self.bus.publish(AgentMessage(
            from_agent=self.name,
            to_agent=to_agent,
            message_type=MessageType.ALERT,
            payload=alert,
            priority=priority
        ))

    async def process_intel(self, intel: Dict[str, Any]):
        """Override to process shared intelligence"""
        pass

    async def process_decision(self, decision: Dict[str, Any]):
        """Override to process captain decisions"""
        pass

    async def on_phase_change(self, payload: Dict[str, Any]):
        """Override to react to phase changes"""
        pass

    async def start(self):
        """Start the agent"""
        self._running = True
        self._shutdown_event.clear()
        logger.info(f"[{self.name}] Agent started")

    async def stop(self):
        """Stop the agent gracefully"""
        self._running = False
        self._shutdown_event.set()
        logger.info(f"[{self.name}] Agent stopped")

    async def wait_for_shutdown(self):
        """Wait for shutdown signal"""
        await self._shutdown_event.wait()


@dataclass
class MissionContext:
    """Mission context shared with all agents"""
    target: str
    scope: List[str]
    constraints: Dict[str, Any] = field(default_factory=dict)
    max_duration_seconds: int = 86400  # 24 hours
    start_time: float = field(default_factory=lambda: datetime.now().timestamp())
    mission_id: str = field(default_factory=lambda: str(uuid4()))

    def is_expired(self) -> bool:
        return (time.time() - self.start_time) > self.max_duration_seconds

    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time