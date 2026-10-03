"""
Deadend AI — CrewAI Middleware
===============================
Security middleware for CrewAI multi-agent orchestration.

Wraps CrewAI task execution to scan agent actions, tool calls,
and inter-agent communications for threats.

Usage::

    from crewai import Agent, Task, Crew
    from deadend.integrations.crewai_middleware import secure_crew

    crew = Crew(agents=[...], tasks=[...])
    secured_crew = secure_crew(crew, mode="enforce")
    result = secured_crew.kickoff()
"""
from __future__ import annotations

import asyncio
import functools
from typing import Any

import structlog

from deadend.config import DeadendConfig
from deadend.exceptions import ThreatDetectedError
from deadend.guardian.engine import GuardianEngine
from deadend.guardian.validators.code import CodeValidator
from deadend.guardian.validators.pii import PIIValidator
from deadend.guardian.validators.secrets import SecretValidator
from deadend.sentinel.engine import SentinelEngine
from deadend.policy.loader import PolicyLoader
from deadend.policy.schema import DeadendPolicy
from deadend.types import AgentEvent, SessionContext
from deadend.warden.engine import WardenEngine

logger = structlog.get_logger(__name__)

__all__ = ["DeadendCrewAIMiddleware", "secure_crew", "secure_agent"]


def _run_sync(coro):
    """Run async code synchronously."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


class DeadendCrewAIMiddleware:
    """
    Security middleware for CrewAI agents and tasks.

    Provides hooks that can be injected into CrewAI's execution pipeline
    to scan agent reasoning, tool usage, and task outputs.

    Args:
        config: Optional DeadendConfig.
        mode: "enforce" or "monitor".
    """

    def __init__(
        self,
        config: DeadendConfig | None = None,
        mode: str = "enforce",
        policy: DeadendPolicy | None = None,
    ) -> None:
        self.mode = mode
        self.policy = policy or PolicyLoader.load()
        
        self.sentinel = SentinelEngine(policy=self.policy.sentinel)
        self.guardian = GuardianEngine(validators=[
            PIIValidator(), SecretValidator(), CodeValidator()
        ])
        self.warden = WardenEngine(policy=self.policy.warden)
        self.session = SessionContext()
        self._violation_count = 0

    def scan_agent_input(self, agent_name: str, task_description: str) -> bool:
        """
        Scan a task description before it's given to an agent.

        Args:
            agent_name: Name of the CrewAI agent.
            task_description: The task prompt.

        Returns:
            True if safe, False if threat detected.
        """
        result = _run_sync(self.sentinel.scan(task_description))
        if not result.passed:
            self._violation_count += 1
            highest = result.detections[0] if result.detections else None
            logger.warning(
                "Deadend: Threat in CrewAI task",
                agent=agent_name,
                threat_type=highest.threat_type.value if highest else "unknown",
            )
            if self.mode == "enforce":
                raise ThreatDetectedError(
                    message=f"Task for agent '{agent_name}' blocked by Deadend",
                    threat_type=highest.threat_type.value if highest else None,
                    severity=highest.severity.value if highest else None,
                )
            return False
        return True

    def scan_tool_call(self, agent_name: str, tool_name: str, tool_input: str) -> bool:
        """
        Scan a tool call before execution.

        Args:
            agent_name: Name of the agent making the call.
            tool_name: Name of the tool being invoked.
            tool_input: The tool's input arguments as a string.

        Returns:
            True if safe, False if threat detected.
        """
        event = AgentEvent(
            session_id=self.session.session_id,
            agent_id=agent_name,
            event_type="tool_call",
            tool_name=tool_name,
            content=tool_input,
        )
        result = _run_sync(self.warden.check(event, self.session))
        if not result.passed:
            self._violation_count += 1
            highest = result.detections[0] if result.detections else None
            logger.warning(
                "Deadend: Tool call blocked",
                agent=agent_name,
                tool=tool_name,
                threat_type=highest.threat_type.value if highest else "unknown",
            )
            if self.mode == "enforce":
                raise ThreatDetectedError(
                    message=f"Tool '{tool_name}' by agent '{agent_name}' blocked",
                    threat_type=highest.threat_type.value if highest else None,
                    severity=highest.severity.value if highest else None,
                )
            return False
        return True

    def scan_agent_output(self, agent_name: str, output: str) -> bool:
        """
        Scan an agent's output for PII, secrets, or malicious code.

        Args:
            agent_name: Name of the agent.
            output: The agent's response text.

        Returns:
            True if safe, False if threat detected.
        """
        result = _run_sync(self.guardian.validate(output))
        if not result.passed:
            self._violation_count += 1
            highest = result.detections[0] if result.detections else None
            logger.warning(
                "Deadend: Threat in agent output",
                agent=agent_name,
                threat_type=highest.threat_type.value if highest else "unknown",
            )
            if self.mode == "enforce":
                raise ThreatDetectedError(
                    message=f"Output from agent '{agent_name}' blocked by Deadend",
                    threat_type=highest.threat_type.value if highest else None,
                    severity=highest.severity.value if highest else None,
                )
            return False
        return True

    def scan_inter_agent_message(
        self, sender: str, receiver: str, message: str
    ) -> bool:
        """
        Scan messages between agents for coordination attacks.

        Args:
            sender: Sending agent name.
            receiver: Receiving agent name.
            message: The message content.

        Returns:
            True if safe, False if threat detected.
        """
        event = AgentEvent(
            session_id=self.session.session_id,
            agent_id=sender,
            event_type="inter_agent_message",
            content=message,
            metadata={"receiver": receiver},
        )
        result = _run_sync(self.warden.check(event, self.session))
        if not result.passed:
            self._violation_count += 1
            logger.warning(
                "Deadend: Suspicious inter-agent message",
                sender=sender, receiver=receiver,
            )
            return False
        return True

    @property
    def violation_count(self) -> int:
        return self._violation_count


def secure_crew(crew: Any, mode: str = "enforce") -> Any:
    """
    Wrap a CrewAI Crew instance with Deadend security.

    This monkey-patches the crew's kickoff method to scan
    all agent interactions.

    Args:
        crew: A CrewAI Crew instance.
        mode: "enforce" or "monitor".

    Returns:
        The same crew instance with security middleware attached.
    """
    middleware = DeadendCrewAIMiddleware(mode=mode)
    original_kickoff = crew.kickoff

    @functools.wraps(original_kickoff)
    def secured_kickoff(*args, **kwargs):
        # Pre-scan all task descriptions
        if hasattr(crew, "tasks"):
            for task in crew.tasks:
                desc = getattr(task, "description", "")
                agent_name = getattr(getattr(task, "agent", None), "role", "unknown")
                middleware.scan_agent_input(agent_name, desc)

        result = original_kickoff(*args, **kwargs)

        # Post-scan the final output
        if isinstance(result, str):
            middleware.scan_agent_output("crew_final_output", result)

        logger.info(
            "Deadend: Crew execution complete",
            violations=middleware.violation_count,
        )
        return result

    crew.kickoff = secured_kickoff
    crew._deadend_middleware = middleware
    return crew


def secure_agent(agent: Any, mode: str = "enforce") -> Any:
    """
    Wrap a single CrewAI Agent with Deadend security.

    Args:
        agent: A CrewAI Agent instance.
        mode: "enforce" or "monitor".

    Returns:
        The same agent with security monitoring attached.
    """
    middleware = DeadendCrewAIMiddleware(mode=mode)
    agent._deadend_middleware = middleware
    return agent
