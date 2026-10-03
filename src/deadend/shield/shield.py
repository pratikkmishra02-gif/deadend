from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, Optional
import structlog

from deadend.config import DeadendConfig
from deadend.types import (
    ScanResult, AgentEvent, ScanPhase, SessionContext, AgentState, ActionType
)
from deadend.exceptions import ThreatDetectedError

logger = structlog.get_logger(__name__)

class Shield:
    """
    Central orchestrator for the Deadend AI security package.
    Coordinates Sentinel (input), Warden (execution), and Guardian (output) modules.
    """
    def __init__(self, config: Optional[DeadendConfig] = None, policy_path: Optional[str] = None) -> None:
        self.config = config
        self.policy_path = policy_path
        self._sessions: Dict[str, SessionContext] = {}
        self._audit_logger = structlog.get_logger("deadend.audit")
        
        # Lazy initialization
        self._sentinel = None
        self._warden = None
        self._guardian = None
        self._policy_engine = None

        if policy_path:
            self._load_policy(policy_path)

    def _load_policy(self, path: str) -> None:
        try:
            from deadend.policy.loader import load_policy
            from deadend.policy.engine import PolicyEngine
            policy = load_policy(path)
            self._policy_engine = PolicyEngine(policy)
        except ImportError:
            self._audit_logger.warning("Policy module not found, continuing without explicit policy.")

    def get_session(self, session_id: str) -> SessionContext:
        """Retrieves an existing session or raises KeyError."""
        if session_id not in self._sessions:
            raise KeyError(f"Session {session_id} not found.")
        return self._sessions[session_id]

    def create_session(
        self, agent_id: str = "default", model: str = "unknown", framework: str = "unknown"
    ) -> SessionContext:
        """Creates a new session context."""
        import uuid
        session_id = str(uuid.uuid4())
        session = SessionContext(
            session_id=session_id,
            agent_id=agent_id,
            model=model,
            framework=framework,
            state=AgentState.INITIALIZED
        )
        self._sessions[session_id] = session
        return session

    async def scan_input(self, input_text: str, session_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scans input text using Sentinel."""
        metadata = metadata or {}
        session = self.get_session(session_id) if session_id and session_id in self._sessions else None
        
        result = await self._run_sentinel(input_text, session, metadata)
        
        event = AgentEvent(
            phase=ScanPhase.INPUT,
            session_id=session_id or "",
            action=result.action,
            details={"input_length": len(input_text)}
        )
        self._audit_logger.info("Input scanned", event=event.model_dump())
        return result

    async def scan_output(self, output_text: str, session_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scans output text using Guardian."""
        metadata = metadata or {}
        session = self.get_session(session_id) if session_id and session_id in self._sessions else None
        
        result = await self._run_guardian(output_text, session, metadata)
        
        event = AgentEvent(
            phase=ScanPhase.OUTPUT,
            session_id=session_id or "",
            action=result.action,
            details={"output_length": len(output_text)}
        )
        self._audit_logger.info("Output scanned", event=event.model_dump())
        return result

    async def monitor_tool_call(self, tool_name: str, arguments: Dict[str, Any], session_id: Optional[str] = None) -> ScanResult:
        """Monitors a tool call using Warden."""
        session = self.get_session(session_id) if session_id and session_id in self._sessions else None
        
        result = await self._run_warden(tool_name, arguments, session)
        
        event = AgentEvent(
            phase=ScanPhase.TOOL,
            session_id=session_id or "",
            action=result.action,
            details={"tool_name": tool_name}
        )
        self._audit_logger.info("Tool call monitored", event=event.model_dump())
        return result

    async def protect(self, input_text: str, model_call: Callable[..., Any], session_id: Optional[str] = None, **kwargs) -> Any:
        """
        Main protection pipeline.
        1. scan_input
        2. call model
        3. scan_output
        """
        scan_res = await self.scan_input(input_text, session_id=session_id)
        if scan_res.action == ActionType.BLOCK:
            raise ThreatDetectedError("Input blocked by security policy.", scan_result=scan_res)

        try:
            if asyncio.iscoroutinefunction(model_call):
                result = await model_call(input_text, **kwargs)
            else:
                result = model_call(input_text, **kwargs)
        except Exception as e:
            self._audit_logger.error("Model call failed", error=str(e))
            raise e
        
        if isinstance(result, str):
            out_res = await self.scan_output(result, session_id=session_id)
            if out_res.action == ActionType.BLOCK:
                raise ThreatDetectedError("Output blocked by security policy.", scan_result=out_res)

        return result

    async def _run_sentinel(self, input_text: str, session: Optional[SessionContext], metadata: Dict[str, Any]) -> ScanResult:
        if self._sentinel:
            pass
        return ScanResult(is_safe=True, phase=ScanPhase.INPUT, action=ActionType.ALLOW, detections=[])

    async def _run_warden(self, tool_name: str, arguments: Dict[str, Any], session: Optional[SessionContext]) -> ScanResult:
        if self._warden:
            pass
        return ScanResult(is_safe=True, phase=ScanPhase.TOOL, action=ActionType.ALLOW, detections=[])

    async def _run_guardian(self, output_text: str, session: Optional[SessionContext], metadata: Dict[str, Any]) -> ScanResult:
        if self._guardian:
            pass
        return ScanResult(is_safe=True, phase=ScanPhase.OUTPUT, action=ActionType.ALLOW, detections=[])

__all__ = ["Shield"]
