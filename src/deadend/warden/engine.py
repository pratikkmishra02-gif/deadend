from __future__ import annotations
import time
from typing import List, Optional

from deadend.types import AgentEvent, SessionContext, DetectionResult, ScanResult, ScanPhase, ToolCall, AgentState, ThreatSeverity, ThreatType, ActionType
from deadend.exceptions import CircuitBreakerOpenError
from deadend.warden.circuit_breaker import CircuitBreaker
from deadend.warden.state_machine import AgentStateMachine
from deadend.warden.monitors.base import BaseMonitor
from deadend.warden.monitors.tool_abuse import ToolAbuseMonitor
from deadend.warden.monitors.escalation import EscalationMonitor
from deadend.warden.monitors.exfiltration import ExfiltrationMonitor
from deadend.warden.monitors.recursion import RecursionMonitor
from deadend.warden.monitors.resource import ResourceMonitor
from deadend.warden.monitors.network import NetworkMonitor
from deadend.warden.monitors.coordination import CoordinationMonitor
from deadend.warden.monitors.intent_drift import IntentDriftMonitor
from deadend.warden.monitors.supply_chain import SupplyChainMonitor
from deadend.warden.monitors.semantic_command import SemanticCommandMonitor

__all__ = ["WardenEngine"]

class WardenEngine:
    """Orchestrates all monitors and circuit breaker."""
    
    def __init__(self, monitors: Optional[List[BaseMonitor]] = None, circuit_breaker: Optional[CircuitBreaker] = None):
        if monitors is None:
            self.monitors = [
                ToolAbuseMonitor(),
                EscalationMonitor(),
                ExfiltrationMonitor(),
                RecursionMonitor(),
                ResourceMonitor(),
                NetworkMonitor(),
                CoordinationMonitor(),
                IntentDriftMonitor(),
                SupplyChainMonitor(),
                SemanticCommandMonitor()
            ]
        else:
            self.monitors = monitors
            
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.state_machine = AgentStateMachine()

    async def check(self, event: AgentEvent, session: SessionContext) -> ScanResult:
        """Run all monitors, check circuit breaker, aggregate results."""
        if not self.circuit_breaker.can_proceed(session.session_id):
            raise CircuitBreakerOpenError(f"Circuit breaker is OPEN for session {session.session_id}")
            
        detections: List[DetectionResult] = []
        start_time = time.time()
        
        for monitor in self.monitors:
            if not monitor.enabled:
                continue
                
            try:
                result = await monitor.check(event, session)
                if result.detected:
                    detections.append(result)
            except Exception:
                pass
                
        is_safe = len(detections) == 0
        
        # Determine action based on detections
        action = ActionType.ALLOW
        if not is_safe:
            # Use the highest severity detection to decide action
            has_critical = any(d.severity == ThreatSeverity.CRITICAL for d in detections)
            has_high = any(d.severity == ThreatSeverity.HIGH for d in detections)
            if has_critical or has_high:
                action = ActionType.BLOCK
            else:
                action = ActionType.WARN
        
        scan_result = ScanResult(
            passed=is_safe,
            phase=ScanPhase.EXECUTION,
            detections=detections,
            action_taken=action,
            latency_ms=(time.time() - start_time) * 1000
        )
        
        if not is_safe:
            self.circuit_breaker.record_violation(session.session_id, detections[0])
            
        return scan_result

    async def check_tool_call(self, tool_call: ToolCall, session: SessionContext) -> ScanResult:
        """Convenience method for tool call monitoring."""
        event = AgentEvent(
            session_id=session.session_id,
            event_type="tool_call",
            tool_name=tool_call.tool_name,
            tool_args=tool_call.arguments,
            content=""
        )
        return await self.check(event, session)

    def get_state(self, session_id: str) -> AgentState:
        """Get the current agent state."""
        return self.state_machine.get_state(session_id)

