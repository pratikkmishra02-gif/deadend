from __future__ import annotations

from phalanx_ai.types import AgentEvent, SessionContext, DetectionResult, ThreatSeverity, ThreatType
from phalanx_ai.warden.monitors.base import BaseMonitor

__all__ = ["RecursionMonitor"]

class RecursionMonitor(BaseMonitor):
    """Detects recursive/looping agent behavior."""
    
    def __init__(self, max_depth: int = 3, max_iterations: int = 50, max_sub_agents: int = 5):
        super().__init__()
        self.max_depth = max_depth
        self.max_iterations = max_iterations
        self.max_sub_agents = max_sub_agents
        
    @property
    def name(self) -> str:
        return 'recursion_monitor'
        
    async def check(self, event: AgentEvent, session: SessionContext) -> DetectionResult:
        if getattr(session, 'depth', 0) > self.max_depth:
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.RESOURCE_ABUSE,
                severity=ThreatSeverity.HIGH,
                confidence=1.0,
                details=f"Agent spawn depth exceeds max depth of {self.max_depth}."
            )
            
        if getattr(session, 'sub_agents_spawned', 0) > self.max_sub_agents:
             return DetectionResult(
                detected=True,
                threat_type=ThreatType.RESOURCE_ABUSE,
                severity=ThreatSeverity.HIGH,
                confidence=0.9,
                details=f"Excessive sub-agents spawned (> {self.max_sub_agents})."
            )
            
        if getattr(session, 'iteration_count', 0) > self.max_iterations:
             return DetectionResult(
                detected=True,
                threat_type=ThreatType.RESOURCE_ABUSE,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.8,
                details=f"Max iterations ({self.max_iterations}) exceeded."
            )
            
        return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
