from __future__ import annotations

from deadend.types import AgentEvent, DetectionResult, SessionContext, ThreatSeverity, ThreatType
from deadend.warden.monitors.base import BaseMonitor

__all__ = ["CoordinationMonitor"]

class CoordinationMonitor(BaseMonitor):
    """Detects multi-agent collusion."""
    
    def __init__(self, max_inter_agent_messages: int = 100, alert_threshold: float = 0.8):
        super().__init__()
        self.max_inter_agent_messages = max_inter_agent_messages
        self.alert_threshold = alert_threshold
        
    @property
    def name(self) -> str:
        return 'coordination_monitor'
        
    async def check(self, event: AgentEvent, session: SessionContext) -> DetectionResult:
        msg_count = getattr(session, 'inter_agent_messages', 0)
        
        if msg_count > self.max_inter_agent_messages:
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.AGENT_COORDINATION,
                severity=ThreatSeverity.HIGH,
                confidence=0.9,
                details=f"Excessive inter-agent messaging ({msg_count} > {self.max_inter_agent_messages})."
            )
            
        if msg_count > self.max_inter_agent_messages * self.alert_threshold:
             return DetectionResult(
                detected=True,
                threat_type=ThreatType.AGENT_COORDINATION,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.7,
                details="High inter-agent messaging detected."
            )
            
        return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
