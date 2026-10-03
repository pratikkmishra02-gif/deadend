from __future__ import annotations

from deadend.types import AgentEvent, SessionContext, DetectionResult, ThreatSeverity, ThreatType
from deadend.warden.monitors.base import BaseMonitor

__all__ = ["IntentDriftMonitor"]

class IntentDriftMonitor(BaseMonitor):
    """Detects when agent actions diverge from stated task."""
    
    def __init__(self, drift_threshold: float = 0.6):
        super().__init__()
        self.drift_threshold = drift_threshold
        
    @property
    def name(self) -> str:
        return 'intent_drift_monitor'
        
    async def check(self, event: AgentEvent, session: SessionContext) -> DetectionResult:
        drift_score = getattr(session, 'calculated_drift_score', 0.0)
        
        if drift_score > self.drift_threshold:
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.PROMPT_INJECTION,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.8,
                details=f"Intent drift score ({drift_score}) exceeded threshold ({self.drift_threshold})."
            )
            
        return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
