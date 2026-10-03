from __future__ import annotations

from deadend.types import AgentEvent, SessionContext, DetectionResult, ThreatSeverity, ThreatType
from deadend.warden.monitors.base import BaseMonitor

__all__ = ["ResourceMonitor"]

class ResourceMonitor(BaseMonitor):
    """Detects resource abuse."""
    
    def __init__(self, max_tokens: int = 100000, max_cost_usd: float = 10.0, max_api_calls_per_minute: int = 60, max_consecutive_tools: int = 10):
        super().__init__()
        self.max_tokens = max_tokens
        self.max_cost_usd = max_cost_usd
        self.max_api_calls_per_minute = max_api_calls_per_minute
        self.max_consecutive_tools = max_consecutive_tools
        
    @property
    def name(self) -> str:
        return 'resource_monitor'
        
    async def check(self, event: AgentEvent, session: SessionContext) -> DetectionResult:
        if getattr(session, 'total_tokens', 0) > self.max_tokens:
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.RESOURCE_ABUSE,
                severity=ThreatSeverity.MEDIUM,
                confidence=1.0,
                details=f"Token usage exceeded budget ({self.max_tokens})."
            )
            
        if getattr(session, 'total_cost', 0.0) > self.max_cost_usd:
             return DetectionResult(
                detected=True,
                threat_type=ThreatType.RESOURCE_ABUSE,
                severity=ThreatSeverity.HIGH,
                confidence=1.0,
                details=f"Cost exceeded budget (${self.max_cost_usd})."
            )
            
        if getattr(session, 'consecutive_tool_calls', 0) > self.max_consecutive_tools:
             return DetectionResult(
                detected=True,
                threat_type=ThreatType.RESOURCE_ABUSE,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.8,
                details=f"Consecutive tool calls limit exceeded ({self.max_consecutive_tools})."
            )
            
        return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
