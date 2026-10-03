from __future__ import annotations
import re

from deadend.types import AgentEvent, SessionContext, DetectionResult, ThreatSeverity, ThreatType
from deadend.warden.monitors.base import BaseMonitor

__all__ = ["NetworkMonitor"]

class NetworkMonitor(BaseMonitor):
    """Monitors network access."""
    
    def __init__(self, allowed_domains: list[str] = None, denied_domains: list[str] = None):
        super().__init__()
        self.allowed_domains = allowed_domains
        self.denied_domains = denied_domains or []
        
    @property
    def name(self) -> str:
        return 'network_monitor'
        
    async def check(self, event: AgentEvent, session: SessionContext) -> DetectionResult:
        if not event.tool_name:
            return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
            
        args_str = str(event.tool_args or {}).lower()
        
        for domain in self.denied_domains:
            if domain in args_str:
                return DetectionResult(
                    detected=True,
                    threat_type=ThreatType.DATA_EXFILTRATION,
                    severity=ThreatSeverity.HIGH,
                    confidence=1.0,
                    details=f"Access to denied domain: {domain}"
                )
                
        if "nmap" in args_str or "-p" in args_str and re.search(r'\d{1,5}-\d{1,5}', args_str):
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.DATA_EXFILTRATION,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.8,
                details="Potential port scanning detected."
            )
            
        return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
