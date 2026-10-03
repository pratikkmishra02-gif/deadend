from __future__ import annotations
import re

from deadend.types import AgentEvent, SessionContext, DetectionResult, ThreatSeverity, ThreatType
from deadend.warden.monitors.base import BaseMonitor

__all__ = ["SupplyChainMonitor"]

class SupplyChainMonitor(BaseMonitor):
    """Monitors package registry interactions."""
    
    REGISTRY_PATTERNS = [
        r'pypi\.org', r'npmjs\.com', r'rubygems\.org', r'maven\.apache\.org'
    ]
    
    PUBLISH_PATTERNS = [
        r'twine\s+upload', r'npm\s+publish', r'gem\s+push', r'mvn\s+deploy'
    ]
    
    def __init__(self, monitored_registries: list[str] = None):
        super().__init__()
        self.monitored_registries = monitored_registries or self.REGISTRY_PATTERNS
        self._reg_compiled = [re.compile(p, re.IGNORECASE) for p in self.monitored_registries]
        self._pub_compiled = [re.compile(p, re.IGNORECASE) for p in self.PUBLISH_PATTERNS]
        
    @property
    def name(self) -> str:
        return 'supply_chain_monitor'
        
    async def check(self, event: AgentEvent, session: SessionContext) -> DetectionResult:
        if not event.tool_name:
            return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
            
        args_str = str(event.tool_args or {})
        
        for pattern in self._pub_compiled:
            if pattern.search(args_str):
                return DetectionResult(
                    detected=True,
                    threat_type=ThreatType.TOOL_ABUSE,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.9,
                    details=f"Package publish/upload operation detected: {pattern.pattern}"
                )
                
        for pattern in self._reg_compiled:
            if pattern.search(args_str):
                return DetectionResult(
                    detected=True,
                    threat_type=ThreatType.TOOL_ABUSE,
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.7,
                    details=f"Interaction with package registry detected: {pattern.pattern}"
                )
                
        return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
