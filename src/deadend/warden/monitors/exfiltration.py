from __future__ import annotations

import re

from deadend.types import AgentEvent, DetectionResult, SessionContext, ThreatSeverity, ThreatType
from deadend.warden.monitors.base import BaseMonitor

__all__ = ["ExfiltrationMonitor"]

class ExfiltrationMonitor(BaseMonitor):
    """Detects data exfiltration."""
    
    DEFAULT_PATTERNS = [
        r'\b\d{3}-\d{2}-\d{4}\b',
        r'\b(?:\d[ -]*?){13,16}\b',
        r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        r'(?i)(?:api_key|apikey|token|password|secret)[\s:=]+[\'"][a-zA-Z0-9_\-]+[\'"]'
    ]
    
    def __init__(self, sensitive_patterns: list[str] = None, allowed_domains: list[str] = None, max_outbound_payload_kb: int = 50):
        super().__init__()
        self.sensitive_patterns = sensitive_patterns or self.DEFAULT_PATTERNS
        self.allowed_domains = allowed_domains or []
        self.max_outbound_payload_kb = max_outbound_payload_kb
        self._compiled_patterns = [re.compile(p) for p in self.sensitive_patterns]
        self._base64_pattern = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
        
    @property
    def name(self) -> str:
        return 'exfiltration_monitor'
        
    async def check(self, event: AgentEvent, session: SessionContext) -> DetectionResult:
        if not event.tool_name:
            return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
            
        args_str = str(event.tool_args or {})
        
        if len(args_str) / 1024 > self.max_outbound_payload_kb:
             return DetectionResult(
                detected=True,
                threat_type=ThreatType.DATA_EXFILTRATION,
                severity=ThreatSeverity.HIGH,
                confidence=0.8,
                details=f"Payload size exceeds {self.max_outbound_payload_kb}KB limit."
            )
            
        for pattern in self._compiled_patterns:
            if pattern.search(args_str):
                return DetectionResult(
                    detected=True,
                    threat_type=ThreatType.DATA_EXFILTRATION,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=0.9,
                    details="Sensitive data pattern detected."
                )
                
        words = args_str.split()
        for word in words:
            if len(word) > 100 and self._base64_pattern.match(word):
                 return DetectionResult(
                    detected=True,
                    threat_type=ThreatType.DATA_EXFILTRATION,
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.6,
                    details="Large base64 encoded string detected."
                )
                
        return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
