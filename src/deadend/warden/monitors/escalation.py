from __future__ import annotations

import re

from deadend.types import AgentEvent, DetectionResult, SessionContext, ThreatSeverity, ThreatType
from deadend.warden.monitors.base import BaseMonitor

__all__ = ["EscalationMonitor"]

class EscalationMonitor(BaseMonitor):
    """Detects privilege escalation attempts in tool arguments and event content.
    
    Scans both ``event.tool_args`` and ``event.content`` to catch escalation
    commands regardless of delivery vector.
    """
    
    ESCALATION_PATTERNS = [
        r'sudo\s+', r'su\s+', r'visudo',
        r'chmod', r'chown', r'icacls',
        r'reg\s+add', r'reg\s+delete',
        r'systemctl', r'service\s+', r'sc\s+'
    ]
    
    def __init__(self, max_privilege_level: str = 'user'):
        super().__init__()
        self.max_privilege_level = max_privilege_level
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.ESCALATION_PATTERNS]
        
    @property
    def name(self) -> str:
        return 'escalation_monitor'
    
    def _build_scan_text(self, event: AgentEvent) -> str:
        """Combine tool_args and content into a single string to scan."""
        parts: list[str] = []
        if event.tool_args:
            parts.append(str(event.tool_args))
        if event.content:
            parts.append(event.content)
        return " ".join(parts)
        
    async def check(self, event: AgentEvent, session: SessionContext) -> DetectionResult:
        scan_text = self._build_scan_text(event)
        if not scan_text:
            return DetectionResult(detected=False, threat_type=ThreatType.PRIVILEGE_ESCALATION, severity=ThreatSeverity.LOW, confidence=0.0)
            
        for pattern in self._compiled_patterns:
            if pattern.search(scan_text):
                return DetectionResult(
                    detected=True,
                    threat_type=ThreatType.PRIVILEGE_ESCALATION,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.9,
                    details=f"Privilege escalation pattern '{pattern.pattern}' detected."
                )
                
        return DetectionResult(detected=False, threat_type=ThreatType.PRIVILEGE_ESCALATION, severity=ThreatSeverity.LOW, confidence=0.0)
