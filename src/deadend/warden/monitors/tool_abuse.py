from __future__ import annotations
import re

from deadend.types import AgentEvent, SessionContext, DetectionResult, ThreatSeverity, ThreatType
from deadend.warden.monitors.base import BaseMonitor

__all__ = ["ToolAbuseMonitor"]

class ToolAbuseMonitor(BaseMonitor):
    """Detects dangerous tool usage patterns in tool arguments and event content.
    
    Scans both ``event.tool_args`` and ``event.content`` to catch malicious
    commands regardless of how they are passed (tool arguments, agent
    narrative, or plain text actions).
    """
    
    DEFAULT_DENIED_PATTERNS = [
        r'rm\s+-rf', r'chmod\s+777', r'dd\s+if=', r'mkfs', r'>\s*/dev/', r'fork\(\)', r':\(\)\{:\|:&\}\;:',
        r'curl', r'wget', r'nc\s+', r'netcat', r'nmap', r'ssh', r'telnet', r'ftp',
        r'whoami', r'ifconfig', r'ipconfig', r'net\s+user', r'net\s+view', r'systeminfo', r'uname\s+-a', r'cat\s+/etc/passwd', r'cat\s+/etc/shadow',
        r'python\s+-c', r'perl\s+-e', r'ruby\s+-e', r'eval\(', r'exec\(', r'os\.system\(', r'subprocess\.',
        r'\.\./', r'\.\.\\', r'/etc/', r'/root/', r'~/\.ssh/', r'\.env', r'\.git/config',
        r'base64', r'xxd', r'od\s+', r'tar\s+czf', r'zip\s+', r'scp\s+'
    ]
    
    def __init__(self, allowed_tools: list[str] = None, denied_patterns: list[str] = None, detect_phantom_actions: bool = True):
        super().__init__()
        self.allowed_tools = allowed_tools
        self.denied_patterns = denied_patterns or self.DEFAULT_DENIED_PATTERNS
        self.detect_phantom_actions = detect_phantom_actions
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.denied_patterns]
        
    @property
    def name(self) -> str:
        return 'tool_abuse_monitor'
    
    def _build_scan_text(self, event: AgentEvent) -> str:
        """Combine tool_args and content into a single string to scan."""
        parts: list[str] = []
        if event.tool_args:
            parts.append(str(event.tool_args))
        if event.content:
            parts.append(event.content)
        return " ".join(parts)
        
    async def check(self, event: AgentEvent, session: SessionContext) -> DetectionResult:
        # --- Tool allowlist gate (only when a named tool is invoked) ---
        if event.tool_name and self.allowed_tools and event.tool_name not in self.allowed_tools:
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.TOOL_ABUSE,
                severity=ThreatSeverity.HIGH,
                confidence=1.0,
                details=f"Tool '{event.tool_name}' is not in the allowed list."
            )
        
        # --- Build combined scan text from tool_args + content ---
        scan_text = self._build_scan_text(event)
        if not scan_text:
            return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
        
        # --- Denied pattern matching ---
        for pattern in self._compiled_patterns:
            if pattern.search(scan_text):
                return DetectionResult(
                    detected=True,
                    threat_type=ThreatType.TOOL_ABUSE,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=0.9,
                    details=f"Detected denied pattern '{pattern.pattern}' in tool call."
                )
                
        # --- Phantom action detection ---
        if self.detect_phantom_actions and event.tool_args:
            args_str = str(event.tool_args)
            desc = event.content.lower() if event.content else ""
            if "rm " in args_str and "remove" not in desc and "delete" not in desc:
                return DetectionResult(
                    detected=True,
                    threat_type=ThreatType.TOOL_ABUSE,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.7,
                    details="Phantom action detected: tool usage might not match description."
                )
            
        return DetectionResult(detected=False, threat_type=ThreatType.TOOL_ABUSE, severity=ThreatSeverity.LOW, confidence=0.0)
