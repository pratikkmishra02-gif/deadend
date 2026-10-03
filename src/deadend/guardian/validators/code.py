from __future__ import annotations

import re
from typing import Optional

from deadend.types import DetectionResult, SessionContext, ThreatSeverity, ThreatType
from .base import BaseValidator

__all__ = ["CodeValidator"]

# Dangerous patterns
DANGEROUS_IMPORTS = re.compile(r'\b(?:import|from)\s+(os|subprocess|socket|shutil|ctypes|pickle|marshal)\b')
DANGEROUS_FUNCTIONS = re.compile(r'\b(eval|exec|compile|__import__|open\s*\([^)]*[\'"][wa+]\w*[\'"])\s*\(')
SHELL_EXEC = re.compile(r'\b(os\.system|subprocess\.(?:run|Popen|call|check_output)|os\.popen)\b')
NETWORK_OPS = re.compile(r'\b(socket\.socket|urllib\.request|requests\.(?:get|post|put|delete))\b')
FS_OPS = re.compile(r'\b(os\.remove|shutil\.rmtree|unlink)\b')
OBFUSCATION = re.compile(r'(?i)\b(exec\s*\(\s*base64\.b64decode|eval\s*\(\s*compile)\b')
REVERSE_SHELL = re.compile(r'socket\..*?dup2.*?execve', re.DOTALL)


class CodeValidator(BaseValidator):
    """Validates generated code for dangerous patterns."""

    @property
    def name(self) -> str:
        return 'code_validator'

    async def validate(self, text: str, context: Optional[SessionContext] = None) -> DetectionResult:
        findings = []
        
        if match := DANGEROUS_IMPORTS.search(text):
            findings.append(f"Dangerous import: {match.group(1)}")
            
        if match := DANGEROUS_FUNCTIONS.search(text):
            findings.append(f"Dangerous function: {match.group(1)}")
            
        if match := SHELL_EXEC.search(text):
            findings.append(f"Shell execution: {match.group(1)}")
            
        if match := NETWORK_OPS.search(text):
            findings.append(f"Network operation: {match.group(1)}")
            
        if match := FS_OPS.search(text):
            findings.append(f"File system operation: {match.group(1)}")
            
        if match := OBFUSCATION.search(text):
            findings.append("Obfuscated code detected")
            
        if REVERSE_SHELL.search(text):
            findings.append("Potential reverse shell pattern")
            
        is_threat = len(findings) > 0
        return DetectionResult(
            detected=is_threat,
            threat_type=ThreatType.MALICIOUS_CODE if is_threat else None,
            severity=ThreatSeverity.HIGH if is_threat else ThreatSeverity.LOW,
            details={"code_findings": findings} if is_threat else {},
            module=self.name
        )
