from __future__ import annotations

import math
import re
from typing import Optional

from deadend.types import DetectionResult, SessionContext, ThreatSeverity, ThreatType
from .base import BaseValidator

__all__ = ["SecretValidator"]

# Compiled regex patterns for Secrets
AWS_ACCESS_KEY = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
AWS_SECRET_KEY = re.compile(r'(?i)(?:aws_secret|aws_key).*?[\'"]([A-Za-z0-9/+=]{40})[\'"]')
GITHUB_TOKEN = re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,})\b')
GOOGLE_API_KEY = re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')
SLACK_TOKEN = re.compile(r'\b(xox[bpso]-[0-9]{10,13}-[a-zA-Z0-9]+)\b')
GENERIC_API_KEY = re.compile(r'(?i)(?:api[_-]?key|token|secret)[^a-z0-9]{1,10}[\'"]?([a-zA-Z0-9_-]{16,})[\'"]?')
JWT_TOKEN = re.compile(r'\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b')
PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----.*?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', re.DOTALL)
DB_CONN = re.compile(r'\b(?:mongodb|postgres|mysql|redis)://[^\s]+')
STRING_LITERAL = re.compile(r'[\'"]([A-Za-z0-9/+=_]{16,})[\'"]')

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


class SecretValidator(BaseValidator):
    """Detects exposed secrets and credentials in output."""

    @property
    def name(self) -> str:
        return 'secret_validator'

    async def validate(self, text: str, context: Optional[SessionContext] = None) -> DetectionResult:
        findings = []
        
        if AWS_ACCESS_KEY.search(text):
            findings.append("AWS Access Key")
        if AWS_SECRET_KEY.search(text):
            findings.append("AWS Secret Key")
        if GITHUB_TOKEN.search(text):
            findings.append("GitHub Token")
        if GOOGLE_API_KEY.search(text):
            findings.append("Google API Key")
        if SLACK_TOKEN.search(text):
            findings.append("Slack Token")
        if JWT_TOKEN.search(text):
            findings.append("JWT Token")
        if PRIVATE_KEY.search(text):
            findings.append("Private Key")
        if DB_CONN.search(text):
            findings.append("Database Connection String")
        if GENERIC_API_KEY.search(text):
            findings.append("Generic API Key")
            
        # Entropy check
        for match in STRING_LITERAL.finditer(text):
            if calculate_entropy(match.group(1)) > 4.5:
                findings.append("High entropy string (potential secret)")
                break
                
        is_threat = len(findings) > 0
        return DetectionResult(
            detected=is_threat,
            threat_type=ThreatType.SECRET_EXPOSURE if is_threat else None,
            severity=ThreatSeverity.CRITICAL if is_threat else ThreatSeverity.LOW,
            details={"secrets": findings} if is_threat else {},
            module=self.name
        )

    async def redact(self, text: str, mask_char: str = '█') -> str:
        redacted = text
        
        def replacer(match):
            return mask_char * len(match.group(0))
            
        redacted = AWS_ACCESS_KEY.sub(replacer, redacted)
        redacted = GITHUB_TOKEN.sub(replacer, redacted)
        redacted = GOOGLE_API_KEY.sub(replacer, redacted)
        redacted = SLACK_TOKEN.sub(replacer, redacted)
        redacted = JWT_TOKEN.sub(replacer, redacted)
        redacted = PRIVATE_KEY.sub(replacer, redacted)
        redacted = DB_CONN.sub(replacer, redacted)
        
        # Mask captured groups
        redacted = AWS_SECRET_KEY.sub(lambda m: m.group(0).replace(m.group(1), mask_char * len(m.group(1))), redacted)
        redacted = GENERIC_API_KEY.sub(lambda m: m.group(0).replace(m.group(1), mask_char * len(m.group(1))), redacted)
        
        return redacted
