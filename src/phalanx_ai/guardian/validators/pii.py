from __future__ import annotations

import re
from typing import Optional

from phalanx_ai.types import DetectionResult, SessionContext, ThreatSeverity, ThreatType
from .base import BaseValidator

__all__ = ["PIIValidator"]

# Compiled regex patterns for PII
SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
PHONE_PATTERN = re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b')
CREDIT_CARD_PATTERN = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
DOB_PATTERN = re.compile(r'(?i)(?:dob|born|birthday)[^a-z0-9]{1,10}\b(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})\b')
ADDRESS_PATTERN = re.compile(r'\b\d+\s+[A-Za-z\s]+(?:St|Ave|Blvd|Rd|Ln|Ct|Dr)\b')
NAME_PATTERN = re.compile(r'(?i)\b(?:name:?\s+|Mr\.\s+|Mrs\.\s+|Dr\.\s+|Ms\.\s+)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b')

def luhn_check(card_num: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(c) for c in card_num if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


class PIIValidator(BaseValidator):
    """Detects personally identifiable information in output."""

    @property
    def name(self) -> str:
        return 'pii_validator'

    async def validate(self, text: str, context: Optional[SessionContext] = None) -> DetectionResult:
        findings = []
        
        if SSN_PATTERN.search(text):
            findings.append("SSN detected")
        
        if EMAIL_PATTERN.search(text):
            findings.append("Email address detected")
            
        if PHONE_PATTERN.search(text):
            findings.append("Phone number detected")
            
        if IP_PATTERN.search(text):
            findings.append("IP address detected")
            
        if ADDRESS_PATTERN.search(text):
            findings.append("Physical address detected")
            
        if DOB_PATTERN.search(text):
            findings.append("Date of birth detected")
            
        if NAME_PATTERN.search(text):
            findings.append("Name pattern detected")
            
        for match in CREDIT_CARD_PATTERN.finditer(text):
            if luhn_check(match.group()):
                findings.append("Credit card number detected")
                break
                
        is_threat = len(findings) > 0
        return DetectionResult(
            detected=is_threat,
            threat_type=ThreatType.PII_EXPOSURE if is_threat else None,
            severity=ThreatSeverity.HIGH if is_threat else ThreatSeverity.LOW,
            details={"findings": findings} if is_threat else {},
            module=self.name
        )

    async def redact(self, text: str, mask_char: str = '█') -> str:
        redacted = text
        
        # Helper to redact matches
        def replacer(match):
            return mask_char * len(match.group(0))

        redacted = SSN_PATTERN.sub(replacer, redacted)
        redacted = EMAIL_PATTERN.sub(replacer, redacted)
        redacted = PHONE_PATTERN.sub(replacer, redacted)
        redacted = IP_PATTERN.sub(replacer, redacted)
        redacted = ADDRESS_PATTERN.sub(replacer, redacted)
        
        # For DOB and Name, we only want to mask the actual matched group, not the prefix, but for simplicity:
        redacted = DOB_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), mask_char * len(m.group(1))), redacted)
        redacted = NAME_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), mask_char * len(m.group(1))), redacted)
        
        # Redact credit cards using Luhn
        for match in CREDIT_CARD_PATTERN.finditer(text):
            if luhn_check(match.group()):
                cc_text = match.group()
                redacted = redacted.replace(cc_text, mask_char * len(cc_text))
                
        return redacted
