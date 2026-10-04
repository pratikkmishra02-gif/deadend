from __future__ import annotations

import re

from deadend.types import DetectionResult, SessionContext, ThreatSeverity, ThreatType

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
    
    def __init__(self, model_name: str = "dslim/bert-base-NER") -> None:
        self.model_name = model_name
        self._pipeline = None
        self._ml_available = False
        self._load_attempted = False
        
        try:
            import torch  # noqa: F401
            import transformers  # noqa: F401
            self._ml_available = True
        except ImportError:
            pass

    def _load_model(self) -> None:
        if self._load_attempted or not self._ml_available:
            return
        self._load_attempted = True
        
        import structlog
        logger = structlog.get_logger(__name__)
        
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from transformers import pipeline as hf_pipeline
            logger.info("Loading PII NER model...", model=self.model_name)
            try:
                self._pipeline = hf_pipeline(
                    "ner",
                    model=self.model_name,
                    device="cpu",
                    aggregation_strategy="simple"
                )
            except Exception as e:
                logger.error("Failed to load PII model", error=str(e))
                self._ml_available = False

    @property
    def name(self) -> str:
        return 'pii_validator'

    async def validate(self, text: str, context: SessionContext | None = None) -> DetectionResult:
        findings = []
        
        # ML NER check for Names, Orgs, Locations
        if self._ml_available:
            self._load_model()
            if self._pipeline:
                try:
                    entities = self._pipeline(text[:2000])
                    for ent in entities:
                        if ent['score'] > 0.85:
                            findings.append(f"ML Detected: {ent['entity_group']} ({ent['word']})")
                except Exception:
                    pass
        
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
        
        # ML NER Redaction (do this first)
        if self._ml_available:
            self._load_model()
            if self._pipeline:
                try:
                    entities = self._pipeline(text[:2000])
                    # Sort entities by start index descending to avoid index shifting when replacing
                    for ent in sorted(entities, key=lambda x: x['start'], reverse=True):
                        if ent['score'] > 0.85:
                            start, end = ent['start'], ent['end']
                            # Mask the exact characters
                            mask_len = end - start
                            redacted = redacted[:start] + (mask_char * mask_len) + redacted[end:]
                except Exception:
                    pass
                    
        # Regex Helper to redact matches
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
