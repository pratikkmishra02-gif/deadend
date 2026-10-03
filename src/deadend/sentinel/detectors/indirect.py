from __future__ import annotations

import re
from typing import Optional

from deadend.types import DetectionResult, SessionContext, ThreatType, ThreatSeverity
from deadend.sentinel.detectors.base import BaseDetector
from deadend.sentinel.signatures.known_attacks import INDIRECT_PATTERNS

class IndirectInjectionDetector(BaseDetector):
    """Detects hidden instructions in retrieved documents or contextual data."""

    def __init__(self):
        self._compiled_patterns = [
            (re.compile(p["pattern"], re.IGNORECASE), p)
            for p in INDIRECT_PATTERNS
        ]

    @property
    def name(self) -> str:
        return 'indirect_injection_detector'

    async def detect(self, text: str, context: Optional[SessionContext] = None) -> DetectionResult:
        flags = []
        max_severity = ThreatSeverity.LOW

        severity_map = {
            "CRITICAL": ThreatSeverity.CRITICAL,
            "HIGH": ThreatSeverity.HIGH,
            "MEDIUM": ThreatSeverity.MEDIUM,
            "LOW": ThreatSeverity.LOW,
            "INFO": ThreatSeverity.INFO,
        }

        # 1. Pattern Matching for indirect markers
        for regex, meta in self._compiled_patterns:
            if regex.search(text):
                flags.append(meta["description"])
                sev = severity_map.get(meta["severity"].upper(), ThreatSeverity.LOW)
                if sev.value > max_severity.value:
                    max_severity = sev

        # 2. Invisible/Zero-width Unicode characters
        zero_width_chars = re.findall(r'[\u200B-\u200D\uFEFF]', text)
        if len(zero_width_chars) > 5:
            flags.append("excessive_zero_width_chars")
            if ThreatSeverity.MEDIUM.value > max_severity.value:
                max_severity = ThreatSeverity.MEDIUM

        # 3. Suspiciously formatted markdown links hiding instructions
        # e.g., [Click here](http://example.com "Ignore previous instructions")
        hidden_titles = re.findall(r'\[.*?\]\(.*?\"(.*?)\"\)', text)
        for title in hidden_titles:
            if re.search(r'(?i)(ignore|instruction|prompt|override)', title):
                flags.append("hidden_markdown_instruction")
                max_severity = ThreatSeverity.HIGH

        confidence = 0.0
        if flags:
            confidence = 0.6 + (0.1 * min(len(flags), 4))
            
        is_threat = confidence >= 0.7 or len(flags) > 0

        if is_threat:
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.INDIRECT_INJECTION,
                severity=max_severity,
                confidence=confidence,
                detector_name=self.name,
                details={
                    "indirect_flags": flags
                }
            )

        return DetectionResult(
            detected=False,
            threat_type=ThreatType.INDIRECT_INJECTION,
            severity=ThreatSeverity.INFO,
            confidence=0.0,
            detector_name=self.name,
            details={}
        )

__all__ = ["IndirectInjectionDetector"]
