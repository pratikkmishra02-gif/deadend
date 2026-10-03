from __future__ import annotations

import re
from typing import Optional

from deadend.types import DetectionResult, SessionContext, ThreatType, ThreatSeverity
from deadend.sentinel.detectors.base import BaseDetector
from deadend.sentinel.signatures.known_attacks import JAILBREAK_PATTERNS

class JailbreakDetector(BaseDetector):
    """Detects jailbreak attempts using known signatures and structural analysis."""

    def __init__(self):
        self._compiled_patterns = [
            (re.compile(p["pattern"], re.IGNORECASE), p)
            for p in JAILBREAK_PATTERNS
        ]

    @property
    def name(self) -> str:
        return 'jailbreak_detector'

    async def detect(self, text: str, context: Optional[SessionContext] = None) -> DetectionResult:
        matched_signatures = []
        max_severity = ThreatSeverity.LOW
        
        severity_map = {
            "CRITICAL": ThreatSeverity.CRITICAL,
            "HIGH": ThreatSeverity.HIGH,
            "MEDIUM": ThreatSeverity.MEDIUM,
            "LOW": ThreatSeverity.LOW,
            "INFO": ThreatSeverity.INFO,
        }
        severity_order = {ThreatSeverity.INFO: 0, ThreatSeverity.LOW: 1, ThreatSeverity.MEDIUM: 2, ThreatSeverity.HIGH: 3, ThreatSeverity.CRITICAL: 4}

        # 1. Pattern Matching
        for regex, meta in self._compiled_patterns:
            if regex.search(text):
                matched_signatures.append(meta["description"])
                sev = severity_map.get(meta["severity"].upper(), ThreatSeverity.LOW)
                if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
                    max_severity = sev

        # 2. Structural Analysis
        structural_flags = []
        if len(text) > 2000 and "system" in text.lower():
            structural_flags.append("long_system_prompt_override")
        
        # Nested instruction detection
        if len(re.findall(r'\[.*?\[.*?\].*?\]', text)) > 0:
            structural_flags.append("nested_instructions")

        confidence = 0.0
        if matched_signatures:
            confidence += 0.7 + (0.1 * min(len(matched_signatures), 3))
        if structural_flags:
            confidence += 0.2 * len(structural_flags)
            
        confidence = min(1.0, confidence)
        is_threat = confidence >= 0.7 or len(matched_signatures) > 0

        if is_threat:
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.JAILBREAK,
                severity=max_severity if matched_signatures else ThreatSeverity.MEDIUM,
                confidence=confidence,
                detector_name=self.name,
                details={
                    "matched_signatures": matched_signatures,
                    "structural_flags": structural_flags
                }
            )

        return DetectionResult(
            detected=False,
            threat_type=ThreatType.JAILBREAK,
            severity=ThreatSeverity.INFO,
            confidence=0.0,
            detector_name=self.name,
            details={}
        )

__all__ = ["JailbreakDetector"]
