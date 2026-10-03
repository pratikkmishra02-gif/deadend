from __future__ import annotations

import re
from typing import Optional

from phalanx_ai.types import DetectionResult, SessionContext, ThreatType, ThreatSeverity
from phalanx_ai.sentinel.detectors.base import BaseDetector
from phalanx_ai.sentinel.signatures.known_attacks import INJECTION_PATTERNS

class InjectionDetector(BaseDetector):
    """Detects prompt injection attacks using patterns and heuristics."""

    def __init__(self, sensitivity: float = 0.7, mode: str = 'strict'):
        self.sensitivity = sensitivity
        self.mode = mode
        self._compiled_patterns = [
            (re.compile(p["pattern"], re.IGNORECASE), p)
            for p in INJECTION_PATTERNS
        ]

    @property
    def name(self) -> str:
        return 'injection_detector'

    def _compute_heuristic_score(self, text: str) -> float:
        score = 0.0
        
        # Count imperative verbs typically used in overrides
        imperatives = re.findall(r'(?i)\b(ignore|forget|disregard|override|print|output|translate|repeat)\b', text)
        score += len(imperatives) * 0.1
        
        # Unusual formatting (excessive special characters/newlines)
        newlines = text.count('\n')
        if newlines > 5:
            score += 0.15
            
        special_chars = len(re.findall(r'[^a-zA-Z0-9\s.,?!]', text))
        if len(text) > 0 and (special_chars / len(text)) > 0.2:
            score += 0.2
            
        return min(1.0, score)

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

        # 2. Heuristic Scoring
        heuristic_score = self._compute_heuristic_score(text)
        
        # 3. Confidence Calculation
        base_confidence = 0.0
        if matched_signatures:
            base_confidence = 0.6 + (0.1 * len(matched_signatures))
            
        confidence = min(1.0, base_confidence + heuristic_score)

        is_threat = confidence >= self.sensitivity or len(matched_signatures) > 0

        if is_threat:
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.PROMPT_INJECTION,
                severity=max_severity if matched_signatures else ThreatSeverity.MEDIUM,
                confidence=confidence,
                detector_name=self.name,
                details={
                    "matched_signatures": matched_signatures,
                    "heuristic_score": heuristic_score,
                    "mode": self.mode
                }
            )

        return DetectionResult(
            detected=False,
            threat_type=ThreatType.PROMPT_INJECTION,
            severity=ThreatSeverity.INFO,
            confidence=0.0,
            detector_name=self.name,
            details={}
        )

__all__ = ["InjectionDetector"]
