from __future__ import annotations

import re
from typing import Optional

from deadend.types import DetectionResult, SessionContext, ThreatType, ThreatSeverity, AgentEvent
from deadend.sentinel.detectors.base import BaseDetector

class SemanticDriftDetector(BaseDetector):
    """Tracks conversation trajectory for multi-turn attacks or topic escalation."""

    def __init__(self, window_size: int = 5, drift_threshold: float = 0.7):
        self.window_size = window_size
        self.drift_threshold = drift_threshold
        
        # Simple keywords for sensitive topics indicating escalation
        self.sensitive_keywords = {
            "hacking", "exploit", "bypass", "password", "credentials",
            "malware", "virus", "illegal", "bomb", "weapon"
        }

    @property
    def name(self) -> str:
        return 'semantic_drift_detector'
        
    def _extract_keywords(self, text: str) -> set[str]:
        """Naively extract alphabetic words as keywords."""
        words = re.findall(r'\b[a-zA-Z]{4,}\b', text.lower())
        return set(words)

    async def detect(self, text: str, context: Optional[SessionContext] = None) -> DetectionResult:
        if not context or not context.events:
            # No context means no drift can be detected
            return DetectionResult(
                detected=False,
                threat_type=ThreatType.TOOL_ABUSE,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                detector_name=self.name,
                details={"reason": "no_context"}
            )
            
        recent_events = context.events[-self.window_size:]
        
        # Build baseline vocabulary from history
        baseline_keywords = set()
        for event in recent_events[:-1]:  # Exclude the current event if it's already in history
            baseline_keywords.update(self._extract_keywords(event.content))
            
        current_keywords = self._extract_keywords(text)
        
        if not baseline_keywords or not current_keywords:
            return DetectionResult(
                detected=False,
                threat_type=ThreatType.TOOL_ABUSE,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                detector_name=self.name,
                details={"reason": "insufficient_keywords"}
            )

        # Calculate Jaccard similarity between baseline and current
        intersection = current_keywords.intersection(baseline_keywords)
        union = current_keywords.union(baseline_keywords)
        similarity = len(intersection) / len(union) if len(union) > 0 else 1.0
        
        drift = 1.0 - similarity
        
        # Check for sensitive topic escalation
        sensitive_matches = current_keywords.intersection(self.sensitive_keywords)
        escalation = len(sensitive_matches) > 0
        
        confidence = drift
        if escalation:
            confidence = min(1.0, confidence + 0.3)
            
        is_threat = confidence >= self.drift_threshold
        
        if is_threat:
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.MULTI_TURN_ATTACK,
                severity=ThreatSeverity.MEDIUM if not escalation else ThreatSeverity.HIGH,
                confidence=confidence,
                detector_name=self.name,
                details={
                    "drift_score": drift,
                    "escalation_topics": list(sensitive_matches),
                    "baseline_vocab_size": len(baseline_keywords)
                }
            )
            
        return DetectionResult(
            detected=False,
            threat_type=ThreatType.MULTI_TURN_ATTACK,
            severity=ThreatSeverity.INFO,
            confidence=0.0,
            detector_name=self.name,
            details={}
        )

__all__ = ["SemanticDriftDetector"]
