from __future__ import annotations

import re
from typing import Optional

from deadend.types import DetectionResult, SessionContext, ThreatSeverity, ThreatType
from .base import BaseValidator

__all__ = ["ToxicityValidator"]

# Simple keyword lists for toxicity categories
CATEGORIES = {
    "violence": ["kill", "murder", "attack", "assault", "destroy"],
    "hate_speech": ["slur1", "slur2", "racist", "bigot"], # Add actual tokens or use model in real app
    "self_harm": ["suicide", "cut myself", "end it all"],
    "illegal_activity": ["hack", "steal", "rob", "fraud", "scam"]
}

class ToxicityValidator(BaseValidator):
    """Detects harmful or toxic content."""

    def __init__(self, blocked_topics: list[str] | None = None, sensitivity: float = 0.7) -> None:
        self.blocked_topics = blocked_topics or []
        self.sensitivity = sensitivity

    @property
    def name(self) -> str:
        return 'toxicity_validator'

    async def validate(self, text: str, context: Optional[SessionContext] = None) -> DetectionResult:
        text_lower = text.lower()
        findings = []
        
        # Check categories
        for category, keywords in CATEGORIES.items():
            matches = [kw for kw in keywords if kw in text_lower]
            if len(matches) > (1.0 - self.sensitivity) * 5: # simple thresholding
                findings.append(f"Toxic content ({category})")
                
        # Check blocked topics
        for topic in self.blocked_topics:
            if topic.lower() in text_lower:
                findings.append(f"Blocked topic detected: {topic}")
                
        is_threat = len(findings) > 0
        return DetectionResult(
            detected=is_threat,
            threat_type=ThreatType.TOXICITY if is_threat else None,
            severity=ThreatSeverity.MEDIUM if is_threat else ThreatSeverity.LOW,
            details={"toxicity_findings": findings} if is_threat else {},
            module=self.name
        )
