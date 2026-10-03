from __future__ import annotations

import uuid

from deadend.sentinel.detectors.base import BaseDetector
from deadend.types import DetectionResult, SessionContext, ThreatSeverity, ThreatType


class CanaryDetector(BaseDetector):
    """Injects and monitors canary tokens in system prompts to detect leakage attempts."""

    def __init__(self, canary_strategy: str = 'rotating'):
        self.canary_strategy = canary_strategy
        self._active_canaries: set[str] = set()

    @property
    def name(self) -> str:
        return 'canary_detector'

    def generate_canary(self) -> str:
        """Generate a unique canary token."""
        return f"CANARY-{uuid.uuid4().hex}"

    def inject_canary(self, system_prompt: str) -> tuple[str, str]:
        """Injects a canary token into the system prompt.
        
        Args:
            system_prompt: The original system prompt.
            
        Returns:
            A tuple of (modified_system_prompt, canary_token).
        """
        token = self.generate_canary()
        self._active_canaries.add(token)
        
        # Simple injection: append to the end. In a real scenario, this could be hidden in XML/HTML comments.
        modified_prompt = f"{system_prompt}\n<!-- {token} -->"
        return modified_prompt, token

    async def detect(self, text: str, context: SessionContext | None = None) -> DetectionResult:
        # Check if any active canaries are present in the text
        leaked_canaries = [canary for canary in self._active_canaries if canary in text]
        
        if leaked_canaries:
            return DetectionResult(
                detected=True,
                threat_type=ThreatType.PROMPT_LEAKAGE,
                severity=ThreatSeverity.CRITICAL,
                confidence=1.0,  # 100% confidence if an exact UUID canary matches
                detector_name=self.name,
                details={
                    "leaked_canaries": leaked_canaries
                }
            )

        return DetectionResult(
            detected=False,
            threat_type=ThreatType.PROMPT_LEAKAGE,
            severity=ThreatSeverity.INFO,
            confidence=0.0,
            detector_name=self.name,
            details={}
        )

__all__ = ["CanaryDetector"]
