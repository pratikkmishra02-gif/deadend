from __future__ import annotations

import asyncio
import time
from typing import Optional

from phalanx_ai.types import ScanResult, SessionContext, ScanPhase
from phalanx_ai.guardian.validators.base import BaseValidator

__all__ = ["GuardianEngine"]


class GuardianEngine:
    """Orchestrates all validators on model outputs."""

    def __init__(self, validators: list[BaseValidator] | None = None, parallel: bool = True) -> None:
        """
        Initialize the GuardianEngine.

        Args:
            validators: List of validators to use.
            parallel: Whether to run validators in parallel.
        """
        self.validators = validators or []
        self.parallel = parallel

    async def validate(self, text: str, context: Optional[SessionContext] = None) -> ScanResult:
        """
        Validate text against all enabled validators.

        Args:
            text: Output text to validate.
            context: Current session context.

        Returns:
            ScanResult containing all detections.
        """
        start_time = time.perf_counter()
        detections = []
        
        enabled_validators = [v for v in self.validators if v.enabled]
        
        if self.parallel:
            tasks = [v.validate(text, context) for v in enabled_validators]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if not isinstance(res, Exception) and res.detected:
                    detections.append(res)
        else:
            for v in enabled_validators:
                res = await v.validate(text, context)
                if res.detected:
                    detections.append(res)

        latency = (time.perf_counter() - start_time) * 1000

        return ScanResult(
            passed=len(detections) == 0,
            detections=detections,
            latency_ms=latency,
            phase=ScanPhase.OUTPUT
        )

    async def redact(self, text: str, strategy: str = 'mask', mask_char: str = '█') -> str:
        """
        Applies redaction based on validator findings.

        Args:
            text: Text to redact.
            strategy: Redaction strategy.
            mask_char: Character to use for masking.

        Returns:
            Redacted string.
        """
        redacted_text = text
        if strategy == 'mask':
            for validator in self.validators:
                if validator.enabled:
                    redacted_text = await validator.redact(redacted_text, mask_char)
        return redacted_text
