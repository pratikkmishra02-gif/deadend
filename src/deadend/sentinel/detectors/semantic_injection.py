"""
Deadend AI — Semantic Injection Detector
==========================================
Uses the ProtectAI DeBERTa-v3 model from Hugging Face to detect prompt
injections semantically — catching zero-day attacks that regex signatures miss.

The model runs entirely locally (no API calls). It is lazy-loaded on first use
and requires the ``deadend[ml]`` extra::

    pip install deadend[ml]

If the ML dependencies are not installed, this detector silently disables
itself and returns no detections (graceful degradation).
"""
from __future__ import annotations

import structlog

from deadend.sentinel.detectors.base import BaseDetector
from deadend.types import DetectionResult, SessionContext, ThreatSeverity, ThreatType

logger = structlog.get_logger(__name__)

__all__ = ["SemanticInjectionDetector"]


class SemanticInjectionDetector(BaseDetector):
    """
    ML-powered prompt injection detector using ProtectAI DeBERTa-v3.

    Classifies input text as INJECTION or SAFE with a confidence score.
    Only fires when confidence exceeds ``threshold`` (default 0.85).

    Args:
        model_name: Hugging Face model identifier.
        threshold: Minimum confidence to report a detection.
    """

    def __init__(
        self,
        model_name: str = "protectai/deberta-v3-base-prompt-injection-v2",
        threshold: float = 0.85,
    ) -> None:
        self.model_name = model_name
        self.threshold = threshold
        self._pipeline = None
        self._ml_available = False
        self._load_attempted = False

        try:
            import torch  # noqa: F401
            import transformers  # noqa: F401
            self._ml_available = True
        except ImportError:
            logger.info(
                "SemanticInjectionDetector disabled: missing ML dependencies. "
                "Install with: pip install deadend[ml]"
            )

    @property
    def name(self) -> str:
        return "semantic_injection_detector"

    def _load_model(self) -> None:
        """Lazy-load the HF pipeline on first scan to avoid startup delay."""
        if self._load_attempted or not self._ml_available:
            return
        self._load_attempted = True

        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from transformers import pipeline as hf_pipeline

            logger.info(
                "Loading semantic injection model (first run may download ~500 MB)...",
                model=self.model_name,
            )
            try:
                self._pipeline = hf_pipeline(
                    "text-classification",
                    model=self.model_name,
                    device="cpu",
                    truncation=True,
                    max_length=512,
                )
                logger.info("Semantic injection model loaded successfully")
            except Exception as e:
                logger.error("Failed to load semantic injection model", error=str(e))
                self._ml_available = False

    async def detect(
        self, text: str, context: SessionContext | None = None
    ) -> DetectionResult:
        """Run semantic classification on the input text.

        Returns a DetectionResult. If ML is unavailable or text is clean,
        returns ``detected=False``.
        """
        # Graceful degradation when ML deps are missing
        if not self._ml_available:
            return DetectionResult(
                detected=False,
                threat_type=ThreatType.PROMPT_INJECTION,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                detector_name=self.name,
            )

        self._load_model()
        if self._pipeline is None:
            return DetectionResult(
                detected=False,
                threat_type=ThreatType.PROMPT_INJECTION,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                detector_name=self.name,
            )

        # Truncate to model's practical limit
        safe_text = text[:2000].strip()
        if not safe_text:
            return DetectionResult(
                detected=False,
                threat_type=ThreatType.PROMPT_INJECTION,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                detector_name=self.name,
            )

        try:
            # Model returns: [{'label': 'INJECTION', 'score': 0.99}]
            result = self._pipeline(safe_text)[0]
            label = result.get("label", "").upper()
            score = float(result.get("score", 0.0))

            if "INJECTION" in label and score >= self.threshold:
                logger.warning(
                    "Semantic injection detected",
                    confidence=score,
                    model=self.model_name,
                )
                return DetectionResult(
                    detected=True,
                    threat_type=ThreatType.PROMPT_INJECTION,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=score,
                    details={
                        "model": self.model_name,
                        "label": label,
                        "reason": "ML classifier detected prompt injection intent",
                    },
                    detector_name=self.name,
                )
        except Exception as e:
            logger.error("Semantic injection scan failed", error=str(e))

        return DetectionResult(
            detected=False,
            threat_type=ThreatType.PROMPT_INJECTION,
            severity=ThreatSeverity.INFO,
            confidence=0.0,
            detector_name=self.name,
        )
