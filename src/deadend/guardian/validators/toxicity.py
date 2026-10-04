from __future__ import annotations

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
    
    def __init__(
        self,
        blocked_topics: list[str] | None = None,
        sensitivity: float = 0.7,
        model_name: str = "unitary/toxic-bert"
    ) -> None:
        self.blocked_topics = blocked_topics or []
        self.sensitivity = sensitivity
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
            logger.info("Loading toxicity ML model...", model=self.model_name)
            try:
                # toxic-bert outputs multi-label toxicity scores
                self._pipeline = hf_pipeline(
                    "text-classification",
                    model=self.model_name,
                    device="cpu",
                    truncation=True,
                    max_length=512,
                    top_k=None # return all scores
                )
            except Exception as e:
                logger.error("Failed to load toxicity model", error=str(e))
                self._ml_available = False

    @property
    def name(self) -> str:
        return 'toxicity_validator'

    async def validate(self, text: str, context: SessionContext | None = None) -> DetectionResult:
        text_lower = text.lower()
        findings = []
        # Run ML model if available
        if self._ml_available:
            self._load_model()
            if self._pipeline:
                try:
                    # ML returns list of dicts: [{'label': 'toxic', 'score': 0.9}, ...]
                    results = self._pipeline(text_lower[:2000])[0]
                    for r in results:
                        if r["score"] > (1.0 - self.sensitivity): # Use sensitivity as threshold
                            findings.append(f"ML Detected: {r['label']} (score: {r['score']:.2f})")
                except Exception:
                    pass

        # Fallback to Check categories
        if not findings:
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
