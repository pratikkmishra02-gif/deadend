"""
Deadend AI — Semantic Command Monitor
========================================
Uses Hugging Face ML models to detect malicious OS command injection,
reverse shells, and RCE payloads in agent tool calls.

The monitor runs entirely locally (no API calls). It is lazy-loaded on
first use and requires the ``deadend[ml]`` extra::

    pip install deadend[ml]

If the ML dependencies are not installed, this monitor silently disables
itself and returns no detections (graceful degradation).
"""
from __future__ import annotations

import structlog

from deadend.types import AgentEvent, SessionContext, DetectionResult, ThreatSeverity, ThreatType
from deadend.warden.monitors.base import BaseMonitor

logger = structlog.get_logger(__name__)

__all__ = ["SemanticCommandMonitor"]


class SemanticCommandMonitor(BaseMonitor):
    """
    ML-powered malicious command detection for Warden.

    Scans tool arguments for OS command injection, reverse shells,
    and RCE payloads using a fine-tuned BERT classifier.

    Args:
        model_name: Hugging Face model identifier.
        threshold: Minimum confidence to report a detection.
    """

    def __init__(
        self,
        model_name: str = "protectai/deberta-v3-base-prompt-injection-v2",
        threshold: float = 0.80,
    ) -> None:
        super().__init__()
        self.model_name = model_name
        self.threshold = threshold
        self._pipeline = None
        self._ml_available = False
        self._load_attempted = False

        try:
            import transformers  # noqa: F401
            import torch  # noqa: F401
            self._ml_available = True
        except ImportError:
            logger.info(
                "SemanticCommandMonitor disabled: missing ML dependencies. "
                "Install with: pip install deadend[ml]"
            )

    @property
    def name(self) -> str:
        return "semantic_command_monitor"

    def _load_model(self) -> None:
        """Lazy-load the HF pipeline on first check."""
        if self._load_attempted or not self._ml_available:
            return
        self._load_attempted = True

        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from transformers import pipeline as hf_pipeline

            logger.info(
                "Loading semantic command detection model...",
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
                logger.info("Semantic command model loaded successfully")
            except Exception as e:
                logger.error("Failed to load semantic command model", error=str(e))
                self._ml_available = False

    def _extract_command(self, event: AgentEvent) -> str:
        """Extract the command string from a tool call event."""
        parts: list[str] = []

        if isinstance(event.tool_args, dict):
            # Check common argument names for bash/python/code tools
            for key in ("command", "cmd", "code", "script", "query", "input", "shell"):
                val = event.tool_args.get(key)
                if isinstance(val, str) and val.strip():
                    parts.append(val)
            # If none matched, stringify the whole dict
            if not parts:
                parts.append(str(event.tool_args))
        elif isinstance(event.tool_args, str):
            parts.append(event.tool_args)

        if event.content:
            parts.append(event.content)

        return " ".join(parts)

    async def check(self, event: AgentEvent, session: SessionContext) -> DetectionResult:
        """Run semantic command classification on tool call events.

        Only processes ``tool_call`` events. Returns ``detected=False`` for
        all other event types or when ML is unavailable.
        """
        # Only scan tool calls
        if event.event_type != "tool_call":
            return DetectionResult(
                detected=False,
                threat_type=ThreatType.TOOL_ABUSE,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                detector_name=self.name,
            )

        # Graceful degradation
        if not self._ml_available:
            return DetectionResult(
                detected=False,
                threat_type=ThreatType.TOOL_ABUSE,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                detector_name=self.name,
            )

        self._load_model()
        if self._pipeline is None:
            return DetectionResult(
                detected=False,
                threat_type=ThreatType.TOOL_ABUSE,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                detector_name=self.name,
            )

        command_text = self._extract_command(event)
        if not command_text.strip():
            return DetectionResult(
                detected=False,
                threat_type=ThreatType.TOOL_ABUSE,
                severity=ThreatSeverity.INFO,
                confidence=0.0,
                detector_name=self.name,
            )

        # Truncate for model limit
        safe_text = command_text[:1000]

        try:
            result = self._pipeline(safe_text)[0]
            label = result.get("label", "").upper()
            score = float(result.get("score", 0.0))

            # Canstralian model labels include INJECTION, MALWARE, RCE, etc.
            malicious_labels = {"INJECTION", "MALWARE", "RCE", "ATTACK", "MALICIOUS"}
            if any(ml in label for ml in malicious_labels) and score >= self.threshold:
                logger.warning(
                    "Semantic command injection detected",
                    label=label,
                    confidence=score,
                    tool=event.tool_name,
                    model=self.model_name,
                )
                return DetectionResult(
                    detected=True,
                    threat_type=ThreatType.TOOL_ABUSE,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=score,
                    details={
                        "model": self.model_name,
                        "label": label,
                        "tool": event.tool_name,
                        "reason": "ML classifier detected OS command injection / RCE payload",
                    },
                    detector_name=self.name,
                )
        except Exception as e:
            logger.error("Semantic command scan failed", error=str(e))

        return DetectionResult(
            detected=False,
            threat_type=ThreatType.TOOL_ABUSE,
            severity=ThreatSeverity.INFO,
            confidence=0.0,
            detector_name=self.name,
        )
