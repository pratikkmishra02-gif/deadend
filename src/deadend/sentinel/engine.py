from __future__ import annotations

import asyncio
import time

import structlog

from deadend.policy.models import SentinelPolicy
from deadend.sentinel.detectors.base import BaseDetector
from deadend.sentinel.detectors.canary import CanaryDetector
from deadend.sentinel.detectors.encoding import EncodingDetector
from deadend.sentinel.detectors.indirect import IndirectInjectionDetector
from deadend.sentinel.detectors.injection import InjectionDetector
from deadend.sentinel.detectors.jailbreak import JailbreakDetector
from deadend.sentinel.detectors.semantic_drift import SemanticDriftDetector
from deadend.sentinel.detectors.semantic_injection import SemanticInjectionDetector
from deadend.types import (
    DetectionResult,
    ScanPhase,
    ScanResult,
    SessionContext,
    ThreatSeverity,
)

logger = structlog.get_logger(__name__)

class SentinelEngine:
    """Orchestrates multiple prompt security detectors to evaluate incoming text."""

    def __init__(
        self, 
        detectors: list[BaseDetector] | None = None, 
        parallel: bool = True,
        policy: SentinelPolicy | None = None
    ):
        """Initialize SentinelEngine with a list of detectors.

        Args:
            detectors: List of BaseDetector instances. If None, default detectors are used.
            parallel: Whether to run detectors in parallel.
            policy: Configuration policy for Sentinel.
        """
        self.parallel = parallel
        self.policy = policy
        
        if detectors is None:
            self.detectors = {
                detector.name: detector for detector in [
                    InjectionDetector(),
                    JailbreakDetector(),
                    EncodingDetector(),
                    CanaryDetector(),
                    IndirectInjectionDetector(),
                    SemanticDriftDetector(),
                    SemanticInjectionDetector()
                ]
            }
        else:
            self.detectors = {d.name: d for d in detectors}
            
        if self.policy:
            for name, detector in self.detectors.items():
                det_config = self.policy.detectors.get(name)
                if det_config:
                    detector.enabled = det_config.enabled
                    if hasattr(detector, 'threshold') and det_config.threshold is not None:
                        detector.threshold = det_config.threshold

    def add_detector(self, detector: BaseDetector) -> None:
        """Add a detector to the engine."""
        self.detectors[detector.name] = detector
        logger.debug("Added detector", detector=detector.name)

    def remove_detector(self, name: str) -> None:
        """Remove a detector from the engine."""
        if name in self.detectors:
            del self.detectors[name]
            logger.debug("Removed detector", detector=name)

    async def scan(self, text: str, context: SessionContext | None = None) -> ScanResult:
        """Scan text using all enabled detectors.

        Args:
            text: The text to analyze.
            context: Optional session context for contextual detectors.

        Returns:
            ScanResult containing all found threats and metadata.
        """
        start_time = time.perf_counter()
        active_detectors = [d for d in self.detectors.values() if d.enabled]
        
        logger.debug("Starting scan", text_length=len(text), active_detectors=len(active_detectors))
        
        results: list[DetectionResult] = []
        if self.parallel:
            tasks = [d.detect(text, context) for d in active_detectors]
            scan_results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, res in enumerate(scan_results):
                if isinstance(res, Exception):
                    logger.error("Detector failed", detector=active_detectors[i].name, error=str(res))
                elif isinstance(res, DetectionResult) and res.detected:
                    results.append(res)
        else:
            for d in active_detectors:
                try:
                    res = await d.detect(text, context)
                    if res.detected:
                        results.append(res)
                except Exception as e:
                    logger.error("Detector failed", detector=d.name, error=str(e))
        
        latency_ms = (time.perf_counter() - start_time) * 1000
        is_safe = len(results) == 0
        
        # Sort threats by severity
        severity_order = {ThreatSeverity.CRITICAL: 4, ThreatSeverity.HIGH: 3, ThreatSeverity.MEDIUM: 2, ThreatSeverity.LOW: 1, ThreatSeverity.INFO: 0}
        results.sort(key=lambda x: severity_order.get(x.severity, 0), reverse=True)
        
        return ScanResult(
            passed=is_safe,
            phase=ScanPhase.INPUT,
            detections=results,
            latency_ms=latency_ms,
        )

__all__ = ["SentinelEngine"]
