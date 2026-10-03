from __future__ import annotations

from typing import Any, Optional

__all__ = [
    "DeadendError",
    "ConfigurationError",
    "PolicyError",
    "PolicyLoadError",
    "PolicyValidationError",
    "DetectionError",
    "ThreatDetectedError",
    "MonitorError",
    "CircuitBreakerOpenError",
    "ValidationError",
    "AuditError",
    "IntegrationError",
]


class DeadendError(Exception):
    """Base exception for all Deadend AI errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message


class ConfigurationError(DeadendError):
    """Raised when there is an error in the Deadend configuration."""
    pass


class PolicyError(DeadendError):
    """Base exception for policy-related errors."""
    pass


class PolicyLoadError(PolicyError):
    """Raised when a policy file cannot be loaded."""
    pass


class PolicyValidationError(PolicyError):
    """Raised when a policy definition is invalid."""
    pass


class DetectionError(DeadendError):
    """Raised when a detector fails to execute properly."""
    pass


class ThreatDetectedError(DeadendError):
    """
    Raised when a threat is detected and the configured action is to BLOCK.
    """

    def __init__(
        self,
        message: str,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        confidence: float = 0.0,
        details: str = "",
        detector_name: str = "unknown",
    ) -> None:
        """
        Initialize a ThreatDetectedError.

        Args:
            message: The exception message.
            threat_type: The type of threat detected.
            severity: The severity of the threat.
            confidence: The confidence level (0.0 to 1.0) of the detection.
            details: Additional details about the threat.
            detector_name: The name of the detector that triggered this error.
        """
        super().__init__(message)
        self.threat_type = threat_type
        self.severity = severity
        self.confidence = confidence
        self.details = details
        self.detector_name = detector_name

    def __str__(self) -> str:
        base = f"ThreatDetectedError: {self.message}"
        if self.threat_type:
            base += f" [Type: {self.threat_type}, Severity: {self.severity}, Confidence: {self.confidence}]"
        if self.details:
            base += f"\nDetails: {self.details}"
        return base


class MonitorError(DeadendError):
    """Raised when there is an error in the monitoring system."""
    pass


class CircuitBreakerOpenError(DeadendError):
    """Raised when an operation is blocked because a circuit breaker is open."""
    pass


class ValidationError(DeadendError):
    """Raised when input/output validation fails outside of policy evaluation."""
    pass


class AuditError(DeadendError):
    """Raised when an audit log fails to write or process."""
    pass


class IntegrationError(DeadendError):
    """Raised when a third-party integration (e.g., LangChain, OpenAI) fails."""
    pass
