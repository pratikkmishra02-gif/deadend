"""
Deadend AI — OpenTelemetry Security Exporter
=============================================
Exports every Deadend security event (detections, scans, approvals)
as OpenTelemetry spans with GenAI semantic conventions.

This allows security teams to pipe Deadend telemetry into any OTel
collector backend (Grafana, Datadog, Splunk, Honeycomb, etc.) for
real-time dashboards, alerting, and compliance audit trails.

Requires the ``deadend[otel]`` extra::

    pip install deadend[otel]

If OTel dependencies are not installed, the exporter silently
disables itself (graceful degradation).
"""
from __future__ import annotations

from typing import Any

import structlog

from deadend.types import DetectionResult, ScanResult

logger = structlog.get_logger(__name__)

__all__ = ["OTelSecurityExporter"]

# Attempt to import OpenTelemetry
_OTEL_AVAILABLE = False
try:
    from opentelemetry import trace
    from opentelemetry.trace import StatusCode
    _OTEL_AVAILABLE = True
except ImportError:
    pass


class OTelSecurityExporter:
    """Exports Deadend security events as OpenTelemetry spans.

    Each detection is emitted as a span with structured attributes
    following the GenAI semantic conventions, making it trivially
    searchable in any OTel-compatible backend.

    Args:
        tracer_name: The OTel tracer name. Defaults to ``"deadend"``.
        service_name: The service name for resource attribution.
        enabled: Master switch. Auto-disables if OTel is not installed.

    Example::

        from deadend.audit.otel_exporter import OTelSecurityExporter

        exporter = OTelSecurityExporter()
        exporter.export_detection(detection_result)
        exporter.export_scan(scan_result)
    """

    def __init__(
        self,
        tracer_name: str = "deadend",
        service_name: str = "deadend-security",
        enabled: bool = True,
    ) -> None:
        self.tracer_name = tracer_name
        self.service_name = service_name
        self.enabled = enabled and _OTEL_AVAILABLE
        self._tracer = None

        if self.enabled:
            self._tracer = trace.get_tracer(
                self.tracer_name,
                schema_url="https://opentelemetry.io/schemas/1.28.0",
            )
            logger.info(
                "OTel security exporter initialized",
                tracer=tracer_name,
                service=service_name,
            )
        elif enabled and not _OTEL_AVAILABLE:
            logger.info(
                "OTel security exporter disabled: missing dependencies. "
                "Install with: pip install deadend[otel]"
            )

    def export_detection(
        self,
        detection: DetectionResult,
        session_id: str = "",
        agent_id: str = "default",
        parent_context: Any = None,
    ) -> None:
        """Export a single DetectionResult as an OTel span.

        Attributes emitted follow the ``deadend.*`` namespace:

        - ``deadend.detected``: bool
        - ``deadend.threat_type``: str
        - ``deadend.severity``: str
        - ``deadend.confidence``: float
        - ``deadend.detector_name``: str
        - ``deadend.session_id``: str
        - ``deadend.agent_id``: str
        - ``deadend.action_taken``: str (if available)
        """
        if not self.enabled or not self._tracer:
            return

        span_name = f"deadend.detection.{detection.detector_name}"

        with self._tracer.start_as_current_span(
            span_name,
            context=parent_context,
        ) as span:
            # Core detection attributes
            span.set_attribute("deadend.detected", detection.detected)
            span.set_attribute("deadend.severity", detection.severity.value)
            span.set_attribute("deadend.confidence", detection.confidence)
            span.set_attribute("deadend.detector_name", detection.detector_name)
            span.set_attribute("deadend.session_id", session_id)
            span.set_attribute("deadend.agent_id", agent_id)
            span.set_attribute("deadend.timestamp", detection.timestamp.isoformat())

            if detection.threat_type:
                span.set_attribute("deadend.threat_type", detection.threat_type.value)

            # Details as a span event (not attribute, to avoid large payloads)
            if detection.details:
                span.add_event(
                    "deadend.detection.details",
                    attributes={"details": str(detection.details)[:4096]},
                )

            # Set span status based on detection
            if detection.detected:
                span.set_status(
                    StatusCode.ERROR,
                    f"Threat detected: {detection.threat_type.value if detection.threat_type else 'unknown'}",
                )
            else:
                span.set_status(StatusCode.OK)

    def export_scan(
        self,
        scan: ScanResult,
        session_id: str = "",
        agent_id: str = "default",
    ) -> None:
        """Export a ScanResult (aggregated detection phase) as an OTel span.

        This creates a parent span for the scan phase with child spans
        for each individual detection.
        """
        if not self.enabled or not self._tracer:
            return

        span_name = f"deadend.scan.{scan.phase.value.lower()}"

        with self._tracer.start_as_current_span(span_name) as parent_span:
            parent_span.set_attribute("deadend.scan.passed", scan.passed)
            parent_span.set_attribute("deadend.scan.phase", scan.phase.value)
            parent_span.set_attribute("deadend.scan.action_taken", scan.action_taken.value)
            parent_span.set_attribute("deadend.scan.latency_ms", scan.latency_ms)
            parent_span.set_attribute("deadend.scan.detection_count", len(scan.detections))
            parent_span.set_attribute("deadend.session_id", session_id)
            parent_span.set_attribute("deadend.agent_id", agent_id)

            # Export each detection as a child span
            context = trace.set_span_in_context(parent_span)
            for detection in scan.detections:
                self.export_detection(
                    detection,
                    session_id=session_id,
                    agent_id=agent_id,
                    parent_context=context,
                )

            if not scan.passed:
                parent_span.set_status(
                    StatusCode.ERROR,
                    f"Scan failed: {scan.action_taken.value}",
                )
            else:
                parent_span.set_status(StatusCode.OK)

    def export_approval(
        self,
        request_id: str,
        decision: str,
        reviewer: str,
        severity: str,
        tool_name: str | None = None,
        session_id: str = "",
        reason: str = "",
    ) -> None:
        """Export a HITL approval decision as an OTel span."""
        if not self.enabled or not self._tracer:
            return

        with self._tracer.start_as_current_span("deadend.hitl.approval") as span:
            span.set_attribute("deadend.hitl.request_id", request_id)
            span.set_attribute("deadend.hitl.decision", decision)
            span.set_attribute("deadend.hitl.reviewer", reviewer)
            span.set_attribute("deadend.hitl.severity", severity)
            span.set_attribute("deadend.session_id", session_id)

            if tool_name:
                span.set_attribute("deadend.hitl.tool_name", tool_name)
            if reason:
                span.set_attribute("deadend.hitl.reason", reason)

            if decision == "REJECTED" or decision == "TIMEOUT":
                span.set_status(StatusCode.ERROR, f"HITL {decision}")
            else:
                span.set_status(StatusCode.OK)
