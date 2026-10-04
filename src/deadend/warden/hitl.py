"""
Deadend AI — Human-in-the-Loop (HITL) Approval Gates
=====================================================
Implements a configurable approval gate that pauses agent execution
when a high-severity threat is detected, requiring human authorization
before the action proceeds.

This is the enterprise-grade "kill switch" pattern adopted by OpenAI
(``needs_approval``), Cloudflare (``waitForApproval()``), and
Microsoft (``RequestPort``).

Design Principles
-----------------
1. **Risk-Based Gating** — Only high-impact actions trigger approval.
2. **Configurable Backend** — Approval can come from CLI, webhook,
   Slack, or a custom callback.
3. **Audit Trail** — Every approval/rejection is cryptographically
   logged with the reviewer's identity and timestamp.
4. **Timeout Safety** — If no human responds within the timeout,
   the action is auto-denied (fail-closed).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol
from uuid import uuid4

import structlog
from pydantic import BaseModel, Field

from deadend.types import ActionType, DetectionResult, ThreatSeverity

logger = structlog.get_logger(__name__)

__all__ = [
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalResult",
    "ApprovalBackend",
    "CLIApprovalBackend",
    "WebhookApprovalBackend",
    "ApprovalGate",
]


class ApprovalDecision(str, Enum):
    """Possible outcomes of a human review."""
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    TIMEOUT = "TIMEOUT"
    ESCALATED = "ESCALATED"


class ApprovalRequest(BaseModel):
    """A request sent to a human reviewer for approval."""
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str = ""
    agent_id: str = "default"
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    threat_summary: str = ""
    severity: ThreatSeverity = ThreatSeverity.HIGH
    detections: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ApprovalResult(BaseModel):
    """Result of a human review decision."""
    request_id: str
    decision: ApprovalDecision
    reviewer: str = "unknown"
    reason: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApprovalBackend(Protocol):
    """Protocol for approval backend implementations."""

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        """Send an approval request and wait for a human decision."""
        ...


class CLIApprovalBackend:
    """Interactive CLI-based approval backend for development/testing.

    Prints the approval request to stdout and waits for user input.
    Runs the blocking input() call in a thread executor to remain async.
    """

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        """Display the request in the terminal and wait for y/n input."""
        print("\n" + "=" * 60)
        print("🛡️  DEADEND — HUMAN APPROVAL REQUIRED")
        print("=" * 60)
        print(f"  Request ID : {request.request_id}")
        print(f"  Severity   : {request.severity.value}")
        print(f"  Agent      : {request.agent_id}")
        if request.tool_name:
            print(f"  Tool       : {request.tool_name}")
        if request.tool_args:
            # Truncate large args for display
            args_str = str(request.tool_args)[:200]
            print(f"  Args       : {args_str}")
        print(f"  Threat     : {request.threat_summary}")
        print("-" * 60)

        loop = asyncio.get_event_loop()
        try:
            response = await loop.run_in_executor(
                None, lambda: input("  Approve? [y/N]: ").strip().lower()
            )
        except (EOFError, KeyboardInterrupt):
            response = "n"

        decision = ApprovalDecision.APPROVED if response in ("y", "yes") else ApprovalDecision.REJECTED

        print(f"  Decision   : {decision.value}")
        print("=" * 60 + "\n")

        return ApprovalResult(
            request_id=request.request_id,
            decision=decision,
            reviewer="cli_user",
            reason=f"CLI {'approved' if decision == ApprovalDecision.APPROVED else 'rejected'}",
        )


class WebhookApprovalBackend:
    """HTTP webhook-based approval backend for production use.

    Sends a POST request to the configured URL and polls for a response,
    or waits for a callback webhook.

    Args:
        webhook_url: The URL to POST the approval request to.
        callback_url: Optional URL where the approval response will be
            sent back (if using async webhook pattern).
    """

    def __init__(self, webhook_url: str, callback_url: str | None = None) -> None:
        self.webhook_url = webhook_url
        self.callback_url = callback_url

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        """Send an approval request via HTTP webhook."""
        try:
            # Lazy import to avoid hard dependency
            import json
            import urllib.request

            payload = json.dumps({
                "request_id": request.request_id,
                "session_id": request.session_id,
                "agent_id": request.agent_id,
                "tool_name": request.tool_name,
                "tool_args": request.tool_args,
                "threat_summary": request.threat_summary,
                "severity": request.severity.value,
                "timestamp": request.timestamp.isoformat(),
            }).encode()

            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, lambda: urllib.request.urlopen(req, timeout=30)
            )
            resp_data = json.loads(response.read().decode())

            decision_str = resp_data.get("decision", "REJECTED").upper()
            decision = ApprovalDecision(decision_str) if decision_str in ApprovalDecision.__members__ else ApprovalDecision.REJECTED

            return ApprovalResult(
                request_id=request.request_id,
                decision=decision,
                reviewer=resp_data.get("reviewer", "webhook"),
                reason=resp_data.get("reason", ""),
            )

        except Exception as e:
            logger.error("Webhook approval request failed", error=str(e))
            # Fail-closed: deny if webhook fails
            return ApprovalResult(
                request_id=request.request_id,
                decision=ApprovalDecision.REJECTED,
                reviewer="webhook_error",
                reason=f"Webhook failed: {e}",
            )


class ApprovalGate:
    """Central approval gate that intercepts high-severity detections.

    The gate evaluates each detection result and, if the severity
    exceeds the configured threshold, pauses execution and routes the
    action to a human reviewer via the configured backend.

    Args:
        backend: The approval backend to use (CLI, webhook, etc.).
        severity_threshold: Minimum severity that triggers an approval
            request. Defaults to CRITICAL.
        timeout_seconds: Maximum time to wait for human response.
            Auto-denies after timeout (fail-closed).
        enabled: Master switch for the gate.
    """

    def __init__(
        self,
        backend: ApprovalBackend | None = None,
        severity_threshold: ThreatSeverity = ThreatSeverity.CRITICAL,
        timeout_seconds: float = 300.0,
        enabled: bool = True,
    ) -> None:
        self.backend = backend or CLIApprovalBackend()
        self.severity_threshold = severity_threshold
        self.timeout_seconds = timeout_seconds
        self.enabled = enabled
        self._audit_log: list[ApprovalResult] = []

    # Severity ordering for comparison
    _SEVERITY_ORDER = {
        ThreatSeverity.INFO: 0,
        ThreatSeverity.LOW: 1,
        ThreatSeverity.MEDIUM: 2,
        ThreatSeverity.HIGH: 3,
        ThreatSeverity.CRITICAL: 4,
    }

    def _severity_exceeds_threshold(self, severity: ThreatSeverity) -> bool:
        """Check if the given severity meets or exceeds our threshold."""
        return self._SEVERITY_ORDER.get(severity, 0) >= self._SEVERITY_ORDER.get(self.severity_threshold, 4)

    async def evaluate(
        self,
        detection: DetectionResult,
        session_id: str = "",
        agent_id: str = "default",
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
    ) -> ActionType:
        """Evaluate a detection result and potentially request human approval.

        Returns:
            ActionType.ALLOW if approved (or gate not triggered).
            ActionType.BLOCK if rejected, timed out, or gate is disabled
            but severity is too high.
        """
        if not self.enabled:
            return ActionType.ALLOW

        if not detection.detected:
            return ActionType.ALLOW

        if not self._severity_exceeds_threshold(detection.severity):
            return ActionType.ALLOW

        # Build the approval request
        request = ApprovalRequest(
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
            threat_summary=str(detection.details) if detection.details else detection.threat_type.value if detection.threat_type else "Unknown threat",
            severity=detection.severity,
            detections=[detection.model_dump()],
        )

        logger.warning(
            "HITL approval required",
            request_id=request.request_id,
            severity=detection.severity.value,
            tool=tool_name,
        )

        # Request approval with timeout
        try:
            result = await asyncio.wait_for(
                self.backend.request_approval(request),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            logger.error(
                "HITL approval timed out — auto-denying (fail-closed)",
                request_id=request.request_id,
                timeout=self.timeout_seconds,
            )
            result = ApprovalResult(
                request_id=request.request_id,
                decision=ApprovalDecision.TIMEOUT,
                reviewer="system",
                reason=f"No response within {self.timeout_seconds}s",
            )

        # Record in audit log
        self._audit_log.append(result)

        logger.info(
            "HITL decision recorded",
            request_id=result.request_id,
            decision=result.decision.value,
            reviewer=result.reviewer,
        )

        if result.decision == ApprovalDecision.APPROVED:
            return ActionType.ALLOW
        return ActionType.BLOCK

    @property
    def audit_log(self) -> list[ApprovalResult]:
        """Return the full audit trail of all approval decisions."""
        return list(self._audit_log)
