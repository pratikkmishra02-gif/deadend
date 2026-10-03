from __future__ import annotations

import json
import logging
from typing import Any

import structlog

from phalanx_ai.types import ScanResult, DetectionResult, ActionType, ScanPhase, ModuleType
from .events import AuditEvent

__all__ = ["AuditLogger"]


class AuditLogger:
    """Structured audit logger."""

    def __init__(self, destination: str = 'stdout', format: str = 'json', include_prompts: bool = False) -> None:
        self.destination = destination
        self.format = format
        self.include_prompts = include_prompts
        
        # Setup structlog
        processors = [
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer() if format == 'json' else structlog.dev.ConsoleRenderer()
        ]
        
        self.logger = structlog.wrap_logger(
            logging.getLogger("phalanx_audit"),
            processors=processors
        )

    async def log(self, event: AuditEvent) -> None:
        """Write structured audit event."""
        log_data = self._format_event(event)
        if self.destination == 'stdout':
            self.logger.info("audit_event", **json.loads(log_data) if self.format == 'json' else {"event": log_data})
        elif self.destination.startswith('file://'):
            filepath = self.destination.replace('file://', '')
            with open(filepath, 'a', encoding='utf-8') as f:
                f.write(log_data + '\n')

    async def log_scan(self, scan_result: ScanResult, session_id: str, phase: ScanPhase) -> None:
        """Log a scan result."""
        event = AuditEvent(
            session_id=session_id,
            event_type=f"SCAN_{phase.name}",
            module=ModuleType.GUARDIAN,
            scan_result=scan_result,
            latency_ms=scan_result.latency_ms
        )
        await self.log(event)

    async def log_threat(self, detection: DetectionResult, session_id: str, action: ActionType) -> None:
        """Log a detected threat."""
        event = AuditEvent(
            session_id=session_id,
            event_type="THREAT_DETECTED",
            module=ModuleType.GUARDIAN,
            severity=detection.severity,
            details=detection.details,
            action_taken=action
        )
        await self.log(event)

    def _format_event(self, event: AuditEvent) -> str:
        """Format event as JSON or text."""
        # Convert to dict, excluding None values
        event_dict = event.model_dump(exclude_none=True)
        # Ensure timestamp is ISO formatted string
        if 'timestamp' in event_dict:
            event_dict['timestamp'] = event_dict['timestamp'].isoformat()
            
        if self.format == 'json':
            return json.dumps(event_dict, default=str)
        else:
            return str(event_dict)
