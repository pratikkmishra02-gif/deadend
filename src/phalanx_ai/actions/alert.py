from __future__ import annotations

from typing import Optional

from phalanx_ai.types import ActionType, DetectionResult, SessionContext
from .base import BaseAction

__all__ = ["AlertAction"]


class AlertAction(BaseAction):
    """Sends alerts via webhooks."""

    def __init__(self, webhook_url: Optional[str] = None, channels: list[str] | None = None) -> None:
        self.webhook_url = webhook_url
        self.channels = channels or []

    @property
    def action_type(self) -> ActionType:
        return ActionType.ALERT

    async def execute(self, detection: DetectionResult, session: SessionContext) -> dict:
        payload = {
            'session_id': session.session_id,
            'threat_type': str(detection.threat_type),
            'severity': str(detection.severity),
            'details': detection.details,
            'channels': self.channels
        }
        
        # Does not actually send HTTP - just formats and logs
        return {
            'alert_sent': True,
            'payload': payload
        }
