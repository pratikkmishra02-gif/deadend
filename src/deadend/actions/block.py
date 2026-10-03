from __future__ import annotations

from deadend.types import ActionType, DetectionResult, SessionContext
from .base import BaseAction

__all__ = ["BlockAction"]


class BlockAction(BaseAction):
    """Blocks or rejects the request."""

    @property
    def action_type(self) -> ActionType:
        return ActionType.BLOCK

    async def execute(self, detection: DetectionResult, session: SessionContext) -> dict:
        return {
            'blocked': True,
            'reason': detection.details,
            'threat_type': detection.threat_type
        }
