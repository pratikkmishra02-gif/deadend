from __future__ import annotations

from deadend.types import ActionType, DetectionResult, SessionContext

from .base import BaseAction

__all__ = ["KillAction"]


class KillAction(BaseAction):
    """Terminates the agent session."""

    @property
    def action_type(self) -> ActionType:
        return ActionType.KILL

    async def execute(self, detection: DetectionResult, session: SessionContext) -> dict:
        session.is_active = False
        return {
            'killed': True,
            'session_id': session.session_id,
            'reason': 'Session terminated due to critical threat.'
        }
