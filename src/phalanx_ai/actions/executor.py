from __future__ import annotations

from phalanx_ai.types import ActionType, DetectionResult, SessionContext
from .base import BaseAction
from .block import BlockAction
from .kill import KillAction
from .alert import AlertAction

__all__ = ["ActionExecutor"]


class ActionExecutor:
    """Executes the right actions based on policy."""

    def __init__(self) -> None:
        self.actions: dict[ActionType, BaseAction] = {
            ActionType.BLOCK: BlockAction(),
            ActionType.KILL: KillAction(),
            ActionType.ALERT: AlertAction()
        }

    async def execute(self, actions: list[ActionType], detection: DetectionResult, session: SessionContext) -> list[dict]:
        """
        Executes each action type in order.

        Args:
            actions: List of action types to execute.
            detection: The detection result.
            session: The session context.

        Returns:
            List of execution results.
        """
        results = []
        for action_type in actions:
            if action in self.actions:
                result = await self.actions[action_type].execute(detection, session)
                results.append(result)
        return results
