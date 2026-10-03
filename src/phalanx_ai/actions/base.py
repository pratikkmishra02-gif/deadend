from __future__ import annotations

from abc import ABC, abstractmethod

from phalanx_ai.types import ActionType, DetectionResult, SessionContext

__all__ = ["BaseAction"]


class BaseAction(ABC):
    """Abstract base class for all actions."""

    @property
    @abstractmethod
    def action_type(self) -> ActionType:
        """The type of action."""
        pass

    @abstractmethod
    async def execute(self, detection: DetectionResult, session: SessionContext) -> dict:
        """
        Execute the action.

        Args:
            detection: The detection result triggering the action.
            session: The session context.

        Returns:
            Dictionary with execution results.
        """
        pass
