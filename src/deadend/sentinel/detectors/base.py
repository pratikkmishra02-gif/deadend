from __future__ import annotations

from abc import ABC, abstractmethod

from deadend.types import DetectionResult, SessionContext


class BaseDetector(ABC):
    """Abstract base class for all prompt security detectors."""

    enabled: bool = True

    @property
    @abstractmethod
    def name(self) -> str:
        """The unique name of the detector."""
        pass

    @abstractmethod
    async def detect(self, text: str, context: SessionContext | None = None) -> DetectionResult:
        """Detect threats in the given text.

        Args:
            text: The user prompt or text to analyze.
            context: The session context, containing history and other metadata.

        Returns:
            A DetectionResult indicating if a threat was found.
        """
        pass

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} enabled={self.enabled}>"

__all__ = ["BaseDetector"]
