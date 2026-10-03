from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from deadend.types import DetectionResult, SessionContext

__all__ = ["BaseValidator"]


class BaseValidator(ABC):
    """Abstract base class for all output validators."""

    enabled: bool = True

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the validator."""
        pass

    @abstractmethod
    async def validate(self, text: str, context: Optional[SessionContext] = None) -> DetectionResult:
        """
        Validate text to check for threats or violations.

        Args:
            text: The text to validate.
            context: The session context.

        Returns:
            DetectionResult with findings.
        """
        pass

    async def redact(self, text: str, mask_char: str = '█') -> str:
        """
        Redact sensitive information found by this validator.

        Args:
            text: Text to redact.
            mask_char: Masking character.

        Returns:
            Redacted string. Defaults to returning the text unchanged.
        """
        return text
