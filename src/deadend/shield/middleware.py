from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

from deadend.shield.shield import Shield
from deadend.types import ScanResult

class BaseMiddleware(ABC):
    """Base middleware class for integrating Deadend AI into frameworks."""
    
    def __init__(self, shield: Shield) -> None:
        self.shield = shield

    @abstractmethod
    async def on_input(self, input_text: str, metadata: Dict[str, Any]) -> ScanResult:
        """Called when input is received."""
        pass

    @abstractmethod
    async def on_output(self, output_text: str, metadata: Dict[str, Any]) -> ScanResult:
        """Called when output is generated."""
        pass

    @abstractmethod
    async def on_tool_call(self, tool_name: str, args: Dict[str, Any], metadata: Dict[str, Any]) -> ScanResult:
        """Called when a tool is invoked."""
        pass

    @abstractmethod
    async def on_error(self, error: Exception, metadata: Dict[str, Any]) -> None:
        """Called when an error occurs in the pipeline."""
        pass

__all__ = ["BaseMiddleware"]
