from __future__ import annotations
from abc import ABC, abstractmethod

from phalanx_ai.types import AgentEvent, SessionContext, DetectionResult

__all__ = ["BaseMonitor"]

class BaseMonitor(ABC):
    """Abstract base class for all monitors."""
    
    def __init__(self):
        self.enabled: bool = True
        
    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of the monitor."""
        pass
        
    @abstractmethod
    async def check(self, event: AgentEvent, session: SessionContext) -> DetectionResult:
        """Performs a check on the event and returns a detection result."""
        pass
