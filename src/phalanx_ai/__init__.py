from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from phalanx_ai._version import __version__
from phalanx_ai.config import PhalanxConfig
from phalanx_ai.types import (
    ActionType,
    DetectionResult,
    ScanResult,
    ThreatSeverity,
    ThreatType,
)

if TYPE_CHECKING:
    # Avoid circular imports but allow type hinting if needed
    pass


def shield(*args: Any, **kwargs: Any) -> Callable:
    """
    Decorator to apply Phalanx protection to a function or method.
    
    This is a stub placeholder for the actual implementation that will wrap
    agent invocations and intercept inputs/outputs.
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*f_args: Any, **f_kwargs: Any) -> Any:
            # Shield implementation will be here
            return func(*f_args, **f_kwargs)
        return wrapper
    
    if len(args) == 1 and callable(args[0]):
        return decorator(args[0])
    return decorator


class Phalanx:
    """
    Main entry point for the Phalanx AI security system.
    """
    def __init__(self, config: PhalanxConfig | None = None) -> None:
        self.config = config or PhalanxConfig()


__all__ = [
    "Phalanx",
    "PhalanxConfig",
    "shield",
    "__version__",
    "ThreatSeverity",
    "ThreatType",
    "ActionType",
    "DetectionResult",
    "ScanResult",
]
