from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from deadend._version import __version__
from deadend.config import DeadendConfig
from deadend.types import (
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
    Decorator to apply Deadend protection to a function or method.
    
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


class Deadend:
    """
    Main entry point for the Deadend AI security system.
    """
    def __init__(self, config: DeadendConfig | None = None) -> None:
        self.config = config or DeadendConfig()


__all__ = [
    "Deadend",
    "DeadendConfig",
    "shield",
    "__version__",
    "ThreatSeverity",
    "ThreatType",
    "ActionType",
    "DetectionResult",
    "ScanResult",
]
