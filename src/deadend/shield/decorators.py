from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, Literal

import structlog

from deadend.exceptions import ThreatDetectedError
from deadend.shield.shield import Shield

logger = structlog.get_logger(__name__)

def shield(
    config: Any | None = None,
    policy: str | None = None,
    on_threat: Literal['raise', 'block', 'warn', 'log'] = 'raise',
    session_id: str | None = None
) -> Callable:
    """Decorator to protect a function with Shield.protect()."""
    shield_instance = Shield(config=config, policy_path=policy)

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            input_text = args[0] if args else kwargs.get('prompt', "")
            if not isinstance(input_text, str):
                input_text = str(input_text)
            
            try:
                async def model_call(text, **call_kwargs):
                    return await func(*args, **kwargs)

                return await shield_instance.protect(input_text, model_call, session_id=session_id)
            except ThreatDetectedError as e:
                return _handle_threat(e, on_threat)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            input_text = args[0] if args else kwargs.get('prompt', "")
            if not isinstance(input_text, str):
                input_text = str(input_text)

            import asyncio
            try:
                async def model_call(text, **call_kwargs):
                    return func(*args, **kwargs)
                
                return asyncio.run(shield_instance.protect(input_text, model_call, session_id=session_id))
            except ThreatDetectedError as e:
                return _handle_threat(e, on_threat)

        return async_wrapper if inspect.iscoroutinefunction(func) else sync_wrapper

    return decorator

def monitor(config: Any | None = None) -> Callable:
    """Lighter decorator that only monitors and logs."""
    return shield(config=config, on_threat='log')

def _handle_threat(e: ThreatDetectedError, on_threat: str) -> Any:
    logger.warning(f"Threat detected: {str(e)}")
    if on_threat == 'raise':
        raise e
    elif on_threat == 'block':
        return None
    return ""

__all__ = ["shield", "monitor"]
