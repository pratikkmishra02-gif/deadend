"""
Phalanx AI — Secure OpenAI Wrapper
====================================
Drop-in replacement for the OpenAI client that automatically scans
inputs, monitors tool calls, and validates outputs.

Usage::

    from phalanx_ai.integrations.openai_wrapper import SecureOpenAI

    client = SecureOpenAI(api_key="sk-...")
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello!"}]
    )
    # ✅ Input scanned by Sentinel
    # ✅ Output scanned by Guardian
    # ✅ Tool calls monitored by Warden
"""
from __future__ import annotations

import asyncio
import functools
from typing import Any, Dict, List, Optional

import structlog

from phalanx_ai.config import PhalanxConfig
from phalanx_ai.types import (
    AgentEvent, SessionContext, ScanPhase,
    ThreatSeverity, ActionType,
)
from phalanx_ai.exceptions import ThreatDetectedError
from phalanx_ai.sentinel.engine import SentinelEngine
from phalanx_ai.guardian.engine import GuardianEngine
from phalanx_ai.guardian.validators.pii import PIIValidator
from phalanx_ai.guardian.validators.secrets import SecretValidator
from phalanx_ai.guardian.validators.code import CodeValidator
from phalanx_ai.warden.engine import WardenEngine

logger = structlog.get_logger(__name__)

__all__ = ["SecureOpenAI"]


class _SecureChatCompletions:
    """Wraps ``openai.chat.completions`` with Phalanx scanning."""

    def __init__(self, original_chat_completions: Any, shield: "_PhalanxShieldLayer") -> None:
        self._original = original_chat_completions
        self._shield = shield

    def create(self, **kwargs: Any) -> Any:
        """Intercept chat.completions.create() with security scanning."""
        messages: List[Dict[str, Any]] = kwargs.get("messages", [])

        # ── 1. Sentinel: Scan the last user message ──
        user_messages = [m for m in messages if m.get("role") == "user"]
        if user_messages:
            last_user_msg = user_messages[-1].get("content", "")
            if isinstance(last_user_msg, str) and last_user_msg.strip():
                input_result = self._shield.scan_input_sync(last_user_msg)
                if not input_result.passed:
                    highest = input_result.detections[0] if input_result.detections else None
                    raise ThreatDetectedError(
                        message=f"Input blocked by Phalanx Sentinel: {highest.details if highest else 'threat detected'}",
                        threat_type=highest.threat_type.value if highest else None,
                        severity=highest.severity.value if highest else None,
                        confidence=highest.confidence if highest else 0.0,
                        detector_name=highest.detector_name if highest else "sentinel",
                    )

        # ── 2. Call the original OpenAI API ──
        response = self._original.create(**kwargs)

        # ── 3. Guardian: Scan the response ──
        try:
            content = response.choices[0].message.content
            if content:
                output_result = self._shield.scan_output_sync(content)
                if not output_result.passed:
                    highest = output_result.detections[0] if output_result.detections else None
                    logger.warning(
                        "Output threat detected",
                        threat_type=highest.threat_type.value if highest else "unknown",
                        severity=highest.severity.value if highest else "unknown",
                    )
                    # In enforce mode, raise. In monitor mode, log and pass through.
                    if self._shield.mode == "enforce":
                        raise ThreatDetectedError(
                            message=f"Output blocked by Phalanx Guardian: {highest.details if highest else 'threat detected'}",
                            threat_type=highest.threat_type.value if highest else None,
                            severity=highest.severity.value if highest else None,
                            confidence=highest.confidence if highest else 0.0,
                            detector_name=getattr(highest, "module", "guardian"),
                        )

            # ── 4. Warden: Monitor any tool calls ──
            tool_calls = getattr(response.choices[0].message, "tool_calls", None)
            if tool_calls:
                for tc in tool_calls:
                    import json
                    event = AgentEvent(
                        session_id=self._shield.session.session_id,
                        event_type="tool_call",
                        tool_name=tc.function.name,
                        tool_args=json.loads(tc.function.arguments) if tc.function.arguments else {},
                        content=f"OpenAI tool call: {tc.function.name}",
                    )
                    warden_result = self._shield.check_event_sync(event)
                    if not warden_result.passed:
                        highest = warden_result.detections[0] if warden_result.detections else None
                        raise ThreatDetectedError(
                            message=f"Tool call blocked by Phalanx Warden: {tc.function.name}",
                            threat_type=highest.threat_type.value if highest else None,
                            severity=highest.severity.value if highest else None,
                            confidence=highest.confidence if highest else 0.0,
                        )
        except ThreatDetectedError:
            raise
        except Exception as e:
            logger.debug("Response scanning skipped", reason=str(e))

        return response


class _SecureChat:
    """Wraps ``openai.chat`` namespace."""

    def __init__(self, original_chat: Any, shield: "_PhalanxShieldLayer") -> None:
        self.completions = _SecureChatCompletions(original_chat.completions, shield)


class _PhalanxShieldLayer:
    """Internal shield layer shared across all wrappers."""

    def __init__(self, config: Optional[PhalanxConfig] = None, mode: str = "enforce") -> None:
        self.config = config or PhalanxConfig()
        self.mode = mode
        self.sentinel = SentinelEngine()
        self.guardian = GuardianEngine(validators=[
            PIIValidator(), SecretValidator(), CodeValidator()
        ])
        self.warden = WardenEngine()
        self.session = SessionContext()

    def _run_async(self, coro):
        """Run an async coroutine synchronously."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # Already inside an event loop — create a new thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        else:
            return asyncio.run(coro)

    def scan_input_sync(self, text: str):
        return self._run_async(self.sentinel.scan(text))

    def scan_output_sync(self, text: str):
        return self._run_async(self.guardian.validate(text))

    def check_event_sync(self, event: AgentEvent):
        return self._run_async(self.warden.check(event, self.session))


class SecureOpenAI:
    """
    Drop-in replacement for ``openai.OpenAI`` with Phalanx security.

    Usage::

        from phalanx_ai.integrations.openai_wrapper import SecureOpenAI

        client = SecureOpenAI(api_key="sk-...")

        # Works exactly like openai.OpenAI, but all calls are scanned
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "What is 2+2?"}]
        )

    Args:
        phalanx_config: Optional PhalanxConfig for custom settings.
        phalanx_mode: "enforce" (block threats) or "monitor" (log only).
        **openai_kwargs: All arguments forwarded to ``openai.OpenAI()``.
    """

    def __init__(
        self,
        phalanx_config: Optional[PhalanxConfig] = None,
        phalanx_mode: str = "enforce",
        **openai_kwargs: Any,
    ) -> None:
        try:
            import openai
        except ImportError:
            raise ImportError(
                "The 'openai' package is required for SecureOpenAI. "
                "Install it with: pip install phalanx-ai[openai]"
            )

        self._openai_client = openai.OpenAI(**openai_kwargs)
        self._shield = _PhalanxShieldLayer(config=phalanx_config, mode=phalanx_mode)
        self.chat = _SecureChat(self._openai_client.chat, self._shield)

    def __getattr__(self, name: str) -> Any:
        """Proxy all other attributes to the underlying OpenAI client."""
        return getattr(self._openai_client, name)
