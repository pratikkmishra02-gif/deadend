"""
Deadend AI — LlamaIndex Security Callback Handler
===================================================
Drop-in callback handler for LlamaIndex that intercepts LLM calls,
retrieval events, and tool executions to enforce Deadend security
policies at runtime.

Usage::

    from llama_index.core import Settings
    from deadend.integrations.llamaindex_callback import DeadendCallbackHandler

    handler = DeadendCallbackHandler(mode="enforce")
    Settings.callback_manager.add_handler(handler)

    # All LLM calls, RAG retrievals, and tool uses are now secured.

Requires the ``llama-index-core`` package::

    pip install llama-index-core
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

__all__ = ["DeadendCallbackHandler"]

# ── Lazy imports to avoid hard dependency ──
_LLAMAINDEX_AVAILABLE = False
_BaseCallbackHandler = object  # Fallback base
_CBEventType = None
_EventPayload = None

try:
    from llama_index.core.callbacks.base import BaseCallbackHandler as _LIBaseHandler
    from llama_index.core.callbacks.schema import CBEventType, EventPayload

    _BaseCallbackHandler = _LIBaseHandler
    _CBEventType = CBEventType
    _EventPayload = EventPayload
    _LLAMAINDEX_AVAILABLE = True
except ImportError:
    logger.debug(
        "LlamaIndex not installed. DeadendCallbackHandler will be "
        "a no-op stub. Install with: pip install llama-index-core"
    )


def _run_async(coro):
    """Run an async coroutine from synchronous context."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result(timeout=10)
    else:
        return asyncio.run(coro)


class DeadendCallbackHandler(_BaseCallbackHandler):
    """LlamaIndex callback handler that enforces Deadend security.

    Hooks into LlamaIndex's event system to scan:
    - **LLM inputs** (Sentinel — prompt injection / jailbreak detection)
    - **Retrieved documents** (Sentinel — indirect injection in RAG chunks)
    - **Tool calls** (Warden — dangerous command detection)
    - **LLM outputs** (Guardian — PII / secret / toxicity scanning)

    Args:
        mode: ``"enforce"`` to block threats, ``"monitor"`` to log only.
        policy_path: Optional path to a Deadend YAML policy file.
        event_starts_to_trace: LlamaIndex event types to trace on start.
        event_ends_to_trace: LlamaIndex event types to trace on end.
    """

    def __init__(
        self,
        mode: str = "enforce",
        policy_path: str | None = None,
        event_starts_to_trace: list | None = None,
        event_ends_to_trace: list | None = None,
    ) -> None:
        self.mode = mode
        self._sentinel = None
        self._warden = None
        self._guardian = None
        self._stats = {
            "scanned": 0,
            "blocked": 0,
            "threats_detected": 0,
        }

        # Initialize engines lazily to avoid circular imports
        self._init_engines(policy_path)

        if _LLAMAINDEX_AVAILABLE:
            super().__init__(
                event_starts_to_trace=event_starts_to_trace or [
                    _CBEventType.LLM,
                    _CBEventType.RETRIEVE,
                ],
                event_ends_to_trace=event_ends_to_trace or [
                    _CBEventType.LLM,
                ],
            )

        logger.info(
            "DeadendCallbackHandler initialized for LlamaIndex",
            mode=self.mode,
            llamaindex_available=_LLAMAINDEX_AVAILABLE,
        )

    def _init_engines(self, policy_path: str | None = None) -> None:
        """Initialize Sentinel, Warden, and Guardian engines."""
        try:
            from deadend.sentinel.engine import SentinelEngine
            self._sentinel = SentinelEngine()
        except Exception as e:
            logger.warning("Failed to init SentinelEngine", error=str(e))

        try:
            from deadend.warden.engine import WardenEngine
            self._warden = WardenEngine()
        except Exception as e:
            logger.warning("Failed to init WardenEngine", error=str(e))

        try:
            from deadend.guardian.engine import GuardianEngine
            from deadend.guardian.validators.pii import PIIValidator
            from deadend.guardian.validators.secrets import SecretValidator
            self._guardian = GuardianEngine(
                validators=[PIIValidator(), SecretValidator()]
            )
        except Exception as e:
            logger.warning("Failed to init GuardianEngine", error=str(e))

        # Load policy if specified
        if policy_path:
            try:
                from deadend.policy.loader import PolicyLoader
                PolicyLoader.load(policy_path)
                logger.info("Loaded policy for LlamaIndex handler", path=policy_path)
            except Exception as e:
                logger.warning("Failed to load policy", error=str(e))

    def _scan_input(self, text: str, source: str = "llm_input") -> bool:
        """Scan input text with Sentinel. Returns True if safe."""
        if not self._sentinel or not text:
            return True

        self._stats["scanned"] += 1
        start = time.monotonic()

        try:
            result = _run_async(self._sentinel.scan(text))
            latency = (time.monotonic() - start) * 1000

            if not result.passed:
                self._stats["threats_detected"] += 1
                logger.warning(
                    "LlamaIndex input threat detected",
                    source=source,
                    action=self.mode,
                    latency_ms=f"{latency:.1f}",
                    detections=[d.threat_type.value for d in result.detections if d.detected],
                )
                if self.mode == "enforce":
                    self._stats["blocked"] += 1
                    return False
            return True

        except Exception as e:
            logger.error("Sentinel scan failed in LlamaIndex handler", error=str(e))
            return True  # Fail-open on scan error

    def _scan_output(self, text: str) -> str | None:
        """Scan output text with Guardian. Returns redacted text or None if blocked."""
        if not self._guardian or not text:
            return text

        try:
            result = _run_async(self._guardian.validate(text))

            if not result.passed:
                self._stats["threats_detected"] += 1
                logger.warning(
                    "LlamaIndex output threat detected",
                    action=self.mode,
                )
                if self.mode == "enforce":
                    # Redact rather than block outputs
                    redacted = _run_async(self._guardian.redact(text))
                    return redacted
            return text

        except Exception as e:
            logger.error("Guardian scan failed in LlamaIndex handler", error=str(e))
            return text

    def _scan_tool_call(self, tool_name: str, tool_args: dict) -> bool:
        """Scan a tool call with Warden. Returns True if safe."""
        if not self._warden:
            return True

        self._stats["scanned"] += 1

        try:
            from deadend.types import AgentEvent, SessionContext

            event = AgentEvent(
                session_id="llamaindex",
                event_type="tool_call",
                tool_name=tool_name,
                tool_args=tool_args,
                content=str(tool_args),
            )
            session = SessionContext(session_id="llamaindex", framework="llamaindex")
            result = _run_async(self._warden.check(event, session))

            if not result.passed:
                self._stats["threats_detected"] += 1
                logger.warning(
                    "LlamaIndex tool call threat detected",
                    tool=tool_name,
                    action=self.mode,
                )
                if self.mode == "enforce":
                    self._stats["blocked"] += 1
                    return False
            return True

        except Exception as e:
            logger.error("Warden scan failed in LlamaIndex handler", error=str(e))
            return True

    # ── LlamaIndex Callback Interface ──

    def on_event_start(
        self,
        event_type: Any,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        """Called when a LlamaIndex event starts."""
        if not _LLAMAINDEX_AVAILABLE or payload is None:
            return event_id

        # Scan LLM inputs
        if event_type == _CBEventType.LLM:
            messages = payload.get(_EventPayload.MESSAGES, [])
            for msg in messages:
                text = str(msg) if not hasattr(msg, "content") else msg.content
                if text and not self._scan_input(text, source="llm_prompt"):
                    if self.mode == "enforce":
                        raise SecurityError(
                            "Deadend blocked LLM input: threat detected in prompt"
                        )

        # Scan retrieved RAG documents for indirect injection
        if event_type == _CBEventType.RETRIEVE:
            nodes = payload.get(_EventPayload.NODES, [])
            for node in nodes:
                text = node.get_content() if hasattr(node, "get_content") else str(node)
                if text and not self._scan_input(text, source="rag_document"):
                    logger.warning(
                        "Indirect injection detected in RAG document",
                        node_id=getattr(node, "node_id", "unknown"),
                    )

        return event_id

    def on_event_end(
        self,
        event_type: Any,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Called when a LlamaIndex event ends."""
        if not _LLAMAINDEX_AVAILABLE or payload is None:
            return

        # Scan LLM outputs
        if event_type == _CBEventType.LLM:
            response = payload.get(_EventPayload.RESPONSE, "")
            if response:
                text = str(response)
                self._scan_output(text)

    def start_trace(self, trace_id: str | None = None) -> None:
        """Called when a LlamaIndex trace starts."""
        pass

    def end_trace(
        self,
        trace_id: str | None = None,
        trace_map: dict[str, list[str]] | None = None,
    ) -> None:
        """Called when a LlamaIndex trace ends."""
        pass

    @property
    def stats(self) -> dict[str, int]:
        """Return scanning statistics."""
        return dict(self._stats)


class SecurityError(Exception):
    """Raised when Deadend blocks an action in enforce mode."""
