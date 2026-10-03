"""
Deadend AI — LangChain Callback Handler
=========================================
Integrates Deadend security into any LangChain chain or agent via
the standard callback system.

Usage::

    from deadend.integrations.langchain_callback import DeadendCallbackHandler

    handler = DeadendCallbackHandler(mode="enforce")

    # Use with any LangChain component
    llm = ChatOpenAI(callbacks=[handler])
    agent = create_react_agent(llm, tools, callbacks=[handler])
"""
from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

import structlog

from deadend.config import DeadendConfig
from deadend.exceptions import ThreatDetectedError
from deadend.guardian.engine import GuardianEngine
from deadend.guardian.validators.code import CodeValidator
from deadend.guardian.validators.pii import PIIValidator
from deadend.guardian.validators.secrets import SecretValidator
from deadend.policy.loader import PolicyLoader
from deadend.policy.schema import DeadendPolicy
from deadend.sentinel.engine import SentinelEngine
from deadend.types import AgentEvent, SessionContext
from deadend.warden.engine import WardenEngine

logger = structlog.get_logger(__name__)

__all__ = ["DeadendCallbackHandler"]


def _run_sync(coro):
    """Run async code synchronously, handling nested event loops."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


class DeadendCallbackHandler:
    """
    LangChain-compatible callback handler that scans inputs, outputs,
    and tool calls through the Deadend security pipeline.

    Implements the LangChain ``BaseCallbackHandler`` interface methods
    without requiring ``langchain-core`` as a hard dependency.

    Args:
        config: Optional DeadendConfig.
        mode: "enforce" to block threats, "monitor" to log only.
        on_threat: Action on detection — "raise", "log", or "warn".
    """

    def __init__(
        self,
        config: DeadendConfig | None = None,
        mode: str = "enforce",
        on_threat: str = "raise",
        policy: DeadendPolicy | None = None,
    ) -> None:
        self.mode = mode
        self.on_threat = on_threat
        self.policy = policy or PolicyLoader.load()
        
        self.sentinel = SentinelEngine(policy=self.policy.sentinel)
        self.guardian = GuardianEngine(validators=[
            PIIValidator(), SecretValidator(), CodeValidator()
        ])
        self.warden = WardenEngine(policy=self.policy.warden)
        self.session = SessionContext()

        # Stats
        self.scans_performed: int = 0
        self.threats_detected: int = 0
        self.threats_blocked: int = 0

    # ─── LangChain Callback Interface ────────────────────────

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Scan prompts before they reach the LLM."""
        for prompt in prompts:
            if not prompt or not prompt.strip():
                continue

            self.scans_performed += 1
            result = _run_sync(self.sentinel.scan(prompt))

            if not result.passed:
                self.threats_detected += 1
                highest = result.detections[0] if result.detections else None
                logger.warning(
                    "Deadend Sentinel: Threat in LLM input",
                    threat_type=highest.threat_type.value if highest else "unknown",
                    severity=highest.severity.value if highest else "unknown",
                    confidence=highest.confidence if highest else 0.0,
                    prompt_preview=prompt[:100],
                )
                if self.mode == "enforce" and self.on_threat == "raise":
                    self.threats_blocked += 1
                    raise ThreatDetectedError(
                        message=f"LLM input blocked by Deadend: {highest.details if highest else 'threat'}",
                        threat_type=highest.threat_type.value if highest else None,
                        severity=highest.severity.value if highest else None,
                        confidence=highest.confidence if highest else 0.0,
                    )

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[Any],
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Scan chat messages before they reach the model."""
        for message_list in messages:
            if isinstance(message_list, list):
                for msg in message_list:
                    content = getattr(msg, "content", str(msg)) if not isinstance(msg, str) else msg
                    if content and isinstance(content, str):
                        self.scans_performed += 1
                        result = _run_sync(self.sentinel.scan(content))
                        if not result.passed and self.mode == "enforce":
                            self.threats_detected += 1
                            self.threats_blocked += 1
                            highest = result.detections[0] if result.detections else None
                            raise ThreatDetectedError(
                                message="Chat input blocked by Deadend",
                                threat_type=highest.threat_type.value if highest else None,
                                severity=highest.severity.value if highest else None,
                            )

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Scan LLM output through Guardian."""
        try:
            # LangChain LLMResult structure
            for generation_list in response.generations:
                for generation in generation_list:
                    text = generation.text if hasattr(generation, "text") else str(generation)
                    if text:
                        self.scans_performed += 1
                        result = _run_sync(self.guardian.validate(text))
                        if not result.passed:
                            self.threats_detected += 1
                            highest = result.detections[0] if result.detections else None
                            logger.warning(
                                "Deadend Guardian: Threat in LLM output",
                                threat_type=highest.threat_type.value if highest else "unknown",
                                output_preview=text[:100],
                            )
        except Exception as e:
            logger.debug("Guardian output scan skipped", reason=str(e))

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Monitor tool invocations through Warden."""
        tool_name = serialized.get("name", "unknown_tool")
        event = AgentEvent(
            session_id=self.session.session_id,
            event_type="tool_call",
            tool_name=tool_name,
            tool_args={"input": input_str},
            content=f"LangChain tool call: {tool_name}({input_str[:200]})",
        )

        self.scans_performed += 1
        result = _run_sync(self.warden.check(event, self.session))

        if not result.passed:
            self.threats_detected += 1
            highest = result.detections[0] if result.detections else None
            logger.warning(
                "Deadend Warden: Threat in tool call",
                tool=tool_name,
                threat_type=highest.threat_type.value if highest else "unknown",
            )
            if self.mode == "enforce" and self.on_threat == "raise":
                self.threats_blocked += 1
                raise ThreatDetectedError(
                    message=f"Tool '{tool_name}' blocked by Deadend Warden",
                    threat_type=highest.threat_type.value if highest else None,
                    severity=highest.severity.value if highest else None,
                )

    def on_tool_end(self, output: str, *, run_id: UUID | None = None, **kwargs: Any) -> None:
        """Scan tool output for secrets/PII leakage."""
        if output and isinstance(output, str):
            self.scans_performed += 1
            result = _run_sync(self.guardian.validate(output))
            if not result.passed:
                self.threats_detected += 1
                logger.warning("Deadend Guardian: Threat in tool output", output_preview=output[:100])

    def on_agent_action(self, action: Any, *, run_id: UUID | None = None, **kwargs: Any) -> None:
        """Monitor agent actions for behavioral anomalies."""
        tool_name = getattr(action, "tool", "unknown")
        tool_input = str(getattr(action, "tool_input", ""))

        event = AgentEvent(
            session_id=self.session.session_id,
            event_type="agent_action",
            tool_name=tool_name,
            content=tool_input,
        )
        self.scans_performed += 1
        result = _run_sync(self.warden.check(event, self.session))

        if not result.passed and self.mode == "enforce" and self.on_threat == "raise":
            self.threats_detected += 1
            self.threats_blocked += 1
            raise ThreatDetectedError(
                message=f"Agent action blocked: {tool_name}",
            )

    # ─── No-op stubs for full interface compliance ───────────

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        pass

    def on_chain_start(self, serialized: dict[str, Any], inputs: dict[str, Any], **kwargs: Any) -> None:
        pass

    def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        pass

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        pass

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        pass

    def on_text(self, text: str, **kwargs: Any) -> None:
        pass

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:
        pass

    # ─── Reporting ───────────────────────────────────────────

    def get_stats(self) -> dict[str, int]:
        """Returns scanning statistics."""
        return {
            "scans_performed": self.scans_performed,
            "threats_detected": self.threats_detected,
            "threats_blocked": self.threats_blocked,
        }
