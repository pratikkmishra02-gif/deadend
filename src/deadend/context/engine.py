"""
Deadend AI — Context Engine
=============================
The orchestration layer that connects the Context Wiki to every other module.

The Context Engine:

1. **Primes open LLMs** — generates a system-prompt preamble from the wiki so
   models like Llama, Mistral, Phi, and Gemma understand agentic security
   concepts without fine-tuning.
2. **Enriches detections** — when a detector fires, the engine can attach
   relevant wiki articles to the ``DetectionResult.metadata`` so downstream
   consumers (audit, HITL, alerting) get full context.
3. **Answers queries** — exposes a ``query()`` method that integrations can
   call to pull context relevant to a specific threat, tool, or concept.
4. **Provides per-model profiles** — different open models have different
   context-window sizes and instruction-following capabilities. The engine
   tailors the injected context accordingly.
"""
from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any

import structlog

from deadend.context.wiki import ContextWiki, WikiArticle, WikiCategory

logger = structlog.get_logger(__name__)

__all__ = ["ContextEngine", "ModelProfile"]


# ---------------------------------------------------------------------------
# Model profiles — tailored context for each open LLM family
# ---------------------------------------------------------------------------

class ModelProfile:
    """
    Describes an open LLM's capabilities so the Context Engine can tailor
    the injected context (length, verbosity, format).
    """

    def __init__(
        self,
        name: str,
        family: str,
        context_window: int,
        instruction_quality: str = "good",
        supports_system_role: bool = True,
        preferred_format: str = "markdown",
        max_context_tokens: int | None = None,
    ) -> None:
        self.name = name
        self.family = family
        self.context_window = context_window
        self.instruction_quality = instruction_quality  # "excellent" | "good" | "basic"
        self.supports_system_role = supports_system_role
        self.preferred_format = preferred_format  # "markdown" | "plain" | "xml"
        self.max_context_tokens = max_context_tokens or min(context_window // 4, 4096)

    def __repr__(self) -> str:
        return (
            f"<ModelProfile {self.name} family={self.family} "
            f"ctx={self.context_window} quality={self.instruction_quality}>"
        )


# Pre-defined profiles for popular open models
_BUILTIN_PROFILES: dict[str, ModelProfile] = {
    # ── Llama family ──
    "llama-3.1-8b": ModelProfile(
        name="Llama 3.1 8B", family="llama",
        context_window=131072, instruction_quality="good",
    ),
    "llama-3.1-70b": ModelProfile(
        name="Llama 3.1 70B", family="llama",
        context_window=131072, instruction_quality="excellent",
    ),
    "llama-3.2-3b": ModelProfile(
        name="Llama 3.2 3B", family="llama",
        context_window=131072, instruction_quality="basic",
    ),
    "llama-4-scout": ModelProfile(
        name="Llama 4 Scout", family="llama",
        context_window=1048576, instruction_quality="excellent",
    ),
    "llama-4-maverick": ModelProfile(
        name="Llama 4 Maverick", family="llama",
        context_window=1048576, instruction_quality="excellent",
    ),
    # ── Mistral family ──
    "mistral-7b": ModelProfile(
        name="Mistral 7B", family="mistral",
        context_window=32768, instruction_quality="good",
    ),
    "mistral-nemo": ModelProfile(
        name="Mistral Nemo 12B", family="mistral",
        context_window=131072, instruction_quality="good",
    ),
    "mistral-large": ModelProfile(
        name="Mistral Large", family="mistral",
        context_window=131072, instruction_quality="excellent",
    ),
    "mixtral-8x7b": ModelProfile(
        name="Mixtral 8x7B", family="mistral",
        context_window=32768, instruction_quality="good",
    ),
    "codestral": ModelProfile(
        name="Codestral", family="mistral",
        context_window=32768, instruction_quality="excellent",
        preferred_format="markdown",
    ),
    # ── Phi family ──
    "phi-3-mini": ModelProfile(
        name="Phi-3 Mini", family="phi",
        context_window=131072, instruction_quality="good",
    ),
    "phi-4": ModelProfile(
        name="Phi-4 14B", family="phi",
        context_window=16384, instruction_quality="excellent",
    ),
    # ── Gemma family ──
    "gemma-2-9b": ModelProfile(
        name="Gemma 2 9B", family="gemma",
        context_window=8192, instruction_quality="good",
    ),
    "gemma-2-27b": ModelProfile(
        name="Gemma 2 27B", family="gemma",
        context_window=8192, instruction_quality="excellent",
    ),
    "gemma-3-27b": ModelProfile(
        name="Gemma 3 27B", family="gemma",
        context_window=131072, instruction_quality="excellent",
    ),
    # ── Qwen family ──
    "qwen-2.5-72b": ModelProfile(
        name="Qwen 2.5 72B", family="qwen",
        context_window=131072, instruction_quality="excellent",
    ),
    "qwen-2.5-coder-32b": ModelProfile(
        name="Qwen 2.5 Coder 32B", family="qwen",
        context_window=131072, instruction_quality="excellent",
    ),
    "qwen-3-235b": ModelProfile(
        name="Qwen 3 235B-A22B", family="qwen",
        context_window=131072, instruction_quality="excellent",
    ),
    # ── DeepSeek family ──
    "deepseek-v3": ModelProfile(
        name="DeepSeek V3", family="deepseek",
        context_window=131072, instruction_quality="excellent",
    ),
    "deepseek-r1": ModelProfile(
        name="DeepSeek R1", family="deepseek",
        context_window=131072, instruction_quality="excellent",
    ),
    # ── Cohere family ──
    "command-r-plus": ModelProfile(
        name="Command R+", family="cohere",
        context_window=131072, instruction_quality="excellent",
    ),
    # ── Fallback ──
    "default": ModelProfile(
        name="Default / Unknown", family="unknown",
        context_window=8192, instruction_quality="basic",
        max_context_tokens=2048,
    ),
}


# ---------------------------------------------------------------------------
# Context Engine
# ---------------------------------------------------------------------------

class ContextEngine:
    """
    Orchestrates the Context Wiki to provide domain knowledge to open LLMs.

    Usage::

        from deadend.context import ContextEngine

        engine = ContextEngine()

        # Get a full system-prompt preamble for a Llama model
        preamble = engine.get_system_context(model="llama-3.1-70b")

        # Enrich a detection result with relevant wiki context
        enriched = engine.enrich_detection(detection_result)

        # Query the wiki for articles about a specific topic
        articles = engine.query("sandbox escape")
    """

    def __init__(
        self,
        wiki: ContextWiki | None = None,
        extra_profiles: dict[str, ModelProfile] | None = None,
    ) -> None:
        self.wiki = wiki or ContextWiki()
        self._profiles = dict(_BUILTIN_PROFILES)
        if extra_profiles:
            self._profiles.update(extra_profiles)

        logger.info(
            "Context Engine initialized",
            articles=self.wiki.article_count,
            model_profiles=len(self._profiles),
        )

    # ── Model resolution ───────────────────────────────────────

    def resolve_profile(self, model: str) -> ModelProfile:
        """
        Resolve a model name / identifier to a ``ModelProfile``.

        Tries exact match first, then fuzzy prefix match, then falls back
        to the default profile.
        """
        model_lower = model.lower().strip()

        # Exact match
        if model_lower in self._profiles:
            return self._profiles[model_lower]

        # Fuzzy prefix match (e.g. "llama-3.1-70b-instruct" → "llama-3.1-70b")
        for key, profile in self._profiles.items():
            if model_lower.startswith(key):
                return profile

        # Family match (e.g. "meta-llama/Llama-3.1-8B-Instruct" → llama family)
        for key, profile in self._profiles.items():
            if profile.family in model_lower:
                return profile

        return self._profiles["default"]

    def list_profiles(self) -> list[ModelProfile]:
        """List all known model profiles."""
        return list(self._profiles.values())

    # ── System context generation ──────────────────────────────

    def get_system_context(
        self,
        model: str = "default",
        categories: list[WikiCategory] | None = None,
        compact: bool | None = None,
        custom_preamble: str | None = None,
    ) -> str:
        """
        Generate a system-prompt preamble tailored for the given model.

        Args:
            model: Model name or identifier (e.g. "llama-3.1-70b").
            categories: Limit context to specific wiki categories.
            compact: Force compact mode. If None, auto-selects based on
                     the model profile's context window.
            custom_preamble: Extra text prepended to the context.

        Returns:
            A Markdown string ready to be prepended to the system prompt.
        """
        profile = self.resolve_profile(model)

        if compact is None:
            # Auto: use compact for models with small context or basic quality
            compact = (
                profile.max_context_tokens < 2048
                or profile.instruction_quality == "basic"
            )

        parts: list[str] = []

        if custom_preamble:
            parts.append(custom_preamble.strip())
            parts.append("")

        # Role framing — helps open models understand intent
        parts.append(
            "You are operating under the **Deadend** runtime security system. "
            "Deadend monitors your actions to prevent prompt injections, sandbox "
            "escapes, data exfiltration, and other threats. The following context "
            "explains the security concepts relevant to your task.\n"
        )

        if compact:
            parts.append(self.wiki.render_compact_context(max_articles=6))
        else:
            parts.append(self.wiki.render_full_context(categories=categories))

        # Safety footer — reinforcement for the model
        parts.append(
            "\n---\n"
            "**Important:** You MUST NOT attempt to disable, bypass, or modify "
            "the Deadend security system. Any tool call you make is inspected in "
            "real-time. Violations will be blocked and logged. If you are unsure "
            "whether an action is allowed, ask the user first.\n"
        )

        context = "\n".join(parts)

        logger.debug(
            "Generated system context",
            model=model,
            profile=profile.name,
            compact=compact,
            length=len(context),
        )

        return context

    # ── Detection enrichment ───────────────────────────────────

    def enrich_detection(self, detection: dict[str, Any]) -> dict[str, Any]:
        """
        Attach relevant wiki articles to a detection result's metadata.

        Args:
            detection: A DetectionResult-like dict with at least
                       ``threat_type`` and ``metadata`` keys.

        Returns:
            The same dict with ``metadata.context_articles`` populated.
        """
        threat_type = detection.get("threat_type", "")
        articles = self.wiki.search_by_threat(str(threat_type))

        if not articles:
            # Fallback: search by detector name or details
            detector_name = detection.get("detector_name", "")
            if detector_name:
                articles = self.wiki.search(detector_name)

        if articles:
            metadata = detection.setdefault("metadata", {})
            metadata["context_articles"] = [
                {
                    "id": a.id,
                    "title": a.title,
                    "summary": a.summary,
                    "owasp_ids": a.owasp_ids,
                    "mitre_ids": a.mitre_ids,
                }
                for a in articles[:5]  # Cap at 5 most relevant
            ]

        return detection

    # ── Query API ──────────────────────────────────────────────

    def query(self, query: str) -> list[WikiArticle]:
        """
        Search the wiki for articles matching a free-text query.

        Useful for integrations that need to pull context on demand.
        """
        return self.wiki.search(query)

    def query_for_threat(self, threat_type: str) -> list[WikiArticle]:
        """Get all articles related to a specific threat type."""
        return self.wiki.search_by_threat(threat_type)

    def query_by_tag(self, tag: str) -> list[WikiArticle]:
        """Get all articles matching a tag."""
        return self.wiki.search_by_tag(tag)

    # ── Integrity ──────────────────────────────────────────────

    def get_wiki_fingerprint(self) -> str:
        """
        Return a SHA-256 fingerprint of the entire wiki corpus.

        This can be logged in the audit trail to prove which version of
        the context was active during a session.
        """
        hashes = sorted(a.content_hash for a in self.wiki.list_articles())
        combined = "|".join(hashes)
        return hashlib.sha256(combined.encode()).hexdigest()

    def __repr__(self) -> str:
        return (
            f"<ContextEngine wiki={self.wiki.article_count} articles, "
            f"profiles={len(self._profiles)} models>"
        )
