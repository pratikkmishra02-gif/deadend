"""
Deadend AI — Context Engine
============================
Provides structured domain knowledge (the "Context Wiki") so that open LLM
models (Llama, Mistral, Phi, Gemma, etc.) can understand what Deadend is,
what threats it guards against, and how to reason about agentic security.

The Context Engine is the single source of truth for all security domain
knowledge inside Deadend.  It powers:

* **System prompt enrichment** — auto-injects threat taxonomy, tool-safety
  rules, and Deadend-specific concepts into the LLM's context window.
* **Retrieval-Augmented Detection** — detectors can query the wiki for
  up-to-date attack descriptions when scoring confidence.
* **Integration helpers** — LangChain / CrewAI / LlamaIndex callbacks can
  pull the context preamble to prime the model before the first tool call.
"""
from __future__ import annotations

from deadend.context.engine import ContextEngine
from deadend.context.wiki import ContextWiki

__all__ = ["ContextEngine", "ContextWiki"]
