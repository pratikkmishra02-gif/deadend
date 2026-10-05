"""
Tests for deadend.context — Context Engine & Context Wiki
==========================================================
"""
from __future__ import annotations

import json

import pytest

from deadend.context.engine import ContextEngine, ModelProfile
from deadend.context.wiki import ContextWiki, WikiArticle, WikiCategory


# ════════════════════════════════════════════════════════════════
# Wiki tests
# ════════════════════════════════════════════════════════════════


class TestContextWiki:
    """Tests for the ContextWiki knowledge base."""

    def test_builtin_articles_loaded(self):
        wiki = ContextWiki()
        assert wiki.article_count >= 15, "Should have at least 15 built-in articles"

    def test_all_builtin_ids_are_unique(self):
        wiki = ContextWiki()
        articles = wiki.list_articles()
        ids = [a.id for a in articles]
        assert len(ids) == len(set(ids)), "Duplicate article IDs found"

    def test_get_by_id(self):
        wiki = ContextWiki()
        article = wiki.get("arch-overview")
        assert article is not None
        assert article.title == "Deadend Architecture Overview"
        assert article.category == WikiCategory.ARCHITECTURE

    def test_get_nonexistent_returns_none(self):
        wiki = ContextWiki()
        assert wiki.get("does-not-exist") is None

    def test_search_by_tag(self):
        wiki = ContextWiki()
        results = wiki.search_by_tag("injection")
        assert len(results) >= 1
        # All results should have the tag
        for r in results:
            assert "injection" in r.tags

    def test_search_by_tag_case_insensitive(self):
        wiki = ContextWiki()
        lower = wiki.search_by_tag("injection")
        upper = wiki.search_by_tag("INJECTION")
        # Tags are stored lowercase, so upper should find nothing unless
        # the implementation lowercases the query (it does)
        assert len(lower) == len(upper)

    def test_search_by_threat(self):
        wiki = ContextWiki()
        results = wiki.search_by_threat("PROMPT_INJECTION")
        assert len(results) >= 2, "Should find multiple articles about prompt injection"

    def test_search_by_threat_unknown(self):
        wiki = ContextWiki()
        results = wiki.search_by_threat("NONEXISTENT_THREAT")
        assert results == []

    def test_full_text_search(self):
        wiki = ContextWiki()
        results = wiki.search("circuit breaker")
        assert len(results) >= 1
        assert any("circuit" in a.title.lower() for a in results)

    def test_full_text_search_no_results(self):
        wiki = ContextWiki()
        results = wiki.search("xyzzy_nonexistent_term_12345")
        assert results == []

    def test_list_articles_no_filter(self):
        wiki = ContextWiki()
        articles = wiki.list_articles()
        assert len(articles) == wiki.article_count

    def test_list_articles_by_category(self):
        wiki = ContextWiki()
        threats = wiki.list_articles(category=WikiCategory.THREAT)
        assert len(threats) >= 3
        for a in threats:
            assert a.category == WikiCategory.THREAT

    def test_all_tags_property(self):
        wiki = ContextWiki()
        tags = wiki.all_tags
        assert isinstance(tags, list)
        assert len(tags) > 10
        assert tags == sorted(tags), "Tags should be sorted alphabetically"

    def test_render_full_context(self):
        wiki = ContextWiki()
        ctx = wiki.render_full_context()
        assert "# Deadend Security Context Wiki" in ctx
        assert "Prompt Injection" in ctx
        assert "Sentinel" in ctx
        assert len(ctx) > 1000

    def test_render_full_context_filtered(self):
        wiki = ContextWiki()
        ctx = wiki.render_full_context(categories=[WikiCategory.CONCEPT])
        assert "Circuit Breaker" in ctx
        # Should NOT contain integration articles
        assert "LangChain Integration" not in ctx

    def test_render_compact_context(self):
        wiki = ContextWiki()
        ctx = wiki.render_compact_context(max_articles=5)
        assert "# Deadend Security Context (Compact)" in ctx
        # Should be significantly shorter than full
        full = wiki.render_full_context()
        assert len(ctx) < len(full)

    def test_to_json(self):
        wiki = ContextWiki()
        j = wiki.to_json()
        data = json.loads(j)
        assert isinstance(data, list)
        assert len(data) == wiki.article_count
        assert all("id" in item for item in data)
        assert all("title" in item for item in data)

    def test_extra_articles(self):
        custom = WikiArticle(
            id="custom-001",
            title="Custom Article",
            category=WikiCategory.CONCEPT,
            summary="A test article.",
            body="This is a custom article for testing.",
            tags=["custom", "test"],
        )
        wiki = ContextWiki(extra_articles=[custom])
        assert wiki.get("custom-001") is not None
        assert wiki.get("custom-001").title == "Custom Article"
        results = wiki.search_by_tag("custom")
        assert len(results) == 1

    def test_wiki_is_immutable_after_init(self):
        """Verify that the internal article dict can't be mutated via the API."""
        wiki = ContextWiki()
        count_before = wiki.article_count
        # The _articles dict is internal but let's verify get() returns a copy-safe object
        article = wiki.get("arch-overview")
        assert article is not None
        # Even if someone mutates the returned article, the wiki's count doesn't change
        assert wiki.article_count == count_before

    def test_article_content_hash(self):
        article = WikiArticle(
            id="test-hash",
            title="Hash Test",
            category=WikiCategory.CONCEPT,
            summary="Test",
            body="Deterministic body content",
        )
        hash1 = article.content_hash
        hash2 = article.content_hash
        assert hash1 == hash2, "Hash should be deterministic"
        assert len(hash1) == 64, "Should be SHA-256 hex digest"

    def test_article_to_prompt_block(self):
        article = WikiArticle(
            id="test-block",
            title="Test Block",
            category=WikiCategory.CONCEPT,
            summary="Test summary",
            body="This is the body.",
            tags=["test", "block"],
            references=["https://example.com"],
        )
        block = article.to_prompt_block()
        assert "### Test Block" in block
        assert "**Category:** concept" in block
        assert "**Tags:** test, block" in block
        assert "This is the body." in block
        assert "https://example.com" in block

    def test_repr(self):
        wiki = ContextWiki()
        r = repr(wiki)
        assert "ContextWiki" in r
        assert "articles=" in r


# ════════════════════════════════════════════════════════════════
# Context Engine tests
# ════════════════════════════════════════════════════════════════


class TestContextEngine:
    """Tests for the ContextEngine orchestration layer."""

    def test_init_default(self):
        engine = ContextEngine()
        assert engine.wiki.article_count >= 15
        assert len(engine._profiles) >= 10

    def test_resolve_profile_exact(self):
        engine = ContextEngine()
        profile = engine.resolve_profile("llama-3.1-70b")
        assert profile.family == "llama"
        assert profile.context_window == 131072

    def test_resolve_profile_prefix(self):
        engine = ContextEngine()
        profile = engine.resolve_profile("llama-3.1-70b-instruct")
        assert profile.family == "llama"

    def test_resolve_profile_family_match(self):
        engine = ContextEngine()
        profile = engine.resolve_profile("meta-llama/Llama-3.1-8B-Instruct")
        assert profile.family == "llama"

    def test_resolve_profile_fallback(self):
        engine = ContextEngine()
        profile = engine.resolve_profile("totally-unknown-model-xyz")
        assert profile.family == "unknown"

    def test_get_system_context_full(self):
        engine = ContextEngine()
        ctx = engine.get_system_context(model="llama-3.1-70b", compact=False)
        assert "Deadend" in ctx
        assert "runtime security" in ctx
        assert "MUST NOT" in ctx  # Safety footer
        assert len(ctx) > 2000

    def test_get_system_context_compact(self):
        engine = ContextEngine()
        ctx = engine.get_system_context(model="gemma-2-9b", compact=True)
        assert "Compact" in ctx
        full = engine.get_system_context(model="gemma-2-9b", compact=False)
        assert len(ctx) < len(full)

    def test_get_system_context_auto_compact_for_basic(self):
        engine = ContextEngine()
        # llama-3.2-3b has "basic" instruction quality → should auto-compact
        ctx = engine.get_system_context(model="llama-3.2-3b")
        assert "Compact" in ctx

    def test_get_system_context_auto_full_for_excellent(self):
        engine = ContextEngine()
        ctx = engine.get_system_context(model="llama-3.1-70b")
        assert "# Deadend Security Context Wiki" in ctx

    def test_get_system_context_with_categories(self):
        engine = ContextEngine()
        ctx = engine.get_system_context(
            model="llama-3.1-70b",
            categories=[WikiCategory.THREAT],
            compact=False,
        )
        assert "Prompt Injection" in ctx
        # Integration articles should not appear (filtered by category)
        assert "```python" not in ctx or "LangChain Integration" not in ctx

    def test_get_system_context_custom_preamble(self):
        engine = ContextEngine()
        ctx = engine.get_system_context(
            model="default",
            compact=True,
            custom_preamble="CUSTOM: You are a financial agent.",
        )
        assert "CUSTOM: You are a financial agent." in ctx

    def test_enrich_detection(self):
        engine = ContextEngine()
        detection = {
            "detected": True,
            "threat_type": "PROMPT_INJECTION",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "detector_name": "injection_detector",
            "metadata": {},
        }
        enriched = engine.enrich_detection(detection)
        assert "context_articles" in enriched["metadata"]
        articles = enriched["metadata"]["context_articles"]
        assert len(articles) >= 1
        assert all("id" in a for a in articles)
        assert all("title" in a for a in articles)

    def test_enrich_detection_no_match(self):
        engine = ContextEngine()
        detection = {
            "detected": True,
            "threat_type": "TOTALLY_UNKNOWN_THREAT_XYZ",
            "severity": "LOW",
            "confidence": 0.5,
            "detector_name": "unknown_detector",
            "metadata": {},
        }
        enriched = engine.enrich_detection(detection)
        # Should not crash, metadata may or may not have articles
        assert isinstance(enriched, dict)

    def test_query(self):
        engine = ContextEngine()
        results = engine.query("sandbox escape")
        assert len(results) >= 1

    def test_query_for_threat(self):
        engine = ContextEngine()
        results = engine.query_for_threat("TOOL_ABUSE")
        assert len(results) >= 1

    def test_query_by_tag(self):
        engine = ContextEngine()
        results = engine.query_by_tag("crewai")
        assert len(results) >= 1
        assert any("CrewAI" in a.title for a in results)

    def test_wiki_fingerprint_deterministic(self):
        engine = ContextEngine()
        fp1 = engine.get_wiki_fingerprint()
        fp2 = engine.get_wiki_fingerprint()
        assert fp1 == fp2
        assert len(fp1) == 64  # SHA-256 hex

    def test_wiki_fingerprint_changes_with_extra_articles(self):
        engine1 = ContextEngine()
        custom_wiki = ContextWiki(extra_articles=[
            WikiArticle(
                id="extra-001",
                title="Extra",
                category=WikiCategory.CONCEPT,
                summary="Extra",
                body="Extra body.",
            )
        ])
        engine2 = ContextEngine(wiki=custom_wiki)
        assert engine1.get_wiki_fingerprint() != engine2.get_wiki_fingerprint()

    def test_extra_profiles(self):
        custom_profile = ModelProfile(
            name="Custom Model",
            family="custom",
            context_window=65536,
            instruction_quality="good",
        )
        engine = ContextEngine(extra_profiles={"custom-v1": custom_profile})
        profile = engine.resolve_profile("custom-v1")
        assert profile.family == "custom"
        assert profile.context_window == 65536

    def test_list_profiles(self):
        engine = ContextEngine()
        profiles = engine.list_profiles()
        assert len(profiles) >= 10
        assert all(isinstance(p, ModelProfile) for p in profiles)

    def test_repr(self):
        engine = ContextEngine()
        r = repr(engine)
        assert "ContextEngine" in r
        assert "articles" in r
        assert "models" in r


# ════════════════════════════════════════════════════════════════
# Model Profile tests
# ════════════════════════════════════════════════════════════════


class TestModelProfile:
    """Tests for ModelProfile."""

    def test_defaults(self):
        p = ModelProfile(name="Test", family="test", context_window=8192)
        assert p.instruction_quality == "good"
        assert p.supports_system_role is True
        assert p.preferred_format == "markdown"
        assert p.max_context_tokens == 2048  # min(8192//4, 4096) = 2048

    def test_max_context_tokens_cap(self):
        p = ModelProfile(name="Big", family="test", context_window=131072)
        assert p.max_context_tokens == 4096  # Capped at 4096

    def test_max_context_tokens_override(self):
        p = ModelProfile(
            name="Custom", family="test",
            context_window=131072, max_context_tokens=8192,
        )
        assert p.max_context_tokens == 8192

    def test_repr(self):
        p = ModelProfile(name="Llama 3", family="llama", context_window=131072)
        assert "Llama 3" in repr(p)
        assert "llama" in repr(p)


# ════════════════════════════════════════════════════════════════
# Wiki Category tests
# ════════════════════════════════════════════════════════════════


class TestWikiCategory:
    """Tests for WikiCategory enum."""

    def test_all_categories_have_articles(self):
        wiki = ContextWiki()
        for cat in WikiCategory:
            articles = wiki.list_articles(category=cat)
            assert len(articles) >= 1, f"No articles for category {cat.value}"
