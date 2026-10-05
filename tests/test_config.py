"""
Tests for blue_agent.config — verify all settings load correctly
and environment overrides work.
"""

from __future__ import annotations

import os

import pytest


def test_settings_singleton():
    """settings is importable and is a Settings instance."""
    from blue_agent.config import Settings, settings
    assert isinstance(settings, Settings)


def test_database_url_format():
    from blue_agent.config import settings
    url = settings.db.url
    assert url.startswith("postgresql+asyncpg://")
    assert settings.db.database in url


def test_sync_database_url():
    from blue_agent.config import settings
    url = settings.db.sync_url
    assert url.startswith("postgresql://")


def test_database_url_property():
    from blue_agent.config import settings
    url = settings.database_url
    assert url.startswith("postgresql://")


def test_llm_effective_base_url_openai():
    from blue_agent.config import LLMSettings
    s = LLMSettings(provider="openai", base_url="")
    assert "openai" in s.effective_base_url


def test_llm_effective_base_url_deepseek():
    from blue_agent.config import LLMSettings
    s = LLMSettings(provider="deepseek", base_url="")
    assert "deepseek" in s.effective_base_url


def test_llm_effective_base_url_ollama():
    from blue_agent.config import LLMSettings
    s = LLMSettings(provider="ollama", base_url="")
    assert "11434" in s.effective_base_url


def test_llm_custom_base_url():
    from blue_agent.config import LLMSettings
    s = LLMSettings(provider="openai", base_url="https://custom.endpoint.com/v1")
    assert s.effective_base_url == "https://custom.endpoint.com/v1"


def test_security_tool_allowlist_not_empty():
    from blue_agent.config import settings
    assert len(settings.security.tool_allowlist) > 0
    assert "apply_patch" in settings.security.tool_allowlist
    assert "run_tests" in settings.security.tool_allowlist


def test_ppo_confidence_threshold():
    from blue_agent.config import settings
    assert 0.0 <= settings.ppo.confidence_threshold <= 1.0
