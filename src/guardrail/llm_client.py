"""Backward-compatible re-export of the guardrail LLM client API.

New code should import from :mod:`guardrail.llm` directly. This module is
kept for compatibility with existing callers and tests.
"""

from __future__ import annotations

from guardrail.llm import (
    AnthropicClient,
    CircuitBreaker,
    FallbackClient,
    GeminiClient,
    LLMClient,
    MockClient,
    OpenAIClient,
    get_client,
)
from guardrail.llm.factory import ProviderClient

__all__ = [
    "LLMClient",
    "CircuitBreaker",
    "FallbackClient",
    "OpenAIClient",
    "AnthropicClient",
    "GeminiClient",
    "MockClient",
    "ProviderClient",
    "get_client",
]
