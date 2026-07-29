"""LLM client package for the guardrail.

This package abstracts LLM providers, circuit-breaker resilience, and
provider-fallback chains behind a small public API.
"""

from __future__ import annotations

from guardrail.llm.base import LLMClient
from guardrail.llm.circuit import CircuitBreaker
from guardrail.llm.factory import ProviderClient, get_client
from guardrail.llm.fallback import FallbackClient
from guardrail.llm.providers import AnthropicClient, GeminiClient, MockClient, OpenAIClient

__all__ = [
    "LLMClient",
    "CircuitBreaker",
    "FallbackClient",
    "ProviderClient",
    "OpenAIClient",
    "AnthropicClient",
    "GeminiClient",
    "MockClient",
    "get_client",
]
