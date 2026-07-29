"""Factory for creating the configured LLM client."""

from __future__ import annotations

from guardrail.config import Settings
from guardrail.llm.base import LLMClient
from guardrail.llm.fallback import FallbackClient
from guardrail.llm.providers import _client_for_provider


class ProviderClient(LLMClient):
    """Wrapper that delegates to the configured single provider."""

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self._client: LLMClient | None = None

    def complete(self, prompt: str) -> str:
        if self._client is None:
            self._client = _client_for_provider(self.settings.llm_provider, self.settings)
        return self._client.complete(prompt)


def get_client(settings: Settings) -> LLMClient:
    """Factory returning the correct LLM client for the configured provider.

    If fallback providers are configured, the returned client will try each
    provider in order with circuit-breaker protection.
    """
    if settings.fallback_providers:
        return FallbackClient(settings)
    return ProviderClient(settings)
