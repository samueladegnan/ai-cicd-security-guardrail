"""Provider-fallback client with per-provider circuit breakers."""

from __future__ import annotations

import logging

from guardrail.config import Settings
from guardrail.llm.base import LLMClient
from guardrail.llm.circuit import CircuitBreaker
from guardrail.llm.providers import _client_for_provider

logger = logging.getLogger(__name__)


class FallbackClient(LLMClient):
    """Client that tries a chain of providers until one succeeds.

    The primary provider is ``settings.llm_provider``. Additional providers
    are read from ``settings.fallback_providers``. Each provider gets its
    own circuit breaker so a flaky provider does not starve the chain.
    """

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self._clients: list[LLMClient] = []
        self._circuit_breakers: dict[str, CircuitBreaker] = {}

    def _clients_for_chain(self) -> list[LLMClient]:
        if self._clients:
            return self._clients
        providers = [self.settings.llm_provider] + list(self.settings.fallback_providers)
        seen: set[str] = set()
        chain: list[LLMClient] = []
        for provider in providers:
            provider = provider.strip().lower()
            if provider in seen or not provider:
                continue
            seen.add(provider)
            settings = self.settings
            if provider != settings.llm_provider:
                from dataclasses import replace as dc_replace

                settings = dc_replace(settings, llm_provider=provider)
            chain.append(_client_for_provider(provider, settings))
        self._clients = chain
        return chain

    def _breaker(self, name: str) -> CircuitBreaker:
        if name not in self._circuit_breakers:
            self._circuit_breakers[name] = CircuitBreaker(
                name,
                threshold=self.settings.circuit_breaker_threshold,
                timeout_seconds=self.settings.circuit_breaker_timeout_seconds,
            )
        return self._circuit_breakers[name]

    def complete(self, prompt: str) -> str:
        last_error: Exception | None = None
        for client in self._clients_for_chain():
            provider = client.settings.llm_provider
            breaker = self._breaker(provider)
            if breaker.is_open():
                logger.warning("Circuit breaker open for provider %s; skipping", provider)
                continue
            try:
                result = client.complete(prompt)
                breaker.record_success()
                return result
            except Exception as exc:
                breaker.record_failure()
                logger.exception("Provider %s failed", provider)
                last_error = exc
        raise RuntimeError(f"All LLM providers failed. Last error: {last_error}") from last_error
