"""Configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Settings:
    """Runtime configuration for the guardrail.

    All values can be supplied via environment variables to keep CI/CD
    integrations secret-free in source control.
    """

    # LLM provider selection: openai | anthropic | gemini | mock
    llm_provider: str = "mock"
    llm_model: str = ""
    llm_api_key: str = ""
    llm_base_url: str = ""

    # Execution behavior
    max_concurrency: int = 3
    cache_enabled: bool = True
    timeout_seconds: int = 60
    retries: int = 2

    # Code context
    context_lines_before: int = 4
    context_lines_after: int = 4

    # Output
    output_json: Optional[str] = None
    output_markdown: Optional[str] = None
    fail_on_unclear: bool = True

    # Optional compliance controls
    frameworks: tuple[str, ...] = ("cert_c", "misra_c", "fips")

    @classmethod
    def from_env(cls) -> "Settings":
        """Build a Settings instance from environment variables."""
        return cls(
            llm_provider=os.getenv("GUARDRAIL_LLM_PROVIDER", "mock").lower(),
            llm_model=os.getenv("GUARDRAIL_LLM_MODEL", ""),
            llm_api_key=os.getenv("GUARDRAIL_LLM_API_KEY", ""),
            llm_base_url=os.getenv("GUARDRAIL_LLM_BASE_URL", ""),
            max_concurrency=int(os.getenv("GUARDRAIL_MAX_CONCURRENCY", "3")),
            cache_enabled=os.getenv("GUARDRAIL_CACHE_ENABLED", "true").lower() in {"1", "true", "yes"},
            timeout_seconds=int(os.getenv("GUARDRAIL_TIMEOUT_SECONDS", "60")),
            retries=int(os.getenv("GUARDRAIL_RETRIES", "2")),
            context_lines_before=int(os.getenv("GUARDRAIL_CONTEXT_BEFORE", "4")),
            context_lines_after=int(os.getenv("GUARDRAIL_CONTEXT_AFTER", "4")),
            output_json=os.getenv("GUARDRAIL_OUTPUT_JSON"),
            output_markdown=os.getenv("GUARDRAIL_OUTPUT_MARKDOWN"),
            fail_on_unclear=os.getenv("GUARDRAIL_FAIL_ON_UNCLEAR", "true").lower() in {"1", "true", "yes"},
            frameworks=tuple(
                f.strip()
                for f in os.getenv("GUARDRAIL_FRAMEWORKS", "cert_c,misra_c,fips").split(",")
                if f.strip()
            ),
        )

    @property
    def effective_model(self) -> str:
        """Return a sensible default model for the configured provider."""
        if self.llm_model:
            return self.llm_model
        defaults = {
            "openai": "gpt-4o-mini",
            "anthropic": "claude-3-5-sonnet-20240620",
            "gemini": "gemini-1.5-flash",
            "mock": "mock",
        }
        return defaults.get(self.llm_provider, "mock")