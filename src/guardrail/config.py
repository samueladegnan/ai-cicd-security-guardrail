"""Configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


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

    # Provider fallback and resilience
    fallback_providers: tuple[str, ...] = ()
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout_seconds: int = 60

    # Execution behavior
    max_concurrency: int = 3
    cache_enabled: bool = True
    cache_backend: str = "memory"  # memory | sqlite
    cache_sqlite_path: str = ".guardrail-cache.db"
    timeout_seconds: int = 60
    retries: int = 2

    # Code context
    context_lines_before: int = 4
    context_lines_after: int = 4
    context_strategy: str = "auto"  # auto | line-window | ast

    # Output
    output_json: str | None = None
    output_markdown: str | None = None
    output_sarif: str | None = None
    fail_on_unclear: bool = True

    # Policy-as-code
    policy_path: str | None = None

    # GitHub PR comments
    github_token: str = ""
    pr_number: int = 0
    pr_comment_mode: str = ""  # "" | "review" | "commit"
    repository: str = ""  # owner/repo
    commit_sha: str = ""

    # Semantic compliance / RAG
    semantic_compliance_enabled: bool = False
    embedding_model: str = "all-MiniLM-L6-v2"
    vector_store_path: str = ".guardrail-vectors.db"

    # Optional compliance controls
    frameworks: tuple[str, ...] = ("cert_c", "misra_c", "fips")

    def __post_init__(self) -> None:
        """Reject invalid runtime limits before they reach worker/API code."""
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than 0")
        if self.retries < 0:
            raise ValueError("retries must not be negative")
        if self.context_lines_before < 0 or self.context_lines_after < 0:
            raise ValueError("context line counts must not be negative")
        if self.circuit_breaker_threshold < 1:
            raise ValueError("circuit_breaker_threshold must be at least 1")
        if self.circuit_breaker_timeout_seconds <= 0:
            raise ValueError("circuit_breaker_timeout_seconds must be greater than 0")

    @classmethod
    def from_env(cls) -> Settings:
        """Build a Settings instance from environment variables."""
        fallback_raw = os.getenv("GUARDRAIL_FALLBACK_PROVIDERS", "")
        fallback_providers = tuple(p.strip() for p in fallback_raw.split(",") if p.strip())
        return cls(
            llm_provider=os.getenv("GUARDRAIL_LLM_PROVIDER", "mock").lower(),
            llm_model=os.getenv("GUARDRAIL_LLM_MODEL", ""),
            llm_api_key=os.getenv("GUARDRAIL_LLM_API_KEY", ""),
            llm_base_url=os.getenv("GUARDRAIL_LLM_BASE_URL", ""),
            fallback_providers=fallback_providers,
            circuit_breaker_threshold=int(os.getenv("GUARDRAIL_CIRCUIT_BREAKER_THRESHOLD", "5")),
            circuit_breaker_timeout_seconds=int(
                os.getenv("GUARDRAIL_CIRCUIT_BREAKER_TIMEOUT", "60")
            ),
            max_concurrency=int(os.getenv("GUARDRAIL_MAX_CONCURRENCY", "3")),
            cache_enabled=os.getenv("GUARDRAIL_CACHE_ENABLED", "true").lower()
            in {"1", "true", "yes"},
            cache_backend=os.getenv("GUARDRAIL_CACHE_BACKEND", "memory").lower(),
            cache_sqlite_path=os.getenv("GUARDRAIL_CACHE_SQLITE_PATH", ".guardrail-cache.db"),
            timeout_seconds=int(os.getenv("GUARDRAIL_TIMEOUT_SECONDS", "60")),
            retries=int(os.getenv("GUARDRAIL_RETRIES", "2")),
            context_lines_before=int(os.getenv("GUARDRAIL_CONTEXT_BEFORE", "4")),
            context_lines_after=int(os.getenv("GUARDRAIL_CONTEXT_AFTER", "4")),
            context_strategy=os.getenv("GUARDRAIL_CONTEXT_STRATEGY", "auto").lower(),
            output_json=os.getenv("GUARDRAIL_OUTPUT_JSON"),
            output_markdown=os.getenv("GUARDRAIL_OUTPUT_MARKDOWN"),
            output_sarif=os.getenv("GUARDRAIL_OUTPUT_SARIF"),
            fail_on_unclear=os.getenv("GUARDRAIL_FAIL_ON_UNCLEAR", "true").lower()
            in {"1", "true", "yes"},
            policy_path=os.getenv("GUARDRAIL_POLICY_PATH"),
            github_token=os.getenv("GUARDRAIL_GITHUB_TOKEN", os.getenv("GITHUB_TOKEN", "")),
            pr_number=int(os.getenv("GUARDRAIL_PR_NUMBER", "0")),
            pr_comment_mode=os.getenv("GUARDRAIL_PR_COMMENT_MODE", ""),
            repository=os.getenv("GUARDRAIL_REPOSITORY", os.getenv("GITHUB_REPOSITORY", "")),
            commit_sha=os.getenv("GUARDRAIL_COMMIT_SHA", os.getenv("GITHUB_SHA", "")),
            semantic_compliance_enabled=os.getenv("GUARDRAIL_SEMANTIC_COMPLIANCE", "false").lower()
            in {"1", "true", "yes"},
            embedding_model=os.getenv("GUARDRAIL_EMBEDDING_MODEL", "all-MiniLM-L6-v2"),
            vector_store_path=os.getenv("GUARDRAIL_VECTOR_STORE_PATH", ".guardrail-vectors.db"),
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
