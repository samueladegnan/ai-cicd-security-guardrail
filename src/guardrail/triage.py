"""Core triage engine: map findings to compliance controls and ask the LLM."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import requests

from guardrail.cache import TriageCache, make_cache, stable_key
from guardrail.compliance import ComplianceRegistry, default_registry
from guardrail.compliance.semantic import SemanticComplianceMapper, seed_default_controls
from guardrail.config import Settings
from guardrail.context import ContextRegistry, get_code_context_for_finding
from guardrail.llm import LLMClient, get_client
from guardrail.logger import get_logger
from guardrail.models import ComplianceHit, Finding, Report, TriageResult, TriageVerdict
from guardrail.policy import get_policy_engine

logger = get_logger(__name__)


class TriageEngine:
    """Orchestrate the classification of static-analysis findings."""

    def __init__(
        self,
        settings: Settings,
        client: LLMClient | None = None,
        compliance_registry: ComplianceRegistry | None = None,
        context_registry: ContextRegistry | None = None,
        cache: TriageCache | None = None,
    ):
        self.settings = settings
        self.client = client or get_client(settings)
        self.compliance_registry = compliance_registry or default_registry()
        self.context_registry = context_registry or ContextRegistry.default(
            strategy=settings.context_strategy
        )
        self.semantic_mapper: SemanticComplianceMapper | None = None
        if settings.semantic_compliance_enabled:
            self.semantic_mapper = SemanticComplianceMapper(
                vector_store_path=settings.vector_store_path,
                embedding_model=settings.embedding_model,
            )
            seed_default_controls(self.semantic_mapper)
        self.cache = cache or make_cache(
            backend=settings.cache_backend,
            sqlite_path=settings.cache_sqlite_path,
        )

    def run(self, findings: list[Finding], repo_root: str = ".") -> Report:
        """Run triage over all findings and return a report."""
        logger.info("Starting triage for %d findings", len(findings))
        report = Report(results=[])
        for finding in findings:
            enriched = self._enrich_finding(finding, repo_root)
            result = self._triage_one(enriched)
            report.results.append(result)
        report.compute_summary()
        return report

    def run_concurrent(self, findings: list[Finding], repo_root: str = ".") -> Report:
        """Run triage concurrently with controlled parallelism."""
        logger.info("Starting concurrent triage for %d findings", len(findings))
        if self.settings.max_concurrency <= 1:
            return self.run(findings, repo_root)

        report = Report(results=[])
        with ThreadPoolExecutor(max_workers=self.settings.max_concurrency) as executor:
            futures = [
                executor.submit(self._triage_one, self._enrich_finding(finding, repo_root))
                for finding in findings
            ]
            for future in futures:
                report.results.append(future.result())
        report.compute_summary()
        return report

    def _enrich_finding(self, finding: Finding, repo_root: str) -> Finding:
        """Load source code context into the finding."""
        snippet = get_code_context_for_finding(
            finding,
            before=self.settings.context_lines_before,
            after=self.settings.context_lines_after,
            repo_root=repo_root,
            registry=self.context_registry,
        )
        if not finding.code_snippet:
            finding = finding.model_copy(update={"code_snippet": snippet}, deep=True)
        return finding

    def _cache_key(self, finding: Finding, hits: list[ComplianceHit]) -> str:
        """Stable hash for the finding and its compliance context."""
        return stable_key(finding, hits)

    def _triage_one(self, finding: Finding) -> TriageResult:
        """Map a single finding to compliance controls and classify it."""
        hits = self.compliance_registry.map_finding(
            finding,
            frameworks=self.settings.frameworks,
            language=finding.language,
        )
        if not hits and self.semantic_mapper is not None:
            hits = self.semantic_mapper.map_finding(finding)
        key = self._cache_key(finding, hits)

        if self.settings.cache_enabled:
            cached = self.cache.get(key)
            if cached is not None:
                return cached

        result = self._classify(finding, hits)

        if self.settings.cache_enabled:
            self.cache.set(key, result)
        return result

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        """Return True if the exception is a transient LLM/API failure."""
        if isinstance(exc, requests.HTTPError) and exc.response is not None:
            return exc.response.status_code in {429, 502, 503, 504}
        # Connection/timeout errors may be retried.
        return isinstance(exc, (requests.ConnectionError, requests.Timeout))

    def _classify(self, finding: Finding, hits: list[ComplianceHit]) -> TriageResult:
        logger.debug(
            "Classifying finding %s at %s:%s", finding.rule_id, finding.file_path, finding.line
        )
        for attempt in range(self.settings.retries + 1):
            try:
                return self.client.triage_finding(finding, hits)
            except Exception as exc:
                if not self._is_retryable(exc) or attempt == self.settings.retries:
                    return TriageResult(
                        finding=finding,
                        verdict=TriageVerdict.UNCLEAR,
                        confidence=0.0,
                        reasoning=f"LLM classification failed after {attempt + 1} attempts: {exc}",
                        compliance_hits=hits,
                        remediation="",
                    )
                # Exponential backoff before retrying.
                time.sleep(2**attempt)
        return TriageResult(
            finding=finding,
            verdict=TriageVerdict.UNCLEAR,
            confidence=0.0,
            reasoning="LLM classification exhausted all retries without a definitive result.",
            compliance_hits=hits,
            remediation="",
        )


def should_fail(report: Report, fail_on_unclear: bool = True) -> bool:
    """Return True if the report should cause a non-zero CI exit code."""
    return report.summary.high_priority > 0 or (fail_on_unclear and report.summary.unclear > 0)


def evaluate_policy(report: Report, settings: Settings) -> bool:
    """Evaluate the report against the configured policy engine.

    Returns True if the pipeline should fail.
    """
    engine = get_policy_engine(settings)
    decision = engine.evaluate(report, settings)
    # A configured policy must fail closed if the engine returns an incomplete
    # or malformed decision rather than silently allowing the build.
    return decision.get("allow") is not True
