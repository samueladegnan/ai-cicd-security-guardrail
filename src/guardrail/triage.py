"""Core triage engine: map findings to compliance controls and ask the LLM."""

from __future__ import annotations

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

import requests

from guardrail.code_fetcher import get_code_context_for_finding
from guardrail.compliance import compliance_hits_for_cwe
from guardrail.config import Settings
from guardrail.llm_client import LLMClient, get_client
from guardrail.models import ComplianceHit, Finding, Report, TriageResult, TriageVerdict


class TriageEngine:
    """Orchestrate the classification of static-analysis findings."""

    def __init__(self, settings: Settings, client: Optional[LLMClient] = None):
        self.settings = settings
        self.client = client or get_client(settings)
        self._cache: Dict[str, TriageResult] = {}

    def run(self, findings: List[Finding], repo_root: str = ".") -> Report:
        """Run triage over all findings and return a report."""
        report = Report(results=[])
        for finding in findings:
            enriched = self._enrich_finding(finding, repo_root)
            result = self._triage_one(enriched)
            report.results.append(result)
        report.compute_summary()
        return report

    def run_concurrent(self, findings: List[Finding], repo_root: str = ".") -> Report:
        """Run triage concurrently with controlled parallelism."""
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
        """Load code context into the finding."""
        snippet = get_code_context_for_finding(
            finding,
            before=self.settings.context_lines_before,
            after=self.settings.context_lines_after,
            repo_root=repo_root,
        )
        # Merge in the snippet if not already present.
        if not finding.code_snippet:
            return finding.model_copy(update={"code_snippet": snippet}, deep=True)
        return finding

    def _cache_key(self, finding: Finding) -> str:
        """Stable hash for the finding and its code context."""
        payload = f"{finding.tool}:{finding.rule_id}:{finding.file_path}:{finding.line}:{finding.column}:{finding.code_snippet}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _triage_one(self, finding: Finding) -> TriageResult:
        """Map a single finding to compliance controls and classify it."""
        key = self._cache_key(finding)
        if self.settings.cache_enabled and key in self._cache:
            return self._cache[key]

        hits = compliance_hits_for_cwe(finding.cwe, frameworks=self.settings.frameworks)
        result = self._classify(finding, hits)

        if self.settings.cache_enabled:
            self._cache[key] = result
        return result

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        """Return True if the exception is a transient LLM/API failure."""
        if isinstance(exc, requests.HTTPError) and exc.response is not None:
            return exc.response.status_code in {429, 502, 503, 504}
        # Connection/timeout errors may be retried.
        return isinstance(exc, (requests.ConnectionError, requests.Timeout))

    def _classify(self, finding: Finding, hits: List[ComplianceHit]) -> TriageResult:
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
                time.sleep(2 ** attempt)


def should_fail(report: Report, fail_on_unclear: bool = True) -> bool:
    """Return True if the report should cause a non-zero CI exit code."""
    if report.summary.high_priority > 0:
        return True
    if fail_on_unclear and report.summary.unclear > 0:
        return True
    return False