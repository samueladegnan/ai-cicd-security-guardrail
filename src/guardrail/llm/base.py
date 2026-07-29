"""Abstract LLM client and prompt/response helpers."""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod

from guardrail.config import Settings
from guardrail.models import ComplianceHit, Finding, TriageResult, TriageVerdict

logger = logging.getLogger(__name__)


class LLMClient(ABC):
    """Abstract base class for LLM clients."""

    def __init__(self, settings: Settings):
        self.settings = settings

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Send a prompt and return the raw text response."""

    def triage_finding(self, finding: Finding, hits: list[ComplianceHit]) -> TriageResult:
        """Build a prompt and return a structured triage result."""
        prompt = self._build_prompt(finding, hits)
        raw = self.complete(prompt)
        return self._parse_response(raw, finding, hits)

    def _build_prompt(self, finding: Finding, hits: list[ComplianceHit]) -> str:
        compliance_text = ""
        if hits:
            lines = []
            for hit in hits:
                lines.append(f"- {hit.framework.upper()} {hit.rule_id}: {hit.title}")
                if hit.description:
                    lines.append(f"  {hit.description}")
            compliance_text = "\n".join(lines)
        else:
            compliance_text = (
                "No explicit compliance rules were mapped. Use your secure-coding knowledge."
            )

        language_hint = finding.language.value if finding.language else "unknown"
        return (
            "You are a senior secure-code reviewer. "
            "A static analysis tool produced a warning. Your task is to classify it "
            "as HIGH_PRIORITY, FALSE_POSITIVE, or UNCLEAR, based on whether it "
            "represents a real security risk aligned with industry compliance frameworks.\n\n"
            "Respond ONLY with a JSON object matching this schema (no markdown, no prose):\n"
            "{\n"
            '  "reasoning": "Step-by-step analysis of the warning and code",\n'
            '  "verdict": "HIGH_PRIORITY" | "FALSE_POSITIVE" | "UNCLEAR",\n'
            '  "confidence": float between 0 and 1,\n'
            '  "compliance_rules": ["framework rule-id", ...],\n'
            '  "remediation": "Concrete next step or fix if high-priority"\n'
            "}\n\n"
            "Use these compliance controls for context:\n"
            f"{compliance_text}\n\n"
            f"Static analysis tool: {finding.tool}\n"
            f"Language: {language_hint}\n"
            f"Rule: {finding.rule_id}\n"
            f"Severity: {finding.severity.value}\n"
            f"CWE: {finding.cwe or 'unknown'}\n"
            f"Message: {finding.message}\n"
            f"Location: {finding.file_path}:{finding.line}:{finding.column}\n\n"
            "Code context:\n"
            f"```{language_hint}\n"
            f"{finding.code_snippet}\n"
            "```\n"
        )

    def _parse_response(
        self, raw: str, finding: Finding, hits: list[ComplianceHit]
    ) -> TriageResult:
        try:
            cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.IGNORECASE)
            cleaned = re.sub(r"\s*```$", "", cleaned)
            data = json.loads(cleaned)
            verdict_str = data.get("verdict", "UNCLEAR").upper()
            verdict = (
                TriageVerdict(verdict_str)
                if verdict_str in {v.value for v in TriageVerdict}
                else TriageVerdict.UNCLEAR
            )
            return TriageResult(
                finding=finding,
                verdict=verdict,
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", "No reasoning provided."),
                compliance_hits=hits,
                remediation=data.get("remediation", ""),
            )
        except Exception:
            logger.exception("Failed to parse LLM response for finding %s", finding.rule_id)
            return TriageResult(
                finding=finding,
                verdict=TriageVerdict.UNCLEAR,
                confidence=0.0,
                reasoning=f"Failed to parse LLM response: {raw}",
                compliance_hits=hits,
                remediation="",
            )
