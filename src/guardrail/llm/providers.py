"""Concrete LLM provider clients."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import requests

from guardrail.config import Settings
from guardrail.llm.base import LLMClient
from guardrail.models import ComplianceHit, Finding, TriageResult, TriageVerdict

logger = logging.getLogger(__name__)


class OpenAIClient(LLMClient):
    """OpenAI-compatible chat completions client."""

    def complete(self, prompt: str) -> str:
        api_key = self.settings.llm_api_key or os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            raise RuntimeError(
                "OpenAI API key is required. Set OPENAI_API_KEY or GUARDRAIL_LLM_API_KEY."
            )
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        model = self.settings.effective_model
        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a precise secure-code reviewer."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 1024,
        }
        base_url = self.settings.llm_base_url or "https://api.openai.com/v1"
        resp = requests.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=self.settings.timeout_seconds,
        )
        resp.raise_for_status()
        return str(resp.json()["choices"][0]["message"]["content"])


class AnthropicClient(LLMClient):
    """Anthropic Messages API client."""

    def complete(self, prompt: str) -> str:
        api_key = self.settings.llm_api_key or os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise RuntimeError(
                "Anthropic API key is required. Set ANTHROPIC_API_KEY or GUARDRAIL_LLM_API_KEY."
            )
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        model = self.settings.effective_model
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": prompt},
            ],
        }
        base_url = self.settings.llm_base_url or "https://api.anthropic.com"
        resp = requests.post(
            f"{base_url}/v1/messages",
            headers=headers,
            json=payload,
            timeout=self.settings.timeout_seconds,
        )
        resp.raise_for_status()
        return str(resp.json()["content"][0]["text"])


class GeminiClient(LLMClient):
    """Google Gemini API client."""

    def complete(self, prompt: str) -> str:
        api_key = self.settings.llm_api_key or os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            raise RuntimeError(
                "Gemini API key is required. Set GEMINI_API_KEY or GUARDRAIL_LLM_API_KEY."
            )
        model = self.settings.effective_model
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        payload: dict[str, Any] = {
            "contents": [
                {
                    "parts": [
                        {"text": "You are a precise secure-code reviewer."},
                        {"text": prompt},
                    ]
                }
            ],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 1024},
        }
        headers = {"Content-Type": "application/json", "x-goog-api-key": api_key}
        resp = requests.post(
            url, headers=headers, json=payload, timeout=self.settings.timeout_seconds
        )
        resp.raise_for_status()
        data = resp.json()
        try:
            return str(data["candidates"][0]["content"]["parts"][0]["text"])
        except (KeyError, IndexError) as exc:
            raise RuntimeError(f"Unexpected Gemini response structure: {data}") from exc


class MockClient(LLMClient):
    """Deterministic client for demos and CI without API keys.

    Uses simple heuristics to classify findings. It is not a substitute for
    a real LLM, but it demonstrates the pipeline without external costs.
    """

    HIGH_SIGNALS = {
        "buffer overflow",
        "stack overflow",
        "heap overflow",
        "out of bounds",
        "use after free",
        "use-after-free",
        "double free",
        "double-free",
        "null pointer",
        "null dereference",
        "format string",
        "strcpy",
        "strcat",
        "gets(",
        "sprintf",
        "malloc",
        "memcpy",
        "memmove",
        "overflow",
        "integer overflow",
        "race condition",
        "command injection",
        "sql injection",
        "cryptographic",
        "weak crypto",
        "insecure",
    }

    FALSE_POSITIVE_SIGNALS = {
        "unused",
        "style",
        "formatting",
        "whitespace",
        "indentation",
        "naming convention",
        "magic number",
        "comment",
        "todo",
        "line length",
        "cyclomatic",
        "cognitive",
        "consider",
        "could be",
        "suggest",
    }

    HIGH_RISK_CWES = {
        "CWE-119",
        "CWE-120",
        "CWE-121",
        "CWE-122",
        "CWE-125",
        "CWE-126",
        "CWE-170",
        "CWE-190",
        "CWE-415",
        "CWE-416",
        "CWE-590",
        "CWE-787",
    }

    def complete(self, prompt: str) -> str:
        text = prompt.lower()
        high = any(sig in text for sig in self.HIGH_SIGNALS)
        false_positive = any(sig in text for sig in self.FALSE_POSITIVE_SIGNALS)

        if high and false_positive:
            has_compliance = (
                "compliance" in text or "cert_c" in text or "misra_c" in text or "fips" in text
            )
            has_style = "unused" in text or "style" in text or "formatting" in text
            if has_compliance:
                high, false_positive = True, False
            elif has_style:
                high, false_positive = False, True
            else:
                high, false_positive = True, False

        if high and not false_positive:
            verdict = TriageVerdict.HIGH_PRIORITY
            confidence = 0.85
        elif false_positive and not high:
            verdict = TriageVerdict.FALSE_POSITIVE
            confidence = 0.80
        else:
            verdict = TriageVerdict.UNCLEAR
            confidence = 0.50

        return json.dumps(
            {
                "reasoning": (
                    f"Mock triage based on keyword signals in the prompt and code context. "
                    f"High signals={high}, false-positive signals={false_positive}."
                ),
                "verdict": verdict.value,
                "confidence": confidence,
                "compliance_rules": [],
                "remediation": (
                    "Review the finding manually or re-run with a real LLM provider."
                    if verdict == TriageVerdict.UNCLEAR
                    else "Apply the appropriate secure-coding fix."
                ),
            }
        )

    def triage_finding(self, finding: Finding, hits: list[ComplianceHit]) -> TriageResult:
        """Mock triage that also leverages the mapped compliance hits and CWE."""
        cwe = (finding.cwe or "").upper()
        if cwe in self.HIGH_RISK_CWES or any(h.framework in {"cert_c", "misra_c"} for h in hits):
            verdict = TriageVerdict.HIGH_PRIORITY
            confidence = 0.90
            remediation = "Fix or explicitly suppress the validated security issue."
        elif any(
            sig in (finding.message + " " + finding.code_snippet).lower()
            for sig in self.FALSE_POSITIVE_SIGNALS
        ):
            verdict = TriageVerdict.FALSE_POSITIVE
            confidence = 0.80
            remediation = "No action required; the warning appears to be stylistic or benign."
        else:
            return super().triage_finding(finding, hits)

        return TriageResult(
            finding=finding,
            verdict=verdict,
            confidence=confidence,
            reasoning="Mock triage based on CWE/compliance mapping and keyword signals.",
            compliance_hits=hits,
            remediation=remediation,
        )


def _client_for_provider(provider: str, settings: Settings) -> LLMClient:
    """Return a concrete client for the named provider."""
    if provider == "openai":
        return OpenAIClient(settings)
    if provider == "anthropic":
        return AnthropicClient(settings)
    if provider == "gemini":
        return GeminiClient(settings)
    if provider == "mock":
        return MockClient(settings)
    raise ValueError(f"Unsupported LLM provider: {provider}")
