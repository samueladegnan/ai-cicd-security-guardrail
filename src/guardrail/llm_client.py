"""LLM client abstraction for triaging static-analysis findings."""

from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List

import requests

from guardrail.config import Settings
from guardrail.models import ComplianceHit, Finding, TriageResult, TriageVerdict


class LLMClient(ABC):
    """Abstract base class for LLM clients."""

    def __init__(self, settings: Settings):
        self.settings = settings

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Send a prompt and return the raw text response."""

    def triage_finding(self, finding: Finding, hits: List[ComplianceHit]) -> TriageResult:
        """Build a prompt and return a structured triage result."""
        prompt = self._build_prompt(finding, hits)
        raw = self.complete(prompt)
        return self._parse_response(raw, finding, hits)

    def _build_prompt(self, finding: Finding, hits: List[ComplianceHit]) -> str:
        compliance_text = ""
        if hits:
            lines = []
            for hit in hits:
                lines.append(f"- {hit.framework.upper()} {hit.rule_id}: {hit.title}")
                if hit.description:
                    lines.append(f"  {hit.description}")
            compliance_text = "\n".join(lines)
        else:
            compliance_text = "No explicit compliance rules were mapped. Use your secure-coding knowledge."

        return (
            "You are a senior secure-code reviewer specialized in C/C++. "
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
            f"Rule: {finding.rule_id}\n"
            f"Severity: {finding.severity.value}\n"
            f"CWE: {finding.cwe or 'unknown'}\n"
            f"Message: {finding.message}\n"
            f"Location: {finding.file_path}:{finding.line}:{finding.column}\n\n"
            "Code context:\n"
            "```c\n"
            f"{finding.code_snippet}\n"
            "```\n"
        )

    def _parse_response(self, raw: str, finding: Finding, hits: List[ComplianceHit]) -> TriageResult:
        try:
            # Strip markdown fences if the LLM returned them despite instructions.
            cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.IGNORECASE)
            cleaned = re.sub(r"\s*```$", "", cleaned)
            data = json.loads(cleaned)
            verdict_str = data.get("verdict", "UNCLEAR").upper()
            verdict = TriageVerdict(verdict_str) if verdict_str in {v.value for v in TriageVerdict} else TriageVerdict.UNCLEAR
            return TriageResult(
                finding=finding,
                verdict=verdict,
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", "No reasoning provided."),
                compliance_hits=hits,
                remediation=data.get("remediation", ""),
            )
        except Exception:
            return TriageResult(
                finding=finding,
                verdict=TriageVerdict.UNCLEAR,
                confidence=0.0,
                reasoning=f"Failed to parse LLM response: {raw}",
                compliance_hits=hits,
                remediation="",
            )


class OpenAIClient(LLMClient):
    def complete(self, prompt: str) -> str:
        api_key = self.settings.llm_api_key or os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            raise RuntimeError("OpenAI API key is required. Set OPENAI_API_KEY or GUARDRAIL_LLM_API_KEY.")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        model = self.settings.effective_model
        payload: Dict[str, Any] = {
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
        return resp.json()["choices"][0]["message"]["content"]


class AnthropicClient(LLMClient):
    def complete(self, prompt: str) -> str:
        api_key = self.settings.llm_api_key or os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise RuntimeError("Anthropic API key is required. Set ANTHROPIC_API_KEY or GUARDRAIL_LLM_API_KEY.")
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        model = self.settings.effective_model
        payload = {
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
        return resp.json()["content"][0]["text"]


class GeminiClient(LLMClient):
    def complete(self, prompt: str) -> str:
        api_key = self.settings.llm_api_key or os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            raise RuntimeError("Gemini API key is required. Set GEMINI_API_KEY or GUARDRAIL_LLM_API_KEY.")
        model = self.settings.effective_model
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        )
        payload = {
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
        headers = {"Content-Type": "application/json"}
        resp = requests.post(url, headers=headers, json=payload, timeout=self.settings.timeout_seconds)
        resp.raise_for_status()
        data = resp.json()
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
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

    # CWEs that are almost always real security issues in C/C++.
    HIGH_RISK_CWES = {
        "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-126",
        "CWE-170", "CWE-190", "CWE-415", "CWE-416", "CWE-590", "CWE-787",
    }

    def complete(self, prompt: str) -> str:
        # The prompt is rich, but for the mock we simply inspect the finding details.
        text = prompt.lower()
        high = any(sig in text for sig in self.HIGH_SIGNALS)
        false_positive = any(sig in text for sig in self.FALSE_POSITIVE_SIGNALS)

        # If both signals are present, let the presence of mapped compliance hits
        # and high-severity keywords tip the scale toward a real issue.
        if high and false_positive:
            has_compliance = "compliance" in text or "cert_c" in text or "misra_c" in text or "fips" in text
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

        # Re-parse to emit the same JSON schema as real LLMs.
        return json.dumps(
            {
                "reasoning": f"Mock triage based on keyword signals in the prompt and code context. High signals={high}, false-positive signals={false_positive}.",
                "verdict": verdict.value,
                "confidence": confidence,
                "compliance_rules": [],
                "remediation": "Review the finding manually or re-run with a real LLM provider." if verdict == TriageVerdict.UNCLEAR else "Apply the appropriate secure-coding fix.",
            }
        )

    def triage_finding(self, finding: "Finding", hits: List[ComplianceHit]) -> TriageResult:
        """Mock triage that also leverages the mapped compliance hits and CWE."""
        cwe = (finding.cwe or "").upper()
        if cwe in self.HIGH_RISK_CWES or any(h.framework in {"cert_c", "misra_c"} for h in hits):
            verdict = TriageVerdict.HIGH_PRIORITY
            confidence = 0.90
            remediation = "Fix or explicitly suppress the validated security issue."
        elif any(sig in (finding.message + " " + finding.code_snippet).lower() for sig in self.FALSE_POSITIVE_SIGNALS):
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


def get_client(settings: Settings) -> LLMClient:
    """Factory returning the correct LLM client for the configured provider."""
    provider = settings.llm_provider
    if provider == "openai":
        return OpenAIClient(settings)
    if provider == "anthropic":
        return AnthropicClient(settings)
    if provider == "gemini":
        return GeminiClient(settings)
    if provider == "mock":
        return MockClient(settings)
    raise ValueError(f"Unsupported LLM provider: {provider}")