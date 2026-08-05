"""Tests for the LLM client abstraction, mock client, and circuit breaker."""

from __future__ import annotations

import pytest
import responses

from guardrail.config import Settings
from guardrail.llm_client import (
    AnthropicClient,
    CircuitBreaker,
    FallbackClient,
    GeminiClient,
    MockClient,
    OpenAIClient,
)
from guardrail.models import ComplianceHit, Finding, Language, Severity, TriageVerdict


def _sample_finding() -> Finding:
    return Finding(
        rule_id="CWE-121",
        message="Possible buffer overflow due to unchecked strcpy.",
        file_path="src/main.c",
        line=10,
        column=5,
        severity=Severity.HIGH,
        cwe="CWE-121",
        tool="sarif",
        language=Language.C,
    )


def test_mock_client_classifies_high_priority():
    client = MockClient(Settings())
    result = client.triage_finding(_sample_finding(), [])
    assert result.verdict == TriageVerdict.HIGH_PRIORITY
    assert result.confidence > 0.5


def test_mock_client_classifies_false_positive():
    finding = Finding(
        rule_id="unused-variable",
        message="Local variable is assigned but never used.",
        file_path="src/main.c",
        line=10,
        severity=Severity.LOW,
        tool="sarif",
        language=Language.C,
    )
    client = MockClient(Settings())
    result = client.triage_finding(finding, [])
    assert result.verdict == TriageVerdict.FALSE_POSITIVE


def test_mock_client_uses_compliance_hits():
    client = MockClient(Settings())
    hits = [ComplianceHit(framework="cert_c", rule_id="STR31-C", title="", description="")]
    result = client.triage_finding(_sample_finding(), hits)
    assert result.verdict == TriageVerdict.HIGH_PRIORITY
    assert result.compliance_hits == hits


def test_circuit_breaker_opens_after_threshold():
    breaker = CircuitBreaker("test", threshold=2, timeout_seconds=60)
    assert not breaker.is_open()
    breaker.record_failure()
    assert not breaker.is_open()
    breaker.record_failure()
    assert breaker.is_open()
    breaker.record_success()
    assert not breaker.is_open()


def test_circuit_breaker_resets_after_timeout():
    import time

    breaker = CircuitBreaker("timeout-test", threshold=1, timeout_seconds=0.05)
    breaker.record_failure()
    assert breaker.is_open()
    time.sleep(0.1)
    assert not breaker.is_open()


def test_fallback_client_tries_providers_in_order(monkeypatch):
    settings = Settings(llm_provider="openai", fallback_providers=("mock",))
    client = FallbackClient(settings)

    def fake_complete(self, prompt: str) -> str:
        return '{"verdict": "HIGH_PRIORITY", "confidence": 0.9, "compliance_rules": [], "remediation": ""}'

    # Patch OpenAI to fail so fallback to mock is exercised.
    monkeypatch.setattr(
        "guardrail.llm_client.OpenAIClient.complete",
        lambda self, prompt: (_ for _ in ()).throw(RuntimeError("API down")),
    )
    monkeypatch.setattr("guardrail.llm_client.MockClient.complete", fake_complete)

    result = client.complete("test prompt")
    assert "HIGH_PRIORITY" in result


def test_fallback_client_raises_when_all_fail(monkeypatch):
    def raise_error(self, prompt: str) -> str:
        raise RuntimeError("API down")

    monkeypatch.setattr("guardrail.llm_client.OpenAIClient.complete", raise_error)
    monkeypatch.setattr("guardrail.llm_client.AnthropicClient.complete", raise_error)
    settings = Settings(llm_provider="openai", fallback_providers=("anthropic",))
    client = FallbackClient(settings)
    with pytest.raises(RuntimeError):
        client.complete("test prompt")


class TestOpenAIClient:
    @responses.activate
    def test_complete_returns_content(self):
        responses.post(
            "https://api.openai.com/v1/chat/completions",
            json={
                "choices": [
                    {
                        "message": {
                            "content": '{"verdict": "HIGH_PRIORITY", "confidence": 0.9, "compliance_rules": [], "remediation": ""}'
                        }
                    }
                ]
            },
            status=200,
        )
        settings = Settings(llm_provider="openai", llm_api_key="sk-test")
        client = OpenAIClient(settings)
        result = client.complete("prompt")
        assert "HIGH_PRIORITY" in result

        request = responses.calls[0].request
        assert request.headers["Authorization"] == "Bearer sk-test"
        assert request.headers["Content-Type"] == "application/json"

    @responses.activate
    def test_complete_raises_on_error(self):
        responses.post(
            "https://api.openai.com/v1/chat/completions",
            json={"error": "invalid"},
            status=401,
        )
        settings = Settings(llm_provider="openai", llm_api_key="sk-test")
        client = OpenAIClient(settings)
        with pytest.raises(Exception):  # noqa: B017 - broad exception assertion is sufficient here
            client.complete("prompt")


class TestAnthropicClient:
    @responses.activate
    def test_complete_returns_content(self):
        responses.post(
            "https://api.anthropic.com/v1/messages",
            json={
                "content": [
                    {
                        "text": '{"verdict": "FALSE_POSITIVE", "confidence": 0.8, "compliance_rules": [], "remediation": ""}'
                    }
                ]
            },
            status=200,
        )
        settings = Settings(llm_provider="anthropic", llm_api_key="sk-test")
        client = AnthropicClient(settings)
        result = client.complete("prompt")
        assert "FALSE_POSITIVE" in result

        request = responses.calls[0].request
        assert request.headers["x-api-key"] == "sk-test"
        assert request.headers["anthropic-version"] == "2023-06-01"
        assert request.headers["Content-Type"] == "application/json"

    @responses.activate
    def test_complete_raises_on_error(self):
        responses.post(
            "https://api.anthropic.com/v1/messages",
            json={"error": "invalid"},
            status=401,
        )
        settings = Settings(llm_provider="anthropic", llm_api_key="sk-test")
        client = AnthropicClient(settings)
        with pytest.raises(Exception):  # noqa: B017
            client.complete("prompt")


class TestGeminiClient:
    @responses.activate
    def test_complete_returns_content(self):
        model = "gemini-1.5-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        responses.post(
            url,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": '{"verdict": "UNCLEAR", "confidence": 0.5, "compliance_rules": [], "remediation": ""}'
                                }
                            ]
                        }
                    }
                ]
            },
            status=200,
        )
        settings = Settings(llm_provider="gemini", llm_api_key="test-key", llm_model=model)
        client = GeminiClient(settings)
        result = client.complete("prompt")
        assert "UNCLEAR" in result

        request = responses.calls[0].request
        assert request.headers["x-goog-api-key"] == "test-key"
        assert "key=" not in request.url
        assert request.headers["Content-Type"] == "application/json"

    @responses.activate
    def test_complete_raises_on_error(self):
        url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
        responses.post(
            url,
            json={"error": "invalid"},
            status=400,
        )
        settings = Settings(llm_provider="gemini", llm_api_key="test-key")
        client = GeminiClient(settings)
        with pytest.raises(Exception):  # noqa: B017
            client.complete("prompt")
