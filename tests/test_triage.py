"""Tests for the triage engine and compliance mapping."""

from __future__ import annotations

from guardrail.code_fetcher import get_code_context_for_finding
from guardrail.compliance import compliance_hits_for_cwe, get_rule, list_frameworks
from guardrail.config import Settings
from guardrail.models import Finding, Severity, TriageVerdict
from guardrail.parsers import parse_report
from guardrail.triage import TriageEngine


def test_list_frameworks():
    assert set(list_frameworks()) == {"cert_c", "misra_c", "fips"}


def test_get_rule():
    rule = get_rule("cert_c", "STR31-C")
    assert rule is not None
    assert "space" in rule["title"].lower()


def test_compliance_hits_for_cwe():
    hits = compliance_hits_for_cwe("CWE-121")
    assert any(hit.framework == "cert_c" for hit in hits)
    assert any("STR" in hit.rule_id for hit in hits)


def test_code_context_for_finding():
    finding = Finding(
        rule_id="test",
        message="test",
        file_path="sample_code/vulnerable.c",
        line=14,
        column=5,
        severity=Severity.HIGH,
        tool="test",
    )
    snippet = get_code_context_for_finding(finding, before=2, after=2, repo_root=".")
    assert "strcpy" in snippet


def test_mock_triage_engine():
    settings = Settings(llm_provider="mock", max_concurrency=1)
    engine = TriageEngine(settings)
    findings = parse_report("tests/fixtures/sample.sarif")
    # Enrich with realistic snippets so the mock can distinguish the cases.
    snippets = [
        "   13     strcpy(buffer, input);\n   14     printf(\"Processed: %s\\n\", buffer);",
        "   12     int result = a + b;\n   13     return result;\n   14 }\n",
    ]
    findings = [
        f.model_copy(update={"code_snippet": snippet}) for f, snippet in zip(findings, snippets)
    ]
    report = engine.run_concurrent(findings)
    assert report.summary.total == 2
    assert report.summary.high_priority >= 1
    assert report.summary.false_positive >= 1