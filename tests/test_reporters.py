"""Tests for output reporters (SARIF, GitHub comments)."""

from __future__ import annotations

import json

from guardrail.models import Finding, Language, Report, Severity, TriageResult, TriageVerdict
from guardrail.reporters.github import LocalGitHubReporter
from guardrail.reporters.sarif import SarifReporter, write_sarif


def _sample_report() -> Report:
    finding = Finding(
        rule_id="CWE-121",
        message="Buffer overflow",
        file_path="src/main.c",
        line=10,
        column=5,
        severity=Severity.HIGH,
        cwe="CWE-121",
        tool="sarif",
        language=Language.C,
    )
    result = TriageResult(
        finding=finding,
        verdict=TriageVerdict.HIGH_PRIORITY,
        confidence=0.85,
        reasoning="Risky strcpy usage.",
        remediation="Use strncpy.",
    )
    report = Report(results=[result])
    report.compute_summary()
    return report


def test_sarif_reporter_builds_valid_schema():
    report = _sample_report()
    sarif = SarifReporter(report).build()
    assert sarif["$schema"].endswith("sarif-schema-2-1-0.json")
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_sarif_reporter_maps_verdicts_to_levels():
    from guardrail.models import TriageVerdict
    from guardrail.reporters.sarif import SarifReporter

    assert SarifReporter._verdict_to_level(TriageVerdict.HIGH_PRIORITY) == "error"
    assert SarifReporter._verdict_to_level(TriageVerdict.FALSE_POSITIVE) == "note"
    assert SarifReporter._verdict_to_level(TriageVerdict.UNCLEAR) == "warning"


def test_sarif_reporter_writes_file(tmp_path):
    report = _sample_report()
    path = tmp_path / "output.sarif"
    write_sarif(report, str(path))
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "runs" in data


def test_local_github_reporter_prints_comments(capsys):
    report = _sample_report()
    reporter = LocalGitHubReporter(
        token="token",
        repository="owner/repo",
        pr_number=1,
        commit_sha="abc123",
    )
    comments = reporter.post_review_comments(report)
    assert len(comments) == 1
    assert comments[0]["path"] == "src/main.c"
    assert "HIGH_PRIORITY" in comments[0]["body"]
    captured = capsys.readouterr()
    assert "HIGH_PRIORITY" in captured.out


def test_github_reporter_not_configured_when_empty():
    reporter = LocalGitHubReporter(token="", repository="", pr_number=0)
    assert not reporter.is_configured()
    report = _sample_report()
    assert reporter.post_review_comments(report) == []
