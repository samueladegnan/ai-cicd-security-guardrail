"""Tests for policy-as-code triage decisions."""

from __future__ import annotations

from guardrail.config import Settings
from guardrail.models import (
    Finding,
    Language,
    Report,
    Severity,
    TriageResult,
    TriageVerdict,
)
from guardrail.policy import BuiltInPolicyEngine, PolicyEngine, get_policy_engine


def _report(high_priority: int = 0, false_positive: int = 0, unclear: int = 0) -> Report:
    results = []
    for _ in range(high_priority):
        results.append(
            TriageResult(
                finding=Finding(
                    rule_id="rule",
                    message="msg",
                    file_path="src/main.c",
                    line=1,
                    severity=Severity.HIGH,
                    language=Language.C,
                ),
                verdict=TriageVerdict.HIGH_PRIORITY,
                confidence=0.9,
            )
        )
    for _ in range(false_positive):
        results.append(
            TriageResult(
                finding=Finding(
                    rule_id="rule",
                    message="msg",
                    file_path="src/main.c",
                    line=1,
                    severity=Severity.LOW,
                    language=Language.C,
                ),
                verdict=TriageVerdict.FALSE_POSITIVE,
                confidence=0.9,
            )
        )
    for _ in range(unclear):
        results.append(
            TriageResult(
                finding=Finding(
                    rule_id="rule",
                    message="msg",
                    file_path="src/main.c",
                    line=1,
                    severity=Severity.MEDIUM,
                    language=Language.C,
                ),
                verdict=TriageVerdict.UNCLEAR,
                confidence=0.9,
            )
        )
    report = Report(results=results)
    report.compute_summary()
    return report


def test_builtin_policy_allows_clean_report():
    engine = BuiltInPolicyEngine()
    report = _report()
    decision = engine.evaluate(report)
    assert decision["allow"] is True
    assert "Built-in policy" in decision["reason"]


def test_builtin_policy_blocks_high_priority():
    engine = BuiltInPolicyEngine()
    report = _report(high_priority=1)
    decision = engine.evaluate(report)
    assert decision["allow"] is False


def test_builtin_policy_respects_fail_on_unclear():
    engine = BuiltInPolicyEngine()
    report = _report(unclear=1)
    decision = engine.evaluate(report, Settings(fail_on_unclear=True))
    assert decision["allow"] is False

    decision = engine.evaluate(report, Settings(fail_on_unclear=False))
    assert decision["allow"] is True


def test_opa_policy_unavailable_without_opa():
    engine = PolicyEngine(policy_path="/does/not/exist.rego")
    assert engine.available() is False
    report = _report(high_priority=1)
    decision = engine.evaluate(report)
    assert decision["allow"] is False
    assert "OPA is not installed" in decision["reason"]


def test_get_policy_engine_defaults_to_builtin():
    settings = Settings(policy_path="")
    engine = get_policy_engine(settings)
    assert isinstance(engine, BuiltInPolicyEngine)


def test_get_policy_engine_uses_opa_when_path_set(tmp_path):
    policy_path = tmp_path / "policy.rego"
    policy_path.write_text("package guardrail\n", encoding="utf-8")
    settings = Settings(policy_path=str(policy_path))
    engine = get_policy_engine(settings)
    assert isinstance(engine, PolicyEngine)
