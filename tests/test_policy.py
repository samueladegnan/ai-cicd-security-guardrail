"""Tests for policy-as-code triage decisions."""

from __future__ import annotations

from types import SimpleNamespace

import guardrail.policy as policy_module
from guardrail import triage
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


def test_policy_normalizes_opa_object_result():
    engine = PolicyEngine(policy_path="policy.rego")
    decision = engine._normalize(
        {
            "result": [
                {
                    "expressions": [
                        {
                            "value": {
                                "allow": True,
                                "reason": "No high-priority findings.",
                                "violations": [],
                            }
                        }
                    ]
                }
            ]
        }
    )
    assert decision == {
        "allow": True,
        "reason": "No high-priority findings.",
        "violations": [],
    }


def test_policy_file_missing_fails_closed():
    engine = PolicyEngine(policy_path="/does/not/exist.rego")
    decision = engine.evaluate(_report())
    assert decision["allow"] is False
    assert "not installed" in decision["reason"]


def test_policy_rejects_non_boolean_allow_value():
    engine = PolicyEngine(policy_path="policy.rego")
    decision = engine._normalize(
        {
            "result": [
                {
                    "expressions": [
                        {"value": {"allow": "true"}},
                    ]
                }
            ]
        }
    )
    assert decision["allow"] is False


def test_policy_rejects_legacy_string_boolean():
    engine = PolicyEngine(policy_path="policy.rego")
    decision = engine._normalize(
        {
            "result": [
                {"path": "data.guardrail.allow", "value": "false"},
            ]
        }
    )
    assert decision["allow"] is False


def test_opa_nonzero_exit_fails_closed(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.rego"
    policy_path.write_text("package guardrail\n", encoding="utf-8")
    monkeypatch.setattr(policy_module.shutil, "which", lambda name: "/usr/bin/opa")
    monkeypatch.setattr(
        policy_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="parse error"),
    )

    decision = PolicyEngine(str(policy_path)).evaluate(_report())
    assert decision["allow"] is False
    assert "OPA evaluation failed: parse error" in decision["reason"]


def test_opa_malformed_json_fails_closed(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.rego"
    policy_path.write_text("package guardrail\n", encoding="utf-8")
    monkeypatch.setattr(policy_module.shutil, "which", lambda name: "/usr/bin/opa")
    monkeypatch.setattr(
        policy_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="not json", stderr=""),
    )

    decision = PolicyEngine(str(policy_path)).evaluate(_report())
    assert decision["allow"] is False
    assert "OPA evaluation error" in decision["reason"]


def test_evaluate_policy_fails_closed_for_incomplete_decision(monkeypatch):
    class IncompleteEngine:
        def evaluate(self, report, settings):
            return {}

    monkeypatch.setattr(triage, "get_policy_engine", lambda settings: IncompleteEngine())
    assert triage.evaluate_policy(_report(), Settings()) is True
