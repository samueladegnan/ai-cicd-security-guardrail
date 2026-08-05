"""Policy-as-code triage decisions with Open Policy Agent (OPA/Rego).

The guardrail can evaluate the generated report against a user-supplied
Rego policy. This decouples security policy from application logic and lets
teams express rules like:

    package guardrail

    default allow = false

    allow if {
        input.summary.high_priority == 0
    }

If OPA is not installed, a configured policy is treated as a failed check;
security policy must not silently fail open.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from guardrail.config import Settings
from guardrail.models import Report


class PolicyEngine:
    """Evaluate a triage report against a Rego policy."""

    def __init__(self, policy_path: str | None = None):
        self.policy_path = policy_path

    def available(self) -> bool:
        """Return True if OPA is installed and a policy path is configured."""
        policy_path = self.policy_path
        return policy_path is not None and Path(policy_path).is_file() and bool(shutil.which("opa"))

    def evaluate(self, report: Report, settings: Settings | None = None) -> dict[str, Any]:
        """Return OPA's decision as a dict.

        The decision must contain at least a boolean ``allow`` key. Optional
        keys include ``reason`` and ``violations``.
        """
        if not self.available():
            return {
                "allow": False,
                "reason": "OPA policy requested but OPA is not installed or policy path is missing.",
            }

        if self.policy_path is None:
            return {"allow": False, "reason": "Policy path is not configured."}
        policy_path = Path(self.policy_path)
        if not policy_path.is_file():
            return {"allow": False, "reason": f"Policy file not found: {self.policy_path}"}

        input_data = self._build_input(report, settings)
        input_json = json.dumps(input_data)
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            tmp.write(input_json)
            tmp_path = tmp.name
        try:
            cmd = [
                "opa",
                "eval",
                "--format=json",
                "--data",
                str(policy_path),
                "--input",
                tmp_path,
                "data.guardrail",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return {"allow": False, "reason": f"OPA evaluation failed: {result.stderr}"}
            parsed = json.loads(result.stdout)
            return self._normalize(parsed)
        except Exception as exc:  # noqa: BLE001
            return {"allow": False, "reason": f"OPA evaluation error: {exc}"}
        finally:
            with contextlib.suppress(OSError):
                Path(tmp_path).unlink()

    def _build_input(self, report: Report, settings: Settings | None = None) -> dict[str, Any]:
        findings = []
        for result in report.results:
            f = result.finding
            findings.append(
                {
                    "rule_id": f.rule_id,
                    "tool": f.tool,
                    "language": f.language.value if f.language else "unknown",
                    "severity": f.severity.value,
                    "verdict": result.verdict.value,
                    "confidence": result.confidence,
                    "cwe": f.cwe,
                    "compliance_hits": [h.model_dump() for h in result.compliance_hits],
                }
            )
        return {
            "summary": report.summary.model_dump(),
            "findings": findings,
            "settings": {
                "llm_provider": settings.llm_provider if settings else "mock",
                "frameworks": list(settings.frameworks) if settings else [],
            },
        }

    def _normalize(self, opa_result: dict[str, Any]) -> dict[str, Any]:
        """Normalize OPA's JSON result into a simple decision dict."""
        value = self._expression_value(opa_result)
        if isinstance(value, dict):
            allow = value.get("allow")
            return {
                "allow": allow if isinstance(allow, bool) else False,
                "reason": str(value.get("reason", "")),
                "violations": self._as_list(value.get("violations", [])),
            }
        # Retain compatibility with older mocked OPA output in integrations.
        return {
            "allow": self._extract_bool(opa_result, "data.guardrail.allow"),
            "reason": self._extract_str(opa_result, "data.guardrail.reason"),
            "violations": self._extract_list(opa_result, "data.guardrail.violations"),
        }

    @staticmethod
    def _expression_value(opa_result: dict[str, Any]) -> Any:
        results = opa_result.get("result", [])
        if not results:
            return None
        expressions = results[0].get("expressions", [])
        return expressions[0].get("value") if expressions else None

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        return list(value) if isinstance(value, (list, tuple)) else []

    @staticmethod
    def _extract_bool(opa_result: dict[str, Any], key: str) -> bool:
        value = opa_result.get("result", [])
        for item in value:
            if item.get("path") == key:
                value = item.get("value")
                return value if isinstance(value, bool) else False
        return False

    @staticmethod
    def _extract_str(opa_result: dict[str, Any], key: str) -> str:
        value = opa_result.get("result", [])
        for item in value:
            if item.get("path") == key:
                return str(item.get("value", ""))
        return ""

    @staticmethod
    def _extract_list(opa_result: dict[str, Any], key: str) -> list:
        value = opa_result.get("result", [])
        for item in value:
            if item.get("path") == key:
                val = item.get("value", [])
                return list(val) if isinstance(val, (list, tuple)) else []
        return []


class BuiltInPolicyEngine(PolicyEngine):
    """Policy engine that uses the built-in should_fail logic."""

    def evaluate(self, report: Report, settings: Settings | None = None) -> dict[str, Any]:
        from guardrail.triage import should_fail

        fail_on_unclear = settings.fail_on_unclear if settings else True
        fail = should_fail(report, fail_on_unclear=fail_on_unclear)
        return {
            "allow": not fail,
            "reason": "Built-in policy evaluation." if not fail else "Built-in policy violation.",
            "violations": [],
        }


def get_policy_engine(settings: Settings) -> PolicyEngine:
    """Return a policy engine for the current settings."""
    if settings.policy_path:
        return PolicyEngine(settings.policy_path)
    return BuiltInPolicyEngine()
