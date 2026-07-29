"""Write guardrail triage results as SARIF for GitHub Advanced Security.

GitHub can ingest SARIF files and surface findings in the Security tab. This
module converts the internal ``Report`` into a valid SARIF 2.1.0 log with one
rule per unique verdict/rule pair and one result per triaged finding.
"""

from __future__ import annotations

import json
from typing import Any

from guardrail import __version__
from guardrail.models import Report, TriageVerdict


class SarifReporter:
    """Convert a guardrail ``Report`` into SARIF 2.1.0."""

    def __init__(self, report: Report, tool_name: str = "ai-cicd-security-guardrail"):
        self.report = report
        self.tool_name = tool_name

    def build(self) -> dict[str, Any]:
        """Return a SARIF 2.1.0 dict."""
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for triage_result in self.report.results:
            f = triage_result.finding
            verdict = triage_result.verdict.value
            rule_id = f"guardrail-{verdict}-{f.rule_id}".replace("_", "-").lower()
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f"{verdict}: {f.rule_id}",
                    "shortDescription": {
                        "text": f"Guardrail triage verdict: {verdict} for rule {f.rule_id}"
                    },
                    "properties": {
                        "tags": [verdict],
                        "precision": "high" if triage_result.confidence > 0.8 else "medium",
                    },
                }

            level = self._verdict_to_level(triage_result.verdict)
            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": (
                        f"{triage_result.verdict.value}: {f.message}\n\n"
                        f"Reasoning: {triage_result.reasoning}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {
                                "startLine": max(1, f.line),
                                "startColumn": max(1, f.column) if f.column else 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "confidence": triage_result.confidence,
                    "compliance_hits": [h.model_dump() for h in triage_result.compliance_hits],
                    "remediation": triage_result.remediation,
                },
            }
            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2-1-0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": __version__,
                            "informationUri": "https://github.com/samueladegnan/ai-cicd-security-guardrail",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def write(self, path: str) -> None:
        """Write the SARIF output to ``path``."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.build(), f, indent=2)

    @staticmethod
    def _verdict_to_level(verdict: TriageVerdict) -> str:
        mapping = {
            TriageVerdict.HIGH_PRIORITY: "error",
            TriageVerdict.FALSE_POSITIVE: "note",
            TriageVerdict.UNCLEAR: "warning",
        }
        return mapping.get(verdict, "warning")


def write_sarif(report: Report, path: str, tool_name: str = "ai-cicd-security-guardrail") -> None:
    """Convenience function to write a SARIF file from a report."""
    SarifReporter(report, tool_name=tool_name).write(path)
