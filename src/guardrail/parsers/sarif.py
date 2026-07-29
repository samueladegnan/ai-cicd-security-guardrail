"""SARIF v2.1.0 parser."""

from __future__ import annotations

import json
from typing import Any

from guardrail.context import infer_language
from guardrail.models import Finding, Language, Severity
from guardrail.parsers.base import BaseReportParser

# Map common SARIF levels to our severity enum.
_LEVEL_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def _extract_cwe_from_rule(rule: dict[str, Any]) -> str | None:
    taxa = rule.get("taxa", [])
    for taxon in taxa:
        if taxon.get("toolComponent", {}).get("name", "").lower() in {"cwe", "cwes"}:
            return str(taxon.get("id"))
    # Fallback: rule id may look like CWE-121
    rule_id = rule.get("id", "")
    if rule_id.startswith("CWE-"):
        return str(rule_id)
    return None


def _infer_language_from_run(run: dict[str, Any]) -> str | None:
    driver = run.get("tool", {}).get("driver", {})
    language = driver.get("language")
    if language:
        return str(language)
    # Sometimes the language is hidden in a property bag.
    prop_language = run.get("properties", {}).get("language")
    if prop_language is not None:
        return str(prop_language)
    return None


class SarifParser(BaseReportParser):
    """Parser for SARIF v2.1.0 reports."""

    @property
    def tool(self) -> str:
        return "sarif"

    @property
    def supported_languages(self) -> tuple[Language, ...]:
        return (Language.C, Language.CPP, Language.JAVASCRIPT, Language.TYPESCRIPT, Language.RUBY)

    def parse(self, path: str) -> list[Finding]:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        findings: list[Finding] = []
        for run in data.get("runs", []):
            sarif_language = _infer_language_from_run(run)
            rules = {}
            for driver_rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rules[driver_rule.get("id")] = driver_rule
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule = rules.get(rule_id, {})
                message_text = result.get("message", {}).get("text", "")
                locations = result.get("locations", [])
                location = locations[0] if locations else {}
                physical = location.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})
                file_path = artifact.get("uri", "")
                line = region.get("startLine", 0)
                column = region.get("startColumn", 0)
                level = result.get("level", "warning")
                cwe = _extract_cwe_from_rule(rule)
                language = infer_language(self.tool, file_path, sarif_language=sarif_language)

                findings.append(
                    Finding(
                        rule_id=rule_id,
                        message=message_text,
                        file_path=file_path,
                        line=line,
                        column=column,
                        severity=_LEVEL_MAP.get(level, Severity.MEDIUM),
                        cwe=cwe,
                        tool=self.tool,
                        language=language,
                        raw=result,
                    )
                )
        return findings
