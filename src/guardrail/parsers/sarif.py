"""SARIF v2.1.0 parser."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from guardrail.models import Finding, Severity


# Map common SARIF levels to our severity enum.
_LEVEL_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def _extract_cwe_from_rule(rule: Dict[str, Any]) -> str | None:
    taxa = rule.get("taxa", [])
    for taxon in taxa:
        if taxon.get("toolComponent", {}).get("name", "").lower() in {"cwe", "cwes"}:
            return taxon.get("id")
    # Fallback: rule id may look like CWE-121
    rule_id = rule.get("id", "")
    if rule_id.startswith("CWE-"):
        return rule_id
    return None


def parse_sarif(path: str) -> List[Finding]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings: List[Finding] = []
    for run in data.get("runs", []):
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

            findings.append(
                Finding(
                    rule_id=rule_id,
                    message=message_text,
                    file_path=file_path,
                    line=line,
                    column=column,
                    severity=_LEVEL_MAP.get(level, Severity.MEDIUM),
                    cwe=cwe,
                    tool="sarif",
                    raw=result,
                )
            )
    return findings