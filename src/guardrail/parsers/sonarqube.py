"""SonarQube issues API JSON parser."""

from __future__ import annotations

import json
from typing import List

from guardrail.models import Finding, Severity


SEVERITY_MAP = {
    "BLOCKER": Severity.CRITICAL,
    "CRITICAL": Severity.CRITICAL,
    "MAJOR": Severity.HIGH,
    "MINOR": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def parse_sonarqube(path: str) -> List[Finding]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings: List[Finding] = []
    issues = data.get("issues", data.get("results", []))
    for issue in issues:
        component = issue.get("component", "")
        # SonarQube returns components as "projectKey:relative/path.c".
        # Keep only the path portion so the code fetcher can locate it.
        if ":" in component:
            component = component.split(":", 1)[1]
        line = issue.get("line", 0)
        text_range = issue.get("textRange", {}) or {}
        findings.append(
            Finding(
                rule_id=issue.get("rule", "unknown"),
                message=issue.get("message", ""),
                file_path=component,
                line=line or text_range.get("startLine", 0),
                column=text_range.get("startOffset", 0),
                severity=SEVERITY_MAP.get(issue.get("severity", "MINOR"), Severity.MEDIUM),
                cwe=None,
                tool="sonarqube",
                raw=issue,
            )
        )
    return findings