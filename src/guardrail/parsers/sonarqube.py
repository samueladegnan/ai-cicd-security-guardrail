"""SonarQube issues API JSON parser."""

from __future__ import annotations

import json

from guardrail.context import infer_language
from guardrail.models import Finding, Language, Severity
from guardrail.parsers.base import BaseReportParser

SEVERITY_MAP = {
    "BLOCKER": Severity.CRITICAL,
    "CRITICAL": Severity.CRITICAL,
    "MAJOR": Severity.HIGH,
    "MINOR": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SonarQubeParser(BaseReportParser):
    """Parser for SonarQube JSON issue reports."""

    @property
    def tool(self) -> str:
        return "sonarqube"

    @property
    def supported_languages(self) -> tuple[Language, ...]:
        return (Language.C, Language.CPP, Language.JAVASCRIPT, Language.TYPESCRIPT, Language.JAVA)

    def parse(self, path: str) -> list[Finding]:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        findings: list[Finding] = []
        issues = data.get("issues", data.get("results", []))
        for issue in issues:
            component = issue.get("component", "")
            # SonarQube returns components as "projectKey:relative/path.c".
            # Keep only the path portion so the code fetcher can locate it.
            if ":" in component:
                component = component.split(":", 1)[1]
            line = issue.get("line", 0)
            text_range = issue.get("textRange", {}) or {}
            cwes = issue.get("cwes") or []
            cwe = cwes[0] if isinstance(cwes, list) and cwes else None
            findings.append(
                Finding(
                    rule_id=issue.get("rule", "unknown"),
                    message=issue.get("message", ""),
                    file_path=component,
                    line=line or text_range.get("startLine", 0),
                    column=text_range.get("startOffset", 0),
                    severity=SEVERITY_MAP.get(issue.get("severity", "MINOR"), Severity.MEDIUM),
                    cwe=cwe,
                    tool=self.tool,
                    language=infer_language(self.tool, component),
                    raw=issue,
                )
            )
        return findings
