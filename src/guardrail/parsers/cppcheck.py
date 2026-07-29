"""cppcheck XML parser."""

from __future__ import annotations

import contextlib

from defusedxml import ElementTree as ET

from guardrail.context import infer_language
from guardrail.models import Finding, Language, Severity
from guardrail.parsers.base import BaseReportParser

SEVERITY_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "style": Severity.LOW,
    "performance": Severity.LOW,
    "portability": Severity.LOW,
    "information": Severity.INFO,
}


class CppcheckParser(BaseReportParser):
    """Parser for cppcheck XML reports."""

    @property
    def tool(self) -> str:
        return "cppcheck"

    @property
    def supported_languages(self) -> tuple[Language, ...]:
        return (Language.C, Language.CPP)

    def parse(self, path: str) -> list[Finding]:
        tree = ET.parse(path)  # noqa: S314 - defusedxml handles this safely
        root = tree.getroot()
        findings: list[Finding] = []

        for error in root.findall("errors/error"):
            for location in error.findall("location"):
                file_path = location.get("file", "")
                line = int(location.get("line", 0) or 0)
                column = 0
                with contextlib.suppress(ValueError):
                    column = int(location.get("column", 0) or 0)

                severity_label = error.get("severity", "warning")
                msg = error.get("msg", "")
                verbose = error.get("verbose", "")
                message = verbose if verbose else msg

                findings.append(
                    Finding(
                        rule_id=error.get("id", "unknown"),
                        message=message,
                        file_path=file_path,
                        line=line,
                        column=column,
                        severity=SEVERITY_MAP.get(severity_label, Severity.MEDIUM),
                        cwe=error.get("cwe"),
                        tool=self.tool,
                        language=infer_language(self.tool, file_path),
                        raw={
                            "id": error.get("id"),
                            "severity": severity_label,
                            "msg": msg,
                        },
                    )
                )
        return findings
