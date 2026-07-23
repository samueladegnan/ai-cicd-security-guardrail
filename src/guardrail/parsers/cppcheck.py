"""cppcheck XML parser."""

from __future__ import annotations

from typing import List

from defusedxml import ElementTree as ET

from guardrail.models import Finding, Severity


SEVERITY_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "style": Severity.LOW,
    "performance": Severity.LOW,
    "portability": Severity.LOW,
    "information": Severity.INFO,
}


def parse_cppcheck_xml(path: str) -> List[Finding]:
    tree = ET.parse(path)  # noqa: S314 - defusedxml handles this safely
    root = tree.getroot()
    findings: List[Finding] = []

    for error in root.findall("errors/error"):
        for location in error.findall("location"):
            file_path = location.get("file", "")
            line = int(location.get("line", 0) or 0)
            column = 0
            try:
                column = int(location.get("column", 0) or 0)
            except ValueError:
                pass

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
                    tool="cppcheck",
                    raw={
                        "id": error.get("id"),
                        "severity": severity_label,
                        "msg": msg,
                    },
                )
            )
    return findings