"""Static analysis report parsers."""

from __future__ import annotations

import json
from pathlib import Path

from guardrail.models import Finding
from guardrail.parsers.cppcheck import CppcheckParser
from guardrail.parsers.sarif import SarifParser
from guardrail.parsers.sonarqube import SonarQubeParser

PARSERS = {
    "sarif": SarifParser(),
    "sonarqube": SonarQubeParser(),
    "cppcheck": CppcheckParser(),
}


def detect_format(file_path: str) -> str:
    """Heuristically detect the static analysis report format."""
    path = Path(file_path)
    suffix = path.suffix.lower()
    name = path.name.lower()

    if suffix == ".sarif" or suffix == ".json" and "sarif" in name:
        return "sarif"
    if suffix == ".xml" and "cppcheck" in name:
        return "cppcheck"
    if suffix == ".xml" and "sonar" in name:
        return "sonarqube"
    if suffix == ".json" and "sonar" in name:
        return "sonarqube"

    # Inspect the complete document when the filename is not descriptive. The
    # previous implementation concatenated a truncated prefix with a read from
    # an already exhausted file handle, so valid larger JSON reports could not
    # be auto-detected.
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            document = f.read().lstrip()
        if document.startswith("<?xml") or document.startswith("<"):
            return "cppcheck"  # default XML parser
        data = json.loads(document)
        if isinstance(data, dict) and "runs" in data:
            return "sarif"
        if isinstance(data, dict) and ("issues" in data or "total" in data):
            return "sonarqube"
    except (OSError, json.JSONDecodeError, TypeError):
        pass

    raise ValueError(f"Could not detect static analysis report format for {file_path}")


def parse_report(file_path: str, fmt: str | None = None) -> list[Finding]:
    """Parse a static analysis report into findings."""
    if fmt is None or (isinstance(fmt, str) and not fmt.strip()):
        fmt = detect_format(file_path)
    parser = PARSERS.get(fmt)
    if not parser:
        raise ValueError(f"Unsupported report format: {fmt}")
    return parser.parse(file_path)
