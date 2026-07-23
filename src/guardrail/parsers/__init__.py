"""Static analysis report parsers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from guardrail.models import Finding
from guardrail.parsers.cppcheck import parse_cppcheck_xml
from guardrail.parsers.sarif import parse_sarif
from guardrail.parsers.sonarqube import parse_sonarqube


PARSERS = {
    "sarif": parse_sarif,
    "sonarqube": parse_sonarqube,
    "cppcheck": parse_cppcheck_xml,
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

    # Try to read a bit and detect JSON/XML
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(200).strip()
        if head.startswith("<?xml") or head.startswith("<"):
            return "cppcheck"  # default XML parser
        data = json.loads(head + f.read(8192))
        if "runs" in data:
            return "sarif"
        if "issues" in data or "total" in data:
            return "sonarqube"
    except Exception:
        pass

    raise ValueError(f"Could not detect static analysis report format for {file_path}")


def parse_report(file_path: str, fmt: str | None = None) -> List[Finding]:
    """Parse a static analysis report into findings."""
    if fmt is None or (isinstance(fmt, str) and not fmt.strip()):
        fmt = detect_format(file_path)
    parser = PARSERS.get(fmt)
    if not parser:
        raise ValueError(f"Unsupported report format: {fmt}")
    return parser(file_path)