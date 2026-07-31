#!/usr/bin/env python3
"""Convert a Bandit JSON report to SARIF 2.1.0.

Bandit keeps JSON as a built-in output format, while SARIF support has varied
between Bandit releases and optional formatter plugins. Keeping this small
conversion in the repository makes CI independent of Bandit's plugin loading.
"""

from __future__ import annotations

import argparse
import json
import posixpath
from pathlib import Path
from typing import Any
from urllib.parse import quote

_SEVERITY_TO_LEVEL = {
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def _normalise_uri(filename: str) -> str:
    """Return a repository-relative, POSIX-style SARIF artifact URI."""
    value = filename.replace("\\", "/") or "unknown"
    while value.startswith("./"):
        value = value[2:]
    normalised = posixpath.normpath(value)
    return quote(normalised, safe="/@:+-._~")


def _positive_int(value: Any, default: int) -> int:
    """Convert a possibly malformed numeric field to a positive integer."""
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def _line_range(result: dict[str, Any]) -> tuple[int, int]:
    """Return the 1-based start and end lines for a Bandit result."""
    start = _positive_int(result.get("line_number"), 1)
    line_range = result.get("line_range")
    if not isinstance(line_range, (list, tuple)) or not line_range:
        return start, start
    return start, max(start, _positive_int(line_range[-1], start))


def _rule(result: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF rule descriptor from a Bandit result."""
    rule_id = str(result.get("test_id", "unknown"))
    description = str(result.get("issue_text", "Bandit finding"))
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": str(result.get("test_name", rule_id)),
        "shortDescription": {"text": description},
    }
    help_uri = result.get("more_info")
    if help_uri:
        rule["helpUri"] = str(help_uri)
    cwe = result.get("issue_cwe") or {}
    if isinstance(cwe, dict) and cwe.get("id"):
        rule["properties"] = {"cwe": f"CWE-{cwe['id']}"}
    return rule


def convert(data: dict[str, Any]) -> dict[str, Any]:
    """Convert parsed Bandit JSON data to a SARIF 2.1.0 object."""
    errors = data.get("errors", [])
    if errors:
        raise ValueError(f"Bandit report contains {len(errors)} scan error(s)")

    results = data.get("results", [])
    if not isinstance(results, list):
        raise ValueError("Bandit report field 'results' must be an array")

    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Each Bandit result must be an object")
        rule_id = str(result.get("test_id", "unknown"))
        rules.setdefault(rule_id, _rule(result))
        start_line, end_line = _line_range(result)
        severity = str(result.get("issue_severity", "MEDIUM")).upper()
        message = str(result.get("issue_text", "Bandit finding"))
        region: dict[str, Any] = {"startLine": start_line, "endLine": end_line}
        if result.get("col_offset") is not None:
            region["startColumn"] = _positive_int(result.get("col_offset"), 0) + 1
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": _SEVERITY_TO_LEVEL.get(severity, "warning"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _normalise_uri(str(result.get("filename", "")))
                            },
                            "region": region,
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2-1-0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bandit",
                        "informationUri": "https://bandit.readthedocs.io/",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def main() -> int:
    """Convert one Bandit JSON file to one SARIF file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Bandit JSON report")
    parser.add_argument("output", type=Path, help="SARIF output path")
    args = parser.parse_args()

    with args.input.open(encoding="utf-8") as source:
        data = json.load(source)
    if not isinstance(data, dict):
        raise ValueError("Bandit report must be a JSON object")

    args.output.write_text(json.dumps(convert(data), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
