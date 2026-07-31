"""Tests for the repository-owned Bandit-to-SARIF converter."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_CONVERTER_PATH = Path(__file__).parents[1] / "scripts" / "bandit_to_sarif.py"
_SPEC = importlib.util.spec_from_file_location("bandit_to_sarif", _CONVERTER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def test_convert_bandit_json_to_sarif() -> None:
    data: dict[str, Any] = {
        "results": [
            {
                "test_id": "B101",
                "test_name": "assert_used",
                "issue_text": "Use of assert detected.",
                "issue_severity": "LOW",
                "filename": "./src/example.py",
                "line_number": 7,
                "line_range": [7, 8],
                "col_offset": 2,
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b101_assert_used.html",
                "issue_cwe": {"id": 617, "link": "https://cwe.mitre.org/data/definitions/617.html"},
            }
        ]
    }

    sarif = _MODULE.convert(data)

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Bandit"
    assert run["tool"]["driver"]["rules"][0]["properties"]["cwe"] == "CWE-617"

    result = run["results"][0]
    assert result["ruleId"] == "B101"
    assert result["level"] == "note"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/example.py"
    assert result["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 7,
        "endLine": 8,
        "startColumn": 3,
    }


def test_convert_rejects_bandit_scan_errors() -> None:
    try:
        _MODULE.convert({"errors": [{"filename": "broken.py", "reason": "syntax error"}]})
    except ValueError as exc:
        assert "scan error" in str(exc)
    else:
        raise AssertionError("Expected Bandit scan errors to be rejected")


def test_convert_empty_bandit_report_to_sarif() -> None:
    sarif = _MODULE.convert({"results": []})

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
