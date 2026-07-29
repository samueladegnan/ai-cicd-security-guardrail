"""Tests for static analysis report parsers."""

from __future__ import annotations

import json
from pathlib import Path

from guardrail.models import Language, Severity
from guardrail.parsers import detect_format, parse_report
from guardrail.parsers.cppcheck import CppcheckParser
from guardrail.parsers.sarif import SarifParser
from guardrail.parsers.sonarqube import SonarQubeParser

FIXTURES = Path(__file__).with_suffix("").parent / "fixtures"


def test_detect_sarif_format():
    path = FIXTURES / "sample.sarif"
    assert detect_format(str(path)) == "sarif"


def test_parse_sarif_finds_buffer_overflow():
    findings = SarifParser().parse(str(FIXTURES / "sample.sarif"))
    assert len(findings) == 2
    buffer_overflow = [f for f in findings if f.rule_id == "CWE-121"][0]
    assert buffer_overflow.file_path == "sample_code/vulnerable.c"
    assert buffer_overflow.line == 14
    assert buffer_overflow.severity == Severity.HIGH
    assert buffer_overflow.tool == "sarif"


def test_parse_sarif_finds_unused_variable():
    findings = SarifParser().parse(str(FIXTURES / "sample.sarif"))
    unused = [f for f in findings if f.rule_id == "unused-variable"][0]
    assert unused.file_path == "sample_code/false_positive.c"
    assert unused.line == 13


def test_parse_sonarqube():
    data = {
        "issues": [
            {
                "rule": "cpp:S5025",
                "message": "Potential buffer overflow",
                "component": "src/main.c",
                "line": 42,
                "severity": "MAJOR",
            }
        ]
    }
    path = FIXTURES / "sonar.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    try:
        findings = SonarQubeParser().parse(str(path))
        assert len(findings) == 1
        assert findings[0].rule_id == "cpp:S5025"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].tool == "sonarqube"
    finally:
        path.unlink(missing_ok=True)


def test_parse_cppcheck(tmp_path):
    xml = """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
    <results version=\"2\">
        <errors>
            <error id=\"bufferOverrun\" severity=\"error\" msg=\"Buffer is accessed out of bounds\" verbose=\"Access out of bounds\">
                <location file=\"src/main.c\" line=\"10\" column=\"4\"/>
            </error>
        </errors>
    </results>"""
    path = tmp_path / "cppcheck.xml"
    path.write_text(xml, encoding="utf-8")
    findings = CppcheckParser().parse(str(path))
    assert len(findings) == 1
    assert findings[0].rule_id == "bufferOverrun"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].tool == "cppcheck"


def test_parse_report_auto_detection():
    findings = parse_report(str(FIXTURES / "sample.sarif"))
    assert len(findings) == 2


def test_sarif_parser_class_attributes():
    parser = SarifParser()
    assert parser.tool == "sarif"
    assert Language.C in parser.supported_languages


def test_parse_sonarqube_extracts_cwe():
    data = {
        "issues": [
            {
                "rule": "c:S3519",
                "message": "Possible buffer overflow",
                "component": "src/main.c",
                "line": 42,
                "severity": "MAJOR",
                "cwes": ["CWE-121"],
            }
        ]
    }
    path = FIXTURES / "sonar_cwe.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    try:
        findings = SonarQubeParser().parse(str(path))
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-121"
    finally:
        path.unlink(missing_ok=True)


def test_sarif_language_inference():
    data = {
        "runs": [
            {
                "tool": {"driver": {"name": "Brakeman", "language": "ruby"}},
                "results": [
                    {
                        "ruleId": "SQL",
                        "message": {"text": "SQL injection"},
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/models/user.rb"},
                                    "region": {"startLine": 12, "startColumn": 5},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    path = FIXTURES / "ruby.sarif"
    path.write_text(json.dumps(data), encoding="utf-8")
    try:
        findings = SarifParser().parse(str(path))
        assert findings[0].language == Language.RUBY
    finally:
        path.unlink(missing_ok=True)
