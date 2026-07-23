"""Tests for the guardrail CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from guardrail.cli import main


FIXTURES = Path(__file__).with_suffix("").parent / "fixtures"


def test_cli_help():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_cli_smoke(tmp_path):
    output_json = tmp_path / "report.json"
    exit_code = main(
        [
            str(FIXTURES / "sample.sarif"),
            "--provider",
            "mock",
            "--repo-root",
            ".",
            "--output-json",
            str(output_json),
        ]
    )
    assert exit_code == 1  # High-priority finding detected in sample report
    data = json.loads(output_json.read_text(encoding="utf-8"))
    assert data["summary"]["total"] == 2


def test_cli_entrypoint():
    """Verify the installed console script runs."""
    result = subprocess.run(
        [sys.executable, "-m", "guardrail", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "1.0.0" in result.stdout