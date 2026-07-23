"""Command-line interface for the AI-Driven CI/CD Security Guardrail."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace as dc_replace
from pathlib import Path

from guardrail.config import Settings
from guardrail.models import Report, TriageVerdict
from guardrail.parsers import parse_report
from guardrail.triage import TriageEngine, should_fail


def _build_markdown(report: Report) -> str:
    lines = [
        "# AI-Driven CI/CD Security Guardrail Report\n",
        "## Summary\n",
        f"- **Total findings triaged:** {report.summary.total}\n",
        f"- **High-priority security risks:** {report.summary.high_priority}\n",
        f"- **False positives:** {report.summary.false_positive}\n",
        f"- **Unclear:** {report.summary.unclear}\n",
        "## Findings\n",
    ]
    if not report.results:
        lines.append("_No findings to report._\n")
    for result in report.results:
        f = result.finding
        lines.append(f"### {f.rule_id} @ `{f.file_path}:{f.line}`\n")
        lines.append(f"- **Verdict:** {result.verdict.value}\n")
        lines.append(f"- **Confidence:** {result.confidence:.2f}\n")
        lines.append(f"- **Severity:** {f.severity.value}\n")
        lines.append(f"- **Message:** {f.message}\n")
        lines.append(f"- **Reasoning:** {result.reasoning}\n")
        if result.compliance_hits:
            lines.append("- **Compliance controls:**\n")
            for hit in result.compliance_hits:
                lines.append(f"  - {hit.framework.upper()} {hit.rule_id}: {hit.title}\n")
        if result.remediation:
            lines.append(f"- **Remediation:** {result.remediation}\n")
        lines.append("\n")
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="guardrail",
        description="AI-driven triage of static-analysis findings for C/C++ secure coding.",
    )
    parser.add_argument(
        "report_path",
        help="Path to the static-analysis report (SARIF, SonarQube JSON, or cppcheck XML).",
    )
    parser.add_argument(
        "--format",
        choices=["sarif", "sonarqube", "cppcheck"],
        help="Explicit report format. If omitted, the format is auto-detected.",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Root directory containing the source files (default: current directory).",
    )
    parser.add_argument(
        "--output-json",
        help="Path to write the JSON report.",
    )
    parser.add_argument(
        "--output-markdown",
        help="Path to write the Markdown report.",
    )
    parser.add_argument(
        "--provider",
        choices=["openai", "anthropic", "gemini", "mock"],
        help="LLM provider. Defaults to the GUARDRAIL_LLM_PROVIDER environment variable or 'mock'.",
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=None,
        help="Maximum number of concurrent LLM requests.",
    )
    parser.add_argument(
        "--no-fail-on-unclear",
        action="store_true",
        help="Do not treat UNCLEAR findings as CI failures.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0",
    )

    args = parser.parse_args(argv)

    settings = Settings.from_env()
    if args.provider:
        settings = dc_replace(settings, llm_provider=args.provider)
    if args.max_concurrency is not None:
        settings = dc_replace(settings, max_concurrency=args.max_concurrency)

    findings = parse_report(args.report_path, fmt=args.format)
    engine = TriageEngine(settings)
    report = engine.run_concurrent(findings, repo_root=args.repo_root)

    json_path = args.output_json or settings.output_json
    md_path = args.output_markdown or settings.output_markdown

    if json_path:
        Path(json_path).write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if md_path:
        Path(md_path).write_text(_build_markdown(report), encoding="utf-8")

    # Always print a concise summary.
    print(f"Guardrail Summary: {report.summary.model_dump_json()}")
    if report.summary.high_priority > 0:
        print("\nHigh-priority findings:")
        for result in report.results:
            if result.verdict == TriageVerdict.HIGH_PRIORITY:
                f = result.finding
                print(f"  - {f.rule_id} at {f.file_path}:{f.line} ({result.confidence:.0%} confidence)")

    fail = should_fail(report, fail_on_unclear=not args.no_fail_on_unclear)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())