"""Command-line interface for the AI-Driven CI/CD Security Guardrail."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace as dc_replace
from pathlib import Path

from guardrail.config import Settings
from guardrail.logger import configure_logging, get_logger
from guardrail.models import Language, Report, TriageVerdict
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


logger = get_logger(__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="guardrail",
        description="AI-driven triage of static-analysis findings across languages.",
    )
    parser.add_argument(
        "report_path",
        help="Path to the static-analysis report (SARIF, SonarQube JSON, or cppcheck XML).",
    )
    parser.add_argument(
        "--format",
        choices=["sarif", "sonarqube", "cppcheck", ""],
        help="Explicit report format. If omitted, the format is auto-detected.",
    )
    parser.add_argument(
        "--language",
        choices=["auto", "c", "cpp", "javascript", "typescript", "python", "ruby", "terraform", ""],
        default=None,
        help="Source language hint. If omitted, language is inferred from the report or file extensions.",
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
        "--fallback-providers",
        default=None,
        help="Comma-separated fallback LLM providers (e.g. openai,anthropic,mock).",
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
        default=None,
        help="Do not treat UNCLEAR findings as CI failures.",
    )
    parser.add_argument(
        "--cache-backend",
        choices=["memory", "sqlite"],
        help="Cache backend: memory or sqlite.",
    )
    parser.add_argument(
        "--cache-sqlite-path",
        help="Path to the SQLite cache database.",
    )
    parser.add_argument(
        "--policy",
        help="Path to an OPA/Rego policy file. If omitted, built-in policy logic is used.",
    )
    parser.add_argument(
        "--output-sarif",
        help="Path to write a SARIF 2.1.0 report for GitHub Advanced Security.",
    )
    parser.add_argument(
        "--pr-comment-mode",
        choices=["", "review", "commit"],
        default=None,
        help="Post high-priority findings as GitHub PR comments.",
    )
    parser.add_argument(
        "--github-token",
        help="GitHub token for PR comments.",
    )
    parser.add_argument(
        "--pr-number",
        type=int,
        default=None,
        help="Pull request number for PR comments.",
    )
    parser.add_argument(
        "--repository",
        help="GitHub repository in owner/repo format.",
    )
    parser.add_argument(
        "--commit-sha",
        help="Commit SHA to associate with PR review comments.",
    )
    parser.add_argument(
        "--semantic-compliance",
        action="store_true",
        help="Enable RAG-based semantic compliance mapping for unmapped rules.",
    )
    parser.add_argument(
        "--vector-store-path",
        help="Path to the semantic compliance vector store.",
    )
    parser.add_argument(
        "--context-strategy",
        choices=["auto", "line-window", "ast"],
        help="Context extraction strategy: auto, line-window, or ast.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0",
    )

    args = parser.parse_args(argv)
    configure_logging(verbose=args.verbose)

    language = None
    if args.language and args.language != "auto":
        language = Language(args.language)

    settings = Settings.from_env()
    if args.provider:
        settings = dc_replace(settings, llm_provider=args.provider)
    if args.fallback_providers is not None:
        settings = dc_replace(
            settings,
            fallback_providers=tuple(
                p.strip() for p in args.fallback_providers.split(",") if p.strip()
            ),
        )
    if args.max_concurrency is not None:
        settings = dc_replace(settings, max_concurrency=args.max_concurrency)
    if args.cache_backend is not None:
        settings = dc_replace(settings, cache_backend=args.cache_backend)
    if args.cache_sqlite_path is not None:
        settings = dc_replace(settings, cache_sqlite_path=args.cache_sqlite_path)
    if args.policy is not None:
        settings = dc_replace(settings, policy_path=args.policy)
    if args.semantic_compliance:
        settings = dc_replace(settings, semantic_compliance_enabled=True)
    if args.vector_store_path is not None:
        settings = dc_replace(settings, vector_store_path=args.vector_store_path)
    if args.context_strategy is not None:
        settings = dc_replace(settings, context_strategy=args.context_strategy)

    # GitHub PR comment settings from CLI override environment defaults.
    if args.github_token is not None:
        settings = dc_replace(settings, github_token=args.github_token)
    if args.pr_number is not None:
        settings = dc_replace(settings, pr_number=args.pr_number)
    if args.repository is not None:
        settings = dc_replace(settings, repository=args.repository)
    if args.commit_sha is not None:
        settings = dc_replace(settings, commit_sha=args.commit_sha)

    findings = parse_report(args.report_path, fmt=args.format)
    # Apply explicit language override if provided.
    if language is not None:
        findings = [f.model_copy(update={"language": language}, deep=True) for f in findings]
    engine = TriageEngine(settings)
    report = engine.run_concurrent(findings, repo_root=args.repo_root)

    json_path = args.output_json or settings.output_json
    md_path = args.output_markdown or settings.output_markdown
    sarif_path = args.output_sarif or settings.output_sarif

    if json_path:
        Path(json_path).write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if md_path:
        Path(md_path).write_text(_build_markdown(report), encoding="utf-8")
    if sarif_path:
        from guardrail.reporters.sarif import write_sarif

        write_sarif(report, sarif_path)

    # Post high-priority findings as PR comments if requested.
    pr_comment_mode = args.pr_comment_mode or settings.pr_comment_mode
    if pr_comment_mode:
        from guardrail.reporters.github import GitHubReporter, LocalGitHubReporter

        if settings.github_token:
            reporter = GitHubReporter(
                token=settings.github_token,
                repository=settings.repository,
                pr_number=settings.pr_number,
                commit_sha=settings.commit_sha,
            )
        else:
            reporter = LocalGitHubReporter(
                token=settings.github_token,
                repository=settings.repository,
                pr_number=settings.pr_number,
                commit_sha=settings.commit_sha,
            )
        reporter.post_review_comments(report)
        reporter.post_summary(report)

    # Always print a concise summary.
    print(f"Guardrail Summary: {report.summary.model_dump_json()}")
    if report.summary.high_priority > 0:
        print("\nHigh-priority findings:")
        for result in report.results:
            if result.verdict == TriageVerdict.HIGH_PRIORITY:
                f = result.finding
                print(
                    f"  - {f.rule_id} at {f.file_path}:{f.line} ({result.confidence:.0%} confidence)"
                )

    from guardrail.triage import evaluate_policy

    if settings.policy_path:
        fail = evaluate_policy(report, settings)
    else:
        fail_on_unclear = (
            not args.no_fail_on_unclear
            if args.no_fail_on_unclear is not None
            else settings.fail_on_unclear
        )
        fail = should_fail(report, fail_on_unclear=fail_on_unclear)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
