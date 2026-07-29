"""Post guardrail findings as inline GitHub PR review comments.

This reporter converts high-priority findings into PR review comments so
developers see security issues directly on the offending lines. It uses the
GitHub REST API and works both in GitHub Actions and from local runs when a
``GITHUB_TOKEN`` is provided.
"""

from __future__ import annotations

import json
import os
from typing import Any, cast

import requests

from guardrail.models import Report, TriageVerdict


class GitHubReporter:
    """Post guardrail findings as GitHub PR review comments."""

    GITHUB_API_URL = "https://api.github.com"

    def __init__(
        self,
        token: str,
        repository: str,
        pr_number: int,
        commit_sha: str = "",
    ):
        self.token = token
        self.repository = repository
        self.pr_number = pr_number
        self.commit_sha = commit_sha or os.getenv("GITHUB_SHA", "")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "ai-cicd-security-guardrail",
            }
        )

    def is_configured(self) -> bool:
        return bool(self.token) and bool(self.repository) and self.pr_number > 0

    def post_review_comments(self, report: Report) -> list[dict[str, Any]]:
        """Post one review comment per high-priority finding and return API responses."""
        if not self.is_configured():
            return []

        comments: list[dict[str, Any]] = []
        for result in report.results:
            if result.verdict != TriageVerdict.HIGH_PRIORITY:
                continue
            f = result.finding
            body = (
                f"🛡️ **AI Guardrail: {result.verdict.value}**\n\n"
                f"**Rule:** {f.rule_id}\n"
                f"**Confidence:** {result.confidence:.0%}\n"
                f"**Reasoning:** {result.reasoning}\n"
            )
            if result.remediation:
                body += f"**Remediation:** {result.remediation}\n"
            if result.compliance_hits:
                hits = ", ".join(
                    f"{h.framework.upper()} {h.rule_id}" for h in result.compliance_hits
                )
                body += f"**Compliance:** {hits}\n"
            payload: dict[str, Any] = {
                "body": body,
                "path": f.file_path,
                "line": max(1, f.line),
                "side": "RIGHT",
            }
            if self.commit_sha:
                payload["commit_id"] = self.commit_sha
            comments.append(payload)

        if not comments:
            return []

        # Create a single review with all comments.
        review_url = f"{self.GITHUB_API_URL}/repos/{self.repository}/pulls/{self.pr_number}/reviews"
        review_payload: dict[str, Any] = {
            "body": "AI Guardrail found high-priority security findings. See inline comments.",
            "event": "COMMENT",
            "comments": comments,
        }
        try:
            resp = self.session.post(review_url, json=review_payload, timeout=30)
            resp.raise_for_status()
            return [cast(dict[str, Any], resp.json())]
        except requests.HTTPError:
            # If the review API fails, fall back to individual issue comments.
            fallback_url = (
                f"{self.GITHUB_API_URL}/repos/{self.repository}/issues/{self.pr_number}/comments"
            )
            fallback_responses = []
            for comment in comments:
                body = comment["body"]
                try:
                    r = self.session.post(fallback_url, json={"body": body}, timeout=30)
                    r.raise_for_status()
                    fallback_responses.append(cast(dict[str, Any], r.json()))
                except Exception:  # noqa: BLE001
                    continue
            return fallback_responses

    def post_summary(self, report: Report) -> dict[str, Any] | None:
        """Post a summary comment on the PR (or issue) thread."""
        if not self.is_configured():
            return None
        summary_url = (
            f"{self.GITHUB_API_URL}/repos/{self.repository}/issues/{self.pr_number}/comments"
        )
        body = (
            f"## AI Guardrail Summary\n\n"
            f"- **Total findings:** {report.summary.total}\n"
            f"- **High priority:** {report.summary.high_priority}\n"
            f"- **False positives:** {report.summary.false_positive}\n"
            f"- **Unclear:** {report.summary.unclear}\n"
        )
        try:
            resp = self.session.post(summary_url, json={"body": body}, timeout=30)
            resp.raise_for_status()
            return cast(dict[str, Any], resp.json())
        except Exception:  # noqa: BLE001
            return None


class LocalGitHubReporter(GitHubReporter):
    """Reporter that writes the JSON payload to stdout instead of calling GitHub.

    Useful for local testing and CI environments without a token.
    """

    def post_review_comments(self, report: Report) -> list[dict[str, Any]]:
        if not self.is_configured():
            return []
        comments: list[dict[str, Any]] = []
        for result in report.results:
            if result.verdict != TriageVerdict.HIGH_PRIORITY:
                continue
            f = result.finding
            comments.append(
                {
                    "path": f.file_path,
                    "line": max(1, f.line),
                    "body": f"{result.verdict.value}: {f.rule_id} ({result.confidence:.0%} confidence)",
                }
            )
        print(json.dumps(comments, indent=2))
        return comments
