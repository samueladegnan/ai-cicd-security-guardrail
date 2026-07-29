---
title: Security Report
permalink: /security/
---

# Security Report

The AI Guardrail runs against itself in CI/CD. Every push and pull request is triaged by the guardrail, and the latest report is published here.

## Latest Guardrail Run

{% assign report = site.data["guardrail-report"] %}
{% if report %}
- **Total findings triaged:** {{ report.summary.total }}
- **High-priority security risks:** {{ report.summary.high_priority }}
- **False positives:** {{ report.summary.false_positive }}
- **Unclear:** {{ report.summary.unclear }}
{% else %}
*This report is generated automatically by the GitHub Actions workflow. Run the pipeline once to populate it.*
{% endif %}

## What the guardrail checks

- Static-analysis findings from SARIF, SonarQube, and cppcheck reports.
- Source context and compliance mappings.
- LLM-based triage into high-priority, false positive, or unclear.

## How the report is produced

The workflow in `.github/workflows/guardrail.yml` runs the guardrail on the repository itself using the mock provider. It generates:

- `guardrail-report.json`: structured JSON report.
- `guardrail-report.md`: human-readable Markdown summary.

The Markdown report is copied into this page when the site is built.

## Security posture

- **No secrets are hard-coded.** API keys are read from environment variables or CI secret stores.
- **Mock provider runs locally.** When using the mock provider, no code leaves the runner.
- **Minimal dependencies.** The project depends only on `requests`, `pydantic`, and `defusedxml`.

