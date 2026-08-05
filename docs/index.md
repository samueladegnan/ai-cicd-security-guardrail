---
title: AI Guardrail | SAST triage in CI
description: A Python CLI and GitHub Action that turns static-analysis findings into explainable CI decisions.
permalink: /
---

<div class="project-badges" aria-label="Project status">
  <a href="https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml"><img src="https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml/badge.svg" alt="CI status"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10 or newer"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License"></a>
</div>

## The problem

Static-analysis tools produce useful signals, but a long report still leaves engineers doing the expensive work. They open the source file, inspect surrounding code, map the issue to a control, and decide whether CI should stop.

AI Guardrail is a small decision layer for that workflow. It reads SARIF, SonarQube JSON, and cppcheck XML, adds bounded source context, maps known controls, and returns one of three explicit outcomes: high priority, false positive, or unclear.

## What happens to the data

The CLI parses a report into typed findings. Each source path is resolved below the configured repository root before context is read. Compliance mappings are attached before a provider classifies the finding. The resulting report can be written as JSON, Markdown, or SARIF and can be used to gate a build.

The local mock provider keeps demos and CI deterministic. Real providers are opt in because source context may leave the build environment. OPA policies fail closed when they are missing, invalid, or incomplete.

## What you can explore

- Run the [browser demo](./demo/) with synthetic reports and custom input. Files stay in the browser
- Read the [architecture notes](./architecture/) for the parser, context, compliance, provider, reporter, and policy boundaries
- Open the [security report](./security/) to see the scoped self-assessment and its limits
- Inspect the [GitHub Action](https://github.com/samueladegnan/ai-cicd-security-guardrail/blob/main/action.yml), Docker entrypoint, and CI workflow
- Run the CLI locally with the committed SARIF fixtures

```bash
pip install -e ".[dev]"
guardrail tests/fixtures/sample.sarif --provider mock --repo-root . --output-markdown report.md
```

The sample produces one high-priority result and one benign warning. The clean fixture exercises a passing run.

## Why this project is worth inspecting

- Typed Python models and parser adapters for three common report formats
- Repo-root and symlink-aware source confinement
- Bounded concurrency, retries, provider fallback, circuit breakers, and SQLite caching
- Compliance mapping for CERT C, MISRA C, FIPS, OWASP, CWE, and CIS AWS
- SARIF output, GitHub review comments, OPA policy gating, and a reusable report renderer
- CI that checks code quality, behavior, container builds, dependencies, generated assets, Bandit severity gates, and a scoped self-assessment

## About the author

Built and maintained by [Sam Degnan](https://github.com/samueladegnan), focused on secure systems, automation, and practical developer tooling.
