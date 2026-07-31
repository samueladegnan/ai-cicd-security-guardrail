---
title: AI Guardrail | Context-aware SAST triage
description: A Python CLI and GitHub Action that turns noisy static-analysis findings into prioritized, explainable security decisions.
permalink: /
---

[![CI](https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml/badge.svg)](https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## The problem

Static-analysis tools are good at finding possibilities and bad at telling a team what deserves attention first. A long warning list still leaves engineers doing the expensive work: opening the source file, checking the surrounding code, mapping the issue to a control, and deciding whether the build should stop.

AI Guardrail is the triage layer for that workflow. It reads SARIF, SonarQube JSON, and cppcheck XML, adds source context and compliance mappings, and returns an explainable verdict: **high priority**, **false positive**, or **unclear**.

## How it works

1. **Parse** supported SAST formats into normalized findings.
2. **Enrich** each finding with a safe line window or optional Tree-sitter context.
3. **Map** CWEs to CERT C, MISRA C, FIPS, OWASP, and CIS AWS controls.
4. **Classify** with OpenAI, Anthropic, Gemini, or a deterministic local mock provider.
5. **Report** JSON, Markdown, SARIF, and optional inline GitHub review comments.
6. **Gate** the pipeline with a predictable exit code or an OPA/Rego policy.

## Built for real pipelines

- A reusable Docker-based GitHub Action, plus a Jenkins example.
- Provider fallback, circuit breakers, bounded concurrency, and SQLite caching.
- SARIF output for GitHub Advanced Security.
- A small dependency-light JavaScript renderer for sharing reports in a browser.
- The project runs its own Bandit SARIF scan of `src/` through Guardrail on every CI/Pages build. See the [Security Report](./security/).

## Try it

Open the [illustrative live demo](./demo/). It runs in the browser with bundled sample reports and needs no API key. Sample data is intentionally synthetic; it is not a scan of your code.

For local use:

```bash
pip install -e ".[dev]"
guardrail tests/fixtures/sample.sarif --provider mock --repo-root . --output-markdown report.md
```

The mock provider is deterministic and local, which makes it useful for tests, demos, and reproducible CI. Select a real provider only when your data-handling policy allows source context to leave the build environment.

## About the author

AI Guardrail is maintained by [Sam Degnan](https://github.com/samueladegnan), a software engineer focused on secure systems, automation, and practical developer tooling.

This project was built with AI assistance. AI tools supported exploration, implementation, documentation, and testing, while the project direction, decisions, review, and final responsibility remain with the maintainer.
