---
title: AI Guardrail
---

[![CI](https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml/badge.svg)](https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What it is

The **AI-Driven CI/CD Security Guardrail** is a Python CLI and reusable GitHub Action that reads static-analysis reports, enriches each finding with source context and compliance mappings, and uses an LLM to classify it as a **high-priority security risk**, a **false positive**, or **unclear**. It returns a CI-friendly exit code so real risks can fail a build while false positives are filtered out.

I built this as a portfolio project to show what secure software engineering, CI/CD automation, LLM integration, and clean Python architecture look like in practice.

## How it works

1. **Ingest:** Parse SARIF, SonarQube JSON, or cppcheck XML reports.
2. **Enrich:** Load the source code around each finding.
3. **Map:** Map CWEs to controls in **CERT C**, **MISRA C**, **FIPS 140-3**, **OWASP**, or **CIS AWS**.
4. **Classify:** Send context to an LLM (OpenAI, Anthropic, Gemini, or a deterministic mock).
5. **Report:** Produce JSON and Markdown reports and a non-zero exit code for real risks.

## What makes it useful

- **Reduces false-positive fatigue** in security pipelines.
- **Works across languages:** C/C++, JavaScript, TypeScript, Ruby, Python, Terraform, and more.
- **Runs without an API key** using the mock provider, perfect for demos and CI.
- **Pluggable architecture:** swap parsers, context extractors, compliance mappers, and LLM providers.

## Live demo

Try it in your browser on the [interactive live demo](./demo). No installation or API key is required.

Or run it locally with Docker:

```bash
docker build -t ai-cicd-security-guardrail:latest .
docker run --rm -v "$(pwd):/workspace" --workdir /workspace ai-cicd-security-guardrail:latest \
  tests/fixtures/sample.sarif \
  --repo-root /workspace \
  --output-markdown /workspace/report.md
```

## Key features

- **Multi-format parser support:** SARIF, SonarQube JSON, cppcheck XML.
- **Compliance-aware context:** CERT C, MISRA C:2012, FIPS 140-3, OWASP Top 10, CWE, and CIS AWS.
- **Provider-agnostic LLM layer:** OpenAI, Anthropic, Gemini, and a zero-cost mock provider.
- **CI/CD ready:** Docker container, reusable GitHub Action, and Jenkins pipeline example.
- **Fast feedback:** In-memory caching and controlled concurrency.

## About the author

Built by [Sam Degnan](https://github.com/samueladegnan), and I put this together to share my work in DevOps, secure coding, compliance mapping, and AI-assisted software engineering.
