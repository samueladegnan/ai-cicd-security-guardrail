---
title: Portfolio Showcase
permalink: /portfolio/
---

# Portfolio Showcase

This page explains why the AI-Driven CI/CD Security Guardrail is a strong portfolio project and what engineering skills it demonstrates.

## The Problem

Modern C/C++ codebases generate thousands of static-analysis warnings. Security teams waste time chasing false positives, while real vulnerabilities can slip through. Existing tooling either:

- Drowns engineers in noise, or
- Requires expensive, proprietary triage platforms.

## The Solution

This project implements a lightweight, open-source **CI/CD guardrail** that:

1. Ingests reports from common SAST tools (SARIF, SonarQube, cppcheck).
2. Enriches each finding with source code context.
3. Maps findings to compliance controls (CERT C, MISRA C, FIPS 140-3).
4. Uses an LLM to classify each finding as **High-Priority Security Risk**, **False Positive**, or **Unclear**.
5. Fails the build when real risks remain.

## Skills Demonstrated

| Skill | Evidence in Project |
|-------|---------------------|
| **Secure Software Engineering** | CWE mapping, compliance controls, vulnerability triage logic. |
| **CI/CD & DevOps** | Reusable GitHub Action, Jenkinsfile, Docker container, CI workflow. |
| **LLM Integration** | Provider-agnostic client for OpenAI, Anthropic, Gemini, and a mock provider. |
| **Python Architecture** | Pydantic models, parser abstraction, threaded triage engine, caching. |
| **Testing & Quality** | pytest suite with coverage, deterministic mock provider for reproducible demos. |
| **Technical Writing** | Architecture docs, README, GitHub Pages site, and inline documentation. |

## Why Hiring Managers Care

- **It solves a real problem** — false-positive fatigue in security pipelines.
- **It is production-shaped** — Dockerized, reusable action, tested, documented.
- **It shows judgment** — uses LLMs where they add value (context-aware classification) but keeps deterministic compliance mapping separate.
- **It is portfolio-friendly** — runs without an API key thanks to the mock provider.

## Project Metrics

- **Languages & Tools:** Python, Docker, GitHub Actions, Jenkins.
- **Test Coverage:** 14 unit tests with `pytest-cov`.
- **Inputs:** SARIF, SonarQube JSON, cppcheck XML.
- **Outputs:** JSON report, Markdown report, CI exit code.
- **Compliance Frameworks:** CERT C, MISRA C:2012, FIPS 140-3.

## Try It Yourself

```bash
git clone https://github.com/samueladegnan/ai-cicd-security-guardrail.git
cd ai-cicd-security-guardrail
pip install -e ".[dev]"
pytest -q
guardrail tests/fixtures/sample.sarif --provider mock --repo-root .
```
