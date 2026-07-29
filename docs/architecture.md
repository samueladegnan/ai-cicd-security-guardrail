---
title: Architecture
permalink: /architecture/
---

# AI Guardrail: Architecture

## Goals

- Reduce false-positive fatigue from static-analysis tools in CI/CD.
- Map every finding to one or more compliance controls.
- Use an LLM to classify findings as a **high-priority security risk**, a **false positive**, or **unclear**.
- Provide a reusable Docker container and native CI/CD integrations for GitHub Actions and Jenkins.
- Stay extensible: new languages, parsers, and compliance frameworks are simple to add.

## High-level data flow

![AI Guardrail data flow](../assets/architecture.svg)

1. **Ingest:** Parse SARIF, SonarQube JSON, or cppcheck XML into normalized `Finding` objects.
2. **Enrich:** For each finding, the triage engine fetches source context (line-window or Tree-sitter AST) and compliance controls (hardcoded rules or RAG embeddings).
3. **Classify:** The LLM client scores the enriched finding, with provider fallback and circuit-breaker protection.
4. **Report:** The CLI aggregates results, writes JSON/Markdown/SARIF, and returns a CI-friendly exit code or posts inline PR comments.
5. **Govern:** An optional OPA/Rego policy decides whether the pipeline is allowed to pass.

## Component responsibilities

| Component | Responsibility |
|-----------|----------------|
| `guardrail/parsers/` | Convert SARIF, SonarQube JSON, and cppcheck XML into `Finding` models. Each parser is a class that declares its tool name and supported languages. |
| `guardrail/context.py` | Pluggable source-context extraction. A registry resolves the right `ContextExtractor` from language or file extension. The default strategy is a safe line window; an optional Tree-sitter extractor returns enclosing functions or classes. |
| `guardrail/compliance/` | Pluggable compliance mapping. A registry of `ComplianceMapper` implementations covers CERT C, MISRA C:2012, FIPS, OWASP Top 10, CWE, and CIS AWS. Optional semantic mapping uses vector embeddings for unmapped rules. |
| `guardrail/llm_client.py` | Provider-agnostic LLM client. Supports OpenAI, Anthropic, Gemini, and a deterministic mock, with multi-provider fallback and circuit breakers. |
| `guardrail/cache.py` | In-memory and persistent SQLite caches keyed by a stable hash of the finding and its compliance context. |
| `guardrail/policy.py` | Optional Open Policy Agent (OPA/Rego) evaluation of triage reports. |
| `guardrail/reporters/` | GitHub PR review comments and GitHub Advanced Security SARIF output. |
| `guardrail/triage.py` | Orchestrates enrichment, compliance mapping, LLM classification, caching, and policy evaluation. |
| `guardrail/cli.py` | Command-line entry point and report formatting. |
| `Dockerfile` / `action.yml` | Reusable container and GitHub Action definitions. |

## Language support

The guardrail can support many languages. The `language` field on each `Finding` is inferred from the report metadata or file extension. You can also override it with the `--language` CLI flag or the `language` action input.

Current language handling:

- **C/C++**: CERT C, MISRA C, FIPS controls.
- **JavaScript / TypeScript**: OWASP Top 10 and CWE.
- **Ruby**: OWASP Top 10 and CWE.
- **Python**: OWASP Top 10 and CWE.
- **Terraform / HCL**: CIS AWS and CWE.
- **Other / unknown**: generic line-window context extraction and OWASP/CWE mapping.

## Security and privacy

- Source code snippets are sent to the configured LLM endpoint only when a real provider is selected.
- The mock provider runs locally and never leaves the container.
- For real providers, follow your organization's data-handling policy. Consider an enterprise LLM gateway or private endpoint.
