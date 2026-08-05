---
title: Architecture | AI Guardrail
description: The data flow, boundaries, and tradeoffs behind AI Guardrail.
permalink: /architecture/
---

# Architecture

AI Guardrail sits between a static-analysis report and a CI decision. It does not scan source code itself. It normalizes findings, adds the context needed to review them, and makes the resulting decision easy to inspect.

## Data flow

![AI Guardrail data flow](../assets/architecture.svg)

1. **Parse** SARIF, SonarQube JSON, or cppcheck XML into typed `Finding` objects
2. **Enrich** each finding with a bounded line window or optional Tree-sitter scope
3. **Map** CWEs and rules to configured compliance frameworks
4. **Classify** with a provider, bounded concurrency, retry handling, fallback, and circuit breakers
5. **Report** JSON, Markdown, SARIF, or GitHub review comments
6. **Gate** the build with built-in logic or an OPA/Rego policy

## Component boundaries

| Component | Responsibility |
| --- | --- |
| `guardrail/parsers/` | Convert supported report formats into `Finding` models |
| `guardrail/context.py` | Resolve source context beneath `repo_root` with line-window and optional AST strategies |
| `guardrail/compliance/` | Map CWEs and rules to CERT C, MISRA C, FIPS, OWASP, CWE, and CIS AWS controls |
| `guardrail/llm/` | Keep provider clients behind one interface with fallback and circuit-breaker behavior |
| `code_fetcher.py` and `llm_client.py` | Compatibility shims for older imports. New code uses `context.py` and `guardrail.llm` directly |
| `guardrail/cache.py` | Cache triage results in memory or SQLite using a stable finding key |
| `guardrail/policy.py` | Evaluate reports with built-in rules or OPA/Rego and fail closed on policy errors |
| `guardrail/reporters/` | Write SARIF and optional GitHub PR comments |
| `guardrail/triage.py` | Orchestrate enrichment, mapping, classification, caching, and report assembly |
| `guardrail/cli.py` | Expose the workflow as a command line tool |
| `Dockerfile` and `action.yml` | Package the workflow as a reusable GitHub Action |

## Source boundary

The context extractor resolves both the repository root and the requested path before reading a file. It refuses paths outside the root, including symlink escapes, and skips known binary and archive extensions. This protects the provider prompt from accidentally including unrelated local files.

## Provider boundary

The mock provider runs locally and is deterministic. Real providers receive the finding and configured source context. That is an explicit data-handling decision, so deployments should use an approved endpoint and policy for sensitive repositories.

## Policy boundary

The built-in policy fails a run when high-priority findings remain and can also fail on unclear findings. An OPA policy can replace that decision. Missing OPA, invalid Rego, malformed output, and non-boolean decisions all fail closed.

## Language handling

Language is inferred from report metadata or file extension and can be overridden by the CLI or action input. Current context and mapping paths cover C and C++, JavaScript and TypeScript, Ruby, Python, Terraform, and generic unknown files.

## Tradeoffs

- A line window is the default because it works across languages and has a small dependency footprint
- Tree-sitter is optional because AST grammars add installation and runtime complexity
- The mock provider is intentionally simple. It exists for deterministic tests and demos, not as a claim of production classification accuracy
- Compliance mappings are explicit and inspectable. Semantic mapping is optional because embeddings add cost and another operational dependency
