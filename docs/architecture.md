---
title: Architecture
permalink: /architecture/
---

# AI-Driven CI/CD Security Guardrail — Architecture

## Goals

- Reduce false-positive fatigue from static-analysis tools in C/C++ pipelines.
- Map every finding to one or more compliance controls (CERT C, MISRA C, FIPS 140-3).
- Use an LLM to classify findings as **High-Priority Security Risk**, **False Positive**, or **Unclear**.
- Provide a reusable Docker container and native CI/CD integrations for GitHub Actions and Jenkins.

## High-Level Data Flow

```
                    ┌───────────────────┐
                    │    SAST Report    │
                    │ (SARIF/Sonar/XML) │
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │      Parser       │
                    │    (findings)     │
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │   Finding Model   │
                    │  (rule/loc/CWE)   │
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │   Triage Engine   │
                    │  (orchestrator)   │
                    └───────────────────┘
                              │
              ────────┬───────┬───────┬───────
                      │       │       │
                      ▼       ▼       ▼
        ┌───────────┐   ┌───────────┐   ┌───────────┐
        │ Code      │   │Compliance │   │   LLM     │
        │ Fetcher   │   │ Mapper    │   │  Client   │
        │(snippets) │   │(CERT/etc) │   │(classify) │
        └───────────┘   └───────────┘   └───────────┘
                              │
                              │
                              ▼
                    ┌───────────────────┐
                    │   Report + Exit   │
                    │  (JSON/MD/exit)   │
                    └───────────────────┘
```

1. **Ingest** — Parse SARIF, SonarQube JSON, or cppcheck XML into a list of normalized `Finding` objects.
2. **Enrich** — For each finding, the Triage Engine fetches nearby source code and looks up compliance controls.
3. **Classify** — The LLM Client scores the enriched finding as `HIGH_PRIORITY`, `FALSE_POSITIVE`, or `UNCLEAR`.
4. **Report** — The CLI aggregates results, writes JSON/Markdown reports, and returns a CI-friendly exit code.

## Component Responsibilities

| Component | Responsibility |
|-----------|--------------|
| `guardrail/parsers/` | Convert SARIF, SonarQube JSON, and cppcheck XML into a normalized `Finding` model. |
| `guardrail/compliance/` | Map CWEs to controls in CERT C, MISRA C, and FIPS. |
| `guardrail/llm_client.py` | Abstract provider-specific API calls. Supports OpenAI, Anthropic, Gemini, and a deterministic mock. |
| `guardrail/triage.py` | Orchestrate code-context enrichment, compliance mapping, LLM classification, and caching. |
| `guardrail/cli.py` | Command-line entry point and report formatting. |
| `Dockerfile` / `action.yml` | Reusable container and GitHub Action definitions. |

## Design Decisions

1. **CWE as the pivot.** Tool-specific rule IDs are too numerous to map exhaustively. CWE is a stable intermediate layer.
2. **Pluggable LLM client.** The abstraction layer keeps CI/CD configurations provider-agnostic.
3. **Mock provider for demos.** Running a real LLM in a portfolio demo would require API keys and budget; the mock provider demonstrates the pipeline without cost.
4. **Minimal dependencies.** `requests`, `pydantic`, and `defusedxml` cover parsing and typed models without pulling in heavy frameworks.
5. **Exit-code semantics.** The tool returns `1` when high-priority (or unclear, by default) findings exist, making it a true CI/CD guardrail.

## Security and Privacy Considerations

- Source code snippets are sent to the configured LLM endpoint only when the user opts into a real provider.
- The mock provider runs entirely locally and never leaves the container.
- For real providers, follow your organization's data-handling policy; consider an enterprise LLM gateway or private endpoint.

## Extending the Guardrail

- Add new parsers by implementing a function with signature `parse_report(path: str) -> List[Finding]` and registering it in `guardrail/parsers/__init__.py`.
- Add new compliance frameworks by adding a rules dictionary and including it in `guardrail/compliance/__init__.py`.
- Add new LLM providers by subclassing `LLMClient` and updating `get_client()`.
