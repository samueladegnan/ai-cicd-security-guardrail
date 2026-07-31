# AI Guardrail

> A Python CLI and GitHub Action that turns noisy static-analysis findings into prioritized, explainable security decisions.

Finding a real vulnerability in a long SAST report still takes engineering judgment. Guardrail handles the repetitive part: it parses findings, adds source context and compliance mappings, and helps a team decide what deserves attention first.

[![CI](https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml/badge.svg)](https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

🌐 **View the portfolio site:** [samueladegnan.github.io/ai-cicd-security-guardrail](https://samueladegnan.github.io/ai-cicd-security-guardrail)

## What this repository contains

This is a production-minded security automation project: a typed Python package, a Docker-based GitHub Action, a reusable JavaScript report renderer, and a GitHub Pages site that documents and exercises the system. The repository tests itself in CI and publishes the resulting self-assessment on its project site.

- 📖 **Project site:** [docs/index.md](docs/index.md) (deployed via GitHub Pages)
- 🎥 **Live demo:** [docs/demo.md](docs/demo.md)
- 🏗️ **Architecture deep-dive:** [docs/architecture.md](docs/architecture.md)
- 🔒 **Security report:** [docs/security.md](docs/security.md)

## Why

Static-analysis tools produce a lot of noise. Most warnings are false positives, but real security issues hide among them. This guardrail parses reports, enriches findings with source context and compliance controls, and uses an LLM to decide which ones actually matter. It returns a CI-friendly exit code so real risks fail a build while false positives are filtered out.

## Key features

- **Multi-format parser support:** SARIF, SonarQube JSON, cppcheck XML.
- **Language-aware triage:** C/C++, JavaScript, TypeScript, Ruby, Python, Terraform, and more.
- **AST-aware context extraction:** Tree-sitter integration extracts enclosing functions/classes when available.
- **Compliance-aware context:** CERT C, MISRA C:2012, FIPS, OWASP Top 10, CWE, and CIS AWS controls.
- **Semantic compliance mapping (RAG):** Vector embeddings fill gaps for unmapped SAST rules.
- **Provider-agnostic LLM layer:** OpenAI, Anthropic, Gemini, plus a zero-cost **mock** provider, with provider fallback and circuit-breaker protection.
- **Policy-as-code triage:** Evaluate results against Open Policy Agent (OPA/Rego) policies.
- **GitHub Advanced Security output:** Write triage results as SARIF for the Security tab.
- **Inline PR comments:** Post high-priority findings as GitHub PR review comments.
- **Persistent SQLite cache:** Skip redundant LLM calls across runs.
- **CI/CD ready:** Docker container, reusable GitHub Action, and Jenkins pipeline example.
- **Interactive report UI:** A reusable vanilla-JS dashboard, published as `guardrail-report-renderer` on npm, for embedding triage results in any web page.
- **Self-assessment:** Bandit scans this repository's `src/` directory, Guardrail triages the SARIF output with its local mock provider, and GitHub Pages publishes that scoped report.

## Quick demo

```bash
guardrail tests/fixtures/sample.sarif --provider mock --repo-root . --output-markdown report.md
```

Output:

```text
Guardrail Summary: {"total":2,"high_priority":1,"false_positive":1,"unclear":0}

High-priority findings:
  - CWE-121 at sample_code/vulnerable.c:14 (90% confidence)
```

The exit code is **1** because a high-priority security finding remains, which is the behavior you want in CI/CD.

See the [live demo](docs/demo.md) for an interactive browser preview, and the README sections below for Docker, real LLM providers, and CI/CD examples.

## Quick start

### Run with Docker (no API key required)

```bash
# Build the image
docker build -t ai-cicd-security-guardrail:latest .

# Run against the sample SARIF report
docker run --rm -v "$(pwd):/workspace" --workdir /workspace ai-cicd-security-guardrail:latest \
  tests/fixtures/sample.sarif \
  --repo-root /workspace \
  --output-markdown /workspace/report.md
```

### Run locally

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .

# Mock provider (no API key)
guardrail tests/fixtures/sample.sarif --provider mock --output-markdown report.md
```

### Run tests

```bash
pip install -e ".[dev]"
pytest
```

### Serve the docs site locally (Docker)

No Ruby/Bundler installation required.

```bash
cd docs

# Option 1: Docker Compose (recommended on Windows)
docker compose up --build

# Option 2: Plain Docker
docker build -t guardrail-docs .
docker run --rm -p 4000:4000 -v "${PWD}:/srv/jekyll" guardrail-docs

# Then open the URL printed by Jekyll, usually:
# http://localhost:4000/ai-cicd-security-guardrail/
```

## Usage

```text
guardrail <report-path> [options]
```

| Option | Description |
|--------|-------------|
| `--format` | `sarif`, `sonarqube`, or `cppcheck` (auto-detected if omitted). |
| `--language` | Source language hint: `c`, `cpp`, `javascript`, `typescript`, `python`, `ruby`, `terraform`. |
| `--repo-root` | Directory containing source files referenced by the report. |
| `--provider` | LLM provider: `openai`, `anthropic`, `gemini`, or `mock`. |
| `--output-json` | Path to write the JSON report. |
| `--output-markdown` | Path to write the Markdown report. |
| `--no-fail-on-unclear` | Do not fail the pipeline for UNCLEAR findings. |

## GitHub Actions integration

The repository runs quality checks, package tests, dependency/SAST checks, container scanning, and a real self-assessment on every push and pull request. The Pages workflow repeats the self-assessment while building the public Security Report tab.

```yaml
- name: AI Guardrail Triage
  uses: ./
  with:
    report-path: ./scan-results.sarif
    provider: mock
    output-markdown: guardrail-report.md
```

See `.github/workflows/guardrail.yml` and `docs/architecture.md` for more.

## Project structure

```text
.
├── action.yml                      # Reusable GitHub Action metadata
├── Dockerfile                      # Production-ready container
├── examples/pipelines/Jenkinsfile  # Jenkins pipeline example
├── pyproject.toml
├── packages/                       # Reusable UI and ecosystem packages
│   └── guardrail-report-renderer/  # npm package for the interactive triage dashboard
├── sample_code/                    # Vulnerable and false-positive samples
├── src/guardrail/
│   ├── cli.py                      # CLI entry point
│   ├── code_fetcher.py             # Backward-compatible context wrapper
│   ├── compliance/                 # Compliance mappers (CERT, MISRA, FIPS, OWASP, CIS)
│   ├── context.py                  # Pluggable source-context extractors
│   ├── llm_client.py               # LLM provider abstraction
│   ├── models.py                   # Pydantic models
│   ├── parsers/                    # SARIF, SonarQube, cppcheck
│   └── triage.py                   # Core triage engine
└── tests/                          # Unit tests and fixtures
```

## Architecture

For a detailed architecture overview, data-flow diagram, and extensibility guide, see [`docs/architecture.md`](docs/architecture.md).

## Environment variables

| Variable | Purpose |
|----------|---------|
| `GUARDRAIL_LLM_PROVIDER` | `openai`, `anthropic`, `gemini`, or `mock`. |
| `GUARDRAIL_LLM_API_KEY` | API key for the selected provider. |
| `GUARDRAIL_LLM_MODEL` | Model name (e.g., `gpt-4o-mini`, `claude-3-5-sonnet-20240620`). |
| `GUARDRAIL_MAX_CONCURRENCY` | Concurrent LLM requests (default: `3`). |
| `GUARDRAIL_OUTPUT_JSON` | Default JSON output path. |
| `GUARDRAIL_OUTPUT_MARKDOWN` | Default Markdown output path. |

## Security & privacy

- The **mock** provider runs entirely locally and sends no data to external services.
- For real LLM providers, code snippets are sent to the configured API endpoint. Use a private/enterprise LLM endpoint where required by policy.
- No API keys are hard-coded; all secrets are loaded from environment variables or CI secret stores.
- The published Docker image runs as root so the GitHub Action can write reports back to the mounted workspace. For local use, you can run with an arbitrary non-root UID/GID using `--user $(id -u):$(id -g)` if your environment supports it.

## Roadmap

- [x] Vector-based semantic compliance mapping for unmapped SAST rules.
- [x] Additional language-aware context extractors (function/class boundaries).
- [x] SARIF output format for integration with GitHub Advanced Security.
- [ ] Fine-tuned classification model for reduced LLM cost and latency.
- [ ] Web dashboard for historical security score trends.

## Advanced usage

### Provider fallback and circuit breaker

```bash
guardrail tests/fixtures/sample.sarif \
  --provider openai \
  --fallback-providers anthropic,gemini,mock
```

### AST context extraction

```bash
guardrail tests/fixtures/sample.sarif \
  --context-strategy ast \
  --provider mock
```

### OPA/Rego policy-as-code

```bash
guardrail tests/fixtures/sample.sarif \
  --policy examples/policy.rego \
  --provider mock
```

### GitHub Advanced Security SARIF output

```bash
guardrail tests/fixtures/sample.sarif \
  --output-sarif guardrail-results.sarif \
  --provider mock
```

### Inline PR comments

```yaml
- uses: ./
  with:
    report-path: ./scan-results.sarif
    provider: mock
    pr-comment-mode: review
    github-token: ${{ secrets.GITHUB_TOKEN }}
    pr-number: ${{ github.event.pull_request.number }}
    repository: ${{ github.repository }}
```

### Persistent SQLite cache

```bash
guardrail tests/fixtures/sample.sarif \
  --cache-backend sqlite \
  --cache-sqlite-path .guardrail-cache.db \
  --provider mock
```

### Semantic compliance mapping

```bash
guardrail tests/fixtures/sample.sarif \
  --semantic-compliance \
  --vector-store-path .guardrail-vectors.db \
  --provider mock
```

## AI-assisted development

This project was built with AI assistance. AI tools supported exploration, implementation, documentation, and testing, while the project direction, decisions, review, and final responsibility remain with the maintainer.

## License

This project is released under the MIT License. See [LICENSE](./LICENSE) for details.

---

*Maintained by Sam Degnan as a practical example of secure Python engineering, CI/CD automation, and explainable security tooling.*
