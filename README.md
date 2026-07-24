# AI-Driven CI/CD Security Guardrail

> Context-aware triage of static-analysis findings for C/C++ using a Large Language Model.

[![CI](https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml/badge.svg)](https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

🌐 **View the portfolio site:** [samueladegnan.github.io/ai-cicd-security-guardrail](https://samueladegnan.github.io/ai-cicd-security-guardrail)

## Portfolio Showcase

This project was built as a **professional portfolio piece** to demonstrate secure software engineering, DevOps automation, LLM integration, and clean Python architecture. It is fully documented, tested, and packaged as a reusable GitHub Action and Docker container.

- 📖 **Project site:** [docs/index.md](docs/index.md) (deployed via GitHub Pages)
- 🎥 **Demo walkthrough:** [docs/demo.md](docs/demo.md)
- 🏗️ **Architecture deep-dive:** [docs/architecture.md](docs/architecture.md)


## Why?

Modern C/C++ codebases generate thousands of static-analysis warnings. Many are false positives, but the real security issues hide among them. This project implements a **CI/CD guardrail** that:

1. Parses reports from **SARIF**, **SonarQube**, and **cppcheck**.
2. Maps each finding to compliance controls in **CERT C**, **MISRA C**, and **FIPS 140-3** via CWE.
3. Sends code context to an LLM (**OpenAI**, **Anthropic Claude**, or **Google Gemini**) and asks it to classify the finding as **High-Priority Security Risk**, **False Positive**, or **Unclear**.
4. Returns a JSON/Markdown report and a non-zero exit code when real risks remain.

## Key Features

- **Multi-format parser support:** SARIF, SonarQube JSON, cppcheck XML.
- **Compliance-aware context:** CERT C, MISRA C:2012, and FIPS controls.
- **Provider-agnostic LLM layer:** OpenAI, Anthropic, Gemini, plus a zero-cost **mock** provider.
- **CI/CD ready:** Docker container, reusable GitHub Action, and Jenkins pipeline example.
- **Fast feedback:** In-memory caching and controlled concurrency.

## Quick Demo

```bash
guardrail tests/fixtures/sample.sarif --provider mock --repo-root . --output-markdown report.md
```

Output:

```text
Guardrail Summary: {"total":2,"high_priority":1,"false_positive":1,"unclear":0}

High-priority findings:
  - CWE-121 at sample_code/vulnerable.c:14 (90% confidence)
```

The exit code is **1** because a high-priority security finding remains — exactly the behavior you want in CI/CD.

See the full [Demo Walkthrough](docs/demo.md) for Docker, real LLM providers, and CI/CD examples.

## Quick Start

### Run with Docker (no API key required)

```bash
# Build the image
docker build -t ai-guardrail .

# Run against the sample SARIF report
docker run --rm -v "$(pwd):/workspace" --workdir /workspace ai-guardrail \
  tests/fixtures/sample.sarif \
  --repo-root /workspace \
  --output-json guardrail-report.json
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

## Usage

```text
guardrail <report-path> [options]
```

| Option | Description |
|--------|-------------|
| `--format` | `sarif`, `sonarqube`, or `cppcheck` (auto-detected if omitted). |
| `--repo-root` | Directory containing source files referenced by the report. |
| `--provider` | LLM provider: `openai`, `anthropic`, `gemini`, or `mock`. |
| `--output-json` | Path to write the JSON report. |
| `--output-markdown` | Path to write the Markdown report. |
| `--no-fail-on-unclear` | Do not fail the pipeline for UNCLEAR findings. |

## GitHub Actions Integration

```yaml
- name: AI Guardrail Triage
  uses: ./
  with:
    report-path: ./scan-results.sarif
    provider: anthropic
    llm-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    output-markdown: guardrail-report.md
```

See [`.github/workflows/guardrail.yml`](.github/workflows/guardrail.yml) and [`docs/architecture.md`](docs/architecture.md) for more.

## Project Structure

```text
.
├── action.yml                      # Reusable GitHub Action metadata
├── Dockerfile                      # Production-ready container
├── Jenkinsfile                     # Jenkins pipeline example
├── pyproject.toml
├── sample_code/                    # Vulnerable and false-positive samples
├── src/guardrail/
│   ├── cli.py                      # CLI entry point
│   ├── code_fetcher.py             # Safe source context loader
│   ├── compliance/                 # CERT C, MISRA C, FIPS rules
│   ├── llm_client.py               # LLM provider abstraction
│   ├── models.py                   # Pydantic models
│   ├── parsers/                    # SARIF, SonarQube, cppcheck
│   └── triage.py                   # Core triage engine
└── tests/                          # Unit tests and fixtures
```

## Architecture

For a detailed architecture overview, data-flow diagram, and extensibility guide, see [`docs/architecture.md`](docs/architecture.md).

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `GUARDRAIL_LLM_PROVIDER` | `openai`, `anthropic`, `gemini`, or `mock`. |
| `GUARDRAIL_LLM_API_KEY` | API key for the selected provider. |
| `GUARDRAIL_LLM_MODEL` | Model name (e.g., `gpt-4o-mini`, `claude-3-5-sonnet-20240620`). |
| `GUARDRAIL_MAX_CONCURRENCY` | Concurrent LLM requests (default: `3`). |
| `GUARDRAIL_OUTPUT_JSON` | Default JSON output path. |
| `GUARDRAIL_OUTPUT_MARKDOWN` | Default Markdown output path. |

## Security & Privacy

- The **mock** provider runs entirely locally and sends no data to external services.
- For real LLM providers, code snippets are sent to the configured API endpoint. Use a private/enterprise LLM endpoint where required by policy.
- No API keys are hard-coded; all secrets are loaded from environment variables or CI secret stores.

## Roadmap

- [ ] Vector-based semantic compliance mapping for unmapped SAST rules.
- [ ] Support for additional SAST tools (Semgrep, CodeQL, Coverity).
- [ ] SARIF output format for integration with GitHub Advanced Security.
- [ ] Fine-tuned classification model for reduced LLM cost and latency.

## License

This project is released under the MIT License. See [LICENSE](./LICENSE) for details.

---

*Built as a portfolio project to demonstrate DevOps, secure coding, compliance mapping, and AI-assisted software engineering.*
