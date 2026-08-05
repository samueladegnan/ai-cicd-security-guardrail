# AI Guardrail

A Python CLI and GitHub Action that turns static-analysis findings into explainable CI decisions.

[![CI](https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml/badge.svg)](https://github.com/samueladegnan/ai-cicd-security-guardrail/actions/workflows/guardrail.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**[Project site](https://samueladegnan.github.io/ai-cicd-security-guardrail/)** · **[Browser demo](https://samueladegnan.github.io/ai-cicd-security-guardrail/demo/)** · **[Security report](https://samueladegnan.github.io/ai-cicd-security-guardrail/security/)**

## The problem

Static-analysis tools find possibilities. Engineers still need to inspect source context, understand impact, map the issue to a control, and decide whether the build should stop.

AI Guardrail is the decision layer for that workflow. It accepts SARIF, SonarQube JSON, and cppcheck XML, then produces three explicit outcomes:

- **High priority** means the finding should block the build
- **False positive** means the finding is not a security issue in the available context
- **Unclear** means an engineer needs to review it

The tool does not replace a SAST engine or prove exploitability. It makes the next decision easier to inspect and automate.

## What happens to a finding

1. Parse the report into a normalized `Finding` model
2. Read bounded source context beneath the configured repository root
3. Map CWEs and rules to selected compliance frameworks
4. Classify with a configured provider or the deterministic local mock
5. Write JSON, Markdown, or SARIF output
6. Return a predictable CI exit code or evaluate an OPA policy

The default provider is local and deterministic. Real providers are opt in because source context may leave the build environment.

## Try it

The [browser demo](https://samueladegnan.github.io/ai-cicd-security-guardrail/demo/) uses clearly labeled synthetic reports. It parses custom SARIF, SonarQube JSON, and cppcheck XML in the browser. It does not upload files or scan your device.

For the actual CLI:

```bash
pip install -e ".[dev]"
guardrail tests/fixtures/sample.sarif \
  --provider mock \
  --repo-root . \
  --output-json report.json \
  --output-markdown report.md
```

The sample contains one intentionally vulnerable C finding and one benign warning. The command returns exit code `1` and writes a report with one high-priority finding. Run the clean fixture to exercise a passing build.

```bash
guardrail tests/fixtures/clean.sarif --provider mock --repo-root .
```

## Why it is technically interesting

- A typed Python pipeline with pluggable report parsers, context strategies, compliance mappers, provider clients, reporters, and policy engines
- Safe source-path resolution that rejects traversal and symlink escapes
- Bounded concurrency, transient retry handling, provider fallback, circuit breakers, and SQLite caching
- SARIF output for GitHub Advanced Security and optional GitHub review comments
- A Docker-based GitHub Action that keeps action inputs and API keys out of process arguments
- A separate dependency-light JavaScript renderer with filtering, search, sorting, expandable context, and export
- CI checks for tests, formatting, types, generated assets, container builds, Bandit severity gates, pip-audit, a complete Trivy report, fixable HIGH/CRITICAL vulnerabilities, detected secrets, and a scoped self-assessment

## Run locally

### Python package

```bash
python -m venv .venv
source .venv/bin/activate
# Windows Git Bash: source .venv/Scripts/activate
pip install -e ".[dev]"
pytest -q
ruff check src tests
ruff format --check src tests
mypy src tests --ignore-missing-imports
```

### Renderer package

```bash
cd packages/guardrail-report-renderer
npm ci
npm test -- --runInBand
npm run build
```

The build command synchronizes package assets into `docs/assets`. CI checks that the generated files are current.

### Documentation site

The site runs with Jekyll in Docker:

```bash
cd docs
docker compose up --build
```

Open `http://localhost:4000/ai-cicd-security-guardrail/`.

## GitHub Action

```yaml
- name: Triage SAST findings
  uses: samueladegnan/ai-cicd-security-guardrail@main
  with:
    report-path: ./scan-results.sarif
    provider: mock
    output-json: guardrail-report.json
    output-markdown: guardrail-report.md
```

For a real provider, pass the API key from a GitHub secret. The Docker entrypoint reads the runner-provided action inputs and exports runtime settings without adding secrets to the command line.

## Useful options

| Option | Purpose |
| --- | --- |
| `--format` | `sarif`, `sonarqube`, or `cppcheck`. Otherwise the document is inspected. |
| `--repo-root` | Root used to resolve source paths. Out-of-tree context is refused. |
| `--provider` | `openai`, `anthropic`, `gemini`, or `mock`. |
| `--output-json`, `--output-markdown`, `--output-sarif` | Write JSON, Markdown, or GitHub-compatible SARIF. |
| `--fallback-providers` | Comma-separated fallback chain such as `anthropic,mock`. |
| `--context-strategy` | `auto`, `line-window`, or `ast`. |
| `--policy` | Rego policy evaluated by OPA. Missing, invalid, or incomplete decisions fail closed. |
| `--no-fail-on-unclear` | Allow unclear results without changing the high-priority failure rule. |

## Project map

```text
src/guardrail/                 Python CLI and triage pipeline
  parsers/                     SARIF, SonarQube, and cppcheck adapters
  compliance/                  Framework and semantic mappings
  llm/                         Provider clients and resilience controls
  context.py                   Source-context strategies and path boundary
  triage.py                    Enrichment, classification, caching, and reports
  policy.py                    Built-in and OPA policy decisions
packages/guardrail-report-renderer/  Reusable browser renderer
sample_code/                   Intentionally vulnerable and benign C inputs
docs/                          Jekyll site, demo, architecture, and report
tests/                         Python tests and report fixtures
```

Read the [architecture notes](docs/architecture.md) for the data flow and extension points. The [security report](docs/security.md) explains the self-assessment scope. Low-severity Bandit findings are published for review, while medium and high findings fail CI before the Guardrail triage step. Container CI preserves all Trivy findings in an artifact, fails on fixable HIGH/CRITICAL vulnerabilities or detected secrets, and leaves unfixed findings visible for review rather than treating them as remediated.

## Security and privacy

- The mock provider never sends source data to a network service
- Real providers receive the finding and configured source context
- Source paths are resolved beneath `--repo-root` before they are read
- API keys come from environment variables or action secrets and are not written to reports
- The container defaults to root for GitHub Actions compatibility. Local users can choose another UID and GID when their mounted workspace permits it

## Scope

This is a focused triage layer, not a replacement for a SAST engine, a proof of exploitability, or a guarantee that a repository is secure. Teams should validate provider behavior, policy rules, and false-positive rates against their own findings.

## License

MIT. See [LICENSE](LICENSE).

Maintained by [Sam Degnan](https://github.com/samueladegnan).
