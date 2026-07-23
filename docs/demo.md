---
title: Demo Walkthrough
permalink: /demo/
---

# Demo Walkthrough

This page shows how to run the guardrail locally, with Docker, and inside CI/CD. All commands below use the built-in **mock** provider, so no API key is required.

## 1. Run the Tests

```bash
pip install -e ".[dev]"
pytest -q
```

Expected output:

```text
14 passed in 0.83s
```

## 2. Run the CLI with the Mock Provider

```bash
guardrail tests/fixtures/sample.sarif \
  --provider mock \
  --repo-root . \
  --output-json report.json \
  --output-markdown report.md
```

Expected output:

```text
Guardrail Summary: {"total":2,"high_priority":1,"false_positive":1,"unclear":0}

High-priority findings:
  - CWE-121 at sample_code/vulnerable.c:14 (90% confidence)
```

The exit code is **1** because a high-priority security finding remains — exactly what you want in CI/CD to fail a build.

The command produces:

- `report.json` — full structured report.
- `report.md` — human-readable Markdown summary.

Sample `report.md` excerpt:

```markdown
# AI-Driven CI/CD Security Guardrail Report
## Summary
- **Total findings triaged:** 2
- **High-priority security risks:** 1
- **False positives:** 1
- **Unclear:** 0

### CWE-121 @ `sample_code/vulnerable.c:14`
- **Verdict:** HIGH_PRIORITY
- **Confidence:** 0.90
- **Compliance controls:**
  - CERT_C STR31-C: Guarantee that storage for strings has sufficient space
- **Remediation:** Fix or explicitly suppress the validated security issue.
```

## 3. Show the CLI Surface

```bash
guardrail --help
```

This is useful for screenshots or recordings.

## 4. Run with Docker

```bash
docker build -t ai-guardrail .
docker run --rm -v "$(pwd):/workspace" --workdir /workspace ai-guardrail \
  tests/fixtures/sample.sarif \
  --repo-root /workspace \
  --output-markdown /workspace/report.md
```

The default provider in the image is `mock`, so it works out of the box.

## 5. Run with a Real LLM Provider

```bash
export GUARDRAIL_LLM_PROVIDER=openai
export GUARDRAIL_LLM_API_KEY=sk-...
export GUARDRAIL_LLM_MODEL=gpt-4o-mini

guardrail tests/fixtures/sample.sarif --repo-root .
```

You can also pass `--provider` directly:

```bash
guardrail tests/fixtures/sample.sarif --provider openai
```

## 6. CI/CD Demos

### GitHub Actions

The repo includes a reusable action. The workflow in `.github/workflows/guardrail.yml` runs on every push/PR and fails the build if high-priority findings remain.

```yaml
- name: AI Guardrail Triage
  uses: ./
  with:
    report-path: ./scan-results.sarif
    provider: anthropic
    llm-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    output-markdown: guardrail-report.md
```

### Jenkins

A sample `Jenkinsfile` is included that runs the guardrail in a Docker container.

## Portfolio Tips

- Run `pytest` and show coverage — it is configured with `pytest-cov`.
- Show the mock-provider demo first so anyone can reproduce without an API key.
- Explain the exit code behavior — it returns `1` on high-priority findings, demonstrating real CI/CD guardrail behavior.
- Walk through the architecture in `docs/architecture.md`.
- Show the GitHub Actions badge after the workflow runs successfully.
