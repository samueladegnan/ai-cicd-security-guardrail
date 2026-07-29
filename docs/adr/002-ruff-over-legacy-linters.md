# ADR 002: Ruff for linting and formatting

## Status

Accepted

## Context

The project previously had no enforced linting or formatting. We needed to add a modern, fast tool to keep the codebase consistent and catch common mistakes early.

## Decision

We adopted **Ruff** as the single tool for linting, formatting, import sorting, and basic code-quality rules.

## Consequences

- **Unified tooling.** Ruff replaces separate tools like Black, isort, flake8, and pydocstyle, reducing configuration and CI time.
- **Fast pre-commit and CI.** Ruff's speed keeps local commits and CI jobs responsive.
- **Consistent style.** The project uses a line length of 100, double quotes, and Python 3.10+ syntax.
- **Future extensibility.** Ruff supports a growing list of rules (bugbear, comprehensions, pyupgrade, etc.) that we can enable as the codebase matures.
