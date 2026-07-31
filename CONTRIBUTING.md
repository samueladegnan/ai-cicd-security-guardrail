# Contributing to AI Guardrail

Thanks for your interest in contributing! This guide covers the workflow we follow and the checks that run in CI.

## Development setup

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install the package in editable mode with all dev dependencies
pip install -e ".[dev]"
```

## Code quality

We use **Ruff** for linting and formatting and **mypy** for type checking.

```bash
# Run all fast checks locally
ruff check src tests
ruff format --check src tests
mypy src tests --ignore-missing-imports

# Run tests
pytest -v
```

Pre-commit hooks are configured for the repository. Install them with:

```bash
pre-commit install
```

## Pull request workflow

1. Fork the repository and create a feature branch.
2. Make your changes, adding or updating tests as needed.
3. Ensure `ruff`, `mypy`, and `pytest` all pass locally.
4. Open a pull request. CI will run the full quality, test, and security matrix.

## Dependency lockfiles

`requirements.txt` and `requirements-dev.txt` are generated with `pip-tools` from `pyproject.toml`.

```bash
python -m piptools compile --generate-hashes --output-file=requirements.txt pyproject.toml
python -m piptools compile --extra=dev --generate-hashes --output-file=requirements-dev.txt pyproject.toml
```

## Security

This is a security-focused project. Please do not commit API keys or secrets. All third-party dependencies are scanned in CI with Bandit and Trivy.
