"""Explainable static-analysis triage for CI/CD pipelines."""

import importlib.metadata

from guardrail.config import Settings
from guardrail.models import Finding, Report, TriageResult, TriageVerdict

try:
    from guardrail._version import __version__  # written at build time by setuptools_scm
except ModuleNotFoundError:  # pragma: no cover - running from source without installing
    try:
        __version__ = importlib.metadata.version("ai-cicd-security-guardrail")
    except importlib.metadata.PackageNotFoundError:
        __version__ = "0.0.0-dev"

__all__ = [
    "__version__",
    "Settings",
    "Finding",
    "Report",
    "TriageResult",
    "TriageVerdict",
]
