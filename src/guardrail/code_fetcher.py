"""Resolve source code context for a finding safely.

This module is kept for backward compatibility. New code should use
:mod:`guardrail.context` directly.
"""

from __future__ import annotations

from guardrail.context import (
    CodeContext,
    ContextRegistry,
)
from guardrail.context import (
    get_code_context_for_finding as _get_code_context_for_finding,
)


def get_code_context(
    file_path: str,
    line: int,
    before: int = 4,
    after: int = 4,
    repo_root: str = ".",
) -> CodeContext:
    """Read a safe window of source code around a given line.

    Kept for backward compatibility — new callers should use
    :class:`guardrail.context.LineWindowContextExtractor`.
    """
    from guardrail.context import LineWindowContextExtractor

    extractor = LineWindowContextExtractor()
    return extractor.extract(file_path, line, repo_root=repo_root, before=before, after=after)


def get_code_context_for_finding(
    finding,
    before: int = 4,
    after: int = 4,
    repo_root: str = ".",
    registry: ContextRegistry | None = None,
) -> str:
    """Convenience wrapper returning the snippet string only."""
    return _get_code_context_for_finding(
        finding,
        before=before,
        after=after,
        repo_root=repo_root,
        registry=registry,
    )
