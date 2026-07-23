"""Resolve source code context for a finding safely."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class CodeContext:
    snippet: str
    start_line: int
    end_line: int


def get_code_context(
    file_path: str,
    line: int,
    before: int = 4,
    after: int = 4,
    repo_root: str = ".",
) -> CodeContext:
    """Read a safe window of source code around a given line.

    Args:
        file_path: Path to the source file. May be relative to repo_root.
        line: 1-based line number to center the window around.
        before: Lines to include before the target line.
        after: Lines to include after the target line.
        repo_root: Base directory for relative paths.

    Returns:
        CodeContext with the snippet and line range. If the file is
        unreadable or missing, the snippet explains why.
    """
    safe_extensions = (
        ".c",
        ".cpp",
        ".cc",
        ".cxx",
        ".h",
        ".hpp",
        ".inc",
    )

    full_path = os.path.abspath(os.path.join(repo_root, file_path))

    if not os.path.exists(full_path):
        return CodeContext(
            snippet=f"[File not found: {file_path}]",
            start_line=line,
            end_line=line,
        )

    if not full_path.endswith(safe_extensions) or not full_path.startswith(
        os.path.abspath(repo_root)
    ):
        return CodeContext(
            snippet=f"[Refusing to read non-source or out-of-tree file: {file_path}]",
            start_line=line,
            end_line=line,
        )

    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            lines: list[str] = f.readlines()
    except OSError:
        return CodeContext(
            snippet=f"[Could not read file: {file_path}]",
            start_line=line,
            end_line=line,
        )

    total = len(lines)
    target = max(1, min(line, total)) if total else 1
    start = max(1, target - before)
    end = min(total, target + after)

    selected = lines[start - 1 : end]
    numbered = [f"{start + i:4d} {ln.rstrip()}" for i, ln in enumerate(selected)]

    return CodeContext(
        snippet="\n".join(numbered),
        start_line=start,
        end_line=end,
    )


def get_code_context_for_finding(
    finding,
    before: int = 4,
    after: int = 4,
    repo_root: str = ".",
) -> str:
    """Convenience wrapper returning the snippet string only."""
    ctx = get_code_context(finding.file_path, finding.line, before, after, repo_root)
    return ctx.snippet