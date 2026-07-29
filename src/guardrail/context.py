"""Source-context extraction strategies for static-analysis findings.

The guardrail no longer assumes all code is C/C++.  A ``ContextExtractor``
registry resolves the right strategy from a finding's language hint or file
extension.  The default strategy is a safe, language-agnostic line window.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from guardrail.models import Finding, Language


@dataclass(frozen=True)
class CodeContext:
    snippet: str
    start_line: int
    end_line: int


class ContextExtractor(ABC):
    """Extract human-readable source context around a finding."""

    languages: ClassVar[tuple[Language, ...]] = ()
    extensions: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def extract(
        self,
        file_path: str,
        line: int,
        repo_root: str = ".",
        before: int = 4,
        after: int = 4,
    ) -> CodeContext:
        """Return a ``CodeContext`` for the given file and line."""

    def supports(self, language: Language, file_path: str) -> bool:
        """Return True if this extractor is a candidate for the finding."""
        if language in self.languages:
            return True
        if not self.extensions:
            return False
        return file_path.lower().endswith(self.extensions)


class TreeSitterContextExtractor(ContextExtractor):
    """AST-aware context extractor using Tree-sitter.

    This extractor attempts to return the enclosing function, class, or scope
    for a finding. If Tree-sitter is not installed or the language grammar is
    unavailable, it falls back to the line-window extractor.
    """

    languages = (
        Language.C,
        Language.CPP,
        Language.JAVASCRIPT,
        Language.TYPESCRIPT,
        Language.PYTHON,
        Language.RUBY,
        Language.GO,
        Language.RUST,
        Language.JAVA,
        Language.KOTLIN,
    )

    def __init__(self) -> None:
        self._fallback = LineWindowContextExtractor()

    def extract(
        self,
        file_path: str,
        line: int,
        repo_root: str = ".",
        before: int = 4,
        after: int = 4,
    ) -> CodeContext:
        try:
            from tree_sitter import Parser
        except ImportError:
            return self._fallback.extract(file_path, line, repo_root, before, after)

        import os as _os

        full_path = Path(_os.path.abspath(_os.path.join(repo_root, file_path)))
        repo_abs = Path(_os.path.abspath(repo_root))
        try:
            full_path.relative_to(repo_abs)
        except ValueError:
            return self._fallback.extract(file_path, line, repo_root, before, after)
        if not full_path.exists() or not full_path.is_file():
            return self._fallback.extract(file_path, line, repo_root, before, after)

        try:
            source = full_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return self._fallback.extract(file_path, line, repo_root, before, after)

        parser = Parser()
        try:
            # Try to load a language grammar. tree-sitter-language-pack is one
            # convenient way to get prebuilt grammars. If it fails, fall back.
            from tree_sitter_language_pack import get_language

            lang = self._ts_language_for_file(file_path)
            parser.set_language(get_language(lang))
        except Exception:  # noqa: BLE001
            return self._fallback.extract(file_path, line, repo_root, before, after)

        try:
            tree = parser.parse(source.encode("utf-8"))
        except Exception:  # noqa: BLE001
            return self._fallback.extract(file_path, line, repo_root, before, after)

        start_byte, end_byte = self._enclosing_scope_bytes(tree.root_node, line)
        if start_byte is None or end_byte is None:
            return self._fallback.extract(file_path, line, repo_root, before, after)

        start = source.count("\n", 0, start_byte) + 1
        end = source.count("\n", 0, end_byte) + 1
        snippet = source[start_byte:end_byte]
        numbered = [f"{start + i:4d} {ln}" for i, ln in enumerate(snippet.splitlines())]
        return CodeContext(snippet="\n".join(numbered), start_line=start, end_line=end)

    @staticmethod
    def _ts_language_for_file(file_path: str) -> str:
        suffix = Path(file_path).suffix.lower()
        mapping = {
            ".c": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".py": "python",
            ".rb": "ruby",
            ".go": "go",
            ".rs": "rust",
            ".java": "java",
            ".kt": "kotlin",
        }
        return mapping.get(suffix, "")

    @classmethod
    def _enclosing_scope_bytes(cls, node, line: int) -> tuple:
        """Return the (start_byte, end_byte) of the deepest scope containing ``line``."""
        target_line = line - 1
        best: tuple = (None, None)
        stack = [node]
        while stack:
            n = stack.pop()
            if n.start_point[0] <= target_line <= n.end_point[0]:
                start_byte = n.start_byte
                end_byte = n.end_byte
                if best[0] is None or end_byte - start_byte < best[1] - best[0]:
                    best = (start_byte, end_byte)
                for child in n.children:
                    stack.append(child)
        return best


class LineWindowContextExtractor(ContextExtractor):
    """Generic, language-agnostic line-window extractor.

    Reads any text file and returns a window of lines.  The file must be inside
    ``repo_root`` and must not look like a binary or archive.
    """

    languages: ClassVar[tuple[Language, ...]] = (Language.GENERIC,)

    # Reasonable set of source-like extensions we are willing to read.
    # Everything else is still allowed via the safe-path checks below.
    extensions: ClassVar[tuple[str, ...]] = (
        ".c",
        ".cpp",
        ".cc",
        ".cxx",
        ".h",
        ".hpp",
        ".inc",
        ".cs",
        ".go",
        ".java",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".kt",
        ".py",
        ".rb",
        ".rs",
        ".swift",
        ".tf",
        ".tfvars",
        ".json",
        ".xml",
        ".yml",
        ".yaml",
        ".sh",
        ".ps1",
        ".md",
    )

    def extract(
        self,
        file_path: str,
        line: int,
        repo_root: str = ".",
        before: int = 4,
        after: int = 4,
    ) -> CodeContext:
        full_path = Path(os.path.abspath(os.path.join(repo_root, file_path)))
        repo_abs = Path(os.path.abspath(repo_root))

        # Refuse to read paths outside the repo root before checking existence.
        try:
            full_path.relative_to(repo_abs)
        except ValueError:
            return CodeContext(
                snippet=f"[Refusing to read out-of-tree file: {file_path}]",
                start_line=line,
                end_line=line,
            )

        if not full_path.exists():
            return CodeContext(
                snippet=f"[File not found: {file_path}]",
                start_line=line,
                end_line=line,
            )

        if not full_path.is_file():
            return CodeContext(
                snippet=f"[Not a regular file: {file_path}]",
                start_line=line,
                end_line=line,
            )

        # Defensive: skip files that look like binaries.
        suffix = full_path.suffix.lower()
        if suffix in {".exe", ".dll", ".so", ".dylib", ".bin", ".zip", ".tar", ".gz"}:
            return CodeContext(
                snippet=f"[Refusing to read binary file: {file_path}]",
                start_line=line,
                end_line=line,
            )

        try:
            with open(full_path, encoding="utf-8", errors="replace") as f:
                lines: list[str] = f.readlines()
        except (OSError, UnicodeDecodeError) as exc:
            return CodeContext(
                snippet=f"[Could not read file: {file_path} — {exc}]",
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


class CContextExtractor(LineWindowContextExtractor):
    """Context extractor for C/C++ source files."""

    languages: ClassVar[tuple[Language, ...]] = (Language.C, Language.CPP, Language.C_Family)
    extensions: ClassVar[tuple[str, ...]] = (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".inc")


class JavaScriptContextExtractor(LineWindowContextExtractor):
    """Context extractor for JavaScript / TypeScript."""

    languages: ClassVar[tuple[Language, ...]] = (Language.JAVASCRIPT, Language.TYPESCRIPT)
    extensions: ClassVar[tuple[str, ...]] = (".js", ".jsx", ".ts", ".tsx")


class RubyContextExtractor(LineWindowContextExtractor):
    """Context extractor for Ruby."""

    languages: ClassVar[tuple[Language, ...]] = (Language.RUBY,)
    extensions: ClassVar[tuple[str, ...]] = (".rb", ".rake", ".gemspec")


class TerraformContextExtractor(LineWindowContextExtractor):
    """Context extractor for Terraform / OpenTofu."""

    languages: ClassVar[tuple[Language, ...]] = (Language.TERRAFORM,)
    extensions: ClassVar[tuple[str, ...]] = (".tf", ".tfvars", ".hcl")


class PythonContextExtractor(LineWindowContextExtractor):
    """Context extractor for Python."""

    languages: ClassVar[tuple[Language, ...]] = (Language.PYTHON,)
    extensions: ClassVar[tuple[str, ...]] = (".py", ".pyw")


class JavaContextExtractor(LineWindowContextExtractor):
    """Context extractor for Java / Kotlin."""

    languages: ClassVar[tuple[Language, ...]] = (Language.JAVA, Language.KOTLIN)
    extensions: ClassVar[tuple[str, ...]] = (".java", ".kt")


class GoContextExtractor(LineWindowContextExtractor):
    """Context extractor for Go."""

    languages: ClassVar[tuple[Language, ...]] = (Language.GO,)
    extensions: ClassVar[tuple[str, ...]] = (".go",)


class RustContextExtractor(LineWindowContextExtractor):
    """Context extractor for Rust."""

    languages: ClassVar[tuple[Language, ...]] = (Language.RUST,)
    extensions: ClassVar[tuple[str, ...]] = (".rs",)


class ContextRegistry:
    """Registry mapping languages/extensions to context extractors."""

    def __init__(self, extractors: Iterable[ContextExtractor] | None = None):
        self._extractors: list[ContextExtractor] = []
        if extractors:
            for extractor in extractors:
                self.register(extractor)

    def register(self, extractor: ContextExtractor) -> None:
        self._extractors.append(extractor)

    def resolve(self, language: Language, file_path: str) -> ContextExtractor:
        """Return the most specific extractor for the given language/path."""
        for extractor in self._extractors:
            if extractor.supports(language, file_path):
                return extractor
        return LineWindowContextExtractor()

    @classmethod
    def default(cls, strategy: str = "auto") -> ContextRegistry:
        """Return the default registry.

        If ``strategy`` is ``ast``, the Tree-sitter extractor is registered
        first. Otherwise language-specific line-window extractors take
        precedence and Tree-sitter is tried as a fallback.
        """
        extractors: list[ContextExtractor] = [
            CContextExtractor(),
            JavaContextExtractor(),
            JavaScriptContextExtractor(),
            PythonContextExtractor(),
            RubyContextExtractor(),
            RustContextExtractor(),
            GoContextExtractor(),
            TerraformContextExtractor(),
            LineWindowContextExtractor(),
        ]
        if strategy == "ast":
            extractors.insert(0, TreeSitterContextExtractor())
        elif strategy == "auto":
            extractors.insert(-1, TreeSitterContextExtractor())
        return cls(extractors)


def infer_language(
    tool: str,
    file_path: str,
    sarif_language: str | None = None,
) -> Language:
    """Infer the source language from SARIF hints or file extensions."""
    if sarif_language:
        mapping = {
            "c": Language.C,
            "cpp": Language.CPP,
            "c++": Language.CPP,
            "cplusplus": Language.CPP,
            "c#": Language.CSHARP,
            "csharp": Language.CSHARP,
            "go": Language.GO,
            "golang": Language.GO,
            "java": Language.JAVA,
            "javascript": Language.JAVASCRIPT,
            "js": Language.JAVASCRIPT,
            "kotlin": Language.KOTLIN,
            "python": Language.PYTHON,
            "ruby": Language.RUBY,
            "rust": Language.RUST,
            "swift": Language.SWIFT,
            "terraform": Language.TERRAFORM,
            "typescript": Language.TYPESCRIPT,
            "ts": Language.TYPESCRIPT,
        }
        lang_key = sarif_language.strip().lower()
        if lang_key in mapping:
            return mapping[lang_key]

    ext_to_lang: dict[str, Language] = {
        ".c": Language.C,
        ".cpp": Language.CPP,
        ".cc": Language.CPP,
        ".cxx": Language.CPP,
        ".h": Language.C,
        ".hpp": Language.CPP,
        ".cs": Language.CSHARP,
        ".go": Language.GO,
        ".java": Language.JAVA,
        ".js": Language.JAVASCRIPT,
        ".jsx": Language.JAVASCRIPT,
        ".ts": Language.TYPESCRIPT,
        ".tsx": Language.TYPESCRIPT,
        ".kt": Language.KOTLIN,
        ".py": Language.PYTHON,
        ".rb": Language.RUBY,
        ".rs": Language.RUST,
        ".swift": Language.SWIFT,
        ".tf": Language.TERRAFORM,
    }

    suffix = Path(file_path).suffix.lower()
    if suffix in ext_to_lang:
        return ext_to_lang[suffix]
    return Language.UNKNOWN


def get_code_context_for_finding(
    finding: Finding,
    before: int = 4,
    after: int = 4,
    repo_root: str = ".",
    registry: ContextRegistry | None = None,
) -> str:
    """Convenience wrapper returning the snippet string only."""
    registry = registry or ContextRegistry.default()
    extractor = registry.resolve(finding.language, finding.file_path)
    ctx = extractor.extract(
        finding.file_path,
        finding.line,
        repo_root=repo_root,
        before=before,
        after=after,
    )
    return ctx.snippet
