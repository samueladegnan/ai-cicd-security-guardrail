"""Tests for source-context extraction and language inference."""

from __future__ import annotations

from guardrail.context import (
    CContextExtractor,
    ContextRegistry,
    LineWindowContextExtractor,
    RubyContextExtractor,
    infer_language,
)
from guardrail.models import Finding, Language, Severity


def test_infer_language_from_extension():
    assert infer_language("sarif", "src/main.c") == Language.C
    assert infer_language("sarif", "lib/utils.cpp") == Language.CPP
    assert infer_language("sarif", "app/user.rb") == Language.RUBY
    assert infer_language("sarif", "infra/main.tf") == Language.TERRAFORM
    assert infer_language("sarif", "app.js") == Language.JAVASCRIPT
    assert infer_language("sarif", "app.ts") == Language.TYPESCRIPT


def test_infer_language_from_sarif_hint():
    assert infer_language("sarif", "file.rb", sarif_language="ruby") == Language.RUBY
    assert infer_language("sarif", "file.c", sarif_language="cplusplus") == Language.CPP


def test_line_window_extractor_reads_python_file(tmp_path):
    path = tmp_path / "main.py"
    path.write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")
    extractor = LineWindowContextExtractor()
    ctx = extractor.extract(str(path), 3, repo_root=str(tmp_path), before=1, after=1)
    assert "2 line2" in ctx.snippet
    assert "4 line4" in ctx.snippet


def test_line_window_extractor_refuses_out_of_tree(tmp_path):
    extractor = LineWindowContextExtractor()
    ctx = extractor.extract("/etc/passwd", 1, repo_root=str(tmp_path))
    assert "out-of-tree" in ctx.snippet


def test_registry_resolves_c_for_c_file():
    registry = ContextRegistry.default()
    extractor = registry.resolve(Language.C, "main.c")
    assert isinstance(extractor, CContextExtractor)


def test_registry_resolves_ruby_for_rb_file():
    registry = ContextRegistry.default()
    extractor = registry.resolve(Language.UNKNOWN, "app/models/user.rb")
    assert isinstance(extractor, RubyContextExtractor)


def test_registry_falls_back_to_line_window():
    registry = ContextRegistry.default()
    extractor = registry.resolve(Language.UNKNOWN, "unknown.xyz")
    assert isinstance(extractor, LineWindowContextExtractor)


def test_get_code_context_for_finding():
    from guardrail.context import get_code_context_for_finding

    finding = Finding(
        rule_id="test",
        message="test",
        file_path="sample_code/vulnerable.c",
        line=14,
        column=5,
        severity=Severity.HIGH,
        tool="test",
        language=Language.C,
    )
    snippet = get_code_context_for_finding(finding, before=2, after=2, repo_root=".")
    assert "strcpy" in snippet
