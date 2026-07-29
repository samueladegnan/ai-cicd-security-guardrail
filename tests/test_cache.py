"""Tests for the triage result cache backends."""

from __future__ import annotations

from guardrail.cache import MemoryCache, SQLiteCache, make_cache, stable_key
from guardrail.models import ComplianceHit, Finding, Language, Severity, TriageResult, TriageVerdict


def _sample_finding() -> Finding:
    return Finding(
        rule_id="CWE-121",
        message="Possible buffer overflow",
        file_path="src/main.c",
        line=10,
        column=5,
        severity=Severity.HIGH,
        cwe="CWE-121",
        tool="sarif",
        language=Language.C,
    )


def _sample_result() -> TriageResult:
    return TriageResult(
        finding=_sample_finding(),
        verdict=TriageVerdict.HIGH_PRIORITY,
        confidence=0.85,
        reasoning="Test reasoning",
        compliance_hits=[
            ComplianceHit(framework="cert_c", rule_id="STR31-C", title="", description="")
        ],
        remediation="Fix it",
    )


def test_memory_cache_roundtrip():
    cache = MemoryCache()
    result = _sample_result()
    key = "test-key"
    assert cache.get(key) is None
    cache.set(key, result)
    cached = cache.get(key)
    assert cached is not None
    assert cached.verdict == TriageVerdict.HIGH_PRIORITY
    assert cached.confidence == 0.85


def test_memory_cache_clear():
    cache = MemoryCache()
    cache.set("key", _sample_result())
    cache.clear()
    assert cache.get("key") is None


def test_sqlite_cache_roundtrip(tmp_path):
    path = tmp_path / "cache.db"
    cache = SQLiteCache(str(path))
    result = _sample_result()
    key = "test-key"
    cache.set(key, result)
    cached = cache.get(key)
    assert cached is not None
    assert cached.verdict == TriageVerdict.HIGH_PRIORITY
    assert cached.finding.rule_id == "CWE-121"


def test_sqlite_cache_clear(tmp_path):
    path = tmp_path / "cache.db"
    cache = SQLiteCache(str(path))
    cache.set("key", _sample_result())
    cache.clear()
    assert cache.get("key") is None


def test_make_cache_factory():
    memory = make_cache("memory")
    assert isinstance(memory, MemoryCache)
    sqlite = make_cache("sqlite", ":memory:")
    assert isinstance(sqlite, SQLiteCache)


def test_stable_key_is_stable_and_unique():
    finding = _sample_finding()
    hits = [ComplianceHit(framework="cert_c", rule_id="STR31-C", title="", description="")]
    key1 = stable_key(finding, hits)
    key2 = stable_key(finding, hits)
    assert key1 == key2
    assert isinstance(key1, str)
    assert len(key1) == 64  # SHA-256 hex

    different_finding = finding.model_copy(update={"line": finding.line + 1})
    key3 = stable_key(different_finding, hits)
    assert key3 != key1
