"""Caching layer for guardrail triage results.

Supports an in-memory dict backend and a persistent SQLite backend.
The cache key is a stable hash of the finding and its context, so
re-running the guardrail on the same report is essentially free.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from abc import ABC, abstractmethod

from guardrail.models import TriageResult


class TriageCache(ABC):
    """Abstract base class for triage result caches."""

    @abstractmethod
    def get(self, key: str) -> TriageResult | None:
        """Return a cached TriageResult or None."""

    @abstractmethod
    def set(self, key: str, result: TriageResult) -> None:
        """Cache a TriageResult."""

    @abstractmethod
    def clear(self) -> None:
        """Clear all cached entries."""


class MemoryCache(TriageCache):
    """In-memory cache, useful for single-shot CLI runs."""

    def __init__(self) -> None:
        self._store: dict[str, TriageResult] = {}

    def get(self, key: str) -> TriageResult | None:
        return self._store.get(key)

    def set(self, key: str, result: TriageResult) -> None:
        self._store[key] = result

    def clear(self) -> None:
        self._store.clear()


class SQLiteCache(TriageCache):
    """Persistent SQLite cache for cross-run result reuse.

    The schema stores a stable SHA-256 key and a JSON blob containing the
    serialized TriageResult. A TTL (in seconds) can be supplied; expired
    entries are treated as cache misses.
    """

    def __init__(self, path: str = ".guardrail-cache.db", ttl_seconds: int | None = None):
        self.path = path
        self.ttl_seconds = ttl_seconds
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS triage_cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at INTEGER DEFAULT (strftime('%s', 'now'))
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def get(self, key: str) -> TriageResult | None:
        conn = sqlite3.connect(self.path)
        try:
            if self.ttl_seconds is not None:
                cutoff = f"strftime('%s', 'now') - {self.ttl_seconds}"
                conn.execute("DELETE FROM triage_cache WHERE created_at < ?", (cutoff,))
            row = conn.execute("SELECT value FROM triage_cache WHERE key = ?", (key,)).fetchone()
        finally:
            conn.close()
        if not row:
            return None
        try:
            return TriageResult.model_validate_json(row[0])
        except Exception:
            return None

    def set(self, key: str, result: TriageResult) -> None:
        value = result.model_dump_json()
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO triage_cache (key, value) VALUES (?, ?)",
                (key, value),
            )
            conn.commit()
        finally:
            conn.close()

    def clear(self) -> None:
        conn = sqlite3.connect(self.path)
        try:
            conn.execute("DELETE FROM triage_cache")
            conn.commit()
        finally:
            conn.close()


def make_cache(backend: str = "memory", sqlite_path: str = ".guardrail-cache.db") -> TriageCache:
    """Factory returning the requested cache backend."""
    if backend == "sqlite":
        return SQLiteCache(sqlite_path)
    return MemoryCache()


def stable_key(finding, hits: list) -> str:
    """Stable hash of a finding and its compliance hits for cache lookups."""
    payload = {
        "tool": finding.tool,
        "rule_id": finding.rule_id,
        "file_path": finding.file_path,
        "line": finding.line,
        "column": finding.column,
        "language": finding.language.value if finding.language else None,
        "code_snippet": finding.code_snippet,
        "cwe": finding.cwe,
    }
    hit_blob = json.dumps([h.model_dump() for h in hits], sort_keys=True)
    raw = json.dumps(payload, sort_keys=True) + hit_blob
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
