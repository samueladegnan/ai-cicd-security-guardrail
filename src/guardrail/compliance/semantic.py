"""Semantic compliance mapping with retrieval-augmented generation (RAG).

When a SAST rule does not match any hardcoded compliance rule, this mapper
embeds the rule text using a small sentence-transformers model and searches a
local vector store of OWASP, CWE, and CIS controls for the nearest neighbors.
The top matches become the compliance hits for that finding.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from guardrail.models import ComplianceHit, Finding


class SemanticComplianceMapper:
    """Embed SAST rule descriptions and retrieve nearest compliance controls."""

    def __init__(
        self,
        vector_store_path: str = ".guardrail-vectors.db",
        embedding_model: str = "all-MiniLM-L6-v2",
    ):
        self.vector_store_path = vector_store_path
        self.embedding_model = embedding_model
        self._encoder: Any | None = None
        self._init_store()

    def _init_store(self) -> None:
        Path(self.vector_store_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.vector_store_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS compliance_vectors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    framework TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    embedding BLOB NOT NULL
                )
                """
            )
            conn.commit()

    @property
    def encoder(self) -> Any:
        """Lazy-load the sentence-transformers encoder."""
        if self._encoder is None:
            try:
                from sentence_transformers import SentenceTransformer

                self._encoder = SentenceTransformer(self.embedding_model)
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError(
                    "sentence-transformers is required for semantic compliance mapping."
                ) from exc
        return self._encoder

    def seed(self, controls: list[dict[str, str]]) -> None:
        """Populate the vector store with compliance controls.

        Each control must have keys: framework, rule_id, title, description.
        """
        if not controls:
            return
        texts = [
            f"{c['framework']} {c['rule_id']}: {c['title']}. {c.get('description', '')}"
            for c in controls
        ]
        embeddings = self.encoder.encode(texts, show_progress_bar=False)
        with sqlite3.connect(self.vector_store_path) as conn:
            for control, embedding in zip(controls, embeddings, strict=True):
                conn.execute(
                    """
                    INSERT INTO compliance_vectors (framework, rule_id, title, description, embedding)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        control["framework"],
                        control["rule_id"],
                        control["title"],
                        control.get("description", ""),
                        json.dumps(embedding.tolist()),
                    ),
                )
            conn.commit()

    def map_finding(self, finding: Finding, top_k: int = 3) -> list[ComplianceHit]:
        """Return the top-k semantic compliance hits for a finding."""
        query = f"{finding.rule_id} {finding.message} {finding.cwe or ''}".strip()
        if not query:
            return []
        try:
            query_embedding = self.encoder.encode([query], show_progress_bar=False)[0]
        except Exception:  # noqa: BLE001
            return []

        rows = self._load_vectors()
        if not rows:
            return []

        scored: list[tuple[float, dict[str, Any]]] = []
        for row in rows:
            try:
                vec = json.loads(row["embedding"])
                similarity = self._cosine_similarity(query_embedding, vec)
                scored.append((similarity, row))
            except Exception:  # noqa: BLE001
                continue

        scored.sort(key=lambda x: x[0], reverse=True)
        hits: list[ComplianceHit] = []
        for similarity, row in scored[:top_k]:
            if similarity < 0.5:
                continue
            hits.append(
                ComplianceHit(
                    framework=row["framework"],
                    rule_id=row["rule_id"],
                    title=row["title"],
                    description=row["description"],
                )
            )
        return hits

    def _load_vectors(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.vector_store_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM compliance_vectors").fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
        import math

        dot = sum(x * y for x, y in zip(a, b, strict=True))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)


def seed_default_controls(mapper: SemanticComplianceMapper) -> None:
    """Seed a small set of default controls for demos and tests."""
    controls = [
        {
            "framework": "owasp",
            "rule_id": "A01:2021",
            "title": "Broken Access Control",
            "description": "Access control enforcement weaknesses.",
        },
        {
            "framework": "owasp",
            "rule_id": "A03:2021",
            "title": "Injection",
            "description": "Injection flaws such as SQL, NoSQL, OS command injection.",
        },
        {
            "framework": "owasp",
            "rule_id": "A02:2021",
            "title": "Cryptographic Failures",
            "description": "Failure to protect data with cryptography.",
        },
        {
            "framework": "cis_aws",
            "rule_id": "2.1.1",
            "title": "Ensure S3 bucket access is restricted",
            "description": "S3 buckets should not allow public access.",
        },
        {
            "framework": "cwe",
            "rule_id": "CWE-79",
            "title": "Cross-site Scripting (XSS)",
            "description": "Improper neutralization of input during web page generation.",
        },
        {
            "framework": "cwe",
            "rule_id": "CWE-89",
            "title": "SQL Injection",
            "description": "Improper neutralization of special elements in SQL.",
        },
    ]
    mapper.seed(controls)
