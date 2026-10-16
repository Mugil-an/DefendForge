"""
Vector Store — Manages the FAISS index and associated document metadata.

Supports two backends:
  - faiss   : Local FAISS index (default, fast, no extra services needed)
  - pgvector: PostgreSQL + pgvector extension (persistent, scalable, survives restarts)

Backend is selected by RAG_VECTOR_STORE env var.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger
from blue_agent.rag.embeddings import get_embedding_dimension

log = get_logger("rag.vector_store")


@dataclass
class Document:
    """A single document stored in the vector store."""
    id: str
    text: str
    metadata: Dict[str, Any]


# ─────────────────────────────────────────────────────────────────────────────
# FAISS backend (default)
# ─────────────────────────────────────────────────────────────────────────────

class FaissVectorStore:
    """
    Local vector database using FAISS (IndexFlatIP for cosine similarity,
    since we normalize our embeddings).
    Stores metadata in a companion JSON file.
    """

    def __init__(self, index_path: Optional[str] = None):
        import faiss as _faiss  # noqa: F401  (imported for side-effects / type narrowing)
        self._faiss = _faiss
        self._index_path = Path(index_path or settings.rag.faiss_index_path)
        self._faiss_file = self._index_path / "index.faiss"
        self._meta_file = self._index_path / "metadata.json"

        self._index = None
        self._docs: Dict[int, Document] = {}
        self._next_id: int = 0

    def initialize(self, dimension: Optional[int] = None) -> None:
        """Create a new index or load an existing one."""
        if self._faiss_file.exists() and self._meta_file.exists():
            self._load()
        else:
            dim = dimension or get_embedding_dimension()
            self._index = self._faiss.IndexFlatIP(dim)
            self._docs = {}
            self._next_id = 0
            self._index_path.mkdir(parents=True, exist_ok=True)
            log.info("vector_store_created", dimension=dim, path=str(self._index_path))

    def _load(self) -> None:
        self._index = self._faiss.read_index(str(self._faiss_file))
        with open(self._meta_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            self._next_id = data.get("next_id", 0)
            docs_raw = data.get("docs", {})
            self._docs = {
                int(k): Document(id=v["id"], text=v["text"], metadata=v["metadata"])
                for k, v in docs_raw.items()
            }
        log.info("vector_store_loaded", docs=len(self._docs), path=str(self._index_path))

    def save(self) -> None:
        """Persist the index and metadata to disk."""
        if self._index is None:
            return
        self._faiss.write_index(self._index, str(self._faiss_file))
        data = {
            "next_id": self._next_id,
            "docs": {
                k: {"id": v.id, "text": v.text, "metadata": v.metadata}
                for k, v in self._docs.items()
            }
        }
        with open(self._meta_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        log.debug("vector_store_saved", docs=len(self._docs))

    def add(self, embeddings: np.ndarray, texts: List[str], metadatas: List[Dict[str, Any]]) -> List[str]:
        """Add documents and their vectors to the store."""
        if self._index is None:
            self.initialize(embeddings.shape[1])
        assert len(embeddings) == len(texts) == len(metadatas)
        doc_ids = []
        for i in range(len(texts)):
            doc_id = str(uuid.uuid4())
            self._docs[self._next_id] = Document(id=doc_id, text=texts[i], metadata=metadatas[i])
            self._next_id += 1
            doc_ids.append(doc_id)
        self._index.add(embeddings.astype(np.float32))
        self.save()
        log.info("vector_store_added", count=len(texts))
        return doc_ids

    def search(self, query_embedding: np.ndarray, top_k: int = 5, threshold: float = 0.0) -> List[Tuple[Document, float]]:
        """
        Search for the top_k most similar documents.
        Returns a list of (Document, similarity_score).
        """
        if self._index is None or self._index.ntotal == 0:
            return []
        q = query_embedding.astype(np.float32)
        if q.ndim == 1:
            q = q.reshape(1, -1)
        scores, indices = self._index.search(q, top_k)
        results = []
        for i in range(len(indices[0])):
            idx = int(indices[0][i])
            score = float(scores[0][i])
            if idx != -1 and score >= threshold and idx in self._docs:
                results.append((self._docs[idx], score))
        return results


# ─────────────────────────────────────────────────────────────────────────────
# pgvector backend
# ─────────────────────────────────────────────────────────────────────────────

class PgVectorStore:
    """
    PostgreSQL + pgvector backend.

    Schema (created automatically):
      CREATE TABLE defend_forge_vectors (
          id          TEXT PRIMARY KEY,
          text        TEXT NOT NULL,
          metadata    JSONB,
          embedding   vector(384)
      );

    Requires the pgvector extension to be installed in Postgres.
    Falls back to FaissVectorStore transparently if unavailable.
    """

    _TABLE = "defend_forge_vectors"

    def __init__(self, dimension: Optional[int] = None):
        self._dim = dimension or get_embedding_dimension()
        self._conn = None
        self._available = False
        self._initialize_db()

    def _initialize_db(self) -> None:
        try:
            import psycopg2  # type: ignore[import]
            import psycopg2.extras  # type: ignore[import]

            db = settings.db
            self._conn = psycopg2.connect(
                host=db.host, port=db.port, user=db.user,
                password=db.password, dbname=db.database,
                connect_timeout=5,
            )
            self._conn.autocommit = True
            cur = self._conn.cursor()

            # Enable pgvector extension
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {self._TABLE} (
                    id       TEXT PRIMARY KEY,
                    text     TEXT NOT NULL,
                    metadata JSONB DEFAULT '{{}}',
                    embedding vector({self._dim})
                );
            """)
            cur.execute(f"""
                CREATE INDEX IF NOT EXISTS {self._TABLE}_vec_idx
                ON {self._TABLE}
                USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 50);
            """)
            self._available = True
            log.info("pgvector_store_initialized", dim=self._dim)
        except Exception as exc:
            log.warning("pgvector_unavailable", error=str(exc), fallback="faiss")
            self._conn = None

    @property
    def available(self) -> bool:
        return self._available

    def add(self, embeddings: np.ndarray, texts: List[str], metadatas: List[Dict[str, Any]]) -> List[str]:
        """Insert documents into pgvector."""
        if not self._available or self._conn is None:
            raise RuntimeError("pgvector not available")
        import psycopg2.extras as extras
        cur = self._conn.cursor()
        doc_ids = []
        for i, (text, meta) in enumerate(zip(texts, metadatas)):
            doc_id = str(uuid.uuid4())
            vec = embeddings[i].tolist()
            cur.execute(
                f"INSERT INTO {self._TABLE} (id, text, metadata, embedding) VALUES (%s, %s, %s, %s::vector)",
                (doc_id, text, json.dumps(meta), vec),
            )
            doc_ids.append(doc_id)
        log.info("pgvector_added", count=len(doc_ids))
        return doc_ids

    def search(self, query_embedding: np.ndarray, top_k: int = 5, threshold: float = 0.0) -> List[Tuple[Document, float]]:
        """Cosine similarity search using pgvector <=> operator."""
        if not self._available or self._conn is None:
            return []
        q = query_embedding.flatten().tolist()
        cur = self._conn.cursor()
        cur.execute(
            f"""
            SELECT id, text, metadata,
                   1 - (embedding <=> %s::vector) AS similarity
            FROM {self._TABLE}
            ORDER BY embedding <=> %s::vector
            LIMIT %s
            """,
            (q, q, top_k),
        )
        rows = cur.fetchall()
        results = []
        for row in rows:
            doc_id, text, meta_raw, score = row
            if score < threshold:
                continue
            if isinstance(meta_raw, str):
                meta = json.loads(meta_raw)
            else:
                meta = meta_raw or {}
            results.append((Document(id=doc_id, text=text, metadata=meta), float(score)))
        return results

    # Compatibility with FaissVectorStore interface expected by Retriever
    @property
    def _index(self):
        """Fake index property — used for ntotal checks."""
        return _PgIndexProxy(self)

    def initialize(self, dimension: Optional[int] = None) -> None:
        """No-op: pgvector initialises during __init__."""
        pass

    def save(self) -> None:
        """No-op: pgvector auto-commits."""
        pass


class _PgIndexProxy:
    """Minimal duck-type proxy to satisfy `store._index.ntotal` checks."""
    def __init__(self, store: PgVectorStore):
        self._store = store

    @property
    def ntotal(self) -> int:
        if not self._store.available or self._store._conn is None:
            return 0
        try:
            cur = self._store._conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM {PgVectorStore._TABLE}")
            return int(cur.fetchone()[0])
        except Exception:
            return 0


# ─────────────────────────────────────────────────────────────────────────────
# Factory — returns the right backend based on RAG_VECTOR_STORE setting
# ─────────────────────────────────────────────────────────────────────────────

def get_vector_store() -> FaissVectorStore | PgVectorStore:
    """
    Return the configured vector store backend.

    RAG_VECTOR_STORE=faiss     → FaissVectorStore (default)
    RAG_VECTOR_STORE=pgvector  → PgVectorStore (with FAISS fallback)
    """
    backend = settings.rag.vector_store.lower()
    if backend == "pgvector":
        store = PgVectorStore()
        if store.available:
            return store
        log.warning("pgvector_init_failed_falling_back_to_faiss")
    # Default or fallback
    return FaissVectorStore()
