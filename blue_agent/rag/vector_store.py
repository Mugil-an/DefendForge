"""
Vector Store — Manages the FAISS index and associated document metadata.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import faiss
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


class FaissVectorStore:
    """
    Local vector database using FAISS (IndexFlatIP for cosine similarity,
    since we normalize our embeddings).
    Stores metadata in a companion JSON file.
    """

    def __init__(self, index_path: Optional[str] = None):
        self._index_path = Path(index_path or settings.rag.faiss_index_path)
        self._faiss_file = self._index_path / "index.faiss"
        self._meta_file = self._index_path / "metadata.json"
        
        self._index: faiss.Index | None = None
        # Maps integer FAISS id -> Document
        self._docs: Dict[int, Document] = {}
        self._next_id: int = 0

    def initialize(self, dimension: Optional[int] = None) -> None:
        """Create a new index or load an existing one."""
        if self._faiss_file.exists() and self._meta_file.exists():
            self._load()
        else:
            dim = dimension or get_embedding_dimension()
            # IndexFlatIP calculates inner product. 
            # With normalized vectors, inner product == cosine similarity.
            self._index = faiss.IndexFlatIP(dim)
            self._docs = {}
            self._next_id = 0
            self._index_path.mkdir(parents=True, exist_ok=True)
            log.info("vector_store_created", dimension=dim, path=str(self._index_path))

    def _load(self) -> None:
        self._index = faiss.read_index(str(self._faiss_file))
        with open(self._meta_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            self._next_id = data.get("next_id", 0)
            docs_raw = data.get("docs", {})
            self._docs = {
                int(k): Document(
                    id=v["id"],
                    text=v["text"],
                    metadata=v["metadata"],
                )
                for k, v in docs_raw.items()
            }
        log.info("vector_store_loaded", docs=len(self._docs), path=str(self._index_path))

    def save(self) -> None:
        """Persist the index and metadata to disk."""
        if self._index is None:
            return
        
        faiss.write_index(self._index, str(self._faiss_file))
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
            
        self._index.add(embeddings)
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
            
        # faiss expects float32
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
