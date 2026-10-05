"""
Tests for blue_agent.rag — embeddings, vector store, and retriever.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from blue_agent.rag.embeddings import get_embedding_dimension
from blue_agent.rag.vector_store import Document


# =========================================================================
# Embeddings
# =========================================================================
class TestEmbeddings:
    def test_get_embedding_dimension(self):
        dim = get_embedding_dimension()
        assert dim > 0
        # all-MiniLM-L6-v2 produces 384-dimensional embeddings
        assert dim == 384

    def test_embed_text_single(self):
        from blue_agent.rag.embeddings import embed_text
        vec = embed_text("This is a test.")
        assert vec.shape == (1, 384)
        # Check if normalized (magnitude approx 1)
        magnitude = np.linalg.norm(vec)
        assert abs(magnitude - 1.0) < 1e-5

    def test_embed_text_batch(self):
        from blue_agent.rag.embeddings import embed_text
        texts = ["Test one.", "Test two.", "Test three."]
        vecs = embed_text(texts)
        assert vecs.shape == (3, 384)


# =========================================================================
# FaissVectorStore
# =========================================================================
class TestFaissVectorStore:
    def test_initialize_new(self, tmp_path):
        from blue_agent.rag.vector_store import FaissVectorStore
        store = FaissVectorStore(index_path=str(tmp_path))
        store.initialize(dimension=128)
        assert store._index is not None
        assert store._index.ntotal == 0
        assert len(store._docs) == 0

    def test_add_and_search(self, tmp_path):
        from blue_agent.rag.vector_store import FaissVectorStore
        store = FaissVectorStore(index_path=str(tmp_path))
        store.initialize(dimension=4)

        # Mock embeddings (normalized for cosine similarity)
        embeddings = np.array([
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.0, 0.0, 1.0, 0.0],
        ], dtype=np.float32)
        texts = ["doc1", "doc2", "doc3"]
        metas = [{"tag": "a"}, {"tag": "b"}, {"tag": "c"}]

        doc_ids = store.add(embeddings, texts, metas)
        assert len(doc_ids) == 3
        assert store._index.ntotal == 3

        # Search for something close to doc1
        q = np.array([0.9, 0.1, 0.0, 0.0], dtype=np.float32)
        q = q / np.linalg.norm(q)  # normalize
        results = store.search(q, top_k=2)
        
        assert len(results) == 2
        best_doc, best_score = results[0]
        assert best_doc.text == "doc1"
        assert best_doc.metadata["tag"] == "a"
        assert best_score > 0.8  # inner product should be high

    def test_save_and_load(self, tmp_path):
        from blue_agent.rag.vector_store import FaissVectorStore
        store1 = FaissVectorStore(index_path=str(tmp_path))
        store1.initialize(dimension=4)
        embeddings = np.array([[1.0, 0.0, 0.0, 0.0]], dtype=np.float32)
        store1.add(embeddings, ["hello"], [{"source": "test"}])
        store1.save()

        # Load into new instance
        store2 = FaissVectorStore(index_path=str(tmp_path))
        store2.initialize()  # Should auto-load
        
        assert store2._index.ntotal == 1
        assert len(store2._docs) == 1
        assert store2._docs[0].text == "hello"


# =========================================================================
# Retriever
# =========================================================================
class TestRetriever:
    def test_add_and_search_integration(self, tmp_path):
        from blue_agent.rag.retriever import Retriever
        from blue_agent.rag.vector_store import FaissVectorStore
        
        store = FaissVectorStore(index_path=str(tmp_path))
        retriever = Retriever(vector_store=store)
        
        texts = [
            "SQL Injection vulnerabilities happen when input is not sanitized.",
            "Cross-Site Scripting allows attackers to run scripts in the victim's browser.",
            "A firewall blocks unauthorized network access.",
        ]
        metas = [{"cat": "sqli"}, {"cat": "xss"}, {"cat": "network"}]
        
        retriever.add_texts(texts, metas)
        
        # Search using actual embeddings
        docs = retriever.search("How do I fix cross-site scripting?", top_k=1, threshold=0.0)
        assert len(docs) == 1
        assert "Cross-Site" in docs[0].text
        assert docs[0].metadata["cat"] == "xss"

    def test_get_context_string(self, tmp_path):
        from blue_agent.rag.retriever import Retriever
        from blue_agent.rag.vector_store import FaissVectorStore
        
        store = FaissVectorStore(index_path=str(tmp_path))
        retriever = Retriever(vector_store=store)
        
        retriever.add_texts(["Some secure coding info."], [{"source": "docs", "category": "sec"}])
        context = retriever.get_context_string("secure coding")
        
        assert "Document 1: docs [sec]" in context
        assert "Some secure coding info." in context

    def test_ingestion(self, tmp_path):
        from blue_agent.rag.retriever import Retriever
        from blue_agent.rag.vector_store import FaissVectorStore
        from blue_agent.rag.knowledge_ingestion import ingest_initial_knowledge, INITIAL_KNOWLEDGE
        
        store = FaissVectorStore(index_path=str(tmp_path))
        retriever = Retriever(vector_store=store)
        
        added = ingest_initial_knowledge(retriever)
        assert added == len(INITIAL_KNOWLEDGE)
        
        # Calling again should skip
        added2 = ingest_initial_knowledge(retriever)
        assert added2 == 0
