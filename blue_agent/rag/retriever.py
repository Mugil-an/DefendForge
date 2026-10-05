"""
Retriever Module — High-level interface for querying the RAG knowledge base.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from blue_agent.logging_cfg import get_logger
from blue_agent.rag.embeddings import embed_text
from blue_agent.rag.vector_store import Document, FaissVectorStore

log = get_logger("rag.retriever")


class Retriever:
    """
    Combines text embedding and FAISS search into a simple retrieve API.
    """

    def __init__(self, vector_store: Optional[FaissVectorStore] = None):
        self.store = vector_store or FaissVectorStore()
        # Ensure it is initialized / loaded
        if self.store._index is None:
            self.store.initialize()

    def add_texts(self, texts: List[str], metadatas: Optional[List[Dict[str, Any]]] = None) -> List[str]:
        """
        Embed and store new texts in the knowledge base.
        """
        if not texts:
            return []
            
        if metadatas is None:
            metadatas = [{} for _ in texts]
            
        embeddings = embed_text(texts)
        return self.store.add(embeddings, texts, metadatas)

    def search(self, query: str, top_k: int = 5, threshold: float = 0.5) -> List[Document]:
        """
        Search for relevant documents given a text query.
        Returns the raw Documents.
        """
        query_embedding = embed_text(query)
        results = self.store.search(query_embedding, top_k=top_k, threshold=threshold)
        
        docs = []
        for doc, score in results:
            log.debug("rag_retrieved_doc", doc_id=doc.id, score=round(score, 3))
            docs.append(doc)
            
        return docs

    def get_context_string(self, query: str, top_k: int = 3, threshold: float = 0.5) -> str:
        """
        Search and format the retrieved documents as a single context string
        for insertion into an LLM prompt.
        """
        docs = self.search(query, top_k=top_k, threshold=threshold)
        if not docs:
            return "No relevant context found in knowledge base."
            
        context_parts = []
        for i, doc in enumerate(docs, 1):
            source = doc.metadata.get("source", "Unknown")
            cat = doc.metadata.get("category", "")
            cat_str = f" [{cat}]" if cat else ""
            context_parts.append(f"--- Document {i}: {source}{cat_str} ---\n{doc.text}\n")
            
        return "\n".join(context_parts)
