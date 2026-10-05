"""
RAG sub-package — embeddings, FAISS vector store, and retrieval interface.
"""

from blue_agent.rag.embeddings import embed_text, get_embedding_dimension, get_embedding_model
from blue_agent.rag.knowledge_ingestion import ingest_initial_knowledge
from blue_agent.rag.retriever import Retriever
from blue_agent.rag.vector_store import Document, FaissVectorStore

__all__ = [
    "Document",
    "FaissVectorStore",
    "Retriever",
    "embed_text",
    "get_embedding_dimension",
    "get_embedding_model",
    "ingest_initial_knowledge",
]
