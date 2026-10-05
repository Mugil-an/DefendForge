"""
Embeddings Module — Generates dense vector representations for text.

Uses sentence-transformers (default: all-MiniLM-L6-v2) for fast,
local embeddings of security knowledge, alerts, and code snippets.
"""

from __future__ import annotations

import warnings
from typing import List, Union

import numpy as np

# Suppress noisy warnings from huggingface_hub / transformers
warnings.filterwarnings("ignore", category=FutureWarning)

from sentence_transformers import SentenceTransformer

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger

log = get_logger("rag.embeddings")

# Global singleton for the model to avoid reloading
_MODEL_INSTANCE: SentenceTransformer | None = None


def get_embedding_model() -> SentenceTransformer:
    """Lazy load the sentence transformer model."""
    global _MODEL_INSTANCE
    if _MODEL_INSTANCE is None:
        model_name = settings.rag.embedding_model
        log.info("loading_embedding_model", model=model_name)
        _MODEL_INSTANCE = SentenceTransformer(model_name)
    return _MODEL_INSTANCE


def embed_text(text: Union[str, List[str]]) -> np.ndarray:
    """
    Generate embeddings for one or more text strings.

    Returns an array of shape (N, D) where D is the embedding dimension.
    """
    model = get_embedding_model()
    # Normalize embeddings to support cosine similarity via dot product
    embeddings = model.encode(text, normalize_embeddings=True)
    if isinstance(text, str):
        embeddings = embeddings.reshape(1, -1)
    return embeddings

def get_embedding_dimension() -> int:
    """Return the vector dimension of the current model."""
    model = get_embedding_model()
    return model.get_sentence_embedding_dimension()
