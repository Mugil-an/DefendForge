"""
Embeddings Module — Generates dense vector representations for text.

Uses sentence-transformers (default: all-MiniLM-L6-v2) for fast,
local embeddings of security knowledge, alerts, and code snippets.
"""

from __future__ import annotations

import warnings
from typing import Any, List, Union

import numpy as np

# Suppress noisy warnings from huggingface_hub / transformers
warnings.filterwarnings("ignore", category=FutureWarning)

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger

log = get_logger("rag.embeddings")

# Global singleton for the model to avoid reloading
_MODEL_INSTANCE: Any = None


class DeterministicEmbeddingFallback:
    """Offline fallback providing deterministic 384-dimensional normalized embeddings."""

    def get_embedding_dimension(self) -> int:
        return 384

    def get_sentence_embedding_dimension(self) -> int:
        return 384

    def encode(self, text: Union[str, List[str]], normalize_embeddings: bool = True) -> np.ndarray:
        if isinstance(text, str):
            single = True
            text_list = [text]
        else:
            single = False
            text_list = text

        results = []
        for t in text_list:
            import hashlib
            # Seed 384 floats deterministically from string content
            h = hashlib.sha384(t.encode("utf-8")).digest()
            # 48 bytes -> repeat 8 times to get 384 values
            raw = (h * 8)[:384]
            arr = np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128.0
            if normalize_embeddings:
                norm = np.linalg.norm(arr)
                if norm > 0:
                    arr = arr / norm
            results.append(arr)

        out = np.vstack(results)
        return out[0] if single else out


def get_embedding_model() -> Any:
    """Lazy load the sentence transformer model with offline fallback."""
    global _MODEL_INSTANCE
    if _MODEL_INSTANCE is None:
        try:
            from sentence_transformers import SentenceTransformer
            model_name = settings.rag.embedding_model
            log.info("loading_embedding_model", model=model_name)
            _MODEL_INSTANCE = SentenceTransformer(model_name)
        except Exception as exc:
            log.warning("embedding_model_download_failed_using_offline_fallback", error=str(exc))
            _MODEL_INSTANCE = DeterministicEmbeddingFallback()
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
    if hasattr(model, "get_embedding_dimension"):
        return model.get_embedding_dimension()
    return model.get_sentence_embedding_dimension()
