"""
Anomaly Detector — abstract interface that all detection backends
must implement.

Concrete implementations:
  - ``IsolationForestDetector``   (isolation_forest.py)
  - ``AutoencoderDetector``       (autoencoder.py)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import numpy as np

from blue_agent.schemas import AnomalyResult


class AnomalyDetectorBase(ABC):
    """
    Contract for anomaly-detection backends.

    Subclasses must implement ``fit``, ``predict_one``, and
    ``predict_batch``.
    """

    @abstractmethod
    def fit(self, X: np.ndarray) -> None:
        """Train / fit the model on *normal* traffic features."""

    @abstractmethod
    def predict_one(self, features: np.ndarray) -> AnomalyResult:
        """
        Score a single feature vector.

        Returns an ``AnomalyResult`` with ``is_anomaly``,
        ``anomaly_score``, and ``confidence``.
        """

    @abstractmethod
    def predict_batch(self, X: np.ndarray) -> List[AnomalyResult]:
        """Score a batch of feature vectors."""

    @abstractmethod
    def save(self, path: str) -> None:
        """Persist model to disk."""

    @abstractmethod
    def load(self, path: str) -> None:
        """Load model from disk."""

    @property
    @abstractmethod
    def is_fitted(self) -> bool:
        """Whether the model has been trained."""
