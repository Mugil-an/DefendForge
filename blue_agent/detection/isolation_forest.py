"""
Isolation Forest anomaly detection backend.

Wraps sklearn's IsolationForest in the ``AnomalyDetectorBase``
interface.  Produces calibrated anomaly scores in [0, 1] and
derives a binary is_anomaly flag from a configurable threshold.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from blue_agent.config import settings
from blue_agent.detection.anomaly_detector import AnomalyDetectorBase
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import AnomalyResult

log = get_logger("detection.isolation_forest")


class IsolationForestDetector(AnomalyDetectorBase):
    """
    Anomaly detector backed by sklearn ``IsolationForest``.

    Anomaly scores are transformed from the raw IF score_samples
    (which range roughly –0.5 … 0.5 where lower = more anomalous)
    into a [0, 1] range where **higher = more anomalous**.

    The ``confidence`` returned is based on how far the score
    sits from the decision boundary.
    """

    def __init__(
        self,
        n_estimators: int = 300,
        max_samples: int | str = 512,
        contamination: float | str = "auto",
        threshold: Optional[float] = None,
        random_state: int = 42,
    ):
        self._model = IsolationForest(
            n_estimators=n_estimators,
            max_samples=max_samples,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self._scaler = StandardScaler()
        self._threshold = threshold or settings.detection.anomaly_threshold
        self._fitted = False

    # ----- ABC implementation -----

    def fit(self, X: np.ndarray) -> None:
        """
        Fit on *normal* (benign) traffic only.

        Parameters
        ----------
        X : ndarray of shape (n_samples, n_features)
        """
        log.info("isolation_forest_fitting", samples=X.shape[0], features=X.shape[1])
        X_scaled = self._scaler.fit_transform(X)
        self._model.fit(X_scaled)
        self._fitted = True
        log.info("isolation_forest_fitted")

    def predict_one(self, features: np.ndarray) -> AnomalyResult:
        """Score a single feature vector."""
        if features.ndim == 1:
            features = features.reshape(1, -1)
        return self.predict_batch(features)[0]

    def predict_batch(self, X: np.ndarray) -> List[AnomalyResult]:
        """Score a batch and return ``AnomalyResult`` per row."""
        if not self._fitted:
            raise RuntimeError("Model not fitted — call fit() or load() first")

        X_eval = (
            self._scaler.transform(X)
            if getattr(self, "_scaler", None) is not None
            else X
        )
        if hasattr(self._model, "predict_proba"):
            probs = self._model.predict_proba(X_eval)
            # Probability of class 1 (Attack)
            anomaly_scores = probs[:, 1] if probs.shape[1] > 1 else probs[:, 0]
        else:
            raw_scores = self._model.score_samples(X_eval)  # higher = more normal
            # Transform to [0, 1] where 1 = very anomalous
            anomaly_scores = self._raw_to_score(raw_scores)

        results: List[AnomalyResult] = []
        for score in anomaly_scores:
            is_anomaly = score >= self._threshold
            # Confidence = how far from the threshold (clamped 0-1)
            if is_anomaly:
                confidence = min(
                    1.0, 0.5 + (score - self._threshold) / (1.0 - self._threshold) * 0.5
                )
            else:
                confidence = min(
                    1.0, 0.5 + (self._threshold - score) / self._threshold * 0.5
                )
            results.append(
                AnomalyResult(
                    is_anomaly=is_anomaly,
                    anomaly_score=round(float(score), 4),
                    confidence=round(float(confidence), 4),
                )
            )
        return results

    def save(self, path: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        artifact = {
            "model": self._model,
            "scaler": getattr(self, "_scaler", None),
            "threshold": self._threshold,
        }
        joblib.dump(artifact, p)
        log.info("isolation_forest_saved", path=str(p))

    def load(self, path: str) -> None:
        artifact = joblib.load(path)
        self._model = artifact["model"]
        self._scaler = artifact.get("scaler")
        self._threshold = artifact.get(
            "threshold", artifact.get("anomaly_threshold", self._threshold)
        )
        self._fitted = True
        log.info("isolation_forest_loaded", path=path)

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    # ----- Internal helpers -----

    @staticmethod
    def _raw_to_score(raw: np.ndarray) -> np.ndarray:
        """
        Map sklearn score_samples → [0, 1].

        sklearn score_samples returns values centred around ~-0.5
        for the offset.  We negate and clip to get a 0-1 anomaly score.
        """
        # Negate so that "more anomalous" = higher value
        inverted = -raw
        # Shift and scale to roughly [0, 1]
        # Typical range of inverted is [0.3, 0.7]
        # We do a simple min-max with guard rails
        lo, hi = inverted.min(), inverted.max()
        if hi - lo < 1e-8:
            return np.full_like(inverted, 0.5)
        scores = (inverted - lo) / (hi - lo)
        return np.clip(scores, 0.0, 1.0)
