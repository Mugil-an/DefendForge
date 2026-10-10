"""
CICIDS Flow Detector — wraps the pre-trained Isolation Forest model
that was trained on CICIDS2017 network-flow features (78 features).

This provides **network-layer** anomaly detection as a complement
to the HTTP-level application detector.  It loads the existing
trained artifact from ``blue_agent/anomaly_detector/models/isolation_forest.joblib``
and exposes it through the standard ``AnomalyDetectorBase`` interface.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

from blue_agent.config import PROJECT_ROOT, settings
from blue_agent.detection.anomaly_detector import AnomalyDetectorBase
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import AnomalyResult

log = get_logger("detection.cicids_flow")

# Default path to the existing trained model
_DEFAULT_MODEL_PATH = Path(settings.detection.model_path) if "random_forest" in settings.detection.model_path else PROJECT_ROOT / "blue_agent" / "anomaly_detector" / "models" / "cicids_random_forest.joblib"


class CICIDSFlowDetector(AnomalyDetectorBase):
    """
    Anomaly detector backed by the pre-trained CICIDS2017 Isolation
    Forest model.

    This detector expects **network-flow features** (78 columns
    from CICIDS2017: Destination Port, Flow Duration, packet lengths,
    IAT statistics, TCP flags, etc.).

    It is NOT interchangeable with the HTTP-level
    ``IsolationForestDetector`` — each operates on a different
    feature space.

    Typical usage::

        detector = CICIDSFlowDetector()
        detector.load()                    # loads existing artifact
        result = detector.predict_one(flow_features)
    """

    def __init__(self, model_path: Optional[str] = None):
        self._model_path = Path(model_path) if model_path else _DEFAULT_MODEL_PATH
        self._pipeline = None           # sklearn Pipeline (imputer + IF)
        self._feature_names: List[str] = []
        self._threshold: float = 0.5
        self._fitted = False

    # ---- ABC implementation ----

    def fit(self, X: np.ndarray) -> None:
        """
        Re-train the CICIDS flow model on new benign data.

        *X* must have columns matching the 78 CICIDS2017 features.
        For most cases you should use ``load()`` with the
        pre-trained artifact instead.
        """
        from sklearn.ensemble import IsolationForest
        from sklearn.impute import SimpleImputer
        from sklearn.pipeline import Pipeline

        log.info("cicids_flow_fitting", samples=X.shape[0], features=X.shape[1])
        pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("isolation_forest", IsolationForest(
                n_estimators=300,
                max_samples=512,
                max_features=0.8,
                random_state=42,
                n_jobs=-1,
            )),
        ])
        pipeline.fit(X)
        self._pipeline = pipeline
        self._fitted = True

        # Derive threshold at 95th percentile of normal scores
        scores = -pipeline.score_samples(X)
        self._threshold = float(np.quantile(scores, 0.95))
        log.info("cicids_flow_fitted", threshold=round(self._threshold, 6))

    def predict_one(self, features: np.ndarray) -> AnomalyResult:
        if features.ndim == 1:
            features = features.reshape(1, -1)
        return self.predict_batch(features)[0]

    def predict_batch(self, X: np.ndarray) -> List[AnomalyResult]:
        """
        Score flow-level feature vectors.

        Parameters
        ----------
        X : ndarray of shape (n_samples, 78)
            Must match the CICIDS2017 feature schema.  If you have
            a DataFrame, use ``.values`` and ensure columns are
            aligned to ``self.feature_names``.
        """
        if not self._fitted:
            raise RuntimeError(
                "Model not fitted — call load() to load the pre-trained "
                "CICIDS artifact, or fit() to train from scratch."
            )

        # Handle DataFrames (align columns if needed)
        if isinstance(X, pd.DataFrame):
            if self._feature_names:
                X = X.reindex(columns=self._feature_names)
            X = X.values

        # Check if model provides score_samples (like IsolationForest) or predict_proba (like RandomForest)
        if hasattr(self._pipeline, "score_samples"):
            raw_scores = -self._pipeline.score_samples(X)  # higher = more anomalous
            
            for score in raw_scores:
                is_anomaly = score >= self._threshold
                # Normalise to [0, 1]: score / (2 * threshold) gives 0.5 at boundary
                norm_score = min(1.0, float(score) / (2.0 * self._threshold))
                # Confidence from distance to threshold
                if is_anomaly:
                    confidence = min(1.0, 0.5 + (score - self._threshold) / (self._threshold + 1e-8) * 0.5)
                else:
                    confidence = min(1.0, 0.5 + (self._threshold - score) / (self._threshold + 1e-8) * 0.5)

                results.append(AnomalyResult(
                    is_anomaly=is_anomaly,
                    anomaly_score=round(norm_score, 4),
                    confidence=round(float(confidence), 4),
                ))
        elif hasattr(self._pipeline, "predict_proba"):
            probs = self._pipeline.predict_proba(X)
            # Assuming index 1 is the anomaly/attack class
            if probs.shape[1] > 1:
                attack_probs = probs[:, 1]
            else:
                attack_probs = probs[:, 0]
                
            for prob in attack_probs:
                is_anomaly = prob >= self._threshold
                # Probability is already 0 to 1
                norm_score = float(prob)
                confidence = float(abs(prob - 0.5) * 2) # 0.5 prob is 0 conf, 1.0 prob is 1.0 conf
                
                results.append(AnomalyResult(
                    is_anomaly=is_anomaly,
                    anomaly_score=round(norm_score, 4),
                    confidence=round(confidence, 4),
                ))
        else:
            raise NotImplementedError("Model in artifact must implement score_samples or predict_proba")
        return results

    def save(self, path: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        artifact = {
            "model": self._pipeline,
            "features": self._feature_names,
            "anomaly_threshold": self._threshold,
        }
        joblib.dump(artifact, p)
        log.info("cicids_flow_saved", path=str(p))

    def load(self, path: Optional[str] = None) -> None:
        """
        Load the pre-trained CICIDS2017 Isolation Forest artifact.

        Parameters
        ----------
        path : str, optional
            Path to the ``.joblib`` artifact.  Defaults to
            ``blue_agent/anomaly_detector/models/isolation_forest.joblib``.
        """
        load_path = Path(path) if path else self._model_path
        if not load_path.exists():
            raise FileNotFoundError(
                f"CICIDS model not found at {load_path}. "
                f"Train it first with blue_agent/anomaly_detector/01_train_anomaly_detector.py"
            )

        artifact = joblib.load(load_path)
        self._pipeline = artifact["model"]
        self._feature_names = artifact.get("features", [])
        self._threshold = artifact.get("anomaly_threshold", 0.5)
        self._fitted = True
        log.info(
            "cicids_flow_loaded",
            path=str(load_path),
            features=len(self._feature_names),
            threshold=round(self._threshold, 6),
        )

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    @property
    def feature_names(self) -> List[str]:
        """The 78 CICIDS2017 feature names the model expects."""
        return list(self._feature_names)

    @property
    def threshold(self) -> float:
        return self._threshold
