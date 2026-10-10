import joblib
import numpy as np
from pathlib import Path
from typing import List, Optional
from sklearn.ensemble import RandomForestClassifier

from blue_agent.detection.anomaly_detector import AnomalyDetectorBase
from blue_agent.schemas import AnomalyResult

class RandomForestDetector(AnomalyDetectorBase):
    def __init__(self, threshold: float = 0.5):
        self._model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42)
        self._threshold = threshold
        self._fitted = False

    def fit(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> None:
        if y is None:
            raise ValueError("RandomForest requires y labels")
        self._model.fit(X, y)
        self._fitted = True

    def predict_one(self, features: np.ndarray) -> AnomalyResult:
        if features.ndim == 1:
            features = features.reshape(1, -1)
        return self.predict_batch(features)[0]

    def predict_batch(self, X: np.ndarray) -> List[AnomalyResult]:
        if not self._fitted:
            raise RuntimeError("Model not fitted")
        
        # predict_proba returns array of shape (n_samples, n_classes)
        probs = self._model.predict_proba(X)
        # Class 1 is attack
        anomaly_scores = probs[:, 1] if probs.shape[1] > 1 else np.zeros(X.shape[0])
        
        results = []
        for score in anomaly_scores:
            is_anomaly = score >= self._threshold
            confidence = float(score) if is_anomaly else float(1.0 - score)
            results.append(AnomalyResult(
                is_anomaly=is_anomaly,
                anomaly_score=float(score),
                confidence=float(confidence)
            ))
        return results

    def save(self, path: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "threshold": self._threshold}, p)

    def load(self, path: str) -> None:
        artifact = joblib.load(path)
        if isinstance(artifact, dict) and "model" in artifact:
            self._model = artifact["model"]
            self._threshold = artifact.get("threshold", 0.5)
        else:
            # Maybe it's just the pipeline/model directly
            self._model = artifact
        self._fitted = True

    @property
    def is_fitted(self) -> bool:
        return self._fitted
