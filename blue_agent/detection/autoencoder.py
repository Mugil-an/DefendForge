"""
Autoencoder-based anomaly detection backend.

Uses a symmetric encoder–decoder architecture trained to
reconstruct *normal* traffic feature vectors.  Anomalies are
detected when reconstruction error exceeds a learned threshold.

This module is designed as a drop-in replacement for the
Isolation Forest backend.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from blue_agent.config import settings
from blue_agent.detection.anomaly_detector import AnomalyDetectorBase
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import AnomalyResult

log = get_logger("detection.autoencoder")


# ---------------------------------------------------------------------------
# Network architecture
# ---------------------------------------------------------------------------
class _AENetwork(nn.Module):
    """
    Symmetric autoencoder with configurable latent dimension.

    Architecture: input → 64 → 32 → latent → 32 → 64 → input
    """

    def __init__(self, input_dim: int, latent_dim: int = 8):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.BatchNorm1d(32),
            nn.Linear(32, latent_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.ReLU(),
            nn.BatchNorm1d(32),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Linear(64, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.encoder(x)
        return self.decoder(z)


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------
class AutoencoderDetector(AnomalyDetectorBase):
    """
    Anomaly detector using reconstruction error of an autoencoder.

    The model is trained on normal traffic.  At inference, the
    per-sample MSE reconstruction error is computed and normalised
    to an anomaly score in [0, 1].  A learned threshold (e.g. 95th
    percentile of training error) separates normal from anomalous.
    """

    def __init__(
        self,
        input_dim: int = 24,
        latent_dim: int = 8,
        lr: float = 1e-3,
        epochs: int = 50,
        batch_size: int = 256,
        threshold_percentile: float = 95.0,
        threshold: Optional[float] = None,
        device: Optional[str] = None,
    ):
        self._input_dim = input_dim
        self._latent_dim = latent_dim
        self._lr = lr
        self._epochs = epochs
        self._batch_size = batch_size
        self._threshold_percentile = threshold_percentile

        self._device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self._net = _AENetwork(input_dim, latent_dim).to(self._device)
        self._threshold = threshold or 0.5
        self._mean: Optional[np.ndarray] = None
        self._std: Optional[np.ndarray] = None
        self._fitted = False

    # ---- ABC ----

    def fit(self, X: np.ndarray) -> None:
        """
        Train the autoencoder on normal traffic.

        Also derives the anomaly threshold from reconstruction
        error on the training set.
        """
        log.info("autoencoder_fitting", samples=X.shape[0], features=X.shape[1])

        # Normalise
        self._mean = X.mean(axis=0)
        self._std = X.std(axis=0) + 1e-8
        X_norm = (X - self._mean) / self._std

        tensor_x = torch.tensor(X_norm, dtype=torch.float32)
        loader = DataLoader(
            TensorDataset(tensor_x),
            batch_size=self._batch_size,
            shuffle=True,
        )

        optimiser = torch.optim.Adam(self._net.parameters(), lr=self._lr)
        criterion = nn.MSELoss(reduction="none")

        self._net.train()
        for epoch in range(self._epochs):
            epoch_loss = 0.0
            for (batch,) in loader:
                batch = batch.to(self._device)
                recon = self._net(batch)
                loss = criterion(recon, batch).mean()
                optimiser.zero_grad()
                loss.backward()
                optimiser.step()
                epoch_loss += loss.item() * batch.size(0)
            if (epoch + 1) % 10 == 0:
                log.debug(
                    "autoencoder_epoch",
                    epoch=epoch + 1,
                    loss=round(epoch_loss / len(tensor_x), 6),
                )

        # Derive threshold from training set reconstruction errors
        self._net.eval()
        with torch.no_grad():
            recon = self._net(tensor_x.to(self._device))
            errors = ((recon.cpu() - tensor_x) ** 2).mean(dim=1).numpy()
        self._threshold = float(np.percentile(errors, self._threshold_percentile))
        self._fitted = True
        log.info(
            "autoencoder_fitted",
            threshold=round(self._threshold, 6),
            percentile=self._threshold_percentile,
        )

    def predict_one(self, features: np.ndarray) -> AnomalyResult:
        if features.ndim == 1:
            features = features.reshape(1, -1)
        return self.predict_batch(features)[0]

    def predict_batch(self, X: np.ndarray) -> List[AnomalyResult]:
        if not self._fitted:
            raise RuntimeError("Model not fitted — call fit() or load() first")

        X_norm = (X - self._mean) / self._std
        tensor_x = torch.tensor(X_norm, dtype=torch.float32).to(self._device)

        self._net.eval()
        with torch.no_grad():
            recon = self._net(tensor_x)
            errors = ((recon.cpu() - tensor_x.cpu()) ** 2).mean(dim=1).numpy()

        results: List[AnomalyResult] = []
        for err in errors:
            # Normalise error to [0, 1] using threshold as midpoint
            score = min(1.0, float(err) / (2.0 * self._threshold + 1e-8))
            is_anomaly = err >= self._threshold
            if is_anomaly:
                confidence = min(1.0, 0.5 + (err - self._threshold) / (self._threshold + 1e-8) * 0.5)
            else:
                confidence = min(1.0, 0.5 + (self._threshold - err) / (self._threshold + 1e-8) * 0.5)
            results.append(AnomalyResult(
                is_anomaly=is_anomaly,
                anomaly_score=round(float(score), 4),
                confidence=round(float(confidence), 4),
            ))
        return results

    def save(self, path: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "state_dict": self._net.state_dict(),
            "input_dim": self._input_dim,
            "latent_dim": self._latent_dim,
            "threshold": self._threshold,
            "mean": self._mean,
            "std": self._std,
        }, p)
        log.info("autoencoder_saved", path=str(p))

    def load(self, path: str) -> None:
        ckpt = torch.load(path, map_location=self._device, weights_only=False)
        self._input_dim = ckpt["input_dim"]
        self._latent_dim = ckpt["latent_dim"]
        self._net = _AENetwork(self._input_dim, self._latent_dim).to(self._device)
        self._net.load_state_dict(ckpt["state_dict"])
        self._threshold = ckpt["threshold"]
        self._mean = ckpt["mean"]
        self._std = ckpt["std"]
        self._fitted = True
        log.info("autoencoder_loaded", path=path)

    @property
    def is_fitted(self) -> bool:
        return self._fitted
