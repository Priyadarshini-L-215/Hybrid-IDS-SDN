"""
VAE Anomaly Detector — Sentinel Core V4
========================================
Wraps the PyTorch VAE (vae_model.pth) + MinMaxScaler (vae_scaler.pkl)
into a clean interface for use by the ML Engine.

Architecture (inferred from state dict):
  Encoder:  16 → Linear(64) → ReLU → Linear(32) → ReLU
  Latent:   fc_mu(32→16), fc_logvar(32→16)
  Decoder:  16 → Linear(32) → ReLU → Linear(64) → ReLU → Linear(16) → Sigmoid
  
Anomaly threshold: MSE reconstruction error > 0.0283
"""

import logging
import numpy as np
from pathlib import Path

import joblib
import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


class _VAE(nn.Module):
    """
    Internal VAE architecture matching the provided vae_model.pth state dict.
    """
    def __init__(self, input_dim: int = 16, latent_dim: int = 16):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
        )
        self.fc_mu = nn.Linear(32, latent_dim)
        self.fc_logvar = nn.Linear(32, latent_dim)

        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim),
            nn.Sigmoid(),
        )

    def encode(self, x: torch.Tensor):
        h = self.encoder(x)
        return self.fc_mu(h), self.fc_logvar(h)

    def reparameterize(self, mu: torch.Tensor, logvar: torch.Tensor) -> torch.Tensor:
        # During inference use the mean only (no sampling noise)
        return mu

    def decode(self, z: torch.Tensor) -> torch.Tensor:
        return self.decoder(z)

    def forward(self, x: torch.Tensor):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        x_recon = self.decode(z)
        return x_recon, mu, logvar


class VaeAnomalyDetector:
    """
    Public interface for the 16-feature VAE anomaly detector.

    Usage::
        detector = VaeAnomalyDetector("models/vae_model.pth", "models/vae_scaler.pkl")
        mse_scores = detector.score(X_raw)          # ndarray of per-sample MSE
        flags      = detector.is_anomaly(X_raw)     # bool ndarray
    """

    DEFAULT_THRESHOLD = 0.3

    def __init__(self, model_path: str | Path, scaler_path: str | Path,
                 threshold: float = DEFAULT_THRESHOLD):
        self.threshold = threshold
        self._ready = False

        try:
            # Load MinMaxScaler
            self.scaler = joblib.load(scaler_path)
            logger.info(f"VAE scaler loaded from {scaler_path}")

            # Build model architecture and load weights
            self.model = _VAE(input_dim=16, latent_dim=16)
            state_dict = torch.load(model_path, map_location="cpu", weights_only=True)
            self.model.load_state_dict(state_dict)
            self.model.eval()
            logger.info(f"VAE model loaded from {model_path} | threshold={threshold}")

            self._ready = True
        except Exception as e:
            logger.error(f"Failed to load VAE detector: {e}")

    @property
    def is_ready(self) -> bool:
        return self._ready

    def raw_mse(self, X: np.ndarray) -> np.ndarray:
        """
        Compute raw per-sample MSE reconstruction error.
        """
        if not self._ready:
            return np.zeros(len(X))

        try:
            # Ensure we only use the first 16 features if more are passed
            # This aligns with the VAE's 16-manifold architecture
            if X.shape[1] > 16:
                X_input = X[:, :16]
            else:
                X_input = X

            X_scaled = self.scaler.transform(X_input).astype(np.float32)
            t = torch.from_numpy(X_scaled)

            with torch.no_grad():
                x_recon, _, _ = self.model(t)

            mse = ((t - x_recon) ** 2).mean(dim=1).numpy()
            return mse
        except Exception as e:
            logger.error(f"VAE raw_mse error: {e}")
            return np.zeros(len(X))

    def score(self, X: np.ndarray) -> np.ndarray:
        """
        Compute normalized anomaly score [0, 1].
        Maps raw MSE to a probability-like score where threshold = 0.5.
        """
        mse = self.raw_mse(X)
        if len(mse) == 0:
            return mse
            
        # Sigmoid normalization around the threshold
        # Scale controls the steepness; threshold/2 provides a reasonable curve
        scale = self.threshold / 2 if self.threshold > 0 else 0.01
        normalized = 1.0 / (1.0 + np.exp(-(mse - self.threshold) / scale))
        return normalized

    def is_anomaly(self, X: np.ndarray) -> np.ndarray:
        """
        Returns a boolean mask — True where reconstruction error exceeds threshold.
        """
        return self.raw_mse(X) > self.threshold
