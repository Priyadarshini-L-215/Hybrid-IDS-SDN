"""
AnomalyScorer: Dynamic threshold engine for the VAE/Autoencoder layer.

Implements:
  - Rolling reconstruction error window (1-hour, max 10,000 samples)
  - Dynamic percentile threshold (top 0.5% = anomaly)
  - Mahalanobis distance in latent space
  - Per-protocol sub-thresholds
"""
import collections
import threading
import numpy as np
from typing import Optional
import structlog
from common.config import ANOMALY_PERCENTILE, ANOMALY_MIN_SAMPLES

logger = structlog.get_logger(__name__)

# Rolling window per protocol (max 10,000 samples each)
_WINDOW_SIZE = 10_000

class AnomalyScorer:
    def __init__(self, percentile: float = ANOMALY_PERCENTILE, min_samples: int = ANOMALY_MIN_SAMPLES):
        self._lock = threading.Lock()
        self.percentile = percentile
        self.min_samples = min_samples
        # Per-protocol error history: {"tcp": deque, "udp": deque, ...}
        self._error_windows: dict[str, collections.deque] = {}
        # Latent space covariance matrix for Mahalanobis (updated periodically)
        self._latent_cov_inv: Optional[np.ndarray] = None
        self._latent_mean: Optional[np.ndarray] = None
        self._cov_sample_count = 0

    def _get_window(self, protocol: str) -> collections.deque:
        proto = (protocol or "unknown").lower()
        if proto not in self._error_windows:
            self._error_windows[proto] = collections.deque(maxlen=_WINDOW_SIZE)
        return self._error_windows[proto]

    def _dynamic_threshold(self, protocol: str) -> float:
        """Returns the current percentile-based threshold for this protocol."""
        window = self._get_window(protocol)
        if len(window) < self.min_samples:
            # Not enough samples yet — return a permissive default
            return float("inf")
        return float(np.percentile(list(window), self.percentile))

    def update_latent_stats(self, latent_vectors: np.ndarray):
        """
        Called periodically to update the latent space mean and inverse covariance.
        Only recalculates when >= 200 new samples have arrived.
        """
        with self._lock:
            self._cov_sample_count += len(latent_vectors)
            if self._cov_sample_count < 200:
                return
            try:
                self._latent_mean = np.mean(latent_vectors, axis=0)
                cov = np.cov(latent_vectors.T)
                # Add ridge regularization for invertibility
                cov += np.eye(cov.shape[0]) * 1e-6
                self._latent_cov_inv = np.linalg.inv(cov)
                self._cov_sample_count = 0
                logger.debug("Latent covariance updated", dim=latent_vectors.shape[1])
            except Exception as e:
                logger.warning("Covariance update failed", error=str(e))

    def mahalanobis_score(self, latent_vector: np.ndarray) -> float:
        """
        Returns Mahalanobis distance from the latent mean.
        Falls back to L2 norm if covariance not yet computed.
        """
        with self._lock:
            if self._latent_cov_inv is None or self._latent_mean is None:
                # Fallback to simple norm if stats not ready
                return float(np.linalg.norm(latent_vector))
            diff = latent_vector - self._latent_mean
            return float(np.sqrt(diff @ self._latent_cov_inv @ diff))

    def score(self, mse: float, latent_vector: np.ndarray, protocol: str) -> float:
        """
        Returns normalized anomaly score in [0, 1].
        Combines MSE percentile rank and Mahalanobis distance.
        """
        with self._lock:
            window = self._get_window(protocol)
            window.append(mse)
            threshold = self._dynamic_threshold(protocol)

        maha = self.mahalanobis_score(latent_vector)
        # Normalize (10.0 = heuristic cap, adjust based on latent dim)
        maha_norm = min(maha / 10.0, 1.0) 

        if threshold == float("inf"):
            mse_norm = 0.0
        else:
            # How far past the threshold? (e.g. 2x threshold = 1.0)
            mse_norm = min(mse / threshold, 1.0) 

        # Weighted combination: 60% Mahalanobis, 40% percentile-MSE
        combined = 0.6 * maha_norm + 0.4 * mse_norm
        return round(combined, 4)
