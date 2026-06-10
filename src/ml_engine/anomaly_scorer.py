import collections
import threading
import time
import numpy as np
from typing import Optional, List, Tuple
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
        # Per-protocol threshold cache to avoid expensive percentile calls
        self._threshold_cache: dict[str, float] = {}
        self._update_counter: dict[str, int] = {}
        
        # Maintain a window of recent normal latent vectors
        self._latent_window = collections.deque(maxlen=2000)
        self._latent_cov_inv: Optional[np.ndarray] = None
        self._latent_mean: Optional[np.ndarray] = None
        self._cov_sample_count = 0

        # Zero-Trust V5 Upgrades
        self._baseline_frozen = False
        self._last_incident_time = 0.0
        # List of tuples: (timestamp, protocol, mse, latent_vector, src_ip)
        self._quarantine_queue: List[Tuple[float, str, float, np.ndarray, Optional[str]]] = []
        self._quarantine_ttl = 60.0  # hold samples for 60 seconds

    def _get_window(self, protocol: str) -> collections.deque:
        proto = (protocol or "unknown").lower()
        if proto not in self._error_windows:
            self._error_windows[proto] = collections.deque(maxlen=_WINDOW_SIZE)
        return self._error_windows[proto]

    def _update_running_percentile(self, protocol: str, mse: float):
        """Updates the running threshold using Robbins-Monro stochastic approximation (O(1))."""
        proto = (protocol or "unknown").lower()
        window = self._get_window(proto)
        
        if len(window) < self.min_samples:
            return
            
        p = self.percentile / 100.0
        
        # Initialize running threshold if not cached
        if proto not in self._threshold_cache or self._threshold_cache[proto] == float("inf"):
            arr = np.array(list(window))
            initial_t = float(np.percentile(arr, self.percentile))
            self._threshold_cache[proto] = initial_t
            self._update_counter[proto] = 0
            return
            
        current_t = self._threshold_cache[proto]
        
        # Determine learning step size based on local variation (Robust MAD)
        arr = np.array(list(window))
        median = np.median(arr)
        mad = np.median(np.abs(arr - median)) or 1e-6
        eta = 0.005 * mad
        
        if mse > current_t:
            new_t = current_t + eta * p
        else:
            new_t = current_t - eta * (1.0 - p)
            
        # Keep threshold reasonable (at least median)
        self._threshold_cache[proto] = max(new_t, float(median))

    def calibrate_on_fp(self, protocol: str, mse: float):
        """Boosts the threshold when an admin-suppressed false positive is encountered."""
        proto = (protocol or "unknown").lower()
        with self._lock:
            if proto in self._threshold_cache:
                current_t = self._threshold_cache[proto]
                if mse > current_t:
                    self._threshold_cache[proto] = float(mse * 1.05)
                    logger.warning("Adaptive Calibration: Boosted VAE threshold due to false positive feedback", 
                                   protocol=proto, old_t=current_t, new_t=self._threshold_cache[proto])

    def _dynamic_threshold(self, protocol: str) -> float:
        """Returns the current percentile-based threshold for this protocol (O(1) cached)."""
        proto = (protocol or "unknown").lower()
        
        if proto not in self._threshold_cache:
            window = self._get_window(protocol)
            if len(window) < self.min_samples:
                return float("inf")
            arr = np.array(list(window))
            self._threshold_cache[proto] = float(np.percentile(arr, self.percentile))
            
        return self._threshold_cache[proto]

    def robust_scale_mse(self, mse: float, protocol: str) -> float:
        """
        Scales MSE using robust statistics (Median and MAD) instead of sensitive mean/std.
        Robust Z-Score = 0.6745 * (mse - median) / MAD
        """
        with self._lock:
            return self._robust_scale_mse_unlocked(mse, protocol)

    def _robust_scale_mse_unlocked(self, mse: float, protocol: str) -> float:
        window = self._get_window(protocol)
        if len(window) < self.min_samples:
            return 0.0
        
        arr = np.array(list(window))
        median = np.median(arr)
        mad = np.median(np.abs(arr - median))
        if mad <= 0:
            mad = 1e-6
            
        # Robust z-score
        z = 0.6745 * (mse - median) / mad
        # Map z-score to [0, 1] using standard logistic sigmoid, shifted so normal center is low
        scaled = 1.0 / (1.0 + np.exp(-z + 2.0))
        return float(scaled)

    def freeze_baseline(self):
        """Freezes baseline updates during active incidents to prevent adversarial poisoning."""
        with self._lock:
            self._last_incident_time = time.time()
            if not self._baseline_frozen:
                self._baseline_frozen = True
                logger.warning("Zero-Trust ML: Baseline updates FROZEN due to active incident lockout.")

    def unfreeze_baseline(self):
        """Unfreezes baseline updates once threats are cleared."""
        with self._lock:
            if self._baseline_frozen:
                self._baseline_frozen = False
                logger.info("Zero-Trust ML: Baseline updates UNFROZEN.")

    def invalidate_quarantine_ip(self, src_ip: str):
        """Retroactively purges all quarantined baseline updates from a source IP flagged as malicious."""
        if not src_ip:
            return
        with self._lock:
            initial_len = len(self._quarantine_queue)
            self._quarantine_queue = [
                item for item in self._quarantine_queue if item[4] != src_ip
            ]
            removed = initial_len - len(self._quarantine_queue)
            if removed > 0:
                logger.info("Zero-Trust ML: Retroactively purged quarantined flows from baseline", 
                            src_ip=src_ip, removed_flows=removed)

    def flush_quarantine(self):
        """Merges expired, clean quarantine entries into the active VAE baseline."""
        with self._lock:
            self._flush_quarantine_unlocked()

    def _flush_quarantine_unlocked(self):
        now = time.time()
        if self._baseline_frozen:
            # SOTA Auto-Unfreeze Cooldown: Check if 5 minutes have elapsed since last incident
            if now - self._last_incident_time > 300.0:
                self._baseline_frozen = False
                logger.info("Zero-Trust ML: Cooldown period elapsed. Baseline updates UNFROZEN automatically.")
            else:
                # Under a baseline freeze, discard expired quarantine elements to prevent contamination
                discard_count = 0
                keep = []
                for item in self._quarantine_queue:
                    if now - item[0] > self._quarantine_ttl:
                        discard_count += 1
                    else:
                        keep.append(item)
                self._quarantine_queue = keep
                if discard_count > 0:
                    logger.debug("Discarded quarantined flows during active freeze", count=discard_count)
                return

        to_merge = []
        keep = []
        for item in self._quarantine_queue:
            if now - item[0] > self._quarantine_ttl:
                to_merge.append(item)
            else:
                keep.append(item)
        self._quarantine_queue = keep

        if not to_merge:
            return

        for _, proto, mse, latent_vector, _ in to_merge:
            window = self._get_window(proto)
            window.append(mse)
            self._update_running_percentile(proto, mse)
            self._latent_window.append(latent_vector)
            self._cov_sample_count += 1

        logger.debug("Merged clean quarantined flows into baseline", count=len(to_merge))

        # Recalculate latent stats periodically from normal window
        if self._cov_sample_count >= 200 and len(self._latent_window) >= 200:
            try:
                arr = np.array(self._latent_window)
                self._latent_mean = np.mean(arr, axis=0)
                cov = np.cov(arr.T)
                # Add ridge regularization for invertibility
                cov += np.eye(cov.shape[0]) * 1e-6
                self._latent_cov_inv = np.linalg.inv(cov)
                self._cov_sample_count = 0
                logger.debug("Latent covariance updated", dim=arr.shape[1])
            except Exception as e:
                logger.warning("Covariance update failed", error=str(e))

    def update_latent_stats(self, latent_vectors: np.ndarray):
        """
        Deprecated. Latent stats are now updated organically in score().
        """
        pass

    def mahalanobis_score(self, latent_vector: np.ndarray) -> float:
        """
        Returns Mahalanobis distance from the latent mean.
        Falls back to 0.0 if covariance not yet computed to prevent cold-start anomalies.
        """
        with self._lock:
            return self._mahalanobis_score_unlocked(latent_vector)

    def _mahalanobis_score_unlocked(self, latent_vector: np.ndarray) -> float:
        if self._latent_cov_inv is None or self._latent_mean is None:
            # Fallback to 0.0 if stats not ready
            return 0.0
        diff = latent_vector - self._latent_mean
        return float(np.sqrt(diff @ self._latent_cov_inv @ diff))

    def score(self, mse: float, latent_vector: np.ndarray, protocol: str, src_ip: Optional[str] = None) -> float:
        """
        Returns normalized anomaly score in [0, 1].
        Combines MSE percentile rank, robust MAD z-score, and Mahalanobis distance.
        """
        with self._lock:
            # 1. Proactively flush quarantine
            self._flush_quarantine_unlocked()

            # 2. Get dynamic threshold
            threshold = self._dynamic_threshold(protocol)

            # 3. Calculate Mahalanobis score
            maha = self._mahalanobis_score_unlocked(latent_vector)
            
            # 4. Calculate robust MAD scaled score
            robust_norm = self._robust_scale_mse_unlocked(mse, protocol)

            # Handle NaN from Mahalanobis (e.g. if latent vector has NaNs)
            if np.isnan(maha):
                maha_norm = 0.0
            else:
                # Normalize (10.0 = heuristic cap, adjust based on latent dim)
                maha_norm = min(maha / 10.0, 1.0) 

            if threshold == float("inf"):
                # Permissive baseline while gathering initial samples
                mse_norm = 0.0
            elif threshold <= 0:
                # If threshold is 0, any MSE > 0 is anomalous, but 0/0 is 0
                mse_norm = 1.0 if mse > 0 else 0.0
            else:
                # How far past the threshold? (e.g. 2x threshold = 1.0)
                mse_norm = min(mse / threshold, 1.0) 

            # Final safety check for NaN
            if np.isnan(mse_norm): mse_norm = 0.0
            if np.isnan(maha_norm): maha_norm = 0.0

            # Zero-trust blend: 50% percentile-MSE, 50% robust MAD z-score
            blended_mse = 0.5 * mse_norm + 0.5 * robust_norm

            # Weighted combination: 60% Mahalanobis, 40% blended-MSE
            combined = 0.6 * maha_norm + 0.4 * blended_mse
            
            # Only update baselines with normal traffic (prevent poisoning from attacks)
            if combined < 0.6:
                if not self._baseline_frozen:
                    # Append to quarantine queue for verification hold instead of immediate baseline inclusion
                    self._quarantine_queue.append((time.time(), protocol, mse, latent_vector, src_ip))

            return round(float(combined), 4)
