import numpy as np
import structlog
from pathlib import Path
import asyncio
from typing import List, Optional
import time

logger = structlog.get_logger("ml_engine.baseline_updater")

class DriftMonitor:
    """
    Monitors reconstruction error distributions to detect concept drift.
    If the network traffic patterns change significantly (e.g., new legitimate services),
    the VAE's MSE will rise, signaling that the baseline is stale.
    """
    def __init__(self, window_size: int = 5000, sensitivity: float = 2.0):
        self.window_size = window_size
        self.sensitivity = sensitivity # Number of standard deviations for drift
        self.mse_history: List[float] = []
        self.baseline_mean: Optional[float] = None
        self.baseline_std: Optional[float] = None
        self.drift_detected = False
        self.last_refresh = time.time()

    def set_baseline(self, mse_scores: np.ndarray):
        """Initializes the baseline statistics from a known 'normal' set."""
        if len(mse_scores) == 0: return
        self.baseline_mean = float(np.mean(mse_scores))
        self.baseline_std = float(np.std(mse_scores))
        logger.info("Drift monitor baseline established", mean=self.baseline_mean, std=self.baseline_std)

    def add_samples(self, mse_scores: np.ndarray) -> bool:
        """
        Adds new MSE samples and returns True if drift is detected.
        Uses a simple Z-score test on the batch mean.
        """
        if self.baseline_mean is None:
            self.set_baseline(mse_scores)
            return False

        batch_mean = np.mean(mse_scores)
        self.mse_history.extend(mse_scores.tolist())
        
        # Trim history
        if len(self.mse_history) > self.window_size:
            self.mse_history = self.mse_history[-self.window_size:]

        # Detect drift: Is the current batch mean significantly higher than baseline?
        # We only care about MSE increasing (more anomalous-looking 'normal' traffic)
        z_score = (batch_mean - self.baseline_mean) / (self.baseline_std + 1e-6)
        
        if z_score > self.sensitivity:
            logger.warning("Network drift detected! MSE distribution shifted.", z_score=z_score)
            self.drift_detected = True
            return True
        
        return False

class BaselineUpdater:
    """
    Handles the background task of refreshing the VAE model or its parameters.
    In a full implementation, this would trigger a retraining job.
    For this V4 upgrade, it performs 'adaptive thresholding' and signals for retraining.
    """
    def __init__(self, ml_engine, drift_monitor: DriftMonitor, broker=None):
        self.ml_engine = ml_engine
        self.monitor = drift_monitor
        self.broker = broker  # Optional: FederatedThreatBroker instance from WorkerPool
        self.is_updating = False

    async def run_update(self, recent_normal_samples: np.ndarray):
        """
        Adaptive refresh: Adjusts the VAE threshold based on recent local 'normal' traffic.
        """
        if self.is_updating: return
        
        # SOTA Zero-Trust: If baseline is frozen, abort update immediately to prevent poisoning
        scorer = getattr(self.ml_engine, "anomaly_scorer", None)
        if scorer and getattr(scorer, "_baseline_frozen", False):
            logger.warning("Baseline auto-refresh skipped: updates are FROZEN due to active threat lockout.")
            return

        self.is_updating = True
        
        try:
            logger.info("Starting baseline auto-refresh...")
            
            # Simulate a computationally intensive update
            await asyncio.sleep(2) 
            
            # Dynamically fetch the current VAE detector from ML Engine
            detector = getattr(self.ml_engine, "vae_detector", None)
            if detector is None or not getattr(detector, "is_ready", False):
                logger.warning("Cannot refresh baseline: VAE detector is None or not ready")
                return
            
            # 1. Re-calculate MSE for the 'normal' samples
            mse = detector.raw_mse(recent_normal_samples)
            
            # 2. Update threshold: Set to 99th percentile of recent normal MSE + 10% buffer
            new_threshold = np.percentile(mse, 99) * 1.1
            old_threshold = detector.threshold
            
            detector.threshold = float(new_threshold)
            self.monitor.set_baseline(mse)
            self.monitor.drift_detected = False
            self.monitor.last_refresh = time.time()
            
            logger.info("Baseline refresh complete", 
                        old_threshold=old_threshold, 
                        new_threshold=new_threshold)
            
            # SOTA Federated Sync: Broadcast the threshold update to peers
            try:
                # Reuse existing broker if passed in; avoid creating a new key-pair per refresh
                broker = self.broker
                if broker is None:
                    from ml_engine.federated_broker import FederatedThreatBroker
                    broker = FederatedThreatBroker(node_id="sentinel-node-1")
                asyncio.create_task(broker.broadcast_vae_threshold(new_threshold))
            except Exception as broadcast_err:
                logger.debug("Failed to broadcast federated threshold update", error=str(broadcast_err))
            
        except Exception as e:
            logger.error("Baseline refresh failed", error=str(e))
        finally:
            self.is_updating = False

baseline_monitor = DriftMonitor()
