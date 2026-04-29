"""
DriftDetector: Wraps ADWIN (river library) to detect ML score distribution shift.

Design Principles:
  - Human-in-the-loop: Drift triggers an operator alert, NOT retraining
  - Lightweight: Only tracks the scalar ML confidence score stream
  - Stateful: Maintains a single ADWIN instance per MLEngine instance
"""
import time
import structlog
from typing import Optional, Callable

logger = structlog.get_logger(__name__)

try:
    from river import drift as river_drift
    RIVER_AVAILABLE = True
except ImportError:
    RIVER_AVAILABLE = False
    logger.warning("river library not installed — drift detection disabled. Run: pip install river")

class DriftDetector:
    def __init__(self, on_drift: Optional[Callable] = None):
        """
        Args:
            on_drift: Async-compatible callback invoked when drift is detected.
                      Receives a dict with drift metadata.
        """
        self.on_drift = on_drift
        self._detector = None
        self._last_drift_time = 0.0
        self._cooldown_sec = 300  # Minimum 5 min between drift alerts
        self._sample_count = 0

        if RIVER_AVAILABLE:
            # ADWIN (Adaptive Windowing) detects change in mean/variance
            self._detector = river_drift.ADWIN(delta=0.002)
            logger.info("ADWIN drift detector initialized", delta=0.002)

    def update(self, score: float) -> bool:
        """
        Feed one ML confidence score into ADWIN.
        Returns True if drift was detected this update.
        """
        if self._detector is None:
            return False

        self._sample_count += 1
        # Normalize score if needed, but ADWIN handles most distributions
        self._detector.update(score)

        if self._detector.drift_detected:
            now = time.time()
            if now - self._last_drift_time > self._cooldown_sec:
                self._last_drift_time = now
                logger.warning("ML Score Drift Detected (ADWIN)",
                               sample_count=self._sample_count)
                if self.on_drift:
                    import asyncio
                    # Call the provided callback (likely async)
                    # Use drift_info dict for the dashboard alert
                    drift_info = {
                        "type": "drift_alert",
                        "detector": "ADWIN",
                        "message": "ML score distribution has shifted significantly. Manual model review recommended.",
                        "samples_observed": self._sample_count,
                        "timestamp": now
                    }
                    
                    # Handle both sync and async callbacks
                    if asyncio.iscoroutinefunction(self.on_drift):
                        asyncio.create_task(self.on_drift(drift_info))
                    else:
                        self.on_drift(drift_info)
                        
                return True
        return False
