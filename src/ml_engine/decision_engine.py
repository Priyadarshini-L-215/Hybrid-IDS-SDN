from typing import Dict, Tuple, Optional
import structlog
import numpy as np
from common.config import (
    ML_WEIGHT_SIG, ML_WEIGHT_RF, ML_WEIGHT_AE,
    ML_THRESHOLD_ATTACK, ML_THRESHOLD_SUSPICIOUS, ML_THRESHOLD_ANOMALY
)

logger = structlog.get_logger(__name__)

class DecisionEngine:
    """
    Unified engine for classification decisions.
    Prioritizes signatures but corroborates with ML and Anomaly detection.
    """
    
    def __init__(self, 
                 weights: Optional[Dict[str, float]] = None, 
                 thresholds: Optional[Dict[str, float]] = None):
        
        # Use config defaults if not provided
        self.weights = weights or {
            "signature": ML_WEIGHT_SIG,
            "ml": ML_WEIGHT_RF,
            "anomaly": ML_WEIGHT_AE,
            "cti": 0.8  # CTI has high influence but not absolute like signatures
        }
        
        self.thresholds = thresholds or {
            "attack": ML_THRESHOLD_ATTACK,
            "suspicious": ML_THRESHOLD_SUSPICIOUS,
            "anomaly": ML_THRESHOLD_ANOMALY
        }
        
        logger.info("Decision Engine initialized", 
                    weights=self.weights, 
                    thresholds=self.thresholds)

    def decide(self, 
               sig_present: bool, 
               ml_score: Optional[float], 
               anomaly_score: Optional[float],
               cti_score: Optional[float] = None,
               prediction: dict = None) -> Tuple[str, float]:
        """
        Calculates final classification and confidence.
        Returns: (classification, final_score)
        """
        
        # 1. Weighted calculation
        # We include all available signals (ML, Anomaly, CTI, and Signatures)
        weighted_sum = 0.0
        active_weight = 0.0

        components = [
            ("ml", ml_score),
            ("anomaly", anomaly_score),
            ("cti", cti_score)
        ]

        if sig_present:
            # Signatures are treated as a high-confidence signal (1.0)
            weighted_sum += self.weights["signature"] * 1.0
            active_weight += self.weights["signature"]

        for name, score in components:
            if score is not None:
                # Sanitize NaN or Inf
                safe_score = np.nan_to_num(score, nan=0.0, posinf=1.0, neginf=0.0)
                weighted_sum += self.weights[name] * float(safe_score)
                active_weight += self.weights[name]

        normalized_score = float(weighted_sum / active_weight) if active_weight > 0 else 0.0
        if np.isnan(normalized_score): normalized_score = 0.0

        # 2. Dynamic Confidence Scaling
        # Apply a subtle penalty to ensure we don't hit 1.0 unless all signals agree perfectly.
        # This prevents "classification saturation" in the UI.
        final_score = normalized_score
        if sig_present:
            # Signatures force a minimum confidence floor but are still nuanced
            final_score = max(0.92, normalized_score * 0.99)
        else:
            # Behavioral detections are capped slightly below 1.0 to reflect probabilistic nature
            final_score = min(0.98, normalized_score)

        # 3. Categorization
        if final_score >= self.thresholds.get("attack", 0.9):
            classification = "attack"
        elif final_score >= self.thresholds.get("suspicious", 0.7):
            classification = "suspicious"
        elif final_score >= self.thresholds.get("anomaly", 0.6):
            classification = "anomaly"
        else:
            classification = "normal"

        logger.info("Decision finalized", 
                     ml=ml_score, 
                     anomaly=anomaly_score, 
                     sig=sig_present,
                     score=round(final_score, 4), 
                     decision=classification,
                     top_features=prediction.get("shap_top3", []) if prediction else [])
                     
        return classification, final_score


    def get_reputation_delta(self, classification: str, score: float) -> float:
        """Calculates reputation impact based on the decision."""
        if classification == "attack":
            return 15.0 * score
        elif classification == "suspicious":
            return 5.0 * score
        elif classification == "anomaly":
            # Zero-day or behavioral anomaly, treat as moderately suspicious
            return 8.0 * score
        else:
            # Slow recovery for normal traffic
            return -0.2
