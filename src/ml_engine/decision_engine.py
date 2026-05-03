from typing import Dict, Tuple, Optional
import structlog
from common.config import (
    ML_WEIGHT_SIG, ML_WEIGHT_RF, ML_WEIGHT_AE,
    ML_THRESHOLD_ATTACK, ML_THRESHOLD_SUSPICIOUS
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
            "suspicious": ML_THRESHOLD_SUSPICIOUS
        }
        
        logger.info("Decision Engine initialized", 
                    weights=self.weights, 
                    thresholds=self.thresholds)

    def decide(self, 
               sig_present: bool, 
               ml_score: float, 
               anomaly_score: float,
               cti_score: float = 0.0) -> Tuple[str, float]:
        """
        Calculates final classification and confidence.
        Returns: (classification, final_score)
        """
        
        # 1. Signatures are high-priority but we still want to record the score
        # If signature is present, we often treat it as a definitive 'attack' 
        # unless it's a low-severity informational alert.
        if sig_present:
            logger.debug("Signature detected, overriding score", score=1.0)
            return "attack", 1.0

        # 2. Weighted calculation for behavioral detection
        # ml_score, anomaly_score, and cti_score should be normalized [0, 1]
        weighted_sum = (self.weights["ml"] * ml_score) + \
                        (self.weights["anomaly"] * anomaly_score) + \
                        (self.weights["cti"] * cti_score)
        
        # Normalize total score based on ACTIVE weights only to prevent dilution.
        # This ensures that if only one component is present, its score is not 
        # artificially lowered by the weights of missing components.
        active_weight = self.weights["ml"]
        if anomaly_score > 0:
            active_weight += self.weights["anomaly"]
        if cti_score > 0:
            active_weight += self.weights["cti"]
        
        normalized_score = weighted_sum / active_weight if active_weight > 0 else 0

        # 3. Categorization
        if normalized_score >= self.thresholds["attack"]:
            classification = "attack"
        elif normalized_score >= self.thresholds.get("anomaly", 0.6):
            # VAE-driven: uncertain RF + high reconstruction error = unknown/zero-day
            classification = "anomaly"
        elif normalized_score >= self.thresholds["suspicious"]:
            classification = "suspicious"
        else:
            classification = "normal"

        logger.debug("Decision finalized", 
                     ml=ml_score, 
                     anomaly=anomaly_score, 
                     score=round(normalized_score, 4), 
                     decision=classification)
                     
        return classification, normalized_score

    def get_reputation_delta(self, classification: str, score: float) -> float:
        """Calculates reputation impact based on the decision."""
        if classification == "attack":
            return 15.0 * score
        elif classification == "suspicious":
            return 5.0 * score
        else:
            # Slow recovery for normal traffic
            return -0.2
