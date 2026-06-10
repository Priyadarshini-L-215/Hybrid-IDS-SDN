from typing import Dict, Tuple, Optional, List
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
                 thresholds: Optional[Dict[str, float]] = None,
                 feature_names: Optional[List[str]] = None):
        
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
        
        self.feature_names = feature_names
        
        from ml_engine.adversarial_guard import AdversarialGuard
        self.adversarial_guard = AdversarialGuard()
        
        from common.soar_engine import SOAREngine
        self.soar_engine = SOAREngine()
        self.anomaly_scorer = None
        
        logger.info("Decision Engine initialized", 
                    weights=self.weights, 
                    thresholds=self.thresholds,
                    has_feature_names=feature_names is not None)

    def decide(self, 
               sig_present: bool, 
               ml_score: Optional[float], 
               anomaly_score: Optional[float],
               cti_score: Optional[float] = None,
               prediction: dict = None,
               event: dict = None) -> Tuple[str, float]:
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

        # 2b. Adversarial Evasion Check
        evasion_score = 0.0
        evasion_reasons = []
        if event and self.adversarial_guard:
            feat_vec = prediction.get("_feature_vector") if prediction else None
            evasion_score, evasion_reasons = self.adversarial_guard.detect_evasion(
                event, features=feat_vec, feature_names=self.feature_names
            )
            if prediction:
                prediction["adversarial_score"] = evasion_score
                prediction["evasion_reasons"] = evasion_reasons

        # 3. Categorization
        if final_score >= self.thresholds.get("attack", 0.9) or evasion_score >= 0.5:
            classification = "attack"
            if evasion_score >= 0.5:
                # Elevate final confidence score to reflect high severity of evasion
                final_score = max(final_score, 0.95)
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
                     evasion_score=evasion_score,
                     score=round(final_score, 4), 
                     decision=classification,
                     top_features=prediction.get("shap_top3", []) if prediction else [])
                     
        # Trigger SOAR playbook execution asynchronously for non-normal events
        if classification != "normal" and event:
            # SOTA Zero-Trust: Freeze baseline updates immediately during active threats
            if hasattr(self, "anomaly_scorer") and self.anomaly_scorer:
                self.anomaly_scorer.freeze_baseline()

            import asyncio
            try:
                loop = asyncio.get_running_loop()
                mitre_info = event.get("mitre")
                # Get the mitre info if signature alert
                if not mitre_info and sig_present:
                    # Construct mock MITRE info from event alert signature or features
                    # mapping to DDoS (T1498) or Scanning (T1595)
                    alert_sig = event.get("alert_sig", "").lower()
                    if "ddos" in alert_sig or "flood" in alert_sig:
                        mitre_info = {"tactic": "Impact", "technique": "T1498"}
                    elif "scan" in alert_sig or "recon" in alert_sig:
                        mitre_info = {"tactic": "Discovery", "technique": "T1595"}
                
                shap_top3 = prediction.get("shap_top3", []) if prediction else []
                
                loop.create_task(self.soar_engine.execute_playbook(
                    classification=classification,
                    confidence=final_score * 100.0,
                    mitre_info=mitre_info,
                    shap_features=shap_top3,
                    event=event
                ))
            except RuntimeError:
                # No running event loop (e.g. running in synchronous tests)
                pass
            except Exception as soar_err:
                logger.error("Failed to trigger SOAR playbook", error=str(soar_err))

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
