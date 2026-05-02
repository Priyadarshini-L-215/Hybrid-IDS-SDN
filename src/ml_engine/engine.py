import json
import time
import collections
import numpy as np
import joblib
import pandas as pd
import structlog
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ort = None
    ONNX_AVAILABLE = False

import shap
from common.config import (
    RF_MODEL_PATH, SCALER_PATH, AUTOENCODER_PATH, 
    MODELS_DIR, ML_THRESHOLD_ATTACK, ML_THRESHOLD_SUSPICIOUS,
    ACTIVE_MODEL_FILE, ACTIVE_SCALER_FILE,
    ANOMALY_PERCENTILE, ANOMALY_MIN_SAMPLES
)
from common.feature_extractor import extract_features_batch, load_feature_names
from ml_engine.decision_engine import DecisionEngine
from ml_engine.anomaly_scorer import AnomalyScorer

logger = structlog.get_logger(__name__)

class MLEngine:
    """
    Unified ML Inference Engine.
    Handles model loading, scaling, feature alignment, and batched prediction.
    """
    
    def __init__(self, model_meta_path: str = "models/model_meta.json"):
        self.meta_path = Path(model_meta_path)
        self.rf_model = None
        self.scaler = None
        self.rf_session = None # ONNX
        self.ae_session = None # ONNX
        
        self.feature_order = []
        self.is_ready = False
        self.fallback_mode = False
        
        self.decision_engine = DecisionEngine()
        self.anomaly_scorer = AnomalyScorer(
            percentile=ANOMALY_PERCENTILE, 
            min_samples=ANOMALY_MIN_SAMPLES
        )
        self.shap_explainer = None
        
        self._load_metadata()
        self._load_models()

    def _load_metadata(self):
        try:
            if self.meta_path.exists():
                with open(self.meta_path, "r") as f:
                    self.meta = json.load(f)
                logger.info("Model metadata loaded", version=self.meta.get("model_version"))
            else:
                logger.warning("Model metadata missing, using defaults")
                self.meta = {"model_version": "v3.0-unknown"}
        except Exception as e:
            logger.error("Failed to load metadata", error=str(e))
            self.meta = {"model_version": "v3.0-error"}

    def reload_config(self):
        """Reloads settings from config.py and updates internal components."""
        try:
            from common.config import refresh_config
            refresh_config()
            from common.config import (
                ML_WEIGHT_SIG, ML_WEIGHT_RF, ML_WEIGHT_AE,
                ML_THRESHOLD_ATTACK, ML_THRESHOLD_SUSPICIOUS,
                ANOMALY_PERCENTILE, ANOMALY_MIN_SAMPLES,
                ACTIVE_MODEL_FILE, ACTIVE_SCALER_FILE
            )
            
            # Update Decision Engine
            self.decision_engine.weights = {
                "signature": ML_WEIGHT_SIG,
                "ml": ML_WEIGHT_RF,
                "anomaly": ML_WEIGHT_AE
            }
            self.decision_engine.thresholds = {
                "attack": ML_THRESHOLD_ATTACK,
                "suspicious": ML_THRESHOLD_SUSPICIOUS
            }
            
            # Update Anomaly Scorer
            if hasattr(self, 'anomaly_scorer'):
                self.anomaly_scorer.percentile = ANOMALY_PERCENTILE
                self.anomaly_scorer.min_samples = ANOMALY_MIN_SAMPLES
            
            # Reload Models
            self._load_models()
                
            logger.info("MLEngine configuration reloaded successfully")
        except Exception as e:
            logger.error("Failed to reload MLEngine config", error=str(e))

    def _load_models(self):
        """Loads Scaler and RF (prefers ONNX)."""
        try:
            # 1. Load Feature Order
            order_path = Path("models/feature_order.json")
            if order_path.exists():
                with open(order_path, "r") as f:
                    self.feature_order = json.load(f)["feature_order"]
                logger.info("Feature order locked", count=len(self.feature_order))
            else:
                self.feature_order = load_feature_names()
                
            # 2. Load Scaler
            from common.config import ACTIVE_MODEL_FILE, ACTIVE_SCALER_FILE, MODELS_DIR
            
            scaler_path = MODELS_DIR / ACTIVE_SCALER_FILE
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                logger.info("Scaler loaded", path=str(scaler_path))
            
            # 3. Load RF (Check extension)
            model_path = MODELS_DIR / ACTIVE_MODEL_FILE
            if ONNX_AVAILABLE and model_path.suffix == ".onnx" and model_path.exists():
                self.rf_session = ort.InferenceSession(str(model_path))
                self.rf_model = None
                logger.info("ONNX RF Pipeline loaded", path=str(model_path))
            elif model_path.exists():
                self.rf_model = joblib.load(model_path)
                self.rf_session = None
                logger.info("Pkl RF Model loaded", path=str(model_path))

            # 4. Load Autoencoder (Stage 3)
            ae_path = MODELS_DIR / "autoencoder.onnx"
            if ONNX_AVAILABLE and ae_path.exists():
                self.ae_session = ort.InferenceSession(str(ae_path))
                logger.info("ONNX Autoencoder loaded", path=str(ae_path))
            
            # 5. Initialize SHAP Explainer (if RF pkl available)
            if self.rf_model and not self.shap_explainer:
                try:
                    self.shap_explainer = shap.TreeExplainer(self.rf_model)
                    logger.info("SHAP TreeExplainer initialized")
                except Exception as e:
                    logger.warning("Failed to init SHAP explainer", error=str(e))

            if (self.rf_model or self.rf_session) and self.scaler:
                self.is_ready = True
                logger.info("ML Engine is fully READY")
            else:
                logger.warning("ML Engine incomplete, entering FALLBACK (Signature-only)")
                self.fallback_mode = True
                
        except Exception as e:
            logger.error("Failed to load models", error=str(e))
            self.fallback_mode = True

    def predict_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processes a batch of raw Suricata events.
        Returns a list of result dicts with scores and decisions.
        """
        if not events:
            return []

        start_time = time.time()
        results = []
        
        # 1. Feature Extraction
        t_extract_start = time.time()
        features_list = extract_features_batch(events, self.feature_order)
        extract_ms = (time.time() - t_extract_start) * 1000
        
        # 2. Inference
        t_infer_start = time.time()
        
        # Filter out None features for batch ML call
        valid_indices = [i for i, f in enumerate(features_list) if f is not None]
        valid_features = [features_list[i] for i in valid_indices]
        
        ml_scores = [0.0] * len(events)
        
        if valid_features and not self.fallback_mode and self.is_ready:
            try:
                X = np.array(valid_features, dtype=np.float32)
                
                if self.rf_session:
                    # ONNX path
                    inputs = {self.rf_session.get_inputs()[0].name: X}
                    outputs = self.rf_session.run(None, inputs)
                    # outputs[1] can be a list of dicts or a numpy array depending on the converter
                    if isinstance(outputs[1], list):
                        ml_scores_valid = [d[1] for d in outputs[1]]
                    else:
                        ml_scores_valid = outputs[1][:, 1]
                elif self.rf_model and self.scaler:
                    # Pkl path - wrap in DataFrame to avoid feature name warnings
                    X_df = pd.DataFrame(X, columns=self.feature_order)
                    X_scaled = self.scaler.transform(X_df)
                    ml_scores_valid = self.rf_model.predict_proba(X_scaled)[:, 1]
                else:
                    ml_scores_valid = [0.0] * len(valid_features)
                
                for i, idx in enumerate(valid_indices):
                    ml_scores[idx] = float(ml_scores_valid[i])
                
                # 2b. Anomaly Detection (Stage 3)
                if self.ae_session:
                    ae_inputs = {self.ae_session.get_inputs()[0].name: X}
                    ae_outputs = self.ae_session.run(None, ae_inputs)
                    X_recon = ae_outputs[0]
                    latent = ae_outputs[1] if len(ae_outputs) > 1 else None
                    
                    # Update anomaly scorer stats
                    if latent is not None:
                        self.anomaly_scorer.update_latent_stats(latent)
                    
                    # Calculate MSE and score per event
                    valid_anomaly_scores = []
                    for j in range(len(X)):
                        mse = np.mean((X[j] - X_recon[j])**2)
                        proto = events[valid_indices[j]].get("proto", "TCP")
                        # If latent is available, use it for Mahalanobis
                        l_vec = latent[j] if latent is not None else np.zeros(1)
                        a_score = self.anomaly_scorer.score(mse, l_vec, proto)
                        valid_anomaly_scores.append(a_score)
                    
                    self.valid_anomaly_scores = valid_anomaly_scores # Cache for assembly
                else:
                    self.valid_anomaly_scores = [0.0] * len(valid_features)
                    
            except Exception as e:
                logger.error("Batch inference failed", error=str(e))
                self.valid_anomaly_scores = [0.0] * len(valid_features)
        else:
            self.valid_anomaly_scores = []
        
        infer_ms = (time.time() - t_infer_start) * 1000
        
        # 3. Final Decision & Assembly
        t_decide_start = time.time()
        batch_count = len(events)
        for i, event in enumerate(events):
            sig_present = (event.get("event_type") == "alert")
            
            # Layer 3: Anomaly (Real)
            anomaly_score = 0.0
            if i in valid_indices:
                v_idx = valid_indices.index(i)
                if v_idx < len(self.valid_anomaly_scores):
                    anomaly_score = self.valid_anomaly_scores[v_idx]
            
            classification, confidence = self.decision_engine.decide(
                sig_present=sig_present,
                ml_score=ml_scores[i],
                anomaly_score=anomaly_score
            )
            
            results.append({
                "prediction": classification,
                "confidence": round(float(confidence) * 100, 2),
                "final_score": round(float(confidence), 4),
                "ml_score": round(float(ml_scores[i]), 4),
                "anomaly_score": round(float(anomaly_score), 4),
                "sig_present": sig_present,
                "model_version": self.meta.get("model_version", "v3.0"),
                "shap_top3": self._get_shap_top3(features_list[i]) if classification != "normal" else [],
                "latency": {
                    "extract_ms": round(extract_ms / batch_count, 2),
                    "infer_ms": round(infer_ms / batch_count, 2),
                    "total_ms": round((time.time() - start_time) * 1000 / batch_count, 2)
                }
            })
            
        return results

    def _get_shap_top3(self, features: Optional[List[float]]) -> List[Dict[str, Any]]:
        """
        Returns the top 3 most influential features for a prediction using SHAP.
        """
        if features is None or not self.shap_explainer or not self.feature_order:
            return []
            
        try:
            X = np.array(features).reshape(1, -1)
            # TreeExplainer.shap_values returns [expected_value, shap_values] or list for multi-class
            # For binary RF, it's often a list of [neg, pos]
            shap_vals = self.shap_explainer.shap_values(X)
            
            # Extract values for the 'attack' class (usually index 1)
            if isinstance(shap_vals, list):
                vals = shap_vals[1][0] if len(shap_vals) > 1 else shap_vals[0][0]
            else:
                # Some versions return a single array for binary
                vals = shap_vals[0] if shap_vals.ndim == 2 else shap_vals

            # Map to feature names and sort
            indexed_features = []
            for i, v in enumerate(vals):
                if i < len(self.feature_order):
                    indexed_features.append({
                        "feature": self.feature_order[i],
                        "impact": float(abs(v))
                    })
            
            # Sort by impact descending
            indexed_features.sort(key=lambda x: x["impact"], reverse=True)
            return indexed_features[:3]
            
        except Exception as e:
            logger.debug("SHAP explanation failed", error=str(e))
            return []
