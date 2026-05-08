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
import warnings
# Suppress sklearn feature name warnings (we use numpy for performance)
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

from common.config import (
    RF_MODEL_PATH, SCALER_PATH, AUTOENCODER_PATH, 
    MODELS_DIR, ML_THRESHOLD_ATTACK, ML_THRESHOLD_SUSPICIOUS,
    ACTIVE_MODEL_FILE, ACTIVE_SCALER_FILE,
    ANOMALY_PERCENTILE, ANOMALY_MIN_SAMPLES,
    AUTOENCODER_THRESHOLD,
    get_cfg
)
from common.model_manifest import get_active_model_spec, load_model_manifest
from common.feature_extractor import extract_features_batch, load_feature_names, validate_feature_vector
from ml_engine.decision_engine import DecisionEngine
from ml_engine.anomaly_scorer import AnomalyScorer
from ml_engine.vae_detector import VaeAnomalyDetector

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
        self.stage_status = {
            "rf": "not_loaded",
            "scaler": "not_loaded",
            "vae": "not_loaded",
        }
        self.load_warnings = []
        
        self.decision_engine = DecisionEngine()
        self.anomaly_scorer = AnomalyScorer(
            percentile=ANOMALY_PERCENTILE, 
            min_samples=ANOMALY_MIN_SAMPLES
        )
        self.shap_explainer = None
        self.vae_detector = None  # Stage 3: Keras VAE anomaly detector
        self.vae_threshold = AUTOENCODER_THRESHOLD
        
        self._load_metadata()
        self._load_models()

    def _load_metadata(self):
        try:
            manifest = load_model_manifest()
            active_spec = get_active_model_spec()

            if self.meta_path.exists():
                with open(self.meta_path, "r") as f:
                    self.meta = json.load(f)
            else:
                self.meta = {"model_version": "v3.0-unknown"}

            if manifest:
                self.meta["manifest_schema_version"] = manifest.get("schema_version", "unknown")
                self.meta["manifest_active_model"] = active_spec.get("name", self.meta.get("model_version", "unknown"))
                self.meta["manifest_model_family"] = active_spec.get("model_family", "unknown")
                self.meta["manifest_feature_count"] = active_spec.get("feature_schema", {}).get("feature_count")

            logger.info(
                "Model metadata loaded",
                version=self.meta.get("model_version"),
                manifest=self.meta.get("manifest_active_model", "absent"),
            )
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
            
            # Update Decision Engine (re-instantiate to ensure thresholds are clean)
            from ml_engine.decision_engine import DecisionEngine
            self.decision_engine = DecisionEngine(
                weights={
                    "signature": ML_WEIGHT_SIG,
                    "ml": ML_WEIGHT_RF,
                    "anomaly": ML_WEIGHT_AE,
                    "cti": 0.8
                },
                thresholds={
                    "attack": ML_THRESHOLD_ATTACK,
                    "suspicious": ML_THRESHOLD_SUSPICIOUS,
                    "anomaly": get_cfg("detection.decision_engine.thresholds.anomaly", 0.6)
                }
            )
            
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
            from common.config import MODELS_DIR
            order_path = MODELS_DIR / "feature_order.json"
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
                self.stage_status["scaler"] = "loaded"
                logger.info("Scaler loaded", path=str(scaler_path))
            else:
                self.load_warnings.append(f"Missing scaler: {scaler_path}")
            
            # 3. Load RF (Check extension)
            model_path = MODELS_DIR / ACTIVE_MODEL_FILE
            if ONNX_AVAILABLE and model_path.suffix == ".onnx" and model_path.exists():
                self.rf_session = ort.InferenceSession(str(model_path))
                self.rf_model = None
                self.stage_status["rf"] = "loaded_onnx"
                logger.info("ONNX RF Pipeline loaded", path=str(model_path))
            elif model_path.exists():
                self.rf_model = joblib.load(model_path)
                self.rf_session = None
                self.stage_status["rf"] = "loaded_pickle"
                logger.info("Pkl RF Model loaded", path=str(model_path))
            else:
                self.load_warnings.append(f"Missing active model: {model_path}")

            # 4. Load VAE Anomaly Detector (Stage 3 — Keras)
            vae_encoder_path = MODELS_DIR / "vae_encoder.keras"
            vae_decoder_path = MODELS_DIR / "vae_decoder.keras"
            vae_scaler_path = MODELS_DIR / "vae_scaler.pkl"
            vae_config_path = MODELS_DIR / "vae_config.json"
            
            if vae_encoder_path.exists() and vae_decoder_path.exists() and vae_scaler_path.exists():
                if vae_config_path.exists():
                    try:
                        with open(vae_config_path) as f:
                            vae_cfg = json.load(f)
                        self.vae_threshold = vae_cfg.get("threshold", self.vae_threshold)
                    except Exception as e:
                        logger.warning("Failed to load vae_config.json", error=str(e))

                self.vae_detector = VaeAnomalyDetector(
                    encoder_path=vae_encoder_path,
                    decoder_path=vae_decoder_path,
                    scaler_path=vae_scaler_path,
                    threshold=self.vae_threshold,
                )
                if self.vae_detector.is_ready:
                    self.stage_status["vae"] = "loaded"
                    logger.info("VAE Anomaly Detector loaded (Keras)",
                                threshold=self.vae_threshold,
                                encoder=str(vae_encoder_path))
                else:
                    logger.warning("VAE Detector failed to initialise; anomaly detection disabled")
                    self.stage_status["vae"] = "disabled"
                    self.vae_detector = None
            else:
                logger.warning("VAE Keras model files not found; anomaly detection disabled")
                self.stage_status["vae"] = "missing"
            
            # 5. Initialize SHAP Explainer (if RF pkl available)
            if self.rf_model and not self.shap_explainer:
                try:
                    # For CalibratedClassifierCV, we need to extract the inner estimator
                    inner_model = self.rf_model
                    if hasattr(self.rf_model, "calibrated_classifiers_"):
                         inner_model = self.rf_model.calibrated_classifiers_[0].estimator
                         logger.info("SHAP: Using inner estimator from CalibratedClassifierCV")
                    
                    self.shap_explainer = shap.TreeExplainer(inner_model)
                    logger.info("SHAP TreeExplainer initialized")
                except Exception as e:
                    logger.warning("Failed to init SHAP explainer", error=str(e))

            if (self.rf_model or self.rf_session) and self.scaler:
                self.is_ready = True
                if self.stage_status.get("vae") in {"missing", "disabled"}:
                    self.fallback_mode = False
                logger.info("ML Engine is fully READY")
            else:
                logger.warning("ML Engine incomplete, entering FALLBACK (Signature-only)")
                self.fallback_mode = True
                
        except Exception as e:
            logger.error("Failed to load models", error=str(e))
            self.fallback_mode = True

    def get_status(self) -> Dict[str, Any]:
        """Returns runtime status for dashboard and diagnostics."""
        if self.fallback_mode:
            mode = "fallback"
        elif self.is_ready and self.stage_status.get("vae") == "loaded":
            mode = "full"
        elif self.is_ready:
            mode = "degraded"
        else:
            mode = "unavailable"

        return {
            "status": mode,
            "ready": self.is_ready,
            "fallback_mode": self.fallback_mode,
            "feature_count": len(self.feature_order),
            "stages": dict(self.stage_status),
            "warnings": list(self.load_warnings),
            "model_version": self.meta.get("model_version", "unknown"),
            "vae_enabled": self.vae_detector is not None,
            "vae_threshold": self.vae_threshold,
        }

    def predict_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processes a batch of raw Suricata events.
        Returns a list of result dicts with scores and decisions.
        """
        if not events:
            return []

        start_time = time.time()
        results = []
        batch_shap_results = {}
        
        # 1. Feature Extraction
        t_extract_start = time.time()
        features_list = extract_features_batch(events, self.feature_order)
        extract_ms = (time.time() - t_extract_start) * 1000

        # Validate feature dimensionality before inference.
        valid_features = []
        valid_indices = []
        invalid_count = 0
        for idx, feature_vector in enumerate(features_list):
            if feature_vector is None:
                continue
            if validate_feature_vector(feature_vector, expected_dim=len(self.feature_order)):
                valid_features.append(feature_vector)
                valid_indices.append(idx)
            else:
                invalid_count += 1

        valid_index_map = {event_idx: pos for pos, event_idx in enumerate(valid_indices)}

        if invalid_count:
            logger.warning(
                "Skipping malformed feature vectors before inference",
                invalid_count=invalid_count,
                expected_dim=len(self.feature_order) if self.feature_order else 77,
            )
        
        # 2. Inference
        t_infer_start = time.time()
        
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
                    # Pkl path — handle dimensionality mismatch between extraction and model
                    expected_dim = getattr(self.scaler, 'n_features_in_', X.shape[1])
                    if X.shape[1] != expected_dim:
                        logger.warning("Feature dimension mismatch, attempting to align", 
                                       extracted=X.shape[1], expected=expected_dim)
                        if X.shape[1] > expected_dim:
                            X = X[:, :expected_dim]
                        else:
                            X = np.pad(X, ((0, 0), (0, expected_dim - X.shape[1])), mode='constant')
                            
                    X_scaled = self.scaler.transform(X)
                    ml_scores_valid = self.rf_model.predict_proba(X_scaled)[:, 1]
                else:
                    ml_scores_valid = [0.0] * len(valid_features)
                
                for i, idx in enumerate(valid_indices):
                    ml_scores[idx] = float(ml_scores_valid[i])
                
                # 2b. VAE Anomaly Detection (Stage 3)
                # Only fires for samples where the RF is uncertain (ml_score < threshold).
                # This avoids wasting compute on high-confidence RF detections.
                batch_anomaly_scores = [0.0] * len(valid_features)
                if self.vae_detector and self.vae_detector.is_ready:
                    # Trigger VAE for samples where RF is uncertain (e.g. score < 0.5)
                    # This provides a second behavioral opinion on doubtful traffic.
                    uncertain_mask = np.array(ml_scores_valid, dtype=np.float32) < 0.5
                    if uncertain_mask.any():
                        X_uncertain = X[uncertain_mask]
                        
                        # 1. Get raw MSE and latent vectors
                        latents, mse_raw = self.vae_detector.get_latent_and_mse(X_uncertain)
                        
                        # 2. Update and get score from anomaly_scorer
                        # We also update global latent stats periodically
                        self.anomaly_scorer.update_latent_stats(latents)
                        
                        uncertain_positions = np.where(uncertain_mask)[0]
                        for pos_idx, pos in enumerate(uncertain_positions):
                            proto = events[valid_indices[pos]].get("proto") or "TCP"
                            score = self.anomaly_scorer.score(
                                mse=float(mse_raw[pos_idx]), 
                                latent_vector=latents[pos_idx],
                                protocol=proto
                            )
                            batch_anomaly_scores[pos] = score
                        
                        n_anomalies = int((np.array(batch_anomaly_scores)[uncertain_positions] > 0.5).sum())
                        if n_anomalies:
                            logger.info("VAE flagged potential anomalies",
                                        count=n_anomalies)
                valid_anomaly_scores = batch_anomaly_scores
                    
                # 2c. Batch SHAP (Performance optimization)
                batch_shap_results = {} # Index -> Top 3 features
                if self.shap_explainer:
                    try:
                        t_shap_start = time.time()
                        # Use scaled features for SHAP if available
                        X_shap = X_scaled if 'X_scaled' in locals() else X
                        
                        shap_vals = self.shap_explainer.shap_values(X_shap)
                        
                        # Standardize to 2D (N, M)
                        if isinstance(shap_vals, list):
                            pos_class_vals = shap_vals[1] if len(shap_vals) > 1 else shap_vals[0]
                        else:
                            pos_class_vals = shap_vals
                            
                        if hasattr(pos_class_vals, "ndim") and pos_class_vals.ndim == 3:
                            # Handle (N, M, 2) output from some shap versions
                            pos_class_vals = pos_class_vals[:, :, 1]

                        # Map back to original indices
                        for i, v_idx in enumerate(valid_indices):
                            vals = pos_class_vals[i]
                            indexed_features = []
                            for f_idx, v in enumerate(vals):
                                if f_idx < len(self.feature_order):
                                    indexed_features.append({
                                        "feature": self.feature_order[f_idx],
                                        "impact": float(abs(v))
                                    })
                            indexed_features.sort(key=lambda x: x["impact"], reverse=True)
                            batch_shap_results[v_idx] = indexed_features[:3]

                        shap_ms = (time.time() - t_shap_start) * 1000
                        logger.debug("Batch SHAP calculated", 
                                     total_ms=round(shap_ms, 2), 
                                     per_event_ms=round(shap_ms/len(valid_features), 2))
                    except Exception as e:
                        logger.warning("Batch SHAP failed", error=str(e))

            except Exception as e:
                logger.error("Batch inference failed", error=str(e))
                valid_anomaly_scores = [0.0] * len(valid_features)
        else:
            valid_anomaly_scores = []
        
        infer_ms = (time.time() - t_infer_start) * 1000
        
        # 3. Final Decision & Assembly
        t_decide_start = time.time()
        batch_count = len(events)
        for i, event in enumerate(events):
            sig_present = (event.get("event_type") == "alert")
            
            # Layer 3: Anomaly (Real)
            anomaly_score = 0.0
            v_idx = valid_index_map.get(i)
            if v_idx is not None and v_idx < len(valid_anomaly_scores):
                anomaly_score = valid_anomaly_scores[v_idx]
            
            shap_top3 = batch_shap_results.get(i, [])
            
            res = {
                "prediction": "unknown", # placeholder
                "ml_score": round(float(ml_scores[i]), 4),
                "anomaly_score": round(float(anomaly_score), 4),
                "sig_present": sig_present,
                "shap_top3": shap_top3
            }

            classification, normalized_score = self.decision_engine.decide(
                sig_present, ml_scores[i], anomaly_score, 0.0, res
            )
            
            res.update({
                "prediction": classification,
                "confidence": round(float(normalized_score) * 100, 2),
                "final_score": round(float(normalized_score), 4),
                "model_version": self.meta.get("model_version", "v3.0"),
                "latency": {
                    "extract_ms": round(extract_ms / batch_count, 2),
                    "infer_ms": round(infer_ms / batch_count, 2),
                    "total_ms": round((time.time() - start_time) * 1000 / batch_count, 2)
                }
            })
            results.append(res)
            
        return results

    def _get_shap_top3(self, features: Optional[List[float]]) -> List[Dict[str, Any]]:
        """
        Legacy single-event SHAP helper. Now deprecated in favor of batched SHAP.
        """
        if features is None or not self.shap_explainer or not self.feature_order:
            return []
            
        try:
            X = np.array(features).reshape(1, -1)
            shap_vals = self.shap_explainer.shap_values(X)
            
            if isinstance(shap_vals, list):
                vals = shap_vals[1][0] if len(shap_vals) > 1 else shap_vals[0][0]
            else:
                vals = shap_vals[0] if shap_vals.ndim == 2 else shap_vals

            indexed_features = []
            for i, v in enumerate(vals):
                if i < len(self.feature_order):
                    indexed_features.append({
                        "feature": self.feature_order[i],
                        "impact": float(abs(v))
                    })
            
            indexed_features.sort(key=lambda x: x["impact"], reverse=True)
            return indexed_features[:3]
            
        except Exception:
            return []
