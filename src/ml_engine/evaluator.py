import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
import structlog
from pathlib import Path
from typing import List, Dict, Any, Union, Optional
import io

logger = structlog.get_logger(__name__)

def validate_dataset(csv_source: Union[str, Path, io.BytesIO], expected_features: List[str]) -> Dict[str, Any]:
    """
    Checks if the dataset contains all required features for the current model.
    Supports both file paths and binary streams (for uploads).
    """
    try:
        # Read only the header to be efficient
        if isinstance(csv_source, (str, Path)):
            df_header = pd.read_csv(csv_source, nrows=0)
        else:
            csv_source.seek(0)
            df_header = pd.read_csv(csv_source, nrows=0)
            csv_source.seek(0)
            
        columns = [c.strip() for c in df_header.columns]
        missing = [f for f in expected_features if f not in columns]
        
        if missing:
            logger.warning("Dataset incompatible", missing_count=len(missing))
            return {
                "compatible": False, 
                "missing_features": missing,
                "total_expected": len(expected_features),
                "found_count": len(columns)
            }
            
        return {
            "compatible": True, 
            "column_count": len(columns),
            "total_expected": len(expected_features)
        }
    except Exception as e:
        logger.error("Dataset validation failed", error=str(e))
        return {"compatible": False, "error": str(e)}

def evaluate_dataset(csv_source: Union[str, Path, io.BytesIO], ml_engine, label_column: str = "Label") -> Dict[str, Any]:
    """
    Runs full batch inference on a dataset and computes classification metrics.
    """
    try:
        logger.info("Starting dataset evaluation", label_col=label_column)
        
        if isinstance(csv_source, (str, Path)):
            df = pd.read_csv(csv_source)
        else:
            csv_source.seek(0)
            df = pd.read_csv(csv_source)
            
        # Clean column names (remove whitespace)
        df.columns = [c.strip() for c in df.columns]
        
        if label_column not in df.columns:
            logger.error("Label column missing", expected=label_column)
            return {"success": False, "error": f"Label column '{label_column}' not found in dataset."}
            
        # 1. Alignment & Feature Extraction
        # Ensure we only use the features the model expects, in the correct order
        try:
            X = df[ml_engine.feature_order].values.astype(np.float32)
        except KeyError as e:
            return {"success": False, "error": f"Missing features in dataset: {str(e)}"}
            
        y_true = df[label_column].values
        
        # 2. Batch Inference
        ml_scores = []
        if ml_engine.rf_session:
             inputs = {ml_engine.rf_session.get_inputs()[0].name: X}
             outputs = ml_engine.rf_session.run(None, inputs)
             if isinstance(outputs[1], list):
                 ml_scores = [d[1] for d in outputs[1]]
             else:
                 ml_scores = outputs[1][:, 1]
        elif ml_engine.rf_model and ml_engine.scaler:
             X_df = pd.DataFrame(X, columns=ml_engine.feature_order)
             X_scaled = ml_engine.scaler.transform(X_df)
             ml_scores = ml_engine.rf_model.predict_proba(X_scaled)[:, 1]
        else:
             return {"success": False, "error": "ML Engine models are not loaded or ready."}

        # 3. Decision Logic (Classification)
        predictions = []
        
        # Pre-calculate anomaly scores if available
        anomaly_scores = np.zeros(len(X))
        if ml_engine.vae_detector and ml_engine.vae_detector.is_ready:
            logger.info("Calculating VAE anomaly scores for evaluation")
            anomaly_scores = ml_engine.vae_detector.score(X)

        for i, score in enumerate(ml_scores):
            classification, _ = ml_engine.decision_engine.decide(
                sig_present=False, 
                ml_score=float(score),
                anomaly_score=float(anomaly_scores[i])
            )
            
            # Map to binary labels for comparison with dataset
            if classification in ["attack", "suspicious", "anomaly"]:
                predictions.append("attack")
            else:
                predictions.append("normal")
            
        # 4. Metrics Generation
        # Map labels if necessary (e.g. if dataset uses 0/1 but model uses normal/attack)
        y_true_mapped = []
        for val in y_true:
            v_str = str(val).lower()
            if v_str in ["0", "0.0", "normal", "benign"]:
                y_true_mapped.append("normal")
            elif v_str in ["1", "1.0", "attack", "malicious", "anomaly"]:
                y_true_mapped.append("attack")
            else:
                y_true_mapped.append(v_str)
        
        unique_true = set(y_true_mapped)
        unique_pred = set(predictions)
        logger.info("Labels found", true=unique_true, pred=unique_pred)
        
        # Ensure they are all strings to avoid sklearn type mixing errors
        y_true_final = [str(x) for x in y_true_mapped]
        pred_final = [str(x) for x in predictions]
        
        report = classification_report(y_true_final, pred_final, output_dict=True, zero_division=0)
        
        # Calculate confusion matrix values safely
        try:
            tn, fp, fn, tp = confusion_matrix(y_true_final, pred_final, labels=["normal", "attack"]).ravel()
            
            # Inject counts into metrics dict for the frontend confusion matrix display
            if "normal" not in report:
                report["normal"] = {}
            if "attack" not in report:
                report["attack"] = {}
                
            report["normal"]["tn"] = int(tn)
            report["normal"]["fp"] = int(fp)
            report["attack"]["fn"] = int(fn)
            report["attack"]["tp"] = int(tp)
        except Exception as cm_err:
            logger.warning("Failed to compute confusion matrix values", error=str(cm_err))
        
        return {
            "success": True,
            "metrics": report,
            "summary": {
                "total_samples": len(df),
                "accuracy": report.get("accuracy", 0),
                "model_version": ml_engine.meta.get("model_version", "v3.0")
            }
        }
        
    except Exception as e:
        logger.error("Dataset evaluation failed", error=str(e), exc_info=True)
        return {"success": False, "error": str(e)}
