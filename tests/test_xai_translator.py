import pytest
from src.common.xai_translator import translate_shap_to_text

def test_translate_shap_empty_normal():
    # Empty SHAP + normal prediction -> Baseline normal traffic
    res = translate_shap_to_text([], "normal", sig_present=False)
    assert "conforms to baseline patterns" in res
    assert "No anomalies detected" in res

def test_translate_shap_empty_signature_alert():
    # Empty SHAP + attack prediction + sig_present=True -> Signature alert
    res = translate_shap_to_text([], "attack", sig_present=True)
    assert "Flagged by rule-based signatures" in res
    assert "Explainable AI is not active" in res

def test_translate_shap_empty_vae_anomaly():
    # Empty SHAP + anomaly prediction + sig_present=False -> VAE Anomaly
    res = translate_shap_to_text([], "anomaly", sig_present=False)
    assert "zero-day anomaly" in res
    assert "VAE detector" in res

    res2 = translate_shap_to_text([], "zero-day anomaly", sig_present=False)
    assert "zero-day anomaly" in res2

def test_translate_shap_empty_ml_fallback():
    # Empty SHAP + attack prediction + sig_present=False -> ML Fallback
    res = translate_shap_to_text([], "attack", sig_present=False)
    assert "Machine learning model flagged this event" in res
    assert "Feature importance details are temporarily unavailable" in res

def test_translate_shap_low_impact_normal():
    # Near-zero impact SHAP + normal prediction -> Baseline normal traffic
    shap = [{"feature": "sbytes", "impact": 0.001}]
    res = translate_shap_to_text(shap, "normal", sig_present=False)
    assert "conforms to baseline patterns" in res

def test_translate_shap_low_impact_attack():
    # Near-zero impact SHAP + attack prediction -> No strongly anomalous features
    shap = [{"feature": "sbytes", "impact": 0.001}]
    res = translate_shap_to_text(shap, "attack", sig_present=False)
    assert "did not identify any strongly anomalous features" in res

def test_translate_shap_active_features():
    # Active SHAP features + attack prediction -> Feature explanation
    shap = [
        {"feature": "sbytes", "impact": 1.5},
        {"feature": "spkts", "impact": 0.8}
    ]
    res = translate_shap_to_text(shap, "attack")
    assert "Flagged primarily due to unusual patterns in source-to-destination byte volume" in res
    assert "Abnormal source-to-destination packet count also contributed" in res

    # Single feature
    res2 = translate_shap_to_text([{"feature": "spkts", "impact": 1.5}], "attack")
    assert "Flagged primarily due to unusual patterns in source-to-destination packet count" in res2
    assert "contributed" not in res2

def test_translate_shap_active_features_normal():
    # Active SHAP features + normal prediction
    shap = [{"feature": "sbytes", "impact": 1.5}]
    res = translate_shap_to_text(shap, "normal")
    assert "Traffic appears normal" in res
    assert "relied heavily on source-to-destination byte volume" in res
