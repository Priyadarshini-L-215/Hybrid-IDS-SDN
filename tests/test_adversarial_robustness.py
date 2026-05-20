import pytest
from src.ml_engine.adversarial_guard import AdversarialGuard
from src.ml_engine.decision_engine import DecisionEngine

@pytest.fixture
def base_http_event():
    return {
        "event_type": "flow",
        "proto": "TCP",
        "app_proto": "http",
        "flow": {
            "pkts_toserver": 10,
            "pkts_toclient": 10,
            "bytes_toserver": 2000,
            "bytes_toclient": 5000,
            "age": 5.0
        }
    }

def test_adversarial_guard_clean_traffic(base_http_event):
    """Clean HTTP traffic should not flag any evasion indicator."""
    guard = AdversarialGuard()
    score, reasons = guard.detect_evasion(base_http_event)
    
    assert score == 0.0
    assert len(reasons) == 0

def test_adversarial_guard_payload_dilution():
    """HTTP flow with large packet count but extremely tiny average bytes should flag payload dilution."""
    diluted_event = {
        "event_type": "flow",
        "proto": "TCP",
        "app_proto": "http",
        "flow": {
            "pkts_toserver": 100,
            "pkts_toclient": 100,
            "bytes_toserver": 500,
            "bytes_toclient": 500,
            "age": 10.0
        }
    }
    guard = AdversarialGuard()
    score, reasons = guard.detect_evasion(diluted_event)
    
    assert score >= 0.4
    assert "suspicious_payload_dilution" in reasons

def test_adversarial_guard_impossible_payload_ratio():
    """TCP flow with massive bytes in a small number of packets should flag impossible ratio."""
    anomalous_event = {
        "event_type": "flow",
        "proto": "TCP",
        "app_proto": "http",
        "flow": {
            "pkts_toserver": 1,
            "pkts_toclient": 1,
            "bytes_toserver": 10000,
            "bytes_toclient": 10000,
            "age": 2.0
        }
    }
    guard = AdversarialGuard()
    score, reasons = guard.detect_evasion(anomalous_event)
    
    assert score >= 0.5
    assert "impossible_packet_payload_ratio" in reasons

def test_adversarial_guard_timing_evasion():
    """High-latency DNS flow with negligible packet activity should flag timing evasion."""
    slowloris_event = {
        "event_type": "flow",
        "proto": "UDP",
        "app_proto": "dns",
        "flow": {
            "pkts_toserver": 2,
            "pkts_toclient": 2,
            "bytes_toserver": 100,
            "bytes_toclient": 100,
            "age": 150.0
        }
    }
    guard = AdversarialGuard()
    score, reasons = guard.detect_evasion(slowloris_event)
    
    assert score >= 0.4
    assert "stealth_timing_evasion" in reasons

def test_decision_engine_integration_evasion(base_http_event):
    """DecisionEngine should boost the classification to attack and set confidence >= 95% if evasion is present."""
    evasive_event = {
        "event_type": "flow",
        "proto": "TCP",
        "app_proto": "http",
        "flow": {
            "pkts_toserver": 1,
            "pkts_toclient": 1,
            "bytes_toserver": 10000,
            "bytes_toclient": 10000,
            "age": 2.0
        }
    }
    
    engine = DecisionEngine()
    prediction_result = {
        "prediction": "unknown",
        "ml_score": 0.05,
        "anomaly_score": 0.1,
        "sig_present": False,
        "shap_top3": []
    }
    
    classification, confidence = engine.decide(
        sig_present=False,
        ml_score=0.05,
        anomaly_score=0.1,
        cti_score=0.0,
        prediction=prediction_result,
        event=evasive_event
    )
    
    assert classification == "attack"
    assert confidence >= 0.95
    assert prediction_result["adversarial_score"] >= 0.5
    assert "impossible_packet_payload_ratio" in prediction_result["evasion_reasons"]
