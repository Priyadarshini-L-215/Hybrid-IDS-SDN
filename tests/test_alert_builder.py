import pytest
import uuid
from src.common.alert_builder import safe_float, normalize_signature, build_alert_payload

def test_safe_float():
    assert safe_float(1.5) == 1.5
    assert safe_float("2.0") == 2.0
    assert safe_float(None) == 0.0
    assert safe_float("") == 0.0
    assert safe_float("invalid") == 0.0

    # Test float('inf') and float('nan')
    import math
    assert safe_float(float('inf')) == 0.0
    assert safe_float(float('-inf')) == 0.0
    assert safe_float(float('nan')) == 0.0

def test_normalize_signature():
    assert normalize_signature(None) is None
    assert normalize_signature("") == ""

    # Test mapping
    assert normalize_signature("SURICATA ICMPv4 unknown code") == "Invalid ICMPv4 Code (Decoder Anomaly)"

    # Test fallback
    assert normalize_signature("SURICATA test_signature_here") == "Test Signature Here"

    # Test regular signature
    assert normalize_signature("Regular Signature") == "Regular Signature"

def test_build_alert_payload_basic():
    event = {
        "event_type": "alert",
        "timestamp": "2023-01-01T12:00:00Z",
        "src_ip": "192.168.1.1",
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 80,
        "proto": "TCP",
        "alert": {
            "signature": "SURICATA TCP invalid header length",
            "severity": 2,
            "category": "Protocol Anomaly"
        }
    }

    prediction = {
        "classification": "attack",
        "confidence": 0.95,
        "ml_score": 0.96,
        "anomaly_score": 0.1,
        "duplicate_count": 3,
        "shap_top3": ["feature1", "feature2", "feature3"]
    }

    event_id = str(uuid.uuid4())

    payload = build_alert_payload(event, prediction, event_id=event_id)

    assert payload["event_id"] == event_id
    assert payload["timestamp"] == "2023-01-01T12:00:00Z"
    assert payload["event_type"] == "alert"
    assert payload["src_ip"] == "192.168.1.1"
    assert payload["dst_ip"] == "10.0.0.1"
    assert payload["src_port"] == 12345
    assert payload["dst_port"] == 80
    assert payload["protocol"] == "TCP"
    assert payload["alert_sig"] == "Invalid TCP Header Length"
    assert payload["prediction"] == "attack"
    assert payload["confidence"] == 95.0
    assert payload["severity"] == 2
    assert payload["category"] == "Protocol Anomaly"
    assert payload["sig_present"] is True
    assert payload["duplicate_count"] == 3
    assert payload["shap_top3"] == ["feature1", "feature2", "feature3"]
    assert payload["anomaly_score"] == 0.1
    assert payload["forensics"]["stage_scores"]["signature"] == 1.0
    assert payload["forensics"]["stage_scores"]["ml"] == 0.96

def test_build_alert_payload_dns_fallback():
    event = {
        "event_type": "dns",
        "dns": {
            "rrname": "example.com"
        }
    }
    prediction = {
        "classification": "normal",
        "confidence": 99.0  # test > 1.0 logic
    }

    payload = build_alert_payload(event, prediction)

    # We didn't provide event_id, it should generate one
    assert "event_id" in payload
    assert isinstance(payload["event_id"], str)

    # Confidence should be normalized and then converted back to percentage format
    # The logic: final_confidence > 1.0 -> final_confidence = final_confidence / 100.0 (0.99)
    # Then: round(final_confidence * 100, 2) -> 99.0
    assert payload["confidence"] == 99.0
    assert payload["alert_sig"] == "DNS Query: example.com"
    assert payload["sig_present"] is False
    assert payload["prediction"] == "normal"
    assert payload["forensics"]["stage_scores"]["signature"] == 0.0

def test_build_alert_payload_http_fallback():
    event = {
        "event_type": "http",
        "http": {
            "http_method": "GET",
            "hostname": "test.local"
        }
    }
    prediction = {}

    payload = build_alert_payload(event, prediction)
    assert payload["alert_sig"] == "HTTP GET -> test.local"
    assert payload["prediction"] == "normal"

def test_build_alert_payload_ssh_fallback():
    event = {
        "event_type": "ssh"
    }
    prediction = {}

    payload = build_alert_payload(event, prediction)
    assert payload["alert_sig"] == "SSH Connection Attempt"

def test_build_alert_payload_generic_flow():
    event = {
        "event_type": "flow",
        "proto": "UDP",
        "dst_port": 53
    }

    # Normal flow
    prediction_normal = {"classification": "normal"}
    payload_normal = build_alert_payload(event, prediction_normal)
    assert payload_normal["alert_sig"] == "UDP Flow"

    # Malicious flow
    prediction_attack = {"classification": "suspicious"}
    payload_attack = build_alert_payload(event, prediction_attack)
    assert payload_attack["alert_sig"] == "UDP Potential Probe (Port 53)"


def test_build_alert_payload_low_confidence_normalization():
    event = {
        "event_type": "flow",
        "proto": "UDP",
        "dst_port": 53
    }
    # Test case representing a flow with a real confidence of 0.76% (final_score = 0.0076)
    prediction = {
        "classification": "normal",
        "confidence": 0.76,
        "final_score": 0.0076
    }
    payload = build_alert_payload(event, prediction)
    assert payload["confidence"] == 0.76

