import pytest
import json
from pathlib import Path
from src.common.feature_extractor import extract_features_from_eve, validate_feature_vector, load_feature_names, DEFAULT_FEATURES

@pytest.fixture
def mock_flow_event():
    return {
        "event_type": "flow",
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 10,
            "pkts_toclient": 5,
            "bytes_toserver": 1000,
            "bytes_toclient": 500,
            "age": 10
        },
        "tcp": {
            "syn": True,
            "ack": True
        }
    }

def test_extract_features_basic(mock_flow_event):
    features = load_feature_names()
    vector = extract_features_from_eve(mock_flow_event, features)
    
    assert vector is not None
    assert len(vector) == 77
    assert validate_feature_vector(vector) is True
    
    # Check some specific values
    # Protocol index (0 for Protocol)
    assert vector[0] == 6.0  # TCP
    
    # Down/Up Ratio (51 index if 0-based, or check feature name)
    # feature_dict["Down/Up Ratio"] = bwd_pkts / fwd_pkts = 5 / 10 = 0.5
    # Wait, let's find the index
    idx = features.index("Down/Up Ratio")
    assert vector[idx] == 0.5

def test_extract_features_zero_pkts():
    event = {
        "event_type": "flow",
        "proto": "UDP",
        "flow": {
            "pkts_toserver": 0,
            "pkts_toclient": 5,
            "bytes_toserver": 0,
            "bytes_toclient": 500,
            "age": 5
        }
    }
    vector = extract_features_from_eve(event)
    assert vector is not None
    
    idx = DEFAULT_FEATURES.index("Down/Up Ratio")
    # bwd_pkts = 5, fwd_pkts = 0 -> ratio should be 0.0
    assert vector[idx] == 0.0
    
    # Fwd Packet Length Mean (fwd_bytes / max(fwd_pkts, 1)) -> 0 / 1 = 0.0
    idx_mean = DEFAULT_FEATURES.index("Fwd Packet Length Mean")
    assert vector[idx_mean] == 0.0

def test_protocol_mapping():
    # Test known protocol
    event_udp = {"event_type": "flow", "proto": "UDP", "flow": {}}
    vector_udp = extract_features_from_eve(event_udp)
    assert vector_udp[0] == 17.0
    
    # Test unknown protocol
    event_unk = {"event_type": "flow", "proto": "UNKNOWN_PROTO", "flow": {}}
    vector_unk = extract_features_from_eve(event_unk)
    assert vector_unk[0] == 255.0

def test_fallback_mechanism(tmp_path):
    # Test with non-existent file
    missing_path = tmp_path / "non_existent.json"
    features = load_feature_names(missing_path)
    assert features == DEFAULT_FEATURES
    
    # Test with invalid JSON
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("invalid json content")
    features_invalid = load_feature_names(invalid_json)
    assert features_invalid == DEFAULT_FEATURES

def test_feature_list_mismatch():
    # Test with wrong number of features
    event = {"event_type": "flow", "flow": {}}
    # Pass a short list of features
    short_features = ["Protocol", "Flow Duration"]
    vector = extract_features_from_eve(event, short_features)
    assert len(vector) == 2
    assert validate_feature_vector(vector) is False

def test_tcp_window_fallback():
    # Test with tcp window in event
    event = {
        "event_type": "flow",
        "tcp": {
            "fwd_window_size": 1024,
            "bwd_window_size": 2048
        },
        "flow": {}
    }
    vector = extract_features_from_eve(event)
    
    idx_fwd = DEFAULT_FEATURES.index("Init Fwd Win Bytes")
    idx_bwd = DEFAULT_FEATURES.index("Init Bwd Win Bytes")
    
    assert vector[idx_fwd] == 1024.0
    assert vector[idx_bwd] == 2048.0
