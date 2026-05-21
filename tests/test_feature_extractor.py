import pytest
import json
import numpy as np
from pathlib import Path
from src.common.feature_extractor import extract_features_from_eve, validate_feature_vector, load_feature_names, DEFAULT_FEATURES

@pytest.fixture
def mock_flow_event():
    return {
        "event_type": "flow",
        "proto": "TCP",
        "src_ip": "192.168.1.10",
        "dest_ip": "8.8.8.8",
        "src_port": 12345,
        "dest_port": 80,
        "app_proto": "http",
        "flow": {
            "pkts_toserver": 10,
            "pkts_toclient": 5,
            "bytes_toserver": 1000,
            "bytes_toclient": 500,
            "age": 10
        },
        "tcp": {
            "syn": True,
            "ack": True,
            "window": 1024
        }
    }

async def test_extract_features_basic(mock_flow_event):
    features = DEFAULT_FEATURES
    vector = await extract_features_from_eve(mock_flow_event, features)
    
    assert vector is not None
    assert len(vector) == 49
    assert validate_feature_vector(vector) is True
    
    # Check some specific values
    # Protocol index (last feature 'app_proto' in V4?)
    # Wait, let's check the list: 'flow_duration' is first.
    assert vector[0] == 10000.0  # 10s * 1000 = 10000ms
    
    # Packets
    assert vector[1] == 10.0 # total_fwd_packets
    assert vector[2] == 5.0  # total_bwd_packets
    
    # Bytes
    assert vector[3] == 1000.0 # total_fwd_bytes
    assert vector[4] == 500.0  # total_bwd_bytes

async def test_extract_features_zero_pkts():
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
    vector = await extract_features_from_eve(event, features=DEFAULT_FEATURES)
    assert vector is not None
    
    # dload = (bwd_bytes * 8) / max(age, 0.001) = (500 * 8) / 5 = 800.0
    idx_dload = DEFAULT_FEATURES.index("dload")
    assert vector[idx_dload] == 800.0

async def test_protocol_mapping():
    # Test known protocol
    # In V4, app_proto is encoded at the end
    event_http = {"event_type": "flow", "app_proto": "http", "flow": {}}
    vector_http = await extract_features_from_eve(event_http, features=DEFAULT_FEATURES)
    # app_proto is the last feature (index 48)
    # We don't know the exact encoding without the model, but it should be a float
    assert isinstance(vector_http[48], float)

def test_fallback_mechanism(tmp_path):
    # Test with non-existent file
    missing_path = tmp_path / "non_existent.json"
    features = load_feature_names(missing_path)
    assert features == DEFAULT_FEATURES

async def test_feature_list_mismatch():
    # Test with wrong number of features
    event = {"event_type": "flow", "flow": {}}
    # Pass a short list of features
    short_features = ["flow_duration", "total_fwd_packets"]
    vector = await extract_features_from_eve(event, short_features)
    assert len(vector) == 2
    # validate_feature_vector(vector, expected_dim=49) should be False
    assert validate_feature_vector(vector, expected_dim=49) is False

async def test_tcp_window_handling():
    # Test with tcp window in event
    event = {
        "event_type": "flow",
        "tcp": {
            "window": 8192
        },
        "flow": {}
    }
    vector = await extract_features_from_eve(event, features=DEFAULT_FEATURES)
    
    idx_swin = DEFAULT_FEATURES.index("swin")
    idx_dwin = DEFAULT_FEATURES.index("dwin")
    
    assert vector[idx_swin] == 8192.0
    assert vector[idx_dwin] == 8192.0
