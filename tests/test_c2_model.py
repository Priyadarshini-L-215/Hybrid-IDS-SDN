import pytest
import numpy as np
from pathlib import Path

from ml_engine.engine import MLEngine
from common.feature_extractor import extract_features_from_eve, load_feature_names

@pytest.mark.asyncio
async def test_c2_feature_extraction():
    # Load feature names first to verify it includes ja3_present
    features = [
        'ja3_present', 'issuer_length', 'subject_length', 'certificate_serial_length',
        'certificate_fingerprint_length', 'certificate_validity_days', 'self_signed_flag',
        'tls_version', 'sni_dns_mismatch', 'domain_length', 'subdomain_depth',
        'dns_entropy', 'resolved_domain_count', 'dynamic_dns_indicator', 'dns_ttl',
        'user_agent_length', 'user_agent_entropy', 'hostname_length', 'url_length',
        'url_entropy', 'http_method_is_post', 'connection_frequency', 
        'repeated_destination_count', 'session_duration', 'beacon_interval_mean',
        'beacon_interval_std', 'packet_ratio', 'byte_ratio', 'is_standard_port'
    ]
    
    # 1. Test TLS event
    tls_event = {
        "event_type": "tls",
        "timestamp": "2026-06-07T12:00:00.000000+00:00",
        "src_ip": "192.168.1.50",
        "dest_ip": "10.0.0.99",
        "dest_port": 443,
        "tls": {
            "ja3": "771,4865-4866-4867,43-51-45-50-65281-23-35",
            "issuerdn": "CN=Test CA",
            "subject": "CN=malicious-c2.com",
            "serial": "12345678",
            "fingerprint": "a1b2c3d4e5f6",
            "notbefore": "2026-01-01T00:00:00",
            "notafter": "2027-01-01T00:00:00",
            "self_signed": False,
            "version": "TLS 1.3",
            "sni": "malicious-c2.com"
        }
    }
    
    vector = await extract_features_from_eve(tls_event, features)
    assert vector is not None
    assert len(vector) == 29
    
    # Check specific features
    feature_map = dict(zip(features, vector))
    assert feature_map['ja3_present'] == 1.0
    assert feature_map['issuer_length'] == len("CN=Test CA")
    assert feature_map['subject_length'] == len("CN=malicious-c2.com")
    assert feature_map['certificate_validity_days'] == 365.0
    assert feature_map['self_signed_flag'] == 0.0
    assert feature_map['tls_version'] == 1.3
    assert feature_map['is_standard_port'] == 1.0

    # 2. Test DNS event
    dns_event = {
        "event_type": "dns",
        "timestamp": "2026-06-07T12:00:01.000000+00:00",
        "src_ip": "192.168.1.50",
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "dns": {
            "query": "super.shady.dynamic-dns.ddns.net",
            "answers": [
                {"ttl": 300, "rdata": "1.2.3.4"}
            ]
        }
    }
    
    vector = await extract_features_from_eve(dns_event, features)
    assert vector is not None
    feature_map = dict(zip(features, vector))
    assert feature_map['domain_length'] == len("super.shady.dynamic-dns.ddns.net")
    assert feature_map['subdomain_depth'] == 4.0  # four dots
    assert feature_map['resolved_domain_count'] == 1.0
    assert feature_map['dynamic_dns_indicator'] == 1.0
    assert feature_map['dns_ttl'] == 300.0
    assert feature_map['is_standard_port'] == 0.0

@pytest.mark.asyncio
async def test_engine_load_and_predict():
    engine = MLEngine()
    assert engine.is_ready
    assert engine.stage_status["scaler"] == "loaded"
    assert engine.rf_model is not None
    assert engine.c2_model is not None
    
    # Run test prediction
    test_event = {
        "event_type": "tls",
        "timestamp": "2026-06-07T12:00:00.000000+00:00",
        "src_ip": "192.168.1.50",
        "dest_ip": "10.0.0.99",
        "dest_port": 443,
        "tls": {
            "ja3": "771,4865-4866-4867",
            "issuerdn": "CN=Test CA",
            "subject": "CN=malicious-c2.com",
            "serial": "12345678",
            "fingerprint": "a1b2c3d4e5f6",
            "self_signed": False,
            "version": "TLS 1.3",
            "sni": "malicious-c2.com"
        }
    }
    
    results = await engine.predict_batch([test_event])
    assert len(results) == 1
    assert "prediction" in results[0]
    assert "ml_score" in results[0]
    assert "c2_score" in results[0]
    assert results[0]["ml_score"] is not None
    assert results[0]["c2_score"] is not None
