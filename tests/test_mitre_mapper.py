import pytest
from src.common.mitre_mapper import get_mitre_info, MITRE_MAPPING

def test_get_mitre_info_prediction():
    info = get_mitre_info("DDoS")
    assert info == MITRE_MAPPING["predictions"]["DDoS"]

def test_get_mitre_info_signature():
    info = get_mitre_info("Unknown", signature="ET SCAN Potential SSH Scan")
    assert info == MITRE_MAPPING["signatures"]["ET SCAN"]

def test_get_mitre_info_fallback():
    info = get_mitre_info("Unknown", signature="Unknown")
    assert info == {
        "tactic": "Discovery",
        "technique": "Network Traffic Analysis",
        "id": "T1040",
        "description": "General network activity monitored for forensics."
    }

def test_get_mitre_info_prediction_priority():
    info = get_mitre_info("DDoS", signature="ET SCAN Potential SSH Scan")
    assert info == MITRE_MAPPING["predictions"]["DDoS"]
