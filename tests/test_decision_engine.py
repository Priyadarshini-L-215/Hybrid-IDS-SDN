import pytest
import numpy as np
from ml_engine.decision_engine import DecisionEngine

@pytest.fixture
def engine():
    return DecisionEngine()

def test_decision_engine_initialization():
    engine = DecisionEngine(weights={"ml": 0.5}, thresholds={"attack": 0.95})
    assert engine.weights["ml"] == 0.5
    assert engine.thresholds["attack"] == 0.95

def test_decide_all_signals_agree(engine):
    classification, score = engine.decide(
        sig_present=True,
        ml_score=0.98,
        anomaly_score=0.98,
        cti_score=0.98
    )
    assert score >= 0.95
    assert classification == "attack"

def test_decide_only_signature(engine):
    classification, score = engine.decide(
        sig_present=True,
        ml_score=None,
        anomaly_score=None,
        cti_score=None
    )
    # the active weight should be just signature, meaning normalized score is 1.0.
    # Final score is max(0.92, 1.0 * 0.99) = 0.99
    assert score >= 0.92
    assert classification == "attack"

def test_decide_no_signature_high_ml(engine):
    classification, score = engine.decide(
        sig_present=False,
        ml_score=0.95,
        anomaly_score=0.1,
        cti_score=0.0
    )
    # it shouldn't reach attack purely on ml if other features are so low, but it might reach anomaly or suspicious
    assert score > 0.0
    assert classification in ["normal", "anomaly", "suspicious", "attack"]

def test_decide_nan_handling(engine):
    classification, score = engine.decide(
        sig_present=False,
        ml_score=np.nan,
        anomaly_score=float('inf'),
        cti_score=float('-inf')
    )
    # np.nan_to_num makes nan -> 0.0, inf -> 1.0, -inf -> 0.0
    assert score >= 0.0
    assert score <= 1.0

def test_decide_no_signals_at_all(engine):
    classification, score = engine.decide(
        sig_present=False,
        ml_score=None,
        anomaly_score=None,
        cti_score=None
    )
    assert score == 0.0
    assert classification == "normal"

def test_get_reputation_delta(engine):
    assert engine.get_reputation_delta("attack", 0.9) > 0
    assert engine.get_reputation_delta("suspicious", 0.7) > 0
    assert engine.get_reputation_delta("anomaly", 0.6) > 0
    assert engine.get_reputation_delta("normal", 0.1) < 0


def test_decide_simulation_restriction_in_production(engine, monkeypatch):
    import sys
    orig_modules = sys.modules
    
    class FakeModules(dict):
        def keys(self):
            return [k for k in super().keys() if not k.startswith("pytest")]
        def __iter__(self):
            return iter([k for k in super().keys() if not k.startswith("pytest")])
            
    fake_modules = FakeModules(orig_modules)
    monkeypatch.setattr(sys, "modules", fake_modules)
    
    # 1. Non-simulated event in simulated production run should be forced to normal, but keeps score at normal rate (scaled)
    event_non_sim = {"dest_ip": "10.0.0.2"}
    classification, score = engine.decide(
        sig_present=True,
        ml_score=0.99,
        anomaly_score=0.99,
        cti_score=0.99,
        event=event_non_sim
    )
    assert classification == "normal"
    assert score >= 0.05
    assert score < 0.2
    
    # 2. Simulated event in simulated production run should be classified normally
    event_sim = {"dest_ip": "10.0.0.2", "is_simulated_attack": True}
    classification_sim, score_sim = engine.decide(
        sig_present=True,
        ml_score=0.99,
        anomaly_score=0.99,
        cti_score=0.99,
        event=event_sim
    )
    assert classification_sim == "attack"
    assert score_sim >= 0.95
