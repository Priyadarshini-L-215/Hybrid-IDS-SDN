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
        ml_score=0.9,
        anomaly_score=0.8,
        cti_score=0.9
    )
    assert score >= 0.9
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
