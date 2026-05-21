import pytest
import time
import numpy as np
from unittest.mock import patch
from ml_engine.anomaly_scorer import AnomalyScorer

def test_anomaly_scorer_robust_scale_mse():
    """Verify that robust scaling uses MAD and Median correctly and handles outliers robustly."""
    scorer = AnomalyScorer(min_samples=10)
    
    # Pre-populate errors to establish distribution
    # Normal distribution with some huge outliers
    normal_errors = [1.0, 1.2, 0.9, 1.1, 1.3, 1.0, 0.8, 1.1, 1.2, 1.0]
    for err in normal_errors:
        scorer._get_window("tcp").append(err)
        
    # Standard deviation would be heavily impacted by an extreme outlier, but MAD is robust.
    # Check that robust scaling returns a score in [0, 1]
    score_normal = scorer.robust_scale_mse(1.0, "tcp")
    assert 0.0 <= score_normal <= 1.0
    
    score_outlier = scorer.robust_scale_mse(100.0, "tcp")
    assert score_outlier > score_normal
    assert score_outlier <= 1.0

def test_anomaly_scorer_quarantine_hold():
    """Verify that clean flows are held in quarantine for 60s before being merged into the baseline."""
    scorer = AnomalyScorer(min_samples=5)
    
    # Mock time.time to control the quarantine clock
    with patch("time.time") as mock_time:
        start_time = 1000.0
        mock_time.return_value = start_time
        
        # Minimum samples in window for dynamic threshold
        for i in range(5):
            scorer._get_window("tcp").append(0.5)
            
        latent = np.random.rand(10)
        
        # A normal flow (low score) should be quarantined
        score = scorer.score(mse=0.5, latent_vector=latent, protocol="tcp", src_ip="192.168.1.100")
        
        # Check it is in quarantine, not yet merged
        assert len(scorer._quarantine_queue) == 1
        assert scorer._quarantine_queue[0][4] == "192.168.1.100"
        
        # Advance time by 30 seconds (TTL is 60)
        mock_time.return_value = start_time + 30.0
        scorer.flush_quarantine()
        assert len(scorer._quarantine_queue) == 1  # Still quarantined
        
        # Advance time by 61 seconds (expired)
        mock_time.return_value = start_time + 61.0
        scorer.flush_quarantine()
        assert len(scorer._quarantine_queue) == 0  # Merged!

def test_anomaly_scorer_baseline_freeze_and_unfreeze():
    """Verify baseline update freezing and manual unfreezing works correctly."""
    scorer = AnomalyScorer(min_samples=5)
    
    for i in range(5):
        scorer._get_window("tcp").append(0.5)
        
    scorer.freeze_baseline()
    assert scorer._baseline_frozen is True
    
    latent = np.random.rand(10)
    scorer.score(mse=0.5, latent_vector=latent, protocol="tcp", src_ip="192.168.1.100")
    
    # Baseline frozen, so no new elements should be appended to the quarantine queue
    assert len(scorer._quarantine_queue) == 0
    
    scorer.unfreeze_baseline()
    assert scorer._baseline_frozen is False
    
    scorer.score(mse=0.5, latent_vector=latent, protocol="tcp", src_ip="192.168.1.100")
    assert len(scorer._quarantine_queue) == 1

def test_anomaly_scorer_retroactive_purge():
    """Verify that retroactive purging removes quarantined flows matching the target IP."""
    scorer = AnomalyScorer(min_samples=5)
    
    for i in range(5):
        scorer._get_window("tcp").append(0.5)
        
    latent = np.random.rand(10)
    scorer.score(mse=0.5, latent_vector=latent, protocol="tcp", src_ip="192.168.1.100")
    scorer.score(mse=0.5, latent_vector=latent, protocol="tcp", src_ip="192.168.1.200")
    
    assert len(scorer._quarantine_queue) == 2
    
    scorer.invalidate_quarantine_ip("192.168.1.100")
    
    # 192.168.1.100 should be removed, leaving only 192.168.1.200
    assert len(scorer._quarantine_queue) == 1
    assert scorer._quarantine_queue[0][4] == "192.168.1.200"

def test_anomaly_scorer_auto_unfreeze_cooldown():
    """Verify that a frozen baseline automatically unfreezes after a 300s silent cooldown."""
    scorer = AnomalyScorer(min_samples=5)
    
    for i in range(5):
        scorer._get_window("tcp").append(0.5)
        
    with patch("time.time") as mock_time:
        start_time = 1000.0
        mock_time.return_value = start_time
        
        scorer.freeze_baseline()
        assert scorer._baseline_frozen is True
        
        # Advance by 299s (should still be frozen)
        mock_time.return_value = start_time + 299.0
        scorer.flush_quarantine()
        assert scorer._baseline_frozen is True
        
        # Advance by 301s (should unfreeze)
        mock_time.return_value = start_time + 301.0
        scorer.flush_quarantine()
        assert scorer._baseline_frozen is False
