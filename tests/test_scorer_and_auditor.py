import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
import numpy as np
from ml_engine.anomaly_scorer import AnomalyScorer
from ml_engine.mitigation_auditor import MitigationAuditor
from ml_engine.firewall import ActiveFirewall

def test_anomaly_scorer_running_percentile():
    """Verify that AnomalyScorer updates dynamic threshold via Robbins-Monro."""
    scorer = AnomalyScorer(percentile=99.5, min_samples=10)
    
    # Check baseline initial state
    assert scorer._dynamic_threshold("TCP") == float("inf")
    
    # Seed samples
    for i in range(15):
        scorer._get_window("TCP").append(float(i) * 0.01)
        
    # Initial compute
    t_initial = scorer._dynamic_threshold("TCP")
    assert t_initial != float("inf")
    assert t_initial > 0
    
    # Run a Robbins-Monro update with a larger value, which should increase threshold slightly
    scorer._update_running_percentile("TCP", t_initial + 1.0)
    t_new = scorer._dynamic_threshold("TCP")
    assert t_new > t_initial

def test_anomaly_scorer_calibrate_on_fp():
    """Verify that calibrate_on_fp boosts VAE threshold on false positive feedback."""
    scorer = AnomalyScorer(percentile=99.5, min_samples=10)
    for i in range(15):
        scorer._get_window("TCP").append(float(i) * 0.01)
        
    t_initial = scorer._dynamic_threshold("TCP")
    
    # Trigger FP calibration on a high MSE value
    high_mse = t_initial * 2.0
    scorer.calibrate_on_fp("TCP", high_mse)
    
    t_calibrated = scorer._dynamic_threshold("TCP")
    assert t_calibrated == pytest.approx(high_mse * 1.05)

@pytest.mark.asyncio
async def test_mitigation_auditor_compliance_and_self_healing():
    """Verify that MitigationAuditor correctly identifies and self-heals missing rules."""
    auditor = MitigationAuditor(interval_seconds=1)
    
    # Mock ActiveFirewall status and compliance state
    mock_status = {
        "permanent_ips": [],
        "temporary_ips": [],
        "reputation": {"1.1.1.1": 30.0},  # offender (above threshold 25)
        "final_blocked_ips": ["2.2.2.2"],  # operator manual block
        "whitelisted_ips": []
    }
    
    with patch.object(ActiveFirewall, "get_detailed_status", return_value=mock_status), \
         patch.object(ActiveFirewall, "block", new_callable=AsyncMock) as mock_block, \
         patch.object(auditor, "_audit_kernel_structures", return_value=True):
         
        # Run audit cycle
        await auditor.audit_mitigations()
        
        # Verify self-healing block rules were triggered for missing IPs
        assert mock_block.call_count == 2
        mock_block.assert_any_call("1.1.1.1", ttl=300)  # rep offender -> temp block (300s)
        mock_block.assert_any_call("2.2.2.2", ttl=0)    # operator manual block -> perm block (ttl=0)
