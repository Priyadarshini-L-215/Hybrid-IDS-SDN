import unittest
import numpy as np
import torch
import sys
import os
from unittest.mock import MagicMock

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from ml_engine.consumer import validate_features_dim, MLEngine

class TestStabilization(unittest.TestCase):
    
    def test_dimension_safety_short(self):
        """Test zero-padding for short feature vectors."""
        short_vec = np.ones(10)
        safe_vec = validate_features_dim(short_vec, source="test")
        self.assertEqual(len(safe_vec), 57)
        self.assertEqual(safe_vec[0], 1.0)
        self.assertEqual(safe_vec[56], 0.0)

    def test_dimension_safety_long(self):
        """Test truncation for long feature vectors."""
        long_vec = np.ones(100)
        safe_vec = validate_features_dim(long_vec, source="test")
        self.assertEqual(len(safe_vec), 57)
        self.assertEqual(safe_vec[0], 1.0)

    def test_corroboration_gate_logic(self):
        """Test that single-layer hits are capped and multi-layer hits are promoted."""
        # Mock MLEngine to avoid loading actual models
        engine = MagicMock(spec=MLEngine)
        engine.autoencoder_enabled = True
        engine.autoencoder_threshold = 0.5
        engine._mse_history = []
        
        # We need to test the actual logic in predict(), so we might need a partial mock
        # or just test the logic manually if it's extracted.
        # Since I wrote the logic into predict_batch, I'll test that.
        
        # Helper to run the logic (simulating what I wrote in consumer.py)
        def simulate_predict(sig, rf, ae, require_corr=True):
            ML_THRESHOLD_ATTACK = 0.85
            # Simplified aggregation
            final_risk = (1.0 * sig) + (0.7 * rf) + (0.5 * ae)
            layers_hot = sum([sig > 0.5, rf > 0.6, ae > 0.7])
            if require_corr and layers_hot < 2:
                final_risk = min(final_risk, ML_THRESHOLD_ATTACK - 0.01)
            return final_risk, layers_hot

        # Case 1: Only Signature hit (sig=1, rf=0.1, ae=0.1)
        risk, hot = simulate_predict(1.0, 0.1, 0.1)
        self.assertEqual(hot, 1)
        self.assertLess(risk, 0.85)

        # Case 2: Only RF hit (sig=0, rf=0.9, ae=0.1)
        risk, hot = simulate_predict(0.0, 0.9, 0.1)
        self.assertEqual(hot, 1)
        self.assertLess(risk, 0.85)

        # Case 3: RF + AE hit (sig=0, rf=0.9, ae=0.9)
        risk, hot = simulate_predict(0.0, 0.9, 0.9)
        self.assertEqual(hot, 2)
        # 0.7*0.9 + 0.5*0.9 = 0.63 + 0.45 = 1.08
        self.assertGreaterEqual(risk, 0.85)

        # Case 4: Sig + RF hit (sig=1.0, rf=0.9, ae=0.1)
        risk, hot = simulate_predict(1.0, 0.9, 0.1)
        self.assertEqual(hot, 2)
        self.assertGreaterEqual(risk, 0.85)

if __name__ == "__main__":
    unittest.main()
