import os
import sys
from pathlib import Path

import numpy as np
import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

os.environ.setdefault("KERAS_BACKEND", "torch")

from ml_engine.vae_detector import VaeAnomalyDetector


def test_vae_detector_loads_and_scores():
    encoder_path = PROJECT_ROOT / "models" / "vae_encoder.keras"
    decoder_path = PROJECT_ROOT / "models" / "vae_decoder.keras"
    scaler_path = PROJECT_ROOT / "models" / "vae_scaler.pkl"

    if not (encoder_path.exists() and decoder_path.exists() and scaler_path.exists()):
        pytest.skip("VAE artifacts are not available")

    detector = VaeAnomalyDetector(
        encoder_path=encoder_path,
        decoder_path=decoder_path,
        scaler_path=scaler_path,
        threshold=0.3,
    )

    assert detector.is_ready

    sample = np.random.rand(4, 49).astype(np.float32)
    scores = detector.score(sample)

    assert scores.shape == (4,)
    assert np.isfinite(scores).all()