#!/usr/bin/env python3
"""
Standalone tri-layer inference test.

This script validates:
1. Tri-layer artifacts can be loaded by MLEngine
2. Routing logic reaches all paths (normal, known attack, zero-day anomaly)
3. No tensor/shape errors occur with 57-feature vectors
"""

import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ml_engine.consumer import MLEngine  # noqa: E402


class IdentityScaler:
    def transform(self, x):
        return np.asarray(x, dtype=np.float32)


class RuleBasedRF:
    def __init__(self, flow_bytes_idx, flow_pkts_idx):
        self.flow_bytes_idx = flow_bytes_idx
        self.flow_pkts_idx = flow_pkts_idx

    def predict(self, x):
        x = np.asarray(x, dtype=np.float32)
        is_attack = (
            x[:, self.flow_bytes_idx] > 500000.0
        ) | (
            x[:, self.flow_pkts_idx] > 50000.0
        )
        return np.where(is_attack, 1, 0)

    def predict_proba(self, x):
        preds = self.predict(x)
        proba = []
        for pred in preds:
            if int(pred) == 1:
                proba.append([0.01, 0.99])
            else:
                proba.append([0.95, 0.05])
        return np.asarray(proba, dtype=np.float32)


class ThresholdAutoencoder(nn.Module):
    """Identity-like reconstruction with intentional failure for noisy vectors."""

    def __init__(self, noise_trigger=500000.0):
        super().__init__()
        self.noise_trigger = noise_trigger
        self.input_dim = 57

    def forward(self, x):
        high_noise = torch.max(torch.abs(x), dim=1, keepdim=True).values > self.noise_trigger
        zeros = torch.zeros_like(x)
        return torch.where(high_noise, zeros, x)


def _vector_from_feature_map(features, overrides):
    vec = np.zeros(len(features), dtype=np.float32)
    feature_index = {name: i for i, name in enumerate(features)}
    for name, value in overrides.items():
        if name in feature_index:
            vec[feature_index[name]] = float(value)
    return vec.tolist()


def main():
    print("[TriLayerTest] Initializing engine and loading artifacts...")
    engine = MLEngine()
    print(f"[TriLayerTest] RF: {engine.rf_model_path}")
    print(f"[TriLayerTest] Scaler: {engine.scaler_path}")
    print(f"[TriLayerTest] Autoencoder: {engine.autoencoder_path}")

    # Deterministic routing test: keep predict() path, replace model objects with test doubles.
    feature_index = {name: i for i, name in enumerate(engine.features)}
    flow_bytes_idx = feature_index.get("Flow Bytes/s")
    flow_pkts_idx = feature_index.get("Flow Packets/s")
    if flow_bytes_idx is None or flow_pkts_idx is None:
        raise RuntimeError("Required features not found: 'Flow Bytes/s' and 'Flow Packets/s'")

    engine.scaler = IdentityScaler()
    engine.rf_model = RuleBasedRF(flow_bytes_idx=flow_bytes_idx, flow_pkts_idx=flow_pkts_idx)
    engine.autoencoder = ThresholdAutoencoder(noise_trigger=500000.0).to(engine.device)
    engine.autoencoder_threshold = 100.0
    engine._mse_history = [10.0] * 50

    normal_vec = _vector_from_feature_map(
        engine.features,
        {
            "Flow Bytes/s": 2000.0,
            "Flow Packets/s": 40.0,
            "Packet Length Std": 10.0,
        },
    )

    known_attack_vec = _vector_from_feature_map(
        engine.features,
        {
            "Flow Bytes/s": 2500000.0,
            "Flow Packets/s": 150000.0,
            "Packet Length Std": 600.0,
        },
    )

    zero_day_vec = _vector_from_feature_map(
        engine.features,
        {
            "Flow Bytes/s": 1000.0,
            "Flow Packets/s": 20.0,
            "Packet Length Std": 5.0,
            "Flow Duration": 50000.0,
            "Active Mean": 900000.0,
            "Idle Max": 9000.0,
            "Fwd IAT Max": 7000.0,
        },
    )

    results = {
        "normal": engine.predict(normal_vec),
        "known_attack": engine.predict(known_attack_vec),
        "zero_day": engine.predict(zero_day_vec),
    }

    print("[TriLayerTest] Results:")
    for name, result in results.items():
        print(f"  - {name}: {result}")

    assert results["normal"]["classification"] == "normal", "Normal sample did not route to normal"
    assert results["known_attack"]["classification"] == "attack", "Attack sample did not route to RF attack"
    assert results["zero_day"]["classification"] == "zero-day anomaly", "Anomaly sample did not route to zero-day"

    print("[TriLayerTest] PASS: Tri-layer routing and tensor shapes are valid.")


if __name__ == "__main__":
    main()
