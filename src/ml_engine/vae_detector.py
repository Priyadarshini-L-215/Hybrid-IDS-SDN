"""
VAE Anomaly Detector — Sentinel Core V4
========================================
Wraps the Keras VAE (encoder.keras + decoder.keras) + MinMaxScaler (vae_scaler.pkl)
into a clean interface for use by the ML Engine.

Updated to support the 49-feature UNSW-NB15 schema.
"""

import logging
import os
import numpy as np
from pathlib import Path
import joblib
from typing import Tuple, Optional, List, Union

# Set Keras backend to torch to maintain consistency with other parts of the system if possible,
# or let it default to tensorflow if installed. Keras 3 is backend-agnostic.
if not os.environ.get("KERAS_BACKEND"):
    os.environ["KERAS_BACKEND"] = "torch"

try:
    import keras
    KERAS_AVAILABLE = True
except ImportError:
    KERAS_AVAILABLE = False

if KERAS_AVAILABLE:
    @keras.saving.register_keras_serializable()
    class Sampling(keras.layers.Layer):
        """Uses (z_mean, z_log_var) to sample z."""
        def call(self, inputs):
            z_mean, z_log_var = inputs
            batch = keras.ops.shape(z_mean)[0]
            dim = keras.ops.shape(z_mean)[1]
            epsilon = keras.random.normal(shape=(batch, dim))
            return z_mean + keras.ops.exp(0.5 * z_log_var) * epsilon

logger = logging.getLogger(__name__)

class VaeAnomalyDetector:
    """
    Public interface for the 49-feature Keras VAE anomaly detector.

    Usage::
        detector = VaeAnomalyDetector("models/vae_encoder.keras", "models/vae_decoder.keras", "models/vae_scaler.pkl")
        mse_scores = detector.score(X_raw)          # ndarray of per-sample MSE
        flags      = detector.is_anomaly(X_raw)     # bool ndarray
    """

    DEFAULT_THRESHOLD = 0.3

    def __init__(self, encoder_path: str | Path, decoder_path: str | Path, scaler_path: str | Path,
                 threshold: float = DEFAULT_THRESHOLD):
        self.threshold = threshold
        self._ready = False
        self.encoder = None
        self.decoder = None
        self.scaler = None

        if not KERAS_AVAILABLE:
            logger.error("Keras not found. VAE detector unavailable.")
            return

        try:
            # Load MinMaxScaler
            self.scaler = joblib.load(scaler_path)
            self.n_features = getattr(self.scaler, 'n_features_in_', 49)
            logger.info(f"VAE scaler loaded from {scaler_path} (features={self.n_features})")

            # Load Keras models
            custom_objects = {'Sampling': Sampling} if KERAS_AVAILABLE else {}
            self.encoder = keras.models.load_model(encoder_path, custom_objects=custom_objects)
            self.decoder = keras.models.load_model(decoder_path, custom_objects=custom_objects)
            
            logger.info(f"VAE encoder/decoder loaded | threshold={threshold}")
            self._ready = True
        except Exception as e:
            logger.error(f"Failed to load VAE detector: {e}")

    @property
    def is_ready(self) -> bool:
        return self._ready

    def get_latent_and_mse(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Compute both latent vectors (z) and MSE reconstruction errors.
        Returns: (z, mse)
        """
        if not self._ready:
            return np.zeros((len(X), 1)), np.zeros(len(X))

        try:
            # 1. Feature Shape Validation
            if X.shape[1] != self.n_features:
                if X.shape[1] > self.n_features:
                    X_input = X[:, :self.n_features]
                else:
                    X_input = np.pad(X, ((0, 0), (0, self.n_features - X.shape[1])), mode='constant')
            else:
                X_input = X

            X_scaled = self.scaler.transform(X_input).astype(np.float32)

            # VAE Inference
            encoder_output = self.encoder.predict(X_scaled, verbose=0)
            if isinstance(encoder_output, list):
                z = encoder_output[0]
            else:
                z = encoder_output

            X_recon = self.decoder.predict(z, verbose=0)
            mse = np.mean(np.power(X_scaled - X_recon, 2), axis=1)

            return z, mse
        except Exception as e:
            logger.error(f"VAE get_latent_and_mse error: {e}")
            return np.zeros((len(X), 1)), np.zeros(len(X))

    def raw_mse(self, X: np.ndarray) -> np.ndarray:
        """
        Compute raw per-sample MSE reconstruction error.
        """
        _, mse = self.get_latent_and_mse(X)
        return mse

    def score(self, X: np.ndarray) -> np.ndarray:
        """
        Compute normalized anomaly score [0, 1].
        Maps raw MSE to a probability-like score where threshold = 0.5.
        """
        mse = self.raw_mse(X)
        if len(mse) == 0:
            return mse
            
        # Sigmoid normalization around the threshold
        scale = self.threshold / 2 if self.threshold > 0 else 0.01
        normalized = 1.0 / (1.0 + np.exp(-(mse - self.threshold) / scale))
        return normalized

    def is_anomaly(self, X: np.ndarray) -> np.ndarray:
        """
        Returns a boolean mask — True where reconstruction error exceeds threshold.
        """
        return self.raw_mse(X) > self.threshold
