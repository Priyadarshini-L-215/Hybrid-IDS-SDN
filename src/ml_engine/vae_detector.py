"""
VAE Anomaly Detector — Sentinel Core V4
========================================
Wraps the Keras VAE (encoder.keras + decoder.keras) + MinMaxScaler (vae_scaler.pkl)
into a clean interface for use by the ML Engine.

Updated to support the 49-feature UNSW-NB15 schema.
"""

import os
if not os.environ.get("KERAS_BACKEND"):
    os.environ["KERAS_BACKEND"] = "torch"

import structlog
import numpy as np
from pathlib import Path
import joblib
from typing import Tuple, Optional, List, Union

try:
    import keras
    KERAS_AVAILABLE = True
except ImportError:
    KERAS_AVAILABLE = False

try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

if KERAS_AVAILABLE:
    @keras.saving.register_keras_serializable(package="Sentinel")
    class Sampling(keras.layers.Layer):
        """Uses (z_mean, z_log_var) to sample z."""
        def call(self, inputs):
            z_mean, z_log_var = inputs
            batch = keras.ops.shape(z_mean)[0]
            dim = keras.ops.shape(z_mean)[1]
            epsilon = keras.random.normal(shape=(batch, dim))
            return z_mean + keras.ops.exp(0.5 * z_log_var) * epsilon

        def get_config(self):
            return super().get_config()

        @classmethod
        def from_config(cls, config):
            return cls(**config)

logger = structlog.get_logger(__name__)

class VaeAnomalyDetector:
    """
    Public interface for the 49-feature Keras VAE anomaly detector.

    Usage::
        detector = VaeAnomalyDetector("models/vae_encoder.keras", "models/vae_decoder.keras", "models/vae_scaler.pkl")
        mse_scores = detector.score(X_raw)          # ndarray of per-sample MSE
        flags      = detector.is_anomaly(X_raw)     # bool ndarray
    """

    DEFAULT_THRESHOLD = 0.3

    VAE_FEATURES = [
        "flow_duration", "total_fwd_packets", "total_bwd_packets", "total_fwd_bytes", "total_bwd_bytes",
        "flow_iat_mean", "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "pkt_len_mean", "pkt_len_std",
        "sload", "dttl", "swin", "dwin", "sinpkt", "ct_state_ttl", "ct_srv_src", "ct_srv_dst",
        "ct_dst_sport_ltm", "smeansz", "dmeansz"
    ]

    def __init__(self, encoder_path: str | Path, decoder_path: str | Path, scaler_path: str | Path,
                 threshold: float = DEFAULT_THRESHOLD, feature_order: Optional[List[str]] = None):
        self.threshold = threshold
        self._ready = False
        self.encoder = None
        self.decoder = None
        self.scaler = None
        self.use_onnx = False

        # Calculate indices of the 22 VAE features in the feature_order
        self.feature_order = feature_order or self.VAE_FEATURES
        self.vae_indices = []
        for f in self.VAE_FEATURES:
            if f in self.feature_order:
                self.vae_indices.append(self.feature_order.index(f))
            else:
                self.vae_indices.append(0)

        try:
            # 1. Load MinMaxScaler
            self.scaler = joblib.load(scaler_path)
            self.n_features = 22  # The model expects 22 features
            logger.info(f"VAE scaler loaded, n_features set to {self.n_features}")

            # 2. Check for ONNX alternatives
            onnx_enc = Path(str(encoder_path).replace(".keras", ".onnx"))
            onnx_dec = Path(str(decoder_path).replace(".keras", ".onnx"))

            if ONNX_AVAILABLE and onnx_enc.exists() and onnx_dec.exists():
                self.encoder = ort.InferenceSession(str(onnx_enc))
                self.decoder = ort.InferenceSession(str(onnx_dec))
                self.use_onnx = True
                logger.info("VAE using ONNX runtime for inference")
            elif KERAS_AVAILABLE:
                # Load Keras models (original logic)
                # Keras 3 uses the serializable registration
                self.encoder = keras.models.load_model(encoder_path, compile=False, safe_mode=False)
                self.decoder = keras.models.load_model(decoder_path, compile=False, safe_mode=False)
                logger.info("VAE using Keras for inference")
            else:
                logger.error("Neither Keras nor ONNX available for VAE detector")
                return

            self._ready = True
        except Exception as e:
            logger.error(f"Failed to load VAE detector: {e}")

    @property
    def is_ready(self) -> bool:
        return self._ready

    @staticmethod
    def _to_numpy(tensor) -> np.ndarray:
        """Convert a framework tensor to a numpy array safely.
        Handles PyTorch (detach), TensorFlow, JAX, and plain ndarrays."""
        if isinstance(tensor, np.ndarray):
            return tensor
        # PyTorch tensors need detach() before numpy()
        if hasattr(tensor, "detach"):
            return tensor.detach().cpu().numpy()
        if hasattr(tensor, "numpy"):
            return tensor.numpy()
        return np.asarray(tensor)

    def get_latent_and_mse(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Compute both latent vectors (z) and MSE reconstruction errors.
        Returns: (z, mse)
        """
        if not self._ready:
            return np.zeros((len(X), 1)), np.zeros(len(X))

        try:
            # 1. Feature Shape Validation using the 49-feature scaler
            scaler_features = getattr(self.scaler, 'n_features_in_', 49)
            if X.shape[1] != scaler_features:
                if X.shape[1] > scaler_features:
                    X_input = X[:, :scaler_features]
                else:
                    X_input = np.pad(X, ((0, 0), (0, scaler_features - X.shape[1])), mode='constant')
            else:
                X_input = X

            X_scaled = self.scaler.transform(X_input).astype(np.float32)
            
            # Slice to only keep the 22 features that the Keras VAE model expects
            X_scaled_sliced = X_scaled[:, self.vae_indices]
 
            # VAE Inference
            if self.use_onnx:
                input_name = self.encoder.get_inputs()[0].name
                z = self.encoder.run(None, {input_name: X_scaled_sliced})[0]
                input_name_dec = self.decoder.get_inputs()[0].name
                X_recon = self.decoder.run(None, {input_name_dec: z})[0]
            else:
                # Direct call is 10x faster than .predict() for micro-batches
                # We use training=False to ensure dropout/batchnorm are in inference mode
                z_output = self.encoder(X_scaled_sliced, training=False)
                # VAE encoders often return [z, z_mean, z_log_var], we want z
                z = z_output[0] if isinstance(z_output, (list, tuple)) else z_output
                
                recon_output = self.decoder(z, training=False)
                X_recon = self._to_numpy(recon_output)
                z = self._to_numpy(z)
 
            mse = np.mean(np.power(X_scaled_sliced - X_recon, 2), axis=1)
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
