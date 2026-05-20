"""
Deep Learning Models (Tier 2 Inference)
Implements Temporal Flow Transformers and Topological GNNs.
Executes asynchronously on GPU if available, else CPU.
"""

import os
import logging
import numpy as np
import time

os.environ["KERAS_BACKEND"] = "torch"
import keras
from keras import layers, ops

logger = logging.getLogger(__name__)

class TemporalTransformer(keras.Model):
    """
    Analyzes a sequence of packet sizes and inter-arrival times (IAT)
    using self-attention to detect slow-rate APTs.
    """
    def __init__(self, sequence_length=10, feature_dim=4, num_heads=2, ff_dim=32, **kwargs):
        super().__init__(**kwargs)
        self.sequence_length = sequence_length
        self.feature_dim = feature_dim
        
        # Transformer Block
        self.att = layers.MultiHeadAttention(num_heads=num_heads, key_dim=feature_dim)
        self.ffn = keras.Sequential([
            layers.Dense(ff_dim, activation="relu"),
            layers.Dense(feature_dim)
        ])
        self.layernorm1 = layers.LayerNormalization(epsilon=1e-6)
        self.layernorm2 = layers.LayerNormalization(epsilon=1e-6)
        self.dropout1 = layers.Dropout(0.1)
        self.dropout2 = layers.Dropout(0.1)
        
        # Classifier Head
        self.global_pool = layers.GlobalAveragePooling1D()
        self.classifier = layers.Dense(1, activation="sigmoid")

    def call(self, inputs, training=False):
        # inputs shape: (batch_size, sequence_length, feature_dim)
        attn_output = self.att(inputs, inputs)
        attn_output = self.dropout1(attn_output, training=training)
        out1 = self.layernorm1(inputs + attn_output)
        
        ffn_output = self.ffn(out1)
        ffn_output = self.dropout2(ffn_output, training=training)
        out2 = self.layernorm2(out1 + ffn_output)
        
        x = self.global_pool(out2)
        return self.classifier(x)

class TopologicalGNN:
    """
    Simulated GraphSAGE model for topological botnet detection.
    (Full DGL/PyG integration requires extensive dependencies, so we use
     an adjacency matrix approximation in Keras for demonstration).
    """
    def __init__(self):
        # Using a simple dense network to approximate graph embedding
        # In production, this would use torch_geometric.nn.SAGEConv
        inputs = keras.Input(shape=(64,)) # 64-dim graph embedding
        x = layers.Dense(32, activation="relu")(inputs)
        x = layers.Dropout(0.2)(x)
        outputs = layers.Dense(1, activation="sigmoid")(x)
        self.model = keras.Model(inputs, outputs)
        
    def predict(self, adjacency_matrix_snapshot):
        # Flatten or embed the adjacency matrix
        # Mock prediction logic for architecture demonstration
        batch_size = adjacency_matrix_snapshot.shape[0] if hasattr(adjacency_matrix_snapshot, 'shape') else 1
        dummy_embeddings = np.random.rand(batch_size, 64)
        return self.model.predict(dummy_embeddings, verbose=0)

class DeepInferenceManager:
    """Manages the lifecycle and hardware routing for Tier 2 models."""
    def __init__(self):
        self.transformer = None
        self.gnn = None
        self.hardware_accelerated = False
        self.is_ready = False
        self._initialize()

    def _initialize(self):
        try:
            import torch
            if torch.cuda.is_available():
                self.hardware_accelerated = True
                logger.info("CUDA GPU detected. Tier 2 models will run with hardware acceleration.")
            else:
                logger.info("No CUDA GPU detected. Tier 2 models will use CPU fallback.")
                
            self.transformer = TemporalTransformer()
            # Compile to build weights
            self.transformer.compile(optimizer="adam", loss="binary_crossentropy")
            dummy_input = np.zeros((1, 10, 4))
            self.transformer.predict(dummy_input, verbose=0) # Build call
            
            self.gnn = TopologicalGNN()
            self.is_ready = True
            logger.info("DeepInferenceManager initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize DeepInferenceManager: {e}")

    def evaluate_sequence(self, sequence_data: np.ndarray) -> float:
        """Returns anomaly probability for a sequence of packets."""
        if not self.is_ready or self.transformer is None:
            return 0.0
        
        # Ensure shape (1, 10, 4)
        if sequence_data.shape != (1, 10, 4):
            # Pad or truncate
            if sequence_data.ndim == 2:
                sequence_data = np.expand_dims(sequence_data, axis=0)
            
            padded = np.zeros((1, 10, 4))
            seq_len = min(sequence_data.shape[1], 10)
            feat_len = min(sequence_data.shape[2], 4)
            padded[0, :seq_len, :feat_len] = sequence_data[0, :seq_len, :feat_len]
            sequence_data = padded

        # Time the inference to prove async latency preservation
        start = time.time()
        score = self.transformer.predict(sequence_data, verbose=0)[0][0]
        duration = (time.time() - start) * 1000
        logger.debug(f"Transformer inference completed in {duration:.2f}ms. Score: {score:.4f}")
        return float(score)

# Singleton instance
deep_manager = DeepInferenceManager()
