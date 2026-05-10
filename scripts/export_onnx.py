import os
import joblib
import onnx
import tf2onnx
import tensorflow as tf
from skl2onnx import to_onnx
from skl2onnx.common.data_types import FloatTensorType
from pathlib import Path
import numpy as np
import sys

# Set paths
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
MODELS_DIR = PROJECT_ROOT / "models"
RF_PATH = MODELS_DIR / "rf_multi_model.pkl"
VAE_PATH = MODELS_DIR / "vae_encoder.keras"

RF_ONNX_PATH = MODELS_DIR / "rf_multi_model.onnx"
VAE_ONNX_PATH = MODELS_DIR / "vae_encoder.onnx"

def export_rf():
    SCALER_PATH = MODELS_DIR / "scaler_multi.pkl"
    RF_ONNX_PIPELINE_PATH = MODELS_DIR / "rf_multi_pipeline.onnx"
    
    print(f"Exporting RF Pipeline from {RF_PATH} and {SCALER_PATH}...")
    if not RF_PATH.exists() or not SCALER_PATH.exists():
        print("Error: RF model or Scaler not found")
        return
    
    rf = joblib.load(RF_PATH)
    scaler = joblib.load(SCALER_PATH)
    
    from sklearn.pipeline import Pipeline
    pipeline = Pipeline([
        ('scaler', scaler),
        ('rf', rf)
    ])
    
    n_features = 49
    initial_type = [('float_input', FloatTensorType([None, n_features]))]
    onx = to_onnx(pipeline, initial_types=initial_type)
    
    with open(RF_ONNX_PIPELINE_PATH, "wb") as f:
        f.write(onx.SerializeToString())
    print(f"Success! RF Pipeline exported to {RF_ONNX_PIPELINE_PATH}")

def export_vae():
    print(f"Exporting VAE from {VAE_PATH}...")
    if not VAE_PATH.exists():
        print("Error: VAE model not found")
        return
    
    # Load keras model with custom objects
    try:
        from ml_engine.vae_detector import Sampling
    except ImportError:
        print("Error: ml_engine.vae_detector not found in path")
        return

    custom_objects = {'Sampling': Sampling}
    model = tf.keras.models.load_model(VAE_PATH, custom_objects=custom_objects, compile=False)
    
    # Strip Sampling layer for inference: use z_mean only
    try:
        z_mean_output = model.get_layer("z_mean").output
        model = tf.keras.Model(inputs=model.inputs, outputs=z_mean_output)
        print("Stripped Sampling layer, using z_mean output for deterministic inference.")
    except Exception as e:
        print(f"Warning: Could not strip Sampling layer: {e}. Exporting full model.")

    # Define input spec
    spec = (tf.TensorSpec((None, 49), tf.float32, name="input"),)
    
    # Convert to ONNX with higher opset for better compatibility
    model_proto, _ = tf2onnx.convert.from_keras(model, input_signature=spec, opset=17)
    
    # Save
    with open(VAE_ONNX_PATH, "wb") as f:
        f.write(model_proto.SerializeToString())
    print(f"Success! VAE Encoder exported to {VAE_ONNX_PATH}")

def export_vae_decoder():
    DEC_PATH = MODELS_DIR / "vae_decoder.keras"
    DEC_ONNX_PATH = MODELS_DIR / "vae_decoder.onnx"
    
    print(f"Exporting VAE Decoder from {DEC_PATH}...")
    if not DEC_PATH.exists():
        print("Error: VAE decoder not found")
        return
    
    model = tf.keras.models.load_model(DEC_PATH, compile=False)
    spec = (tf.TensorSpec((None, 16), tf.float32, name="input"),) # Latent dim is 16
    
    model_proto, _ = tf2onnx.convert.from_keras(model, input_signature=spec, opset=17)
    
    with open(DEC_ONNX_PATH, "wb") as f:
        f.write(model_proto.SerializeToString())
    print(f"Success! VAE Decoder exported to {DEC_ONNX_PATH}")

if __name__ == "__main__":
    export_rf()
    export_vae()
    export_vae_decoder()
