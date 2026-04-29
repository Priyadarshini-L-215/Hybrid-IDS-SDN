import os
import sys
import joblib
import json
import torch
import numpy as np
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.common.config import RF_MODEL_PATH, SCALER_PATH, AUTOENCODER_PATH, MODELS_DIR

def export_rf_to_onnx():
    print(f"Loading RF model from {RF_MODEL_PATH}...")
    try:
        model = joblib.load(RF_MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
    except Exception as e:
        print(f"Error loading models: {e}")
        return

    from skl2onnx import to_onnx
    from skl2onnx.common.data_types import FloatTensorType

    # Prepare input definition (77 features)
    initial_type = [('float_input', FloatTensorType([None, 77]))]
    
    print("Converting RF model to ONNX...")
    # Wrap model and scaler if needed, but for now let's just convert the model
    # Usually we want the whole pipeline
    from sklearn.pipeline import Pipeline
    pipeline = Pipeline([
        ('scaler', scaler),
        ('rf', model)
    ])
    
    onnx_model = to_onnx(pipeline, initial_types=initial_type, target_opset=12)
    
    onnx_path = MODELS_DIR / "rf_pipeline.onnx"
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"Saved RF ONNX to {onnx_path}")

def export_ae_to_onnx():
    print(f"Loading AutoEncoder from {AUTOENCODER_PATH}...")
    # We need the class definition from consumer.py
    from src.ml_engine.consumer import DenseAutoencoder
    
    try:
        state_dict = torch.load(AUTOENCODER_PATH, map_location='cpu')
        model = DenseAutoencoder.from_state_dict(state_dict)
        model.load_state_dict(state_dict)
        model.eval()
    except Exception as e:
        print(f"Error loading AE: {e}")
        return

    print("Converting AutoEncoder to ONNX...")
    dummy_input = torch.randn(1, 77)
    onnx_path = MODELS_DIR / "autoencoder.onnx"
    
    torch.onnx.export(
        model,
        dummy_input,
        onnx_path,
        export_params=True,
        opset_version=12,
        do_constant_folding=True,
        input_names=['input'],
        output_names=['output'],
        dynamic_axes={'input': {0: 'batch_size'}, 'output': {0: 'batch_size'}}
    )
    print(f"Saved AE ONNX to {onnx_path}")

if __name__ == "__main__":
    try:
        import skl2onnx
        import onnxruntime
    except ImportError:
        print("Required libraries (skl2onnx, onnxruntime) not found. Please install them first.")
        sys.exit(1)
        
    export_rf_to_onnx()
    export_ae_to_onnx()
