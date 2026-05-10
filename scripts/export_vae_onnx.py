import os
import sys
from pathlib import Path
import logging

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.config import MODELS_DIR

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("export_vae_onnx")

def export_vae():
    """
    Exports Keras VAE encoder/decoder to ONNX format.
    Requires: pip install tf2onnx onnxruntime
    """
    try:
        import keras
        import tf2onnx
        import onnx
        
        encoder_path = MODELS_DIR / "vae_encoder.keras"
        decoder_path = MODELS_DIR / "vae_decoder.keras"
        
        if not encoder_path.exists():
            logger.error(f"Encoder not found at {encoder_path}")
            return

        # 1. Load Keras models
        encoder = keras.models.load_model(encoder_path, compile=False)
        decoder = keras.models.load_model(decoder_path, compile=False)
        
        # 2. Export Encoder
        logger.info("Exporting VAE Encoder to ONNX...")
        onnx_encoder_path = MODELS_DIR / "vae_encoder.onnx"
        model_proto, _ = tf2onnx.convert.from_keras(encoder, output_path=str(onnx_encoder_path))
        logger.info(f"Encoder exported to {onnx_encoder_path}")
        
        # 3. Export Decoder
        logger.info("Exporting VAE Decoder to ONNX...")
        onnx_decoder_path = MODELS_DIR / "vae_decoder.onnx"
        model_proto, _ = tf2onnx.convert.from_keras(decoder, output_path=str(onnx_decoder_path))
        logger.info(f"Decoder exported to {onnx_decoder_path}")
        
        logger.info("VAE ONNX export complete.")
        
    except ImportError:
        logger.error("Required libraries (tf2onnx, onnx) not found. Please install them to use this script.")
    except Exception as e:
        logger.error(f"Export failed: {e}")

if __name__ == "__main__":
    export_vae()
