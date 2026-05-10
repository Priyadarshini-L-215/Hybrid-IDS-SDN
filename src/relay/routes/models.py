import io
import os
import time
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends
from pydantic import BaseModel, Field
import structlog
import yaml

from common.config import CONFIG_PATH, MODELS_DIR
from relay.middleware.auth import require_api_key
from ml_engine.evaluator import validate_dataset, evaluate_dataset

logger = structlog.get_logger("relay.routes.models")

class ModelActivationRequest(BaseModel):
    model_file: str = Field(..., description="Filename of the ML model")
    scaler_file: str = Field(..., description="Filename of the associated scaler")

MAX_UPLOAD_SIZE = 100 * 1024 * 1024 # 100MB
MAX_PCAP_SIZE = 50 * 1024 * 1024   # 50MB

async def validate_file(file: UploadFile, allowed_exts: list, max_size: int):
    # 1. Extension check
    ext = Path(file.filename).suffix.lower()
    if ext not in allowed_exts:
        raise HTTPException(status_code=400, detail=f"Invalid file type. Allowed: {allowed_exts}")
    
    # 2. Size check
    # We read a bit to check size if not provided
    size = 0
    if hasattr(file.file, "seek") and hasattr(file.file, "tell"):
        file.file.seek(0, 2)
        size = file.file.tell()
        file.file.seek(0)
    
    if size > max_size:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum allowed: {max_size / (1024*1024)}MB")
    
    return True

router = APIRouter(prefix="/api", tags=["Models"])

def safe_pcap_path(project_root: Path, pcap_path: str) -> str:
    """Validates that a pcap_path is within the allowed data/pcaps directory."""
    if not pcap_path:
        return None

    pcap_dir = (project_root / "data" / "pcaps").resolve()

    # Strip leading slashes to prevent absolute paths from overriding the base directory
    clean_path = str(pcap_path).lstrip("\\/")

    resolved_path = (pcap_dir / clean_path).resolve()

    # Verify it's within the allowed directory
    if not resolved_path.is_relative_to(pcap_dir):
        raise ValueError("Invalid PCAP path: Path traversal detected")

    # Verify file actually exists
    if not resolved_path.exists() or not resolved_path.is_file():
        raise ValueError(f"PCAP file not found: {clean_path}")

    return str(resolved_path)

# We need to access the globally initialized ML Engine from app.py
# We'll use a getter function dependency or just import it dynamically to avoid circular imports.
def get_engine():
    from relay.app import get_ml_engine
    return get_ml_engine()

@router.get("/models")
async def list_models():
    """Lists available models and scalers."""
    try:
        from common.config import ACTIVE_MODEL_FILE, ACTIVE_SCALER_FILE
        
        models = [f.name for f in MODELS_DIR.glob("*.onnx")] + \
                 [f.name for f in MODELS_DIR.glob("*.pkl") if "scaler" not in f.name]
        scalers = [f.name for f in MODELS_DIR.glob("*scaler*.pkl")]
        
        return {
            "models": sorted(list(set(models))),
            "scalers": sorted(list(set(scalers))),
            "active_model": ACTIVE_MODEL_FILE,
            "active_scaler": ACTIVE_SCALER_FILE
        }
    except Exception as e:
        logger.error("Failed to list models", error=str(e))
        return {"models": [], "scalers": [], "error": str(e)}

@router.post("/models/active", dependencies=[Depends(require_api_key)])
async def set_active_model(req: ModelActivationRequest):
    """Updates the active model in config and reloads the engine."""
    model_file = req.model_file
    scaler_file = req.scaler_file
    
    if not model_file or not scaler_file:
        raise HTTPException(status_code=400, detail="model_file and scaler_file are required")
        
    try:
        # Load existing config
        cfg = {}
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r") as f:
                cfg = yaml.safe_load(f) or {}
                
        # Update model paths
        if "detection" not in cfg: cfg["detection"] = {}
        if "ml" not in cfg["detection"]: cfg["detection"]["ml"] = {}
        
        cfg["detection"]["ml"]["active_model"] = model_file
        cfg["detection"]["ml"]["active_scaler"] = scaler_file
        
        # Save config
        with open(CONFIG_PATH, "w") as f:
            yaml.dump(cfg, f, default_flow_style=False)
            
        # 1. Reload local engine
        engine = get_engine()
        if engine:
            engine.reload_config()
            
        # 2. Signal consumer to reload
        try:
            import subprocess
            import signal
            pid_res = subprocess.run(["pgrep", "-f", "src/ml_engine/consumer.py"], capture_output=True, text=True)
            if pid_res.returncode == 0:
                for pid in pid_res.stdout.split():
                    os.kill(int(pid), signal.SIGHUP)
                logger.info("Signaled consumer to reload model")
        except Exception as e:
            logger.warning("Failed to signal consumer", error=str(e))
            
        return {"success": True, "message": f"Active model swapped to {model_file}"}
    except Exception as e:
        logger.error("Failed to swap model", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/evaluate/dataset", dependencies=[Depends(require_api_key)])
async def run_evaluation(
    file: Optional[UploadFile] = File(None),
    dataset_path: Optional[str] = Form(None),
    label_column: str = Form("Label")
):
    """Evaluates a dataset (uploaded or local) and returns metrics."""
    engine = get_engine()
    if not engine or not engine.is_ready:
         return {"success": False, "error": "ML Engine is not ready or in fallback mode."}
         
    source = None
    try:
        if file:
            await validate_file(file, [".csv"], MAX_UPLOAD_SIZE)
            content = await file.read()
            source = io.BytesIO(content)
            logger.info("Evaluating uploaded file", filename=file.filename)
        elif dataset_path:
            path = Path(dataset_path).resolve()
            allowed_dir = (BASE_DIR / "data").resolve()
            if not path.is_relative_to(allowed_dir):
                return {"success": False, "error": "Invalid dataset path: must be within the data directory"}
            if not path.exists():
                return {"success": False, "error": f"Path not found: {dataset_path}"}
            source = path
            logger.info("Evaluating local path", path=dataset_path)
        else:
            return {"success": False, "error": "No dataset provided (upload a file or provide a local path)"}
            
        # 1. Validate features
        v_res = validate_dataset(source, engine.feature_order)
        if not v_res["compatible"]:
            return {
                "success": False, 
                "error": "Dataset incompatible with current model features.",
                "incompatibility_details": v_res
            }
            
        # 2. Run evaluation
        e_res = evaluate_dataset(source, engine, label_column=label_column)
        return e_res
        
    except Exception as e:
        logger.error("Evaluation endpoint error", error=str(e))
        return {"success": False, "error": str(e)}

@router.post("/models/train", dependencies=[Depends(require_api_key)])
async def run_training(
    pcap_path: Optional[str] = Form(None),
    label: Optional[str] = Form("Attack")
):
    """Triggers the model training pipeline, optionally adding data from a PCAP."""
    logger.info("Starting model training pipeline", from_pcap=bool(pcap_path))
    try:
        import sys
        project_root = Path(__file__).resolve().parents[3]
        python_path = sys.executable
        
        # 1. If PCAP provided, convert and append to dataset first
        if pcap_path:
            try:
                safe_path = safe_pcap_path(project_root, pcap_path)
            except ValueError as ve:
                return {"success": False, "error": str(ve)}

            conv_script = project_root / "scripts" / "pcap_to_csv.py"
            conv_process = await asyncio.create_subprocess_exec(
                str(python_path), str(conv_script), safe_path, label,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(project_root)
            )
            try:
                await asyncio.wait_for(conv_process.communicate(), timeout=300)
            except asyncio.TimeoutError:
                conv_process.kill()
                await conv_process.communicate()
                return {"success": False, "error": "PCAP conversion timed out after 300 seconds"}
            if conv_process.returncode != 0:
                return {"success": False, "error": "PCAP conversion failed"}
        
        # 2. Run train.py
        train_script = project_root / "models" / "train.py"
        process = await asyncio.create_subprocess_exec(
            str(python_path), str(train_script),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(project_root)
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=900)
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            return {"success": False, "error": "Training timed out after 900 seconds"}
        
        if process.returncode == 0:
            return {"success": True, "message": "Training complete. Metrics updated.", "output": stdout.decode()[-1000:]}
        else:
            return {"success": False, "error": stderr.decode() or stdout.decode()}
            
    except Exception as e:
        logger.error("Training endpoint error", error=str(e))
        return {"success": False, "error": str(e)}

@router.post("/evaluate/pcap", dependencies=[Depends(require_api_key)])
async def run_pcap_evaluation(
    file: Optional[UploadFile] = File(None),
    pcap_path: Optional[str] = Form(None)
):
    """Evaluates a PCAP file and returns flow predictions."""
    logger.info("Starting PCAP evaluation")
    try:
        import subprocess
        project_root = Path(__file__).resolve().parents[3]
        python_path = project_root / ".venv" / "bin" / "python3"
        eval_script = project_root / "scripts" / "evaluate_pcap.py"
        
        target_path = pcap_path
        
        # If file uploaded, save to temp first
        temp_pcap = None
        if file:
            await validate_file(file, [".pcap", ".pcapng"], MAX_PCAP_SIZE)
            temp_pcap = project_root / "data" / "pcap_eval" / f"upload_{int(time.time())}.pcap"

            # Read file content asynchronously, then write to disk in a separate thread to avoid blocking the event loop
            file_content = await file.read()
            def write_file():
                temp_pcap.parent.mkdir(parents=True, exist_ok=True)
                with open(temp_pcap, "wb") as f:
                    f.write(file_content)
            await asyncio.to_thread(write_file)

            target_path = str(temp_pcap)
        elif target_path:
            try:
                target_path = safe_pcap_path(project_root, target_path)
            except ValueError as ve:
                return {"success": False, "error": str(ve)}
            
        if not target_path:
            return {"success": False, "error": "No PCAP source provided"}

        process = await asyncio.create_subprocess_exec(
            str(python_path), str(eval_script), target_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(project_root)
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            return {"success": False, "error": "PCAP evaluation timed out after 600 seconds"}
            
        if process.returncode == 0:
            output = stdout.decode()
            # The script outputs a table. We'll return the raw output for now.
            return {"success": True, "results": output}
        else:
            return {"success": False, "error": stderr.decode() or stdout.decode()}
            
    except Exception as e:
        logger.error("PCAP evaluation error", error=str(e))
        return {"success": False, "error": str(e)}
    finally:
        if temp_pcap and temp_pcap.exists():
            temp_pcap.unlink()
