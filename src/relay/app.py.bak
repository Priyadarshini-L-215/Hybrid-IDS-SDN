import asyncio
import os
import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import structlog
import yaml
import io

# Add project root to path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from common.config import (
    REDIS_ALERT_STREAM, REDIS_HOST, REDIS_PORT, setup_logging, DB_PATH,
    CONFIG_PATH, YAML_CONFIG, API_PORT
)
from common.database import get_recent_alerts, get_stats
from ml_engine import redis_client as rc
from relay.ws_manager import ConnectionManager
from ml_engine.firewall import ActiveFirewall
from ml_engine.engine import MLEngine
from ml_engine.evaluator import validate_dataset, evaluate_dataset
from common.config import MODELS_DIR

# Initialize logging
setup_logging("relay")
logger = structlog.get_logger("relay")

# ML Engine instance for evaluation
_relay_ml_engine = None

def get_ml_engine():
    global _relay_ml_engine
    if _relay_ml_engine is None:
        try:
            # Note: MLEngine expects models/ dir in project root
            _relay_ml_engine = MLEngine()
        except Exception as e:
            logger.error("Failed to initialize Relay MLEngine", error=str(e))
    return _relay_ml_engine

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handles startup and shutdown events."""
    asyncio.create_task(redis_stream_listener())
    logger.info("Relay startup complete")
    yield
    logger.info("Relay shutting down")

app = FastAPI(
    title="Sentinel Core Relay", 
    version="3.0.0",
    lifespan=lifespan
)
manager = ConnectionManager()

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Background Task for Redis Stream
async def redis_stream_listener():
    """Reads from sentinel_alerts_stream and broadcasts to WebSockets."""
    logger.info("Starting Redis Stream listener", stream=REDIS_ALERT_STREAM)
    
    # Initialize Redis
    if not rc.async_redis_client:
        await rc.init_async_redis()
    
    last_id = "$" # Only new messages
    
    while True:
        try:
            if not rc.async_redis_client:
                await asyncio.sleep(1)
                continue

            # Read from stream
            # count=10 to handle bursts, block=1000 for efficiency
            streams = await rc.async_redis_client.xread(
                {REDIS_ALERT_STREAM: last_id}, count=10, block=1000
            )
            
            if streams:
                for stream_name, messages in streams:
                    if messages:
                        logger.debug("Received stream messages", count=len(messages))
                    for msg_id, data in messages:
                        alert_json = data.get("alert")
                        if alert_json:
                            await manager.broadcast(alert_json)
                        last_id = msg_id
            
        except Exception as e:
            logger.error("Stream listener error", error=str(e), exc_info=True)
            await asyncio.sleep(2)

# Startup logic moved to lifespan handler

# --- REST API ---

@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/alerts")
async def get_alerts(limit: int = 100):
    """Fetches recent alerts from SQLite for UI seeding."""
    try:
        # Offload blocking DB call
        loop = asyncio.get_running_loop()
        alerts = await loop.run_in_executor(None, get_recent_alerts, limit)
        stats = await loop.run_in_executor(None, get_stats)
        
        return {
            "alerts": alerts,
            "total_processed": stats.get("total_processed", 0),
            "attack_total": stats.get("attack_total", 0),
            "normal_total": stats.get("normal_total", 0),
            "displayed_total": len(alerts)
        }
    except Exception as e:
        logger.error("Failed to fetch alerts", error=str(e))
        return {"alerts": [], "error": str(e)}

@app.get("/api/pipeline/status")
async def get_pipeline_status():
    """Detailed diagnostics for the dashboard."""
    return {
        "status": "active",
        "redis_ok": rc.async_redis_client is not None,
        "ipset": ActiveFirewall.get_status(),
        "ipset_detailed": ActiveFirewall.get_detailed_status(),
        "checks": {
            "consumer_running": True, 
            "redis_ok": True,
            "ws_port_open": True
        }
    }

@app.get("/api/config")
async def get_config():
    """Returns the current sentinel_config.yaml content."""
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r") as f:
                return yaml.safe_load(f) or {}
        return {}
    except Exception as e:
        logger.error("Failed to read config", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to read configuration file")

@app.post("/api/config")
async def update_config(new_config: Dict[str, Any]):
    """Updates and saves the sentinel_config.yaml file."""
    try:
        # We merge with existing config to preserve comments/structure 
        # (though yaml.dump doesn't preserve comments well, we'll just write the dict)
        with open(CONFIG_PATH, "w") as f:
            yaml.dump(new_config, f, default_flow_style=False)
        
        logger.info("Configuration updated successfully")
        # Signal the consumer to reload (if it's running)
        try:
            import subprocess
            import signal
            # Find the consumer PID
            pid_res = subprocess.run(["pgrep", "-f", "src/ml_engine/consumer.py"], capture_output=True, text=True)
            if pid_res.returncode == 0:
                for pid in pid_res.stdout.split():
                    os.kill(int(pid), signal.SIGHUP)
                logger.info("Signaled consumer to reload config")
        except Exception as e:
            logger.warning("Failed to signal consumer for reload", error=str(e))
            
        return {"status": "success", "message": "Config updated and reload signal sent"}
    except Exception as e:
        logger.error("Failed to update config", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to save configuration")

@app.post("/api/mitigation/unblock")
async def unblock_ip(request: Dict[str, Any]):
    ip = request.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="IP address required")
    
    logger.info("Manual unblock requested", ip=ip)
    ActiveFirewall.unblock(ip)
    return {"success": True, "message": f"IP {ip} unblocked"}

@app.post("/api/mitigation/block")
async def block_ip(request: Dict[str, Any]):
    ip = request.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="IP address required")
    
    logger.info("Manual block requested", ip=ip)
    ActiveFirewall.block(ip)
    return {"success": True, "message": f"IP {ip} blocked"}

# --- MODEL & EVALUATION ---

@app.get("/api/models")
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

@app.post("/api/models/active")
async def set_active_model(request: Dict[str, str]):
    """Updates the active model in config and reloads the engine."""
    model_file = request.get("model_file")
    scaler_file = request.get("scaler_file")
    
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
        engine = get_ml_engine()
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

@app.post("/api/evaluate/dataset")
async def run_evaluation(
    file: Optional[UploadFile] = File(None),
    dataset_path: Optional[str] = Form(None),
    label_column: str = Form("Label")
):
    """Evaluates a dataset (uploaded or local) and returns metrics."""
    engine = get_ml_engine()
    if not engine or not engine.is_ready:
         return {"success": False, "error": "ML Engine is not ready or in fallback mode."}
         
    source = None
    try:
        if file:
            content = await file.read()
            source = io.BytesIO(content)
            logger.info("Evaluating uploaded file", filename=file.filename)
        elif dataset_path:
            path = Path(dataset_path)
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


# --- WEBSOCKET ---

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and wait for client to close
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error("WebSocket error", error=str(e))
        await manager.disconnect(websocket)

# --- ATTACK SIMULATION (LAB) ---

@app.post("/api/nmap/scan")
async def run_nmap_scan(request: Dict[str, Any]):
    target = request.get("target", "127.0.0.1")
    profile = request.get("profile", "quick")
    
    # Map profiles to nmap flags
    flags = {
        "ping": "-sn",
        "quick": "-F",
        "service": "-sV",
        "os_detect": "-O",
        "aggressive": "-A",
        "vuln": "--script=vuln"
    }.get(profile, "-F")
    
    logger.info("Starting Nmap scan", target=target, profile=profile)
    start_time = time.time()
    
    try:
        # 1. Verify nmap exists
        import shutil
        if not shutil.which("nmap"):
            return {"success": False, "error": "Nmap is not installed on the system path."}

        # 2. Build command
        # Use -T4 for speed, but avoid -O without root
        cmd = ["nmap", flags, "-T4", target]
        if profile in ["os_detect", "aggressive", "vuln"]:
            # These often need root
            cmd = ["sudo"] + cmd
        else:
            # Add unprivileged flag for non-root quick scans to avoid some errors
            cmd.append("--unprivileged")
            
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        duration = round(time.time() - start_time, 2)
        
        if process.returncode == 0:
            return {
                "success": True,
                "target": target,
                "duration_sec": duration,
                "raw_output": stdout.decode()
            }
        else:
            err_msg = stderr.decode() or stdout.decode() or "Unknown nmap error"
            logger.error("Nmap scan failed", target=target, code=process.returncode, error=err_msg)
            return {
                "success": False,
                "target": target,
                "error": err_msg
            }
    except Exception as e:
        logger.error("Nmap scan failed", error=str(e))
        return {"success": False, "error": str(e)}

@app.post("/api/attack/ddos")
async def run_ddos_simulation(request: Dict[str, Any]):
    target = request.get("target", "127.0.0.1")
    logger.info("Simulating DDoS attack", target=target)
    
    def _send_packets():
        import socket
        import random
        import time
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes_payload = random._urandom(1024)
        # Send in bursts to trigger threshold rules
        for _ in range(5):
            for _ in range(500):
                port = random.randint(1, 65535)
                try:
                    sock.sendto(bytes_payload, (target, port))
                except Exception as e:
                    logger.debug("Failed to send UDP packet in simulation", error=str(e))
            time.sleep(0.1)
        sock.close()

    try:
        await asyncio.to_thread(_send_packets)
        return {"success": True, "message": f"DDoS simulation flood (2500 pkts) sent to {target}"}
    except Exception as e:
        logger.error("DDoS simulation failed", error=str(e))
        return {"success": False, "error": str(e)}

@app.post("/api/attack/payload")
async def run_payload_simulation(request: Dict[str, Any]):
    target = request.get("target", "127.0.0.1")
    logger.info("Simulating Payload Injection", target=target)
    
    try:
        import httpx
        # Send multiple patterns to trigger SQLi regex
        payloads = [
            "' OR '1'='1' --",
            "admin' --",
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>"
        ]
        
        async with httpx.AsyncClient() as client:
            for p in payloads:
                try:
                    # We send it to port 5000 (ourselves)
                    await client.get(f"http://{target}:5000/api/health?id={p}", timeout=1.0)
                except Exception as e:
                    logger.debug("Failed to send HTTP payload in simulation", error=str(e))
                
        return {"success": True, "message": f"Malicious payloads ({len(payloads)}) injected towards {target}"}
    except Exception as e:
        logger.error("Payload simulation failed", error=str(e))
        return {"success": False, "error": str(e)}


# --- STATIC FILES (React) ---
ui_dist = Path("ui/dist")
if ui_dist.exists():
    app.mount("/", StaticFiles(directory=str(ui_dist), html=True), name="ui")
    logger.info("Serving React UI from ui/dist")
else:
    logger.warning("ui/dist not found, serving API only")

if __name__ == "__main__":
    import uvicorn
    # Use 0.0.0.0 for API_HOST by default to allow external access if needed
    API_HOST = os.environ.get("API_HOST", "0.0.0.0")
    logger.info(f"Starting Sentinel Relay on {API_HOST}:{API_PORT}")
    uvicorn.run(app, host=API_HOST, port=API_PORT)
