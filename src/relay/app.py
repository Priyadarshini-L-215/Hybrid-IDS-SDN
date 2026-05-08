import asyncio
import os
from pathlib import Path
from contextlib import asynccontextmanager

# Set Keras backend BEFORE importing any ML modules
if not os.environ.get("KERAS_BACKEND"):
    os.environ["KERAS_BACKEND"] = "torch"

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import structlog

# Add project root to path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from common.config import (
    REDIS_ALERT_STREAM, setup_logging, API_PORT
)
from ml_engine import redis_client as rc
from relay.ws_manager import ConnectionManager
from ml_engine.engine import MLEngine
from ml_engine.firewall import ActiveFirewall

# Import routers
from relay.routes import system, simulation, forensics, models, lab, pcap

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

manager = ConnectionManager()

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


_redis_stream_task = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handles startup and shutdown events."""
    global _redis_stream_task
    _redis_stream_task = asyncio.create_task(redis_stream_listener())
    logger.info("Relay startup complete")
    yield
    if _redis_stream_task:
        _redis_stream_task.cancel()
        try:
            await _redis_stream_task
        except asyncio.CancelledError:
            pass
    await rc.close_async_redis()
    try:
        from ml_engine.cti_client import close_cti_client
        await close_cti_client()
    except Exception:
        pass
    try:
        await ActiveFirewall.close()
    except Exception:
        pass
    logger.info("Relay shutting down")

app = FastAPI(
    title="Sentinel Core Relay", 
    version="3.0.0",
    lifespan=lifespan
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(system.router)
app.include_router(models.router)
app.include_router(lab.router)
app.include_router(forensics.router)
app.include_router(pcap.router)
app.include_router(simulation.router)

# --- WEBSOCKET ---
@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time alert streaming."""
    try:
        await manager.connect(websocket)
    except Exception as e:
        logger.error("Failed to establish WebSocket connection", error=str(e))
        try:
            await websocket.close(code=1000, reason="Connection failed")
        except Exception:
            pass
        return
    
    try:
        while True:
            # Keep connection alive and wait for client to close
            await websocket.receive_text()
    except WebSocketDisconnect:
        logger.debug("WebSocket client disconnected")
        try:
            await manager.disconnect(websocket)
        except Exception as e:
            logger.debug("Error disconnecting WebSocket", error=str(e))
    except Exception as e:
        logger.error("WebSocket error", error=str(e), exc_info=True)
        try:
            await manager.disconnect(websocket)
        except Exception:
            pass

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
    uvicorn.run("relay.app:app", host=API_HOST, port=API_PORT, reload=True)
