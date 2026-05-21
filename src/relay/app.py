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
    REDIS_ALERT_STREAM, setup_logging, API_PORT, DEV_MODE
)
from ml_engine import redis_client as rc
from relay.ws_manager import ConnectionManager
from ml_engine.engine import MLEngine
from ml_engine.firewall import ActiveFirewall



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
                    if not messages:
                        continue
                    
                    logger.debug("Received stream messages", count=len(messages))
                    
                    # BATCH BROADCAST: Send all messages in the batch at once
                    alert_jsons = [m[1].get("alert") for m in messages if m[1].get("alert")]
                    if alert_jsons:
                        await manager.broadcast_batch(alert_jsons)
                    
                    # Update last_id to the last message in the batch
                    last_id = messages[-1][0]
            
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
    except Exception as e:
        logger.error("Failed to close CTI client during shutdown", error=str(e))
    try:
        await ActiveFirewall.close()
    except Exception as e:
        logger.error("Failed to close firewall during shutdown", error=str(e))
    logger.info("Relay shutting down")

app = FastAPI(
    title="Sentinel Core Relay", 
    version="3.0.0",
    lifespan=lifespan
)

# Middleware
# Restrict CORS to localhost origins only — prevents CSRF from third-party sites.
# For production deployments, set SENTINEL_CORS_ORIGIN env var to the actual dashboard URL.
import os as _os
_cors_origins = _os.environ.get(
    "SENTINEL_CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Request ID Middleware
import time as _time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response as StarletteResponse
from common.metrics import PROM_API_REQUESTS, PROM_API_LATENCY


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        # Add to structlog context for this request
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Records per-endpoint request counts and latency for Prometheus scraping."""

    async def dispatch(self, request: Request, call_next):
        # Normalise the path (strip IDs) for low-cardinality metric labels
        path = request.url.path
        start = _time.perf_counter()
        response = await call_next(request)
        elapsed = _time.perf_counter() - start

        PROM_API_REQUESTS.labels(
            method=request.method,
            endpoint=path,
            status_code=str(response.status_code)
        ).inc()
        PROM_API_LATENCY.labels(endpoint=path).observe(elapsed)
        return response


app.add_middleware(RequestIDMiddleware)
app.add_middleware(PrometheusMiddleware)

# Include Routers
from relay.routes import (
    health, config_api, mitigation_api, intelligence_api,
    simulation, forensics, models, lab, pcap
)

app.include_router(health.router)
app.include_router(config_api.router)
app.include_router(mitigation_api.router)
app.include_router(intelligence_api.router)
app.include_router(models.router)
app.include_router(lab.router)
app.include_router(forensics.router)
app.include_router(pcap.router)
app.include_router(simulation.router)

# Developer-only routes — only mounted when DEV_MODE is enabled.
# This ensures /api/dev/reset is NEVER reachable in production.
if DEV_MODE:
    from relay.routes import dev as dev_routes
    app.include_router(dev_routes.router)
    logger.warning("DEV_MODE is enabled — developer endpoints are active")



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
            # Keep connection alive and handle ping/pong
            msg = await websocket.receive_text()
            try:
                import orjson
                data = orjson.loads(msg)
                if data.get('type') == 'ping':
                    await websocket.send_text(orjson.dumps({'type': 'pong'}).decode())
            except Exception:
                pass
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
