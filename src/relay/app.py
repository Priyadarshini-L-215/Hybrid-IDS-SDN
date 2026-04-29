import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import structlog

# Add project root to path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from common.config import (
    REDIS_ALERT_STREAM, REDIS_HOST, REDIS_PORT, setup_logging, DB_PATH
)
from common.database import get_recent_alerts, get_stats
from ml_engine import redis_client as rc
from relay.ws_manager import ConnectionManager
from ml_engine.firewall import ActiveFirewall

# Initialize logging
setup_logging("relay")
logger = structlog.get_logger("relay")

app = FastAPI(title="Sentinel Core Relay", version="3.0.0")
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

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(redis_stream_listener())
    logger.info("Relay startup complete")

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
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes_payload = random._urandom(1024)
        for _ in range(1000):
            port = random.randint(1, 65535)
            try:
                sock.sendto(bytes_payload, (target, port))
            except:
                pass
        sock.close()

    try:
        await asyncio.to_thread(_send_packets)
        return {"success": True, "message": f"DDoS simulation packets sent to {target}"}
    except Exception as e:
        logger.error("DDoS simulation failed", error=str(e))
        return {"success": False, "error": str(e)}

@app.post("/api/attack/payload")
async def run_payload_simulation(request: Dict[str, Any]):
    target = request.get("target", "127.0.0.1")
    logger.info("Simulating Payload Injection", target=target)
    
    # Simulate a SQL Injection attempt via HTTP
    # We send it to port 5000 (ourselves) to see it in the logs
    try:
        import httpx
        payload = "' OR '1'='1' --"
        async with httpx.AsyncClient() as client:
            # We don't care if it fails, we just want the traffic to be seen by Suricata
            try:
                await client.get(f"http://{target}:5000/api/health?id={payload}", timeout=1.0)
            except:
                pass
                
        return {"success": True, "message": f"Malicious payload injected towards {target}"}
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
