import json
import logging
import time
import asyncio
import collections
import sqlite3
import sys
from typing import Optional, List
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml_engine import redis_client
from ml_engine.firewall import ActiveFirewall
from common.config import REDIS_QUEUE_NAME, BATCH_SIZE, BATCH_FLUSH_INTERVAL
from common.database import batch_add_alerts
from common.net_utils import get_local_ip, get_gateway_ip
from common.alert_builder import build_alert_payload

logger = logging.getLogger(__name__)


class WorkerPool:
    """
    Async Worker Pool that consumes from Redis queue and processes events.
    
    Each worker task:
    1. Pops event from Redis queue (async)
    2. Extracts features + ML prediction
    3. Immediate WebSocket broadcast (async)
    4. Accumulates in batch buffer for SQLite persistence
    """

    def __init__(self, worker_count=4, ml_engine=None, broadcast_func=None, loop=None):
        self.worker_count = worker_count
        self.ml_engine = ml_engine
        self.broadcast_func = broadcast_func
        self._loop = loop  # Resolved lazily if None
        
        self.batch_buffer = []
        self.batch_lock = asyncio.Lock()
        self.batch_flush_interval = BATCH_FLUSH_INTERVAL
        
        self.worker_tasks = []
        self.flusher_task = None
        self.running = False
        
        # --- Stateful Flow Correlation (IPS) ---
        self.flow_history = collections.defaultdict(list)
        self.port_history = collections.defaultdict(dict)
        self.correlation_lock = asyncio.Lock()
        self.WINDOW_SIZE = 10.0  
        self.PORT_SCAN_THRESHOLD = 25   
        self.DOS_FLOW_THRESHOLD = 100   
        
        # Metrics (atomic via GIL — no lock needed for simple int increments)
        self.events_processed = 0
        self.events_flushed = 0
        self.errors = 0

    def start(self):
        """Start async worker tasks and flusher."""
        if self.running:
            return
            
        self.running = True
        
        # Start worker tasks
        for i in range(self.worker_count):
            task = asyncio.create_task(self._worker_loop(f"Worker-{i}"))
            self.worker_tasks.append(task)
        
        # Start flusher task
        self.flusher_task = asyncio.create_task(self._batch_flusher())
        
        logger.info(f"[WorkerPool] Started {self.worker_count} async workers")

    async def _worker_loop(self, worker_name):
        """Async worker loop: non-blocking pop from Redis."""
        # Ensure async redis is initialized
        if redis_client.async_redis_client is None:
            await redis_client.init_async_redis()
            
        while self.running:
            try:
                # Async blocking pop (wait up to 1s)
                if redis_client.async_redis_client is None:
                    await asyncio.sleep(1)
                    continue
                    
                res = await redis_client.async_redis_client.blpop(REDIS_QUEUE_NAME, timeout=1)
                
                if not res:
                    continue
                
                pop_ts = time.time()
                event_json = res[1]
                event = json.loads(event_json)
                
                if event.get("_tracer"):
                    event["_worker_pop_ts"] = pop_ts
                    logger.info(f"[TRACER] T3a Worker pop at {pop_ts:.6f}")
                
                processed = await self._process_event(event, worker_name)
                
                if processed:
                    # 1. Immediate Broadcast
                    if self.broadcast_func:
                        try:
                            await self.broadcast_func(json.dumps(processed))
                        except (ConnectionError, BrokenPipeError) as exc:
                            logger.error(f"[{worker_name}] Broadcast error: {exc}")
                        except Exception as exc: # Fallback for unknown broadcast issues
                            logger.error(f"[{worker_name}] Broadcast unexpected error: {exc}")

                    async with self.batch_lock:
                        self.batch_buffer.append(processed)
                        self.events_processed += 1
                        
                        # Threshold flush
                        if len(self.batch_buffer) >= 20: # Slightly larger threshold for async
                            await self._flush_batch()
                
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.error(f"[{worker_name}] Data format error: {exc}")
                self.errors += 1
            except Exception as exc:
                logger.error(f"[{worker_name}] Runtime error: {exc}")
                self.errors += 1
                await asyncio.sleep(0.1)

    async def _process_event(self, event, worker_name):
        """Process event, correlate, and enrich."""
        try:
            src_ip = event.get("src_ip")
            dest_ip = event.get("dest_ip")
            src_port = event.get("src_port")
            dest_port = event.get("dest_port")
            event_type = event.get("event_type")
            
            # --- Noise Filtering ---
            CONTROL_PORTS = {3000, 3001, 5000, 5001, 6379, 8765, 8766, 8777}
            local_ip = get_local_ip() or "127.0.0.1"
            gateway_ip = get_gateway_ip() or "172.25.16.1"
            INTERNAL_IPS = {"127.0.0.1", "::1", local_ip, gateway_ip}
            
            is_internal_bridge = (src_ip in INTERNAL_IPS and dest_ip in INTERNAL_IPS)
            is_control_port = (src_port in CONTROL_PORTS or dest_port in CONTROL_PORTS)
            
            if (is_control_port or is_internal_bridge or src_ip == "127.0.0.1") and event_type != "alert":
                return None
            
            # --- Tracer Bypass ---
            if event.get("_tracer"):
                worker_done_ts = time.time()
                alert_info = event.get("alert", {})
                alert = {
                    "timestamp": event.get("timestamp"),
                    "src_ip": event.get("src_ip"),
                    "dest_ip": event.get("dest_ip"),
                    "src_port": event.get("src_port"),
                    "dest_port": event.get("dest_port"),
                    "event_type": event.get("event_type"),
                    "alert_sig": alert_info.get("signature", "SENTINEL_LATENCY_PROBE"),
                    "protocol": event.get("proto") or "TCP",
                    "prediction": "normal",
                    "confidence": 100.0,
                    "severity": alert_info.get("severity", 3),
                    "category": alert_info.get("category", "Diagnostic"),
                    "id": event.get("_tracer_id"), # Use id for tracers if present
                    "_tracer": True,
                    "_tracer_id": event.get("_tracer_id"),
                    "_tracer_inject_ts": event.get("_tracer_inject_ts"),
                    "_watcher_read_ts": event.get("_watcher_read_ts"),
                    "_redis_push_ts": event.get("_redis_push_ts"),
                    "_worker_pop_ts": event.get("_worker_pop_ts"),
                    "_worker_done_ts": worker_done_ts,
                    "raw_event": event
                }
                return alert

            # --- ML Engine Inference ---
            feature_vector = self.ml_engine.extract_features(event)
            if not feature_vector:
                return None
            
            prediction = self.ml_engine.predict(feature_vector)
            if prediction.get("classification") == "error":
                prediction = {"classification": "normal", "confidence": 0.0, "layer": "error_fallback"}

            # --- Build alert using shared utility ---
            alert = build_alert_payload(event, prediction)
            
            # Filter out benign flow events that the shared builder marked as normal flows
            if event.get("event_type") == "flow" and alert["prediction"] == "normal":
                if not alert["prediction"] in {"attack", "zero-day anomaly"}:
                    return None
            
            # --- Stateful Flow Correlation ---
            if src_ip and src_ip not in INTERNAL_IPS:
                now = time.time()
                async with self.correlation_lock:
                    self.flow_history[src_ip].append(now)
                    if dest_port: self.port_history[src_ip][str(dest_port)] = now
                    
                    # Prune
                    cutoff = now - self.WINDOW_SIZE
                    self.flow_history[src_ip] = [ts for ts in self.flow_history[src_ip] if ts >= cutoff]
                    self.port_history[src_ip] = {p: ts for p, ts in self.port_history[src_ip].items() if ts >= cutoff}
                    
                    # Fix: Delete empty IP keys to prevent slow memory leak
                    if not self.flow_history[src_ip]:
                        del self.flow_history[src_ip]
                    if src_ip in self.port_history and not self.port_history[src_ip]:
                        del self.port_history[src_ip]
                    
                    # Only proceed if IP still in history (wasn't just deleted)
                    if src_ip in self.port_history and len(self.port_history[src_ip]) > self.PORT_SCAN_THRESHOLD:
                        alert.update({"prediction": "attack", "confidence": 99.0, "category": "Reconnaissance", "alert_sig": f"Port Scan ({len(self.port_history[src_ip])} ports)"})
                        self.port_history[src_ip].clear()
                    elif src_ip in self.flow_history and len(self.flow_history[src_ip]) > self.DOS_FLOW_THRESHOLD:
                        alert.update({"prediction": "attack", "confidence": 98.0, "category": "Resource Exhaustion", "alert_sig": "DoS Pattern Detected"})

            # --- IPS Actions ---
            if alert["prediction"] in {"attack", "zero-day anomaly"} and alert["confidence"] >= 95.0:
                ActiveFirewall.block(alert["src_ip"])
                alert["category"] = f"IPS Blocked - {alert['category']}"
            
            return alert
        except (KeyError, TypeError, ValueError) as exc:
            logger.error(f"[{worker_name}] Processing logic error: {exc}")
            return None
        except Exception as exc:
            logger.error(f"[{worker_name}] Processing unexpected error: {exc}")
            return None

    async def _batch_flusher(self):
        """Periodic background flush to database."""
        while self.running:
            await asyncio.sleep(self.batch_flush_interval)
            async with self.batch_lock:
                if self.batch_buffer:
                    await self._flush_batch()

    async def _flush_batch(self):
        """Offload SQLite write to thread pool executor to avoid blocking loop."""
        if not self.batch_buffer:
            return
        
        batch = list(self.batch_buffer)
        self.batch_buffer.clear()
        
        loop = asyncio.get_running_loop()
        try:
            # SQLite is blocking; run in executor
            await loop.run_in_executor(None, batch_add_alerts, batch)
            self.events_flushed += len(batch)
        except sqlite3.Error as exc:
            logger.error(f"[BatchFlusher] Database error: {exc}")
        except Exception as exc:
            logger.error(f"[BatchFlusher] Flush unexpected error: {exc}")

    def stop(self):
        """Stop all tasks."""
        self.running = False
        for task in self.worker_tasks:
            task.cancel()
        if self.flusher_task:
            self.flusher_task.cancel()
        logger.info("[WorkerPool] Async workers stopped")

    def get_status(self):
        return f"Processed: {self.events_processed}, Flushed: {self.events_flushed}, Buffered: {len(self.batch_buffer)}, Errors: {self.errors}"
