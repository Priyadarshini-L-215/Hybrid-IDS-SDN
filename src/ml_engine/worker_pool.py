import threading
import json
import logging
import time
import asyncio
import collections
import sys
from typing import Optional
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml_engine.redis_client import redis_client
from ml_engine.firewall import ActiveFirewall
from common.config import REDIS_QUEUE_NAME, BATCH_SIZE, BATCH_FLUSH_INTERVAL
from common.database import batch_add_alerts

logger = logging.getLogger(__name__)


class WorkerPool:
    """
    Pool of worker threads that consume from Redis queue and process events.
    
    Each worker:
    1. Pops event from Redis queue
    2. Extracts features + ML prediction
    3. Accumulates in batch buffer
    4. Periodic flush to database + WebSocket broadcast
    """

    def __init__(self, worker_count=4, ml_engine=None, broadcast_func=None, loop=None):
        """
        Initialize worker pool.
        
        Args:
            worker_count: Number of parallel worker threads
            ml_engine: MLEngine instance for feature extraction + prediction
            broadcast_func: async function(message: str) for WebSocket broadcast
            loop: The event loop to run the broadcast_func in
        """
        self.worker_count = worker_count
        self.ml_engine = ml_engine
        self.broadcast_func = broadcast_func
        self.loop = loop or asyncio.get_event_loop()
        self.batch_buffer = []
        self.batch_lock = threading.RLock()
        self.batch_flush_interval = BATCH_FLUSH_INTERVAL
        self.workers = []
        self.flusher_thread = None
        self.running = False
        
        # --- Stateful Flow Correlation (IPS) ---
        # Tracks flow timestamps per source IP: {ip: [ts1, ts2, ...]}
        self.flow_history = collections.defaultdict(list)
        # Tracks unique destination ports per source IP: {ip: set(...)}
        self.port_history = collections.defaultdict(set)
        self.correlation_lock = threading.RLock()
        self.WINDOW_SIZE = 10.0  # seconds
        self.PORT_SCAN_THRESHOLD = 25   # unique ports within window
        self.DOS_FLOW_THRESHOLD = 100   # flows within window
        
        # Metrics
        self.events_processed = 0
        self.events_flushed = 0
        self.errors = 0
        self.metrics_lock = threading.Lock()

    def start(self):
        """Start worker threads and batch flusher."""
        self.running = True
        
        # Start worker threads
        for i in range(self.worker_count):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"Worker-{i}",
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        # Start batch flusher thread
        self.flusher_thread = threading.Thread(
            target=self._batch_flusher,
            name="BatchFlusher",
            daemon=True
        )
        self.flusher_thread.start()
        
        logger.info(f"[WorkerPool] Started {self.worker_count} parallel workers")

    def _worker_loop(self):
        """
        Main worker loop: consume from Redis, process, accumulate.
        """
        worker_name = threading.current_thread().name
        
        while self.running:
            try:
                # Blocking pop from Redis (1 second timeout)
                event_json = redis_client.blpop(REDIS_QUEUE_NAME, timeout=1)
                
                if not event_json:
                    # Timeout; check again
                    continue
                
                pop_ts = time.time()  # T3a: moment event was popped from Redis
                
                # event_json is (key, value)
                event = json.loads(event_json[1])
                
                # Stamp tracer events with T3a
                if event.get("_tracer"):
                    event["_worker_pop_ts"] = pop_ts
                    logger.info(f"[TRACER] T3a Worker pop at {pop_ts:.6f}")
                
                # Process event
                processed = self._process_event(event, worker_name)
                
                if processed:
                    # Broadcast immediately
                    if self.broadcast_func and self.loop:
                        try:
                            asyncio.run_coroutine_threadsafe(
                                self.broadcast_func(json.dumps(processed)), 
                                self.loop
                            )
                        except Exception as e:
                            logger.error(f"[{worker_name}] Broadcast schedule error: {e}")

                    # Add to batch buffer
                    with self.batch_lock:
                        self.batch_buffer.append(processed)
                        
                        # Increment processed counter
                        with self.metrics_lock:
                            self.events_processed += 1
                        
                        # Flush if buffer hits 10 events (don't wait for interval)
                        if len(self.batch_buffer) >= 10:
                            self._flush_batch()
                
            except Exception as e:
                logger.error(f"[{worker_name}] Error: {e}")
                with self.metrics_lock:
                    self.errors += 1
                time.sleep(0.1)

    def _process_event(self, event, worker_name):
        """
        Extract features, predict, correlate, return enriched alert.
        
        Args:
            event: Suricata EVE event (dict)
            worker_name: Name of calling worker thread (for logging)
            
        Returns:
            Alert dict or None if processing failed
        """
        try:
            # --- TRACER BYPASS: Handle diagnostic probes immediately ---
            if event.get("_tracer"):
                worker_done_ts = time.time()  # T3b: Processing complete
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
                    "_tracer": True,
                    "_tracer_id": event.get("_tracer_id"),
                    "_tracer_inject_ts": event.get("_tracer_inject_ts"),
                    "_watcher_read_ts": event.get("_watcher_read_ts"),
                    "_redis_push_ts": event.get("_redis_push_ts"),
                    "_worker_pop_ts": event.get("_worker_pop_ts"),
                    "_worker_done_ts": worker_done_ts,
                    "raw_event": event
                }
                logger.info(f"[TRACER] T3b Worker done at {worker_done_ts:.6f}")
                return alert

            start_time = time.perf_counter()
            
            # Feature extraction
            feature_vector = self.ml_engine.extract_features(event)
            if not feature_vector:
                return None
            
            extract_time = (time.perf_counter() - start_time) * 1000  # ms
            
            # ML Prediction
            start_time_predict = time.perf_counter()
            prediction = self.ml_engine.predict(feature_vector)
            predict_time = (time.perf_counter() - start_time_predict) * 1000  # ms
            
            # Log timing (debug level)
            logger.debug(
                f"[{worker_name}] {event.get('src_ip', 'unknown')} → "
                f"{event.get('dest_ip', 'unknown')}: "
                f"extract={extract_time:.1f}ms, predict={predict_time:.1f}ms, "
                f"confidence={prediction.get('confidence', 0):.0f}%"
            )
            
            # 1. Classification Override (Suricata Priority)
            final_classification = prediction.get("classification")
            final_confidence = prediction.get("confidence")
            
            if event.get("event_type") == "alert":
                final_classification = "attack"
                final_confidence = max(final_confidence, 90.0)

            # 2. Dynamic Signature Enrichment (Fixes "Unknown" signatures)
            alert_info = event.get("alert", {})
            sig = alert_info.get("signature")
            
            if not sig:
                etype = event.get("event_type", "flow")
                if etype == "dns":
                    dns = event.get("dns", {})
                    sig = f"DNS Query: {dns.get('rrname', 'unknown')}"
                elif etype == "http":
                    http = event.get("http", {})
                    sig = f"HTTP {http.get('http_method')} -> {http.get('hostname', 'unknown')}"
                elif etype == "ssh":
                    sig = "SSH Connection Attempt"
                else:
                    proto = event.get("proto", event.get("protocol", "TCP"))
                    port = event.get("dest_port", "")
                    sig = f"{proto} Potential Probe (Port {port})" if final_classification == "attack" else f"{proto} Flow"

            # Build enriched alert
            alert = {
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "src_port": event.get("src_port"),
                "dest_port": event.get("dest_port"),
                "event_type": event.get("event_type"),
                "alert_sig": sig,
                "protocol": event.get("proto") or event.get("protocol", "unknown"),
                "prediction": final_classification,
                "confidence": final_confidence,
                "severity": alert_info.get("severity", 5),
                "category": alert_info.get("category", "ML Detection"),
                "raw_event": event
            }
            
            # --- 3. Stateful Flow Correlation (IPS) ---
            src_ip = alert.get("src_ip")
            if src_ip and src_ip not in ("127.0.0.1", "::1", "172.25.16.1"):
                now = time.time()
                with self.correlation_lock:
                    self.flow_history[src_ip].append(now)
                    if alert.get("dest_port"):
                        self.port_history[src_ip].add(alert["dest_port"])
                    
                    # Prune stale entries outside window
                    self.flow_history[src_ip] = [
                        ts for ts in self.flow_history[src_ip]
                        if now - ts < self.WINDOW_SIZE
                    ]
                    
                    detected = False
                    if len(self.port_history[src_ip]) > self.PORT_SCAN_THRESHOLD:
                        alert["prediction"] = "attack"
                        alert["confidence"] = 99.0
                        alert["alert_sig"] = f"Stateful Port Scan (Targeting {len(self.port_history[src_ip])} ports)"
                        alert["category"] = "Reconnaissance"
                        detected = True
                        self.port_history[src_ip].clear()  # Reset after detection
                    
                    if len(self.flow_history[src_ip]) > self.DOS_FLOW_THRESHOLD:
                        alert["prediction"] = "attack"
                        alert["confidence"] = 98.0
                        alert["alert_sig"] = "Volumetric Flow Anomaly (DoS Pattern)"
                        alert["category"] = "Resource Exhaustion"
                        detected = True
                    
                    if detected:
                        final_classification = alert["prediction"]
                        final_confidence = alert["confidence"]

            # --- 4. Active IPS (Firewall) ---
            if alert["prediction"] == "attack" and alert["confidence"] >= 95.0:
                ActiveFirewall.block(alert["src_ip"])
                alert["category"] = f"IPS Blocked - {alert.get('category', 'Threat')}"
            
            return alert
            
        except Exception as e:
            logger.error(f"[{worker_name}] Process error: {e}")
            with self.metrics_lock:
                self.errors += 1
            return None

    def _batch_flusher(self):
        """
        Periodically flush accumulated alerts to database.
        Runs in background thread.
        """
        while self.running:
            time.sleep(self.batch_flush_interval)
            with self.batch_lock:
                if self.batch_buffer:
                    self._flush_batch()

    def _flush_batch(self):
        """
        Flush batch_buffer to database (must be called with batch_lock held).
        """
        if not self.batch_buffer:
            return
        
        batch_size = len(self.batch_buffer)
        
        try:
            # Batch insert to SQLite
            batch_add_alerts(self.batch_buffer)
            
            with self.metrics_lock:
                self.events_flushed += batch_size
            
            logger.debug(f"[BatchFlusher] Flushed {batch_size} alerts to database")
            self.batch_buffer.clear()
            
        except Exception as e:
            logger.error(f"[BatchFlusher] Flush error: {e}")
            with self.metrics_lock:
                self.errors += 1

    def stop(self):
        """Stop all workers gracefully."""
        logger.info("[WorkerPool] Stopping workers...")
        self.running = False
        
        for worker in self.workers:
            worker.join(timeout=5)
        
        if self.flusher_thread:
            self.flusher_thread.join(timeout=5)
        
        # Final flush
        with self.batch_lock:
            if self.batch_buffer:
                self._flush_batch()
        
        logger.info("[WorkerPool] All workers stopped")

    def get_metrics(self):
        """Get worker pool metrics."""
        with self.metrics_lock:
            return {
                "events_processed": self.events_processed,
                "events_flushed": self.events_flushed,
                "buffer_size": len(self.batch_buffer),
                "errors": self.errors
            }

    def get_status(self):
        """Get human-readable status."""
        metrics = self.get_metrics()
        return (
            f"[WorkerPool] "
            f"Processed: {metrics['events_processed']}, "
            f"Flushed: {metrics['events_flushed']}, "
            f"Buffered: {metrics['buffer_size']}, "
            f"Errors: {metrics['errors']}"
        )
