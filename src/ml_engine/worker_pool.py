import json
import time
import asyncio
import structlog
from typing import Optional, List, Callable
from common.config import REDIS_QUEUE_NAME, BATCH_SIZE, BATCH_FLUSH_INTERVAL
from ml_engine import redis_client as rc
from ml_engine.firewall import ActiveFirewall
from ml_engine.engine import MLEngine
from ml_engine.drift_detector import DriftDetector
from common.alert_builder import build_alert_payload

logger = structlog.get_logger(__name__)

class WorkerPool:
    """
    Async Worker Pool for processing Redis Streams.
    Orchestrates: Consume -> ML Engine -> Decision -> IPS Mitigation -> Broadcast.
    """

    def __init__(self, 
                 worker_count: int = 4, 
                 ml_engine: MLEngine = None, 
                 broadcast_func: Callable = None):
        
        self.worker_count = worker_count
        self.ml_engine = ml_engine or MLEngine()
        self.broadcast_func = broadcast_func
        
        self.running = False
        self.worker_tasks = []
        
        # Stats
        self.processed_count = 0
        self.error_count = 0
        self.start_time = time.time()
        
        # Initialize Drift Detector
        self.drift_detector = DriftDetector(on_drift=self._on_drift_detected)

    async def start(self):
        """Start async worker tasks."""
        if self.running: return
        self.running = True
        
        # Ensure Redis is ready
        if not rc.async_redis_client:
            await rc.init_async_redis()

        # Start workers
        for i in range(self.worker_count):
            task = asyncio.create_task(self._worker_loop(f"worker-{i}"))
            self.worker_tasks.append(task)
            
        logger.info("Worker pool started", count=self.worker_count)

    async def _worker_loop(self, worker_id: str):
        """Main loop: XREADGROUP -> Batch Process -> ACK."""
        group_name = "sentinel_workers"
        
        # Ensure group exists
        try:
            await rc.async_redis_client.xgroup_create(
                REDIS_QUEUE_NAME, group_name, id="0", mkstream=True
            )
        except Exception:
            pass # Already exists

        while self.running:
            try:
                # 1. Read Batch
                streams = await rc.async_redis_client.xreadgroup(
                    group_name, worker_id, {REDIS_QUEUE_NAME: ">"}, count=BATCH_SIZE, block=100
                )
                
                if not streams:
                    continue
                
                logger.debug("Worker received batch", worker=worker_id, count=len(streams[0][1]))
                batch_msgs = []
                batch_ids = []
                
                # Unpack Stream Response
                for _, messages in streams:
                    for msg_id, data in messages:
                        try:
                            # data["event"] is the JSON payload from ingestion
                            event_data = json.loads(data["event"])
                            batch_msgs.append(event_data)
                            batch_ids.append(msg_id)
                        except Exception as e:
                            logger.error("Failed to parse event", error=str(e), msg_id=msg_id)
                            await rc.async_redis_client.xack(REDIS_QUEUE_NAME, group_name, msg_id)
                
                if not batch_msgs:
                    continue

                # 2. Process Batch via ML Engine
                t_batch_start = time.time()
                results = self.ml_engine.predict_batch(batch_msgs)
                t_batch_end = time.time()
                batch_lat = (t_batch_end - t_batch_start) * 1000 / (len(results) or 1)
                
                # Update drift detector with ML scores
                for res in results:
                    self.drift_detector.update(res.get("ml_score", 0.0))
                
                # 3. Finalize Alerts and Mitigation
                alerts_to_send = []
                for i, res in enumerate(results):
                    raw_event = batch_msgs[i]
                    
                    # Create standard alert payload
                    alert = build_alert_payload(raw_event, res)
                    alert["processing_time_ms"] = batch_lat
                    
                    # Apply Mitigation Logic
                    await self._apply_mitigation(alert, res)
                    
                    alerts_to_send.append(alert)
                    self.processed_count += 1
                
                # 4. Broadcast
                if self.broadcast_func:
                    for alert in alerts_to_send:
                        await self.broadcast_func(json.dumps(alert))
                
                # 5. ACK Batch
                if batch_ids:
                    await rc.async_redis_client.xack(REDIS_QUEUE_NAME, group_name, *batch_ids)

            except Exception as e:
                logger.error("Worker loop error", error=str(e), worker=worker_id)
                self.error_count += 1
                await asyncio.sleep(1)

    async def _on_drift_detected(self, drift_info: dict):
        """Broadcast drift alert to WebSocket clients via the broadcast func."""
        if self.broadcast_func:
            try:
                await self.broadcast_func(json.dumps(drift_info))
            except Exception as e:
                logger.error("Failed to broadcast drift alert", error=str(e))

    async def _apply_mitigation(self, alert: dict, res: dict):
        """Interface with ActiveFirewall for IPS actions."""
        src_ip = alert.get("src_ip")
        if not src_ip: return
        
        # Calculate reputation delta from decision engine
        delta = self.ml_engine.decision_engine.get_reputation_delta(
            res["prediction"], res["final_score"]
        )
        
        # Trigger firewall
        action = ActiveFirewall.process_incident(src_ip, delta)
        
        if action in {"permanent_block", "temp_block", "rate_limit"}:
            alert["mitigation"] = action.replace('_', ' ').upper()
            alert["is_mitigated"] = True
            alert["category"] = f"IPS {action.replace('_', ' ').title()} - {alert.get('category', 'Threat')}"
            logger.warning("IPS Mitigation Triggered", ip=src_ip, action=action, score=res["final_score"])

    def stop(self):
        self.running = False
        for t in self.worker_tasks: t.cancel()
        logger.info("Worker pool stopped")

    def get_status(self):
        return {
            "processed": self.processed_count,
            "errors": self.error_count,
            "uptime": round(time.time() - self.start_time, 2)
        }
