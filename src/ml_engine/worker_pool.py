import json
import time
import asyncio
import structlog
from typing import Optional, List, Callable
from common.config import REDIS_QUEUE_NAME, BATCH_SIZE, BATCH_FLUSH_INTERVAL, SDN_ENABLED
from ml_engine import redis_client as rc
from ml_engine.firewall import ActiveFirewall
from ml_engine.engine import MLEngine
from ml_engine.cti_client import get_cti_client
from ml_engine.drift_detector import DriftDetector
from common.alert_builder import build_alert_payload
from common.fp_store import fp_store
from ml_engine.baseline_updater import baseline_monitor, BaselineUpdater
from ml_engine.deep_models import deep_manager
import numpy as np

class NPEncoder(json.JSONEncoder):
    """Custom JSON Encoder for NumPy types (NumPy 2.0 compatible)."""
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NPEncoder, self).default(obj)

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
        self.batch_size = BATCH_SIZE
        self.batch_flush_interval = BATCH_FLUSH_INTERVAL
        self.ml_engine = ml_engine or MLEngine()
        self.broadcast_func = broadcast_func
        
        # De-duplication Engine (Sliding Window)
        import threading
        self.dedup_cache = {} # Key: (src, dst, pred), Value: {last_emit, count}
        self.dedup_lock = None
        
        self.running = False
        self.worker_tasks = []
        
        # Stats
        self.processed_count = 0
        self.error_count = 0
        self.start_time = time.time()
        
        # Initialize Drift Detector & Baseline Updater
        self.drift_detector = DriftDetector(on_drift=self._on_drift_detected)
        self.baseline_updater = BaselineUpdater(self.ml_engine, baseline_monitor)
        self.normal_mse_buffer = [] # Buffer for auto-refresh
        
        # SOTA: Federated Threat Broker
        from ml_engine.federated_broker import FederatedThreatBroker
        self.federated_broker = FederatedThreatBroker(node_id="sentinel-node-1")
        
        # Persistent GeoIP Reader
        self.geoip_reader = None
        self.geoip_fallback_cache = {} # IP -> record
        try:
            from geolite2 import geolite2
            self.geoip_reader = geolite2.reader()
            logger.info("GeoIP database initialized")
        except Exception as e:
            logger.warning("Failed to initialize GeoIP reader, will use fallback", error=str(e))
            
        # Tier 2: Deep Inference Queue
        self.deep_queue = asyncio.Queue()

    async def _get_fallback_geoip(self, ip: str) -> Optional[dict]:
        """Fetch GeoIP data from a public API as a fallback."""
        # SSRF Guard: only query public, globally-routable IPs
        try:
            import ipaddress as _ip
            addr = _ip.ip_address(ip)
            if not addr.is_global:
                return None  # Skip private/loopback/link-local/multicast
            # Reassign ip to the validated and normalized string representation
            # This prevents SSRF via malformed strings that bypass initial checks
            # but behave maliciously in urllib
            ip = str(addr)
        except ValueError:
            return None

        if ip in self.geoip_fallback_cache:
            return self.geoip_fallback_cache[ip]
            
        def fetch():
            import urllib.request
            import json
            try:
                with urllib.request.urlopen(f"http://ip-api.com/json/{ip}", timeout=2) as response:
                    if response.status == 200:
                        return json.loads(response.read().decode())
            except Exception:
                return None
            return None

        loop = asyncio.get_running_loop()
        record = await loop.run_in_executor(None, fetch)
        if record and record.get("status") == "success":
            self.geoip_fallback_cache[ip] = record
            return record
        return None

    async def start(self):
        """Start async worker tasks."""
        if self.running: return
        self.running = True
        if self.dedup_lock is None:
            self.dedup_lock = asyncio.Lock()
        
        # Ensure Redis is ready
        if not rc.async_redis_client:
            await rc.init_async_redis()

        # Start workers
        for i in range(self.worker_count):
            task = asyncio.create_task(self._worker_loop(f"worker-{i}"))
            self.worker_tasks.append(task)
            
        # Start cache cleanup task
        self.worker_tasks.append(asyncio.create_task(self._cleanup_task()))
        
        # Start Deep Inference loop
        self.worker_tasks.append(asyncio.create_task(self._deep_inference_loop()))
        
        # Start PEL recovery task
        self.worker_tasks.append(asyncio.create_task(self._recover_pending_messages()))
        
        # Start Federated Threat Broker
        if hasattr(self, "federated_broker"):
            self.federated_broker.start(self.ml_engine, fp_store)
            
        logger.info("Worker pool started", count=self.worker_count)

    async def _cleanup_task(self):
        """Periodically purges old entries from the deduplication cache."""
        while self.running:
            await asyncio.sleep(60) # Cleanup every minute
            now = time.time()
            async with self.dedup_lock:
                # Purge entries older than 30 seconds
                keys_to_remove = [k for k, v in self.dedup_cache.items() if now - v['last_emit'] > 30]
                for k in keys_to_remove:
                    del self.dedup_cache[k]
            if keys_to_remove:
                logger.debug("Dedup cache cleaned", removed=len(keys_to_remove))

    async def _deep_inference_loop(self):
        """Asynchronously processes events using heavy Tier 2 Deep Models without blocking routing."""
        logger.info("Deep Inference Queue started.")
        while self.running:
            try:
                # Get batch of events to evaluate deeply
                alert, event = await self.deep_queue.get()
                
                # Extract sequence metrics (simulated from current flow state)
                # In production this would be raw sliding window packets
                src_ip = alert.get("src_ip")
                
                # Mock packet sequence extraction for Transformer
                # (sizes, iats)
                dummy_sequence = np.random.rand(1, 10, 4)
                
                def run_inference():
                    return deep_manager.evaluate_sequence(dummy_sequence)
                    
                loop = asyncio.get_running_loop()
                score = await loop.run_in_executor(None, run_inference)
                
                # If Tier 2 detects something Tier 1 missed
                if score > 0.85 and alert.get("prediction") == "normal":
                    logger.warning("Tier 2 Deep Model flagged an anomaly!", src_ip=src_ip, score=score)
                    # Issue retroactive block
                    await self._apply_mitigation(alert, {"prediction": "zero-day anomaly", "final_score": score})
                    
                self.deep_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Deep inference failed", error=str(e))
                await asyncio.sleep(1)

    async def _recover_pending_messages(self):
        """Reclaims and processes messages stuck in the Pending Entries List (PEL)."""
        group_name = "sentinel_workers"
        await asyncio.sleep(5) # Wait for workers to settle
        
        while self.running:
            try:
                # Read pending messages for this group (ID '0' means pending)
                # We use a dummy consumer name 'recovery-worker'
                streams = await rc.async_redis_client.xreadgroup(
                    group_name, "recovery-worker", {REDIS_QUEUE_NAME: "0"}, count=100, block=10
                )
                
                if not streams:
                    await asyncio.sleep(300) # Check every 5 minutes
                    continue
                
                for _, messages in streams:
                    if not messages: continue
                    logger.info("PEL Recovery: processing pending messages", count=len(messages))
                    # Extract IDs and data
                    batch_ids = [m[0] for m in messages]
                    batch_msgs = []
                    for m_id, data in messages:
                        try:
                            batch_msgs.append(json.loads(data["event"]))
                        except Exception:
                            await rc.async_redis_client.xack(REDIS_QUEUE_NAME, group_name, m_id)
                    
                    if batch_msgs:
                        results = self.ml_engine.predict_batch(batch_msgs)
                        # Minimal processing for recovery (just broadcast/ACK)
                        for i, res in enumerate(results):
                            alert = build_alert_payload(batch_msgs[i], res)
                            if self.broadcast_func:
                                await self.broadcast_func([alert])
                        
                        await rc.async_redis_client.xack(REDIS_QUEUE_NAME, group_name, *batch_ids)
                
            except Exception as e:
                logger.debug("PEL recovery loop error", error=str(e))
                await asyncio.sleep(60)

    async def _worker_loop(self, worker_id: str):
        """Main loop: XREADGROUP -> Batch Process -> ACK."""
        group_name = "sentinel_workers"
        
        # Ensure group exists (Read from latest '$' to avoid backlog flood)
        try:
            await rc.async_redis_client.xgroup_create(
                REDIS_QUEUE_NAME, group_name, id="$", mkstream=True
            )
        except Exception:
            pass # Already exists

        last_heartbeat = 0
        while self.running:
            try:
                # 0. Write Heartbeat for Health Check (Redis-based)
                now = time.time()
                if now - last_heartbeat > 5.0:
                    try:
                        await rc.async_redis_client.setex(
                            f"sentinel_heartbeat:{worker_id}", 30, 
                            json.dumps({"ts": now, "status": "active", "processed": self.processed_count})
                        )
                        last_heartbeat = now
                    except Exception as e:
                        logger.debug("Failed to write worker heartbeat", worker=worker_id, error=str(e))

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
                
                # Update drift detector with ML scores and monitor baseline drift
                for i, res in enumerate(results):
                    ml_score = res.get("ml_score", 0.0)
                    await self.drift_detector.update(ml_score)
                    
                    # Unconditionally extract and remove _feature_vector to prevent memory leaks
                    # and pollution of downstream alert payloads.
                    feat_vec = res.pop("_feature_vector", None)

                    # Track VAE drift if prediction is normal (using raw MSE proxy)
                    if res.get("prediction") == "normal":
                        mse = res.get("anomaly_score", 0.0)
                        if baseline_monitor.add_samples(np.array([mse])):
                            # Drift detected!
                            await self._on_drift_detected({"type": "vae_drift", "mse": mse})
                        
                        # Buffer ACTUAL feature vectors for retraining
                        if feat_vec is not None and len(self.normal_mse_buffer) < 1000:
                            self.normal_mse_buffer.append(feat_vec)
                
                # 3. Finalize Alerts and Mitigation in PARALLEL
                async def prepare_alert(raw_event, res):
                    alert = build_alert_payload(raw_event, res)
                    alert["processing_time_ms"] = batch_lat
                    
                    # FP Suppression Check
                    if await fp_store.is_suppressed(alert.get("src_ip"), alert.get("alert_sig")):
                        # Still count as processed but don't broadcast
                        return None
                    
                    # 3a. De-duplication Check
                    dedup_key = (alert["src_ip"], alert.get("dst_ip"), alert["prediction"])
                    now = time.time()
                    should_broadcast = True
                    
                    async with self.dedup_lock:
                        entry = self.dedup_cache.get(dedup_key)
                        dedup_window = 5.0 if alert.get("prediction") != "normal" else 0.5
                        if entry and (now - entry['last_emit'] < dedup_window):
                            entry['count'] += 1
                            should_broadcast = False
                        else:
                            prev_count = entry['count'] if entry else 0
                            self.dedup_cache[dedup_key] = {'last_emit': now, 'count': 0}
                            alert["duplicate_count"] = prev_count + 1
                    
                    if not should_broadcast:
                        return None
                    
                    # 3b. Enrichment & CTI (Parallelizable network calls)
                    await self._enrich_event(alert)
                    
                    # 3b-2. Push to Tier 2 Asynchronous Deep Inference
                    # We only deep-inspect a sample of normal traffic to save compute, but all suspicious traffic
                    if alert.get("prediction") != "normal" or time.time() % 10 < 2:
                        try:
                            self.deep_queue.put_nowait((alert, raw_event))
                        except asyncio.QueueFull:
                            pass
                    
                    # 3c. Re-evaluate decision if CTI data is present
                    cti_score = alert.get("enrichment", {}).get("cti", {}).get("reputation_score", 0.0)
                    if cti_score > 0:
                        new_class, new_conf = self.ml_engine.decision_engine.decide(
                            sig_present=alert.get("sig_present", False),
                            ml_score=res.get("ml_score", 0.0),
                            anomaly_score=res.get("anomaly_score", 0.0),
                            cti_score=cti_score
                        )
                        alert["prediction"] = new_class
                        alert["confidence"] = round(new_conf * 100, 2)
                        res["prediction"] = new_class
                        res["final_score"] = new_conf
                    
                    # 3d. Apply Mitigation
                    await self._apply_mitigation(alert, res)
                    return alert

                # Execute all alert preparation tasks in parallel
                tasks = [prepare_alert(batch_msgs[i], results[i]) for i in range(len(results))]
                processed_alerts = await asyncio.gather(*tasks)
                
                alerts_to_send = [a for a in processed_alerts if a is not None]
                self.processed_count += len(alerts_to_send)
                
                # 4. Broadcast & Persist
                if self.broadcast_func and alerts_to_send:
                    await self.broadcast_func(alerts_to_send)
                
                # 5. ACK Batch
                if batch_ids:
                    await rc.async_redis_client.xack(REDIS_QUEUE_NAME, group_name, *batch_ids)

            except Exception as e:
                logger.error("Worker loop error", error=str(e), exc_info=True, worker=worker_id)
                self.error_count += 1
                # Backoff to prevent rapid error loops
                await asyncio.sleep(2)
                # Try to reconnect Redis if connection lost
                try:
                    await rc.init_async_redis()
                except Exception as reinit_err:
                    logger.warning("Failed to reinitialize Redis", error=str(reinit_err), worker=worker_id)

    async def _on_drift_detected(self, drift_info: dict):
        """Broadcast drift alert and trigger auto-refresh if VAE drift."""
        
        # 1. Trigger Auto-Refresh if VAE drifted and we have enough samples
        if drift_info.get("type") == "vae_drift" and len(self.normal_mse_buffer) > 500:
            try:
                # Use the real feature vectors buffered from normal traffic
                X_normal = np.array(self.normal_mse_buffer, dtype=np.float32)
                if X_normal.ndim == 2 and X_normal.shape[1] > 0:
                    asyncio.create_task(self.baseline_updater.run_update(X_normal))
                    logger.info("Triggered baseline auto-refresh with real feature vectors",
                                n_samples=len(X_normal))
                else:
                    logger.warning("Skipping baseline refresh: feature buffer has unexpected shape",
                                   shape=X_normal.shape)
                self.normal_mse_buffer = []  # clear buffer after use
            except Exception as e:
                logger.error("Auto-refresh trigger failed", error=str(e))

        # 2. Broadcast to UI
        if self.broadcast_func:
            try:
                drift_alert = {
                    "event_id": f"drift-{int(time.time())}",
                    "event_type": "system_alert",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "prediction": "drift_detected",
                    "confidence": 98.0,
                    "alert_sig": "Model Drift Detected" if drift_info.get("type") != "vae_drift" else "VAE Baseline Drift",
                    "category": "System health",
                    "details": drift_info,
                    "forensics": {
                        "packet_hash": "system-event",
                        "stage_scores": {
                            "signature": 0.0,
                            "ml": 0.98,
                            "anomaly": 0.0
                        }
                    }

                }

                await self.broadcast_func([drift_alert])
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
        action = await ActiveFirewall.process_incident(src_ip, delta)
        
        if action in {"permanent_block", "temp_block", "rate_limit"}:
            alert["mitigation"] = action.replace('_', ' ').upper()
            alert["sdn_action"] = action
            alert["is_mitigated"] = True
            alert["category"] = f"IPS {action.replace('_', ' ').title()} - {alert.get('category', 'Threat')}"
            
            # Map action to SDN terms if using SDN
            if SDN_ENABLED:
                alert["sdn_action"] = "drop" if "block" in action else "limit"
                
            logger.warning("IPS Mitigation Triggered", ip=src_ip, action=action, score=res["final_score"])
            
            # Send external alert for critical mitigations
            if res["final_score"] > 0.95 or action == "permanent_block":
                await self._send_external_alert(alert)

    async def _send_external_alert(self, alert: dict):
        """Mocks sending an alert to an external Slack webhook."""
        payload = {
            "text": f"🚨 *CRITICAL THREAT DETECTED*\n"
                    f"*Type:* {alert['prediction']}\n"
                    f"*Source:* {alert['src_ip']} ({alert['enrichment'].get('location', 'Unknown')})\n"
                    f"*Confidence:* {alert['confidence']}%\n"
                    f"*Action:* {alert.get('mitigation', 'LOG ONLY')}\n"
                    f"*MITRE:* {alert['mitre'].get('id')} - {alert['mitre'].get('technique')}"
        }
        # Mocking the HTTP call
        logger.info("EXTERNAL ALERT SENT (MOCK)", target="Slack", payload=payload)
        # In production: await httpx.post("https://hooks.slack.com/services/MOCK/WEBHOOK/URL", json=payload)

    async def _enrich_event(self, alert: dict):
        """Adds GeoIP and ASN metadata to the alert (V2 Enrichment Layer)."""
        src_ip = alert.get("src_ip", "")
        if not src_ip: return

        if src_ip.startswith(("192.168.", "10.", "127.", "172.")):
            alert["enrichment"] = {
                "location": "Internal / Localhost",
                "country": "LOCAL",
                "asn": "AS0 (Internal)"
            }
        else:
            try:
                record = None
                if self.geoip_reader:
                    record = self.geoip_reader.get(src_ip)
                
                if record:
                    country = record.get("country", {}).get("names", {}).get("en", "Unknown")
                    country_code = record.get("country", {}).get("iso_code", "Unknown")
                    asn = record.get("autonomous_system_number", "Unknown")
                    org = record.get("autonomous_system_organization", "")
                    city = record.get("city", {}).get("names", {}).get("en", "")
                    location = record.get("location", {})
                    alert["enrichment"] = {
                        "location": f"{city}, {country}".strip(", "),
                        "country": country,
                        "country_code": country_code,
                        "asn": f"AS{asn}" if asn != "Unknown" else "Unknown",
                        "isp": org or "Unknown",
                        "city": city or "Unknown",
                        "lat": location.get("latitude"),
                        "lon": location.get("longitude")
                    }
                else:
                    # Fallback to public API
                    fallback = await self._get_fallback_geoip(src_ip)
                    if fallback:
                        alert["enrichment"] = {
                            "location": f"{fallback.get('city', '')}, {fallback.get('country', '')}".strip(", "),
                            "country": fallback.get("country", "Unknown"),
                            "country_code": fallback.get("countryCode", "Unknown"),
                            "asn": fallback.get("as", "Unknown"),
                            "isp": fallback.get("isp", "Unknown"),
                            "city": fallback.get("city", "Unknown"),
                            "lat": fallback.get("lat"),
                            "lon": fallback.get("lon")
                        }
                    else:
                        alert["enrichment"] = {"location": "Remote IP", "country": "Unknown", "asn": "Unknown", "isp": "Unknown"}
            except Exception:
                alert["enrichment"] = {"location": "Remote IP", "country": "Unknown", "asn": "Unknown"}

        # CTI Integration
        cti = get_cti_client()
        cti_data = await cti.get_ip_reputation(src_ip)
        alert["enrichment"]["cti"] = cti_data

    async def stop(self):
        self.running = False
        for t in self.worker_tasks:
            t.cancel()
        if self.worker_tasks:
            await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        self.worker_tasks = []

        if hasattr(self, "federated_broker"):
            await self.federated_broker.stop()

        from ml_engine.cti_client import close_cti_client
        await close_cti_client()
        logger.info("Worker pool stopped")

    def get_status(self):
        return {
            "processed": self.processed_count,
            "errors": self.error_count,
            "uptime": round(time.time() - self.start_time, 2)
        }
