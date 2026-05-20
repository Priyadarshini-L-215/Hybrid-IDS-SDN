import asyncio
import json
import structlog
from typing import Optional
from ml_engine import redis_client as rc

logger = structlog.get_logger("ml_engine.federated_broker")

class FederatedThreatBroker:
    """
    State-of-the-Art (SOTA) Multi-Agent Federated Threat Exchange Broker.
    
    Uses Redis Pub/Sub to asynchronously synchronize dynamic ML model baselines 
    and administrative false-positive suppressions across multiple Sentinel controllers 
    operating in the network.
    """
    
    CHANNEL_NAME = "sentinel:threat_exchange"

    def __init__(self, node_id: str = "sentinel-node-1"):
        self.node_id = node_id
        self.running = False
        self.listen_task: Optional[asyncio.Task] = None

    async def broadcast_vae_threshold(self, new_threshold: float) -> int:
        """Broadcasts a VAE threshold update to all peer nodes."""
        payload = {
            "node_id": self.node_id,
            "type": "vae_threshold",
            "value": float(new_threshold)
        }
        return await self._publish(payload)

    async def broadcast_fp_suppression(self, src_ip: str, alert_sig: str) -> int:
        """Broadcasts a new false-positive suppression rule to all peer nodes."""
        payload = {
            "node_id": self.node_id,
            "type": "fp_suppression",
            "src_ip": src_ip,
            "alert_sig": alert_sig
        }
        return await self._publish(payload)

    async def _publish(self, payload: dict) -> int:
        try:
            client = rc.async_redis_client
            if client:
                message = json.dumps(payload)
                subs = await client.publish(self.CHANNEL_NAME, message)
                logger.debug("Broadcasted threat message", payload=payload, subscribers=subs)
                return subs
        except Exception as e:
            logger.error("Failed to publish threat update", error=str(e))
        return 0

    def start(self, ml_engine, fp_store):
        """Starts the background Pub/Sub listener loop."""
        if self.running:
            return
        self.running = True
        self.listen_task = asyncio.create_task(self._listen_loop(ml_engine, fp_store))
        logger.info("Federated Threat Broker started", node_id=self.node_id)

    async def stop(self):
        """Stops the background Pub/Sub listener loop."""
        self.running = False
        if self.listen_task:
            self.listen_task.cancel()
            try:
                await self.listen_task
            except asyncio.CancelledError:
                pass
        logger.info("Federated Threat Broker stopped")

    async def _listen_loop(self, ml_engine, fp_store):
        while self.running:
            try:
                client = rc.async_redis_client
                if not client:
                    await asyncio.sleep(5)
                    continue

                pubsub = client.pubsub()
                await pubsub.subscribe(self.CHANNEL_NAME)
                logger.info("Subscribed to federated threat exchange channel", channel=self.CHANNEL_NAME)

                async for message in pubsub.listen():
                    if not self.running:
                        break
                    try:
                        if message and message["type"] == "message":
                            await self._handle_message(message["data"], ml_engine, fp_store)
                    except Exception as loop_err:
                        logger.error("PubSub processing error", error=str(loop_err))
                        
            except asyncio.CancelledError:
                break
            except Exception as conn_err:
                logger.error("PubSub subscribe connection failed", error=str(conn_err))
                await asyncio.sleep(5)

    async def _handle_message(self, data_str: str, ml_engine, fp_store):
        try:
            data = json.loads(data_str)
            sender_id = data.get("node_id")
            
            # Skip messages broadcasted by ourselves to prevent loop feedback
            if sender_id == self.node_id:
                return

            msg_type = data.get("type")
            if msg_type == "vae_threshold":
                new_threshold = float(data.get("value", 0.0))
                # Sync VAE baseline threshold on current ML Engine
                detector = getattr(ml_engine, "vae_detector", None)
                if detector:
                    old_threshold = detector.threshold
                    detector.threshold = new_threshold
                    logger.info("Federated Sync: Updated VAE threshold from peer", 
                                peer=sender_id, old=old_threshold, new=new_threshold)
                                
            elif msg_type == "fp_suppression":
                src_ip = data.get("src_ip")
                alert_sig = data.get("alert_sig")
                if src_ip and alert_sig:
                    # Sync local false-positive suppression rules
                    await fp_store.add_suppression(src_ip, alert_sig)
                    logger.info("Federated Sync: Added suppression rule from peer", 
                                peer=sender_id, src_ip=src_ip, alert_sig=alert_sig)
                                
        except Exception as e:
            logger.error("Failed to process federated sync message", error=str(e))
