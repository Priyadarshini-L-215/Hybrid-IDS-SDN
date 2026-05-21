import asyncio
import json
import structlog
import time
from typing import Optional
from ml_engine import redis_client as rc
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

logger = structlog.get_logger("ml_engine.federated_broker")

class FederatedThreatBroker:
    """
    State-of-the-Art (SOTA) Multi-Agent Federated Threat Exchange Broker.
    
    Uses Redis Pub/Sub to asynchronously synchronize cryptographically verified 
    ML model baselines and administrative false-positive suppressions across multiple 
    Sentinel controllers operating in the network.
    """
    
    CHANNEL_NAME = "sentinel:threat_exchange"

    def __init__(self, node_id: str = "sentinel-node-1"):
        self.node_id = node_id
        self.running = False
        self.listen_task: Optional[asyncio.Task] = None
        self._private_key = None
        self._public_key_pem = None
        self._init_keys()

    def _init_keys(self):
        """Initializes elliptic curve keys for the federated node."""
        from pathlib import Path
        keys_dir = Path("data/keys")
        keys_dir.mkdir(parents=True, exist_ok=True)
        priv_path = keys_dir / f"{self.node_id}_private.pem"
        pub_path = keys_dir / f"{self.node_id}_public.pem"
        
        if priv_path.exists():
            try:
                with open(priv_path, "rb") as f:
                    self._private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
                logger.info("Loaded node ECDSA private key for federated security", node_id=self.node_id)
            except Exception as e:
                logger.error("Failed to load private key, generating new...", error=str(e))
                self._generate_new_keys(priv_path, pub_path)
        else:
            self._generate_new_keys(priv_path, pub_path)
            
        self._public_key_pem = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Publish public key to Redis registry
        try:
            client = rc.redis_client
            if client:
                client.hset("sentinel:node_keys", self.node_id, self._public_key_pem.decode('utf-8'))
                logger.info("Registered public key in threat exchange registry", node_id=self.node_id)
        except Exception as e:
            logger.warning("Failed to register public key in Redis", error=str(e))

    def _generate_new_keys(self, priv_path, pub_path):
        logger.info("Generating new ECDSA P-256 key pair...", node_id=self.node_id)
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        # Save private key
        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        # Save public key
        with open(pub_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
        self._private_key = private_key

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
                # Add timestamp to prevent replay attacks
                payload["timestamp"] = time.time()
                
                # Sort keys for deterministic canonical serialization
                canonical_str = json.dumps(payload, sort_keys=True)
                
                # Cryptographically sign canonical payload
                signature_bytes = self._private_key.sign(
                    canonical_str.encode('utf-8'),
                    ec.ECDSA(hashes.SHA256())
                )
                
                wrapped = {
                    "payload": payload,
                    "signature": signature_bytes.hex(),
                    "sender_id": self.node_id
                }
                
                message = json.dumps(wrapped)
                subs = await client.publish(self.CHANNEL_NAME, message)
                logger.debug("Broadcasted secure threat message", payload=payload, subscribers=subs)
                return subs
        except Exception as e:
            logger.error("Failed to publish secure threat update", error=str(e))
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
            wrapped = json.loads(data_str)
            sender_id = wrapped.get("sender_id")
            
            # Skip messages broadcasted by ourselves to prevent loop feedback
            if sender_id == self.node_id:
                return

            payload = wrapped.get("payload")
            sig_hex = wrapped.get("signature")
            
            if not payload or not sig_hex or not sender_id:
                logger.warning("Threat exchange: Blocked malformed unsecure message (missing wrapper fields)")
                return

            # 1. Anti-Replay Skew Verification
            msg_time = float(payload.get("timestamp", 0))
            if time.time() - msg_time > 10.0:
                logger.warning("Threat exchange: Blocked expired threat message due to replay skew", 
                               sender=sender_id, age=round(time.time() - msg_time, 2))
                return

            # 2. Cryptographic Signature Verification
            client = rc.async_redis_client
            if not client:
                logger.error("Async Redis client unavailable for key lookup")
                return

            peer_key_pem = await client.hget("sentinel:node_keys", sender_id)
            if not peer_key_pem:
                logger.warning("Threat exchange: Public key not registered for peer node", peer=sender_id)
                await client.hincrby("sentinel:peer_failures", sender_id, 1)
                return

            try:
                peer_pub_key = serialization.load_pem_public_key(peer_key_pem.encode('utf-8'))
                
                # Reconstruct canonical payload string for verification
                canonical_str = json.dumps(payload, sort_keys=True)
                sig_bytes = bytes.fromhex(sig_hex)
                
                # Elliptic curve cryptographically verified signature match
                peer_pub_key.verify(
                    sig_bytes,
                    canonical_str.encode('utf-8'),
                    ec.ECDSA(hashes.SHA256())
                )
            except InvalidSignature:
                logger.critical("SECURITY ALERT: Invalid cryptographic signature from federated peer!", 
                                peer=sender_id)
                await client.hincrby("sentinel:peer_failures", sender_id, 1)
                return
            except Exception as parse_err:
                logger.error("Failed to parse peer public key or verify signature", error=str(parse_err))
                return

            # 3. Process validated payload
            msg_type = payload.get("type")
            if msg_type == "vae_threshold":
                new_threshold = float(payload.get("value", 0.0))
                # Sync VAE baseline threshold on current ML Engine
                detector = getattr(ml_engine, "vae_detector", None)
                if detector:
                    old_threshold = detector.threshold
                    detector.threshold = new_threshold
                    logger.info("Federated Sync: Updated VAE threshold from verified peer", 
                                peer=sender_id, old=old_threshold, new=new_threshold)
                                
            elif msg_type == "fp_suppression":
                src_ip = payload.get("src_ip")
                alert_sig = payload.get("alert_sig")
                if src_ip and alert_sig:
                    # Sync local false-positive suppression rules
                    await fp_store.add_suppression(src_ip, alert_sig)
                    logger.info("Federated Sync: Added suppression rule from verified peer", 
                                peer=sender_id, src_ip=src_ip, alert_sig=alert_sig)
                                
        except Exception as e:
            logger.error("Failed to process secured federated sync message", error=str(e))
