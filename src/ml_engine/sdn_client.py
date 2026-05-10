# sdn_client.py - SDN Client using requests as fallback for httpx
# Interfaces with the SentinelRestController REST API via executor for async.

import requests
import asyncio
import structlog
from typing import Optional, List, Dict, Any

logger = structlog.get_logger(__name__)

class SDNClient:
    """SDN Mitigation Client — communicates with Ryu Controller via REST."""

    def __init__(self, controller_url: Optional[str] = None):
        from common.config import SDN_CONTROLLER_HOST, SDN_CONTROLLER_PORT
        if controller_url is None:
            controller_url = f"http://{SDN_CONTROLLER_HOST}:{SDN_CONTROLLER_PORT}"
        self.base_url = controller_url.rstrip('/')
        self.api_url = f"{self.base_url}/sdn"

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    async def block(self, ip: str, ttl: int = 0) -> bool:
        """Install DROP flow rule for source IP."""
        def fetch():
            try:
                return requests.post(f"{self.api_url}/block", json={"ip": ip, "ttl": ttl}, timeout=5.0)
            except Exception:
                return None

        try:
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(None, fetch)
            if resp and resp.status_code == 200:
                logger.info("SDN: Blocked IP", ip=ip, ttl=ttl)
                return True
            if resp:
                logger.error("SDN: Block failed", status=resp.status_code, body=resp.text)
        except Exception as e:
            logger.error("SDN: Block connection error", error=str(e))
        return False

    async def unblock(self, ip: str) -> bool:
        """Remove DROP flow rule."""
        def fetch():
            try:
                return requests.post(f"{self.api_url}/unblock", json={"ip": ip}, timeout=5.0)
            except Exception:
                return None

        try:
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(None, fetch)
            if resp and resp.status_code == 200:
                logger.info("SDN: Unblocked IP", ip=ip)
                return True
            if resp:
                logger.error("SDN: Unblock failed", status=resp.status_code, body=resp.text)
        except Exception as e:
            logger.error("SDN: Unblock connection error", error=str(e))
        return False

    async def get_flows(self) -> Dict[str, Any]:
        """Fetch current flow rules and stats from controller."""
        def fetch():
            try:
                return requests.get(f"{self.api_url}/flows", timeout=5.0)
            except Exception:
                return None

        try:
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(None, fetch)
            if resp and resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.error("SDN: Get flows failed", error=str(e))
        return {"blocked_ips": [], "status": "offline"}

    async def close(self):
        pass

    # Synchronous Variants
    
    def block_sync(self, ip: str, ttl: int = 0) -> bool:
        """Synchronous version of block."""
        try:
            resp = requests.post(f"{self.api_url}/block", json={"ip": ip, "ttl": ttl}, timeout=3.0)
            return resp.status_code == 200
        except Exception as e:
            logger.error("SDN: Block sync error", error=str(e))
        return False

    def unblock_sync(self, ip: str) -> bool:
        """Synchronous version of unblock."""
        try:
            resp = requests.post(f"{self.api_url}/unblock", json={"ip": ip}, timeout=3.0)
            return resp.status_code == 200
        except Exception as e:
            logger.error("SDN: Unblock sync error", error=str(e))
        return False

    def get_flows_sync(self) -> Dict[str, Any]:
        """Synchronous version of get_flows."""
        try:
            resp = requests.get(f"{self.api_url}/flows", timeout=3.0)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.error("SDN: Get flows sync failed", error=str(e))
        return {"blocked_ips": [], "status": "offline"}
