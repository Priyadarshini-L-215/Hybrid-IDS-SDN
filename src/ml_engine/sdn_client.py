# sdn_client.py - Async Client for Ryu SDN Controller
# Interfaces with the SentinelRestController REST API.

import httpx
import structlog
from typing import Optional, List, Dict, Any

logger = structlog.get_logger(__name__)

class SDNClient:
    """SDN Mitigation Client — communicates with Ryu Controller via REST."""

    def __init__(self, controller_url: str = "http://127.0.0.1:8080"):
        self.base_url = controller_url.rstrip('/')
        self.api_url = f"{self.base_url}/sdn"
        self._client = httpx.AsyncClient(timeout=5.0)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    async def block(self, ip: str, ttl: int = 0) -> bool:
        """Install DROP flow rule for source IP."""
        try:
            resp = await self._client.post(f"{self.api_url}/block", json={"ip": ip, "ttl": ttl})
            if resp.status_code == 200:
                logger.info("SDN: Blocked IP", ip=ip, ttl=ttl)
                return True
            logger.error("SDN: Block failed", status=resp.status_code, body=resp.text)
        except Exception as e:
            logger.error("SDN: Block connection error", error=str(e))
        return False

    async def unblock(self, ip: str) -> bool:
        """Remove DROP flow rule."""
        try:
            resp = await self._client.post(f"{self.api_url}/unblock", json={"ip": ip})
            if resp.status_code == 200:
                logger.info("SDN: Unblocked IP", ip=ip)
                return True
            logger.error("SDN: Unblock failed", status=resp.status_code, body=resp.text)
        except Exception as e:
            logger.error("SDN: Unblock connection error", error=str(e))
        return False

    async def get_flows(self) -> Dict[str, Any]:
        """Fetch current flow rules and stats from controller."""
        try:
            resp = await self._client.get(f"{self.api_url}/flows")
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.error("SDN: Get flows failed", error=str(e))
        return {"blocked_ips": [], "status": "offline"}

    async def close(self):
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # Synchronous Variants (for use in non-async contexts/nested loops)
    
    def block_sync(self, ip: str, ttl: int = 0) -> bool:
        """Synchronous version of block."""
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.post(f"{self.api_url}/block", json={"ip": ip, "ttl": ttl})
                return resp.status_code == 200
        except Exception as e:
            logger.error("SDN: Block sync error", error=str(e))
        return False

    def unblock_sync(self, ip: str) -> bool:
        """Synchronous version of unblock."""
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.post(f"{self.api_url}/unblock", json={"ip": ip})
                return resp.status_code == 200
        except Exception as e:
            logger.error("SDN: Unblock sync error", error=str(e))
        return False

    def get_flows_sync(self) -> Dict[str, Any]:
        """Synchronous version of get_flows."""
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{self.api_url}/flows")
                if resp.status_code == 200:
                    return resp.json()
        except Exception as e:
            logger.error("SDN: Get flows sync failed", error=str(e))
        return {"blocked_ips": [], "status": "offline"}
