# sdn_client.py - SDN Client
# Interfaces with the SentinelRestController REST API.

import httpx
import requests
import structlog
import httpx
from typing import Optional, Dict, Any

logger = structlog.get_logger(__name__)

class SDNClient:
    """SDN Mitigation Client — communicates with Ryu Controller via REST."""

    def __init__(self, controller_url: Optional[str] = None):
        from common.config import SDN_CONTROLLER_HOST, SDN_CONTROLLER_PORT
        if controller_url is None:
            controller_url = f"http://{SDN_CONTROLLER_HOST}:{SDN_CONTROLLER_PORT}"
        self.base_url = controller_url.rstrip('/')
        self.api_url = f"{self.base_url}/sdn"
        self._async_client = None

    async def __aenter__(self):
        self._async_client = httpx.AsyncClient(timeout=5.0)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    async def block(self, ip: str, ttl: int = 0) -> bool:
        """Install DROP flow rule for source IP."""
        try:
            if not self._async_client:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(f"{self.api_url}/block", json={"ip": ip, "ttl": ttl})
                    return resp.status_code == 200
            
            resp = await self._async_client.post(f"{self.api_url}/block", json={"ip": ip, "ttl": ttl})
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
            if self._async_client:
                resp = await self._async_client.post(f"{self.api_url}/unblock", json={"ip": ip})
                if resp.status_code == 200:
                    logger.info("SDN: Unblocked IP", ip=ip)
                    return True
                logger.error("SDN: Unblock failed", status=resp.status_code, body=resp.text)
            else:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(f"{self.api_url}/unblock", json={"ip": ip})
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
            if not self._async_client:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(f"{self.api_url}/flows")
                    if resp.status_code == 200:
                        return resp.json()
                    return {"blocked_ips": [], "status": "offline"}

            resp = await self._async_client.get(f"{self.api_url}/flows")
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.error("SDN: Get flows failed", error=str(e))
        return {"blocked_ips": [], "status": "offline"}

    async def block_shape(self, ip: str, protocol: str, dport: int, ttl: int = 300) -> bool:
        """Install DROP flow rule for a specific source IP, protocol, and destination port shape."""
        try:
            client = self._async_client or httpx.AsyncClient(timeout=5.0)
            resp = await client.post(
                f"{self.api_url}/block_shape", 
                json={"ip": ip, "protocol": protocol, "dport": dport, "ttl": ttl}
            )
            if not self._async_client:
                await client.aclose()
            if resp.status_code == 200:
                logger.info("SDN: Blocked protocol shape", ip=ip, proto=protocol, dport=dport, ttl=ttl)
                return True
            logger.error("SDN: Block shape failed", status=resp.status_code, body=resp.text)
        except Exception as e:
            logger.error("SDN: Block shape connection error", error=str(e))
        return False

    async def redirect_to_honeypot(self, ip: str, honeypot_ip: str, ttl: int = 300) -> bool:
        """Redirects all traffic from a source IP to a dynamic honeypot decoy."""
        try:
            client = self._async_client or httpx.AsyncClient(timeout=5.0)
            resp = await client.post(
                f"{self.api_url}/redirect", 
                json={"ip": ip, "honeypot_ip": honeypot_ip, "ttl": ttl}
            )
            if not self._async_client:
                await client.aclose()
            if resp.status_code == 200:
                logger.info("SDN: Redirected IP to Honeypot decoy", ip=ip, honeypot=honeypot_ip, ttl=ttl)
                return True
            logger.error("SDN: Honeypot redirect failed", status=resp.status_code, body=resp.text)
        except Exception as e:
            logger.error("SDN: Honeypot redirect connection error", error=str(e))
        return False

    async def quarantine_host(self, ip: str, vlan_id: Optional[int] = None, ttl: int = 300) -> bool:
        """Tells Ryu controller to isolate the specified source IP in a quarantine VLAN."""
        try:
            if vlan_id is None:
                from common.config import QUARANTINE_VLAN_ID
                vlan_id = QUARANTINE_VLAN_ID

            client = self._async_client or httpx.AsyncClient(timeout=5.0)
            resp = await client.post(
                f"{self.api_url}/quarantine", 
                json={"ip": ip, "vlan_id": vlan_id, "ttl": ttl}
            )
            if not self._async_client:
                await client.aclose()
            if resp.status_code == 200:
                logger.info("SDN: Quarantined host into VLAN", ip=ip, vlan_id=vlan_id, ttl=ttl)
                return True
            logger.error("SDN: Quarantine failed", status=resp.status_code, body=resp.text)
        except Exception as e:
            logger.error("SDN: Quarantine connection error", error=str(e))
        return False

    async def close(self):
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None

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
